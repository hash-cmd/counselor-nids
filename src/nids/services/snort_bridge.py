"""Snort bridge — Snort and the ML detectors analyse the same traffic.

Snort writes alerts (signature rules and inspectors). For every alert the correlator
finds the flow it belongs to, asks the ML detectors for their verdict on that flow
(the same advice request detectors use with each other), and records whether the ML
agrees:

    confirmed    Snort flagged it and the ML says attack
    disputed     Snort flagged it but the ML says normal (possible Snort false alarm)
    no_verdict   the flow was found but no detector had a confident verdict
    unmatched    no captured flow matches the alert (e.g. ICMP, which is not flow-extracted)

Flows the ML flagged and Snort did not are the "ML only" detections; they are counted
from the sets ``nids:flagged:ml`` (written by detector services) and ``nids:flagged:snort``.

Snort is also a counselor (services/snort_counselor.py): each alert is linked to its flows as
soon as they are indexed, so detectors started with --snort-counselor can take Snort's advice
on conflicts; and every Confirmed / Disputed verdict updates that rule's trust.

Snort alerts are about one flow (a web attack in one request) or about a host's
behaviour (a port scan stands for many probe connections). Host-level alerts are
linked to every flow between the two hosts within ``HOST_WINDOW`` seconds.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import redis

from . import bus, flow_index
from . import snort_counselor as counsel
from .detector import RemoteCounselor

ALERTS = f"{bus.PREFIX}:snort:alerts"
STATS = f"{bus.PREFIX}:stats:snort"
FLAGGED_SNORT = f"{bus.PREFIX}:flagged:snort"
FLAGGED_ML = bus.FLAGGED_ML
ACTIVE = bus.SNORT_ACTIVE  # detectors keep answering advice while this is set

HOST_LEVEL_GIDS = {122}  # port_scan inspector
HOST_WINDOW = 30.0
DEFAULT_CONFIG = Path(__file__).resolve().parents[3] / "snort" / "nids.lua"


def snort_command(target: str, log_dir: str, config: Path = DEFAULT_CONFIG,
                  include_path: str = "/etc/snort") -> list[str]:
    exe = shutil.which("snort") or "/usr/sbin/snort"
    source = ["-r", target] if target.endswith((".pcap", ".pcapng")) else ["-i", target]
    return [exe, "-c", str(config), "--include-path", include_path, *source, "-l", log_dir, "-q"]


def follow_alerts(path: Path, done, poll: float = 0.5):
    """Yield alerts appended to an alert_json file, and ``None`` once per poll as a
    heartbeat; stop once ``done()`` is true and the file is drained. ``done`` is checked
    before reading, so nothing written last is lost."""
    offset, buffer = 0, ""
    while True:
        finished = done()
        if path.exists():
            with open(path) as f:
                f.seek(offset)
                buffer += f.read()
                offset = f.tell()
            *lines, buffer = buffer.split("\n")
            for line in lines:
                if line.strip():
                    yield json.loads(line)
        if finished:
            return
        yield None
        time.sleep(poll)


@dataclass
class Pending:
    alert: dict
    seen: float = field(default_factory=time.monotonic)
    early: bool = False  # already linked for the Snort counselor


class Correlator:
    def __init__(self, r: redis.Redis, min_accuracy: float = 0.9, wait: float = 120.0,
                 advice_timeout: float = 5.0):
        self.r, self.min_accuracy, self.wait, self.advice_timeout = r, min_accuracy, wait, advice_timeout
        self.pending: list[Pending] = []

    def add(self, alert: dict) -> None:
        self.r.hincrby(STATS, "alerts", 1)
        self.r.hset(counsel.RULE_NAMES, counsel.rule_key(alert), alert.get("msg", ""))
        self.pending.append(Pending(alert))

    def link_early(self) -> None:
        """Record each alert's rule on its flows as soon as they are indexed, for the Snort
        counselor: detectors judge a flow seconds after it ends, before the full linking
        below (which waits for their verdicts) runs."""
        pipe = self.r.pipeline()
        for item in self.pending:
            if item.early:
                continue
            flows = self.flows_for(item.alert)
            if flows:
                for record_id in flows:
                    key = f"{counsel.FLOW_RULES}{record_id}"
                    pipe.sadd(key, counsel.rule_key(item.alert))
                    pipe.expire(key, counsel.TTL)
                item.early = True
        pipe.execute()

    def flows_for(self, alert: dict) -> list[int]:
        at = float(alert["seconds"])
        if alert.get("gid") in HOST_LEVEL_GIDS:
            return flow_index.find_host_flows(self.r, alert["proto"], alert["src_addr"], alert["dst_addr"],
                                             at, HOST_WINDOW)
        if alert.get("src_port") is None:
            return []
        found = flow_index.find_flow(self.r, alert["proto"], alert["src_addr"], alert["src_port"],
                                    alert["dst_addr"], alert["dst_port"], at)
        return [] if found is None else [found]

    def analysed_up_to(self) -> float:
        """Latest flow every detector has classified (all of them once the stream ended)."""
        if stream_ended(self.r):
            return np.inf
        names = [bus.text(d) for d in self.r.hkeys(bus.SUBSCRIPTIONS)]
        marks = [self.r.get(watermark_key(n)) for n in names]
        return min((float(m) for m in marks if m is not None), default=-np.inf) if all(marks) else -np.inf

    def process(self, final: bool = False) -> int:
        """Link what can be linked; give up on alerts older than ``wait`` (or all, if final).
        Flows are only indexed once they end, and classified a little later, so an alert
        waits until its flows exist and every detector has analysed them."""
        self.link_early()
        analysed = self.analysed_up_to()
        ready, still = [], []
        for item in self.pending:
            expired = final or time.monotonic() - item.seen > self.wait
            if item.alert.get("gid") in HOST_LEVEL_GIDS and not (expired or analysed == np.inf
                                                                   or time.monotonic() - item.seen > 2 * HOST_WINDOW):
                # covers every flow between two hosts in the window: wait until the
                # window has been captured (stream end, or live time has passed it)
                still.append(item)
                continue
            flows = self.flows_for(item.alert)
            if flows and (max(flows) <= analysed or expired):
                ready.append((item.alert, flows))
            elif not flows and expired:
                self.publish(item.alert, [], None)
            else:
                still.append(item)
        self.pending = still

        if ready:
            ids = sorted({i for _, flows in ready for i in flows})
            position = {record_id: k for k, record_id in enumerate(ids)}
            found, attack, confidence, who = self.ml_verdict(ids)
            for alert, flows in ready:
                rows = [position[f] for f in flows]
                self.resolve(alert, flows, found[rows], attack[rows], confidence[rows], who[rows])
        return len(ready)

    def ml_verdict(self, record_ids: list[int]):
        """The ML's verdict per flow: (found, attack, confidence, detector).

        Detectors are specialists: one trained on DoS confidently calls a DDoS flow
        normal. So — as with cross-checking — the flow is an attack if any detector with
        acceptable accuracy says so (the most confident of those is reported), and normal
        only when none does.
        """
        n = len(record_ids)
        attack_conf, normal_conf = np.full(n, -np.inf), np.full(n, -np.inf)
        attack_by, normal_by = np.full(n, None, dtype=object), np.full(n, None, dtype=object)
        timestamps = np.array(record_ids, dtype=float)
        for name in sorted(bus.text(d) for d in self.r.hkeys(bus.SUBSCRIPTIONS)):
            found, pred, conf = RemoteCounselor(self.r, name, self.advice_timeout).advise_many(timestamps, 0)
            ok = found & (conf >= self.min_accuracy)
            for says, best, by in ((pred, attack_conf, attack_by), (~pred, normal_conf, normal_by)):
                better = ok & says & (conf > best)
                best[better], by[better] = conf[better], name
        attack = np.isfinite(attack_conf)
        found = attack | np.isfinite(normal_conf)
        confidence = np.where(attack, attack_conf, np.where(found, normal_conf, 0.0))
        return found, attack, confidence, np.where(attack, attack_by, normal_by)

    def resolve(self, alert: dict, record_ids: list[int], found, attack, confidence, who) -> None:
        if not found.any():
            verdict = None
        else:
            # host-level alerts cover many flows: the ML agrees if it flags most of them
            share = attack[found].mean()
            first = int(np.flatnonzero(found)[0])
            verdict = {"attack": bool(share >= 0.5), "share": float(share),
                       "confidence": float(confidence[found].mean()), "detector": who[first]}
        pipe = self.r.pipeline()
        pipe.sadd(FLAGGED_SNORT, *record_ids)
        pipe.expire(FLAGGED_SNORT, flow_index.TTL)
        if verdict is not None:  # the AI agreed or disagreed with this rule: adapt its trust
            # A disagreement counts against the rule only if the AI flagged nothing from this
            # source: if it flags the source elsewhere, the dispute more likely shows a blind
            # spot of the AI (e.g. slow DoS connections) than a Snort false alarm.
            if verdict["attack"] or not self.r.hget(bus.ML_SOURCES, alert.get("src_addr", "")):
                counsel.record_agreement(pipe, counsel.rule_key(alert), verdict["attack"])
        pipe.execute()
        self.publish(alert, record_ids, verdict)

    def publish(self, alert: dict, record_ids: list[int], verdict: dict | None) -> None:
        if not record_ids:
            agreement = "unmatched"
        elif verdict is None:
            agreement = "no_verdict"
        else:
            agreement = "confirmed" if verdict["attack"] else "disputed"
        entry = {
            "seconds": alert.get("seconds", 0), "msg": alert.get("msg", ""),
            "gid": alert.get("gid", 0), "sid": alert.get("sid", 0), "priority": alert.get("priority", 0),
            "class": alert.get("class", ""), "proto": alert.get("proto", ""),
            "src": f"{alert.get('src_addr', '')}:{alert.get('src_port', '')}".rstrip(":"),
            "dst": f"{alert.get('dst_addr', '')}:{alert.get('dst_port', '')}".rstrip(":"),
            "flows": len(record_ids), "record_id": record_ids[0] if record_ids else -1,
            "agreement": agreement,
            "ml_verdict": "" if verdict is None else ("attack" if verdict["attack"] else "normal"),
            "ml_share": "" if verdict is None else verdict["share"],
            "ml_confidence": "" if verdict is None else verdict["confidence"],
            "ml_detector": "" if verdict is None else verdict["detector"],
        }
        entry["time"] = time.time()
        pipe = self.r.pipeline()
        pipe.xadd(ALERTS, entry, maxlen=bus.ALERTS_KEPT, approximate=True)
        pipe.hincrby(STATS, agreement, 1)
        pipe.hincrby(bus.SNORT_RULES, entry["msg"], 1)
        if alert.get("src_addr"):
            pipe.hincrby(bus.SNORT_SOURCES, alert["src_addr"], 1)
        pipe.execute()


def watermark_key(detector: str) -> str:
    return f"{bus.PREFIX}:watermark:{detector}"


def stream_ended(r: redis.Redis) -> bool:
    """True once every detector service has seen the end of the flow stream."""
    subscribed = r.hlen(bus.SUBSCRIPTIONS)
    return subscribed > 0 and r.scard(bus.ENDED) >= subscribed


def run(r: redis.Redis, target: str | None = None, follow: Path | None = None,
        min_accuracy: float = 0.9, wait: float = 120.0, config: Path = DEFAULT_CONFIG,
        include_path: str = "/etc/snort", trust_file: Path | None = None) -> dict:
    """Run Snort on ``target`` (pcap or interface), or follow an existing alert_json file,
    and correlate until Snort and the flow stream have both finished. With ``trust_file``
    (live mode), Snort rule trust is loaded from it and saved to it every minute."""
    correlator = Correlator(r, min_accuracy, wait)
    if trust_file is not None:
        counsel.load_trust(r, trust_file)
    saved = time.monotonic()
    r.set(ACTIVE, 1, ex=24 * 3600)
    process = None
    if follow is None:
        if target is None:
            raise ValueError("give a pcap/interface to run Snort on, or an alert file to follow")
        log_dir = tempfile.mkdtemp(prefix="nids-snort-")
        process = subprocess.Popen(snort_command(target, log_dir, config, include_path),
                                   env={**os.environ, "NIDS_SNORT_RULES": str(config.parent / "rules")})
        follow = Path(log_dir) / "alert_json.txt"

    def snort_done():
        return process is not None and process.poll() is not None

    live = target is not None and not str(target).endswith((".pcap", ".pcapng"))
    newest = [0.0]  # packet time of the latest alert

    def publish_progress():
        """How far Snort's alerts are linked, for detectors waiting on its advice: live,
        Snort runs in real time (allow 2 s for it to write alerts); a recording is read
        as fast as possible, so progress is the latest alert's packet time, then all."""
        if snort_done():
            progress = counsel.DONE
        elif live:
            progress = time.time() - 2.0
        else:
            progress = newest[0]
        r.set(counsel.PROGRESS, progress, ex=3600)

    try:
        for alert in follow_alerts(follow, snort_done):
            if alert is None:  # heartbeat
                bus.beat(r, "snort", running=process is None or process.poll() is None)
                correlator.process()
                publish_progress()
                if trust_file is not None and time.monotonic() - saved > 60:
                    counsel.save_trust(r, trust_file)
                    saved = time.monotonic()
            else:
                correlator.add(alert)
                newest[0] = max(newest[0], float(alert.get("seconds", 0)))
        # Snort finished (pcap); keep linking while the flow extractor catches up.
        correlator.process()
        publish_progress()
        while correlator.pending and not stream_ended(r):
            correlator.process()
            time.sleep(1)
        correlator.process(final=True)
    finally:
        r.delete(ACTIVE)
        if trust_file is not None:
            counsel.save_trust(r, trust_file)
        if process is not None and process.poll() is None:
            process.terminate()
    return {bus.text(k): int(v) for k, v in r.hgetall(STATS).items()}
