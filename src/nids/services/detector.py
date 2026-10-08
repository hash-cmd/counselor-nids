"""Detector service — one detector as an independent process (Figure 1, 6-8).

The main loop classifies the samples the Observer routes to it and asks the other
detectors for advice over Redis. A background thread answers their advice requests
from this detector's own decisions.
"""

import hashlib
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import joblib

import numpy as np
import pandas as pd
import redis

from ..counselor import CounselorNetwork
from ..detector.detector import Detector
from . import bus
from . import feedback
from .snort_counselor import RedisSnortCounselor, wait_for_snort


class RemoteCounselor:
    """Another detector service, reached through Redis.

    Exposes the same ``advise_many`` as a local Detector, so CounselorNetwork can use
    it unchanged.
    """

    def __init__(self, r: redis.Redis, name: str, timeout: float = 5.0):
        self.r, self.name, self.timeout = r, name, timeout

    def advise_many(self, timestamps: np.ndarray, window: float):
        n = len(timestamps)
        none = (np.zeros(n, dtype=bool), np.zeros(n, dtype=bool), np.zeros(n))
        if n == 0:
            return none
        request_id = uuid.uuid4().hex
        self.r.rpush(bus.advice_requests(self.name), json.dumps({
            "timestamps": np.asarray(timestamps, dtype=float).tolist(),
            "window": window,
            "reply_to": bus.advice_reply(request_id),
        }))
        try:
            reply = self.r.blpop(bus.advice_reply(request_id), timeout=self.timeout)
        except redis.TimeoutError:
            reply = None
        if reply is None:
            return none
        answer = json.loads(reply[1])
        return (np.array(answer["found"], dtype=bool), np.array(answer["prediction"], dtype=bool),
                np.array(answer["confidence"], dtype=float))


@dataclass
class State:
    detector: Detector | None = None  # the current model (replaced when a retrained one is installed)
    watermark: float = -np.inf  # latest timestamp this detector has analysed
    ended: bool = False
    stop: threading.Event = field(default_factory=threading.Event)


RELOAD_EVERY = 30.0  # seconds between checks for an installed, retrained model


def installed_model(path: Path, seen: float) -> tuple[Detector | None, float]:
    """A newer model file at ``path`` if one was installed since ``seen`` (its mtime) and it
    matches its SHA256SUMS line — model files are pickles, so a file that does not match is
    never loaded. Returns (detector or None, the mtime it was checked at)."""
    try:
        mtime = path.stat().st_mtime
        if mtime == seen:
            return None, seen
        sums = (path.parent / "SHA256SUMS").read_text().split()
        expected = dict(zip(sums[1::2], sums[0::2])).get(path.name)
        if expected != hashlib.sha256(path.read_bytes()).hexdigest():
            return None, seen  # being written, or not promoted: check again later
        detector = joblib.load(path)
        detector.clear_history()
        return detector, mtime
    except (OSError, ValueError, EOFError):
        return None, seen


def serve_advice(r: redis.Redis, name: str, state: State, wait: float) -> None:
    """Answer advice requests. Waits (up to ``wait`` s) until this detector has analysed
    the requested timestamps, since detectors run concurrently."""
    while not state.stop.is_set():
        request = r.blpop(bus.advice_requests(name), timeout=1)
        if request is None:
            continue
        request = json.loads(request[1])
        timestamps = np.array(request["timestamps"], dtype=float)
        deadline = time.monotonic() + wait
        while (state.watermark < timestamps.max() and not state.ended
               and time.monotonic() < deadline):
            time.sleep(0.02)
        found, prediction, confidence = state.detector.advise_many(timestamps, request["window"])
        r.rpush(request["reply_to"], json.dumps({
            "found": found.tolist(), "prediction": prediction.tolist(),
            "confidence": confidence.tolist()}))
        r.expire(request["reply_to"], 60)


def _endpoints(frame: pd.DataFrame) -> tuple[pd.Series | None, pd.Series | None]:
    """Source and destination as "ip:port" when the flows carry them (packet captures);
    replayed flow records only know the destination port."""
    port = frame["conn_dst_port"] if "conn_dst_port" in frame else frame.get("Destination Port")
    if "src_ip" in frame:
        src = frame["src_ip"].astype(str) + ":" + frame["src_port"].astype(int).astype(str)
        dst = frame["dst_ip"].astype(str) + ":" + port.astype(int).astype(str)
        return src, dst
    if port is not None:
        return None, "port " + port.astype(int).astype(str)
    return None, None


def record(r: redis.Redis, name: str, frame: pd.DataFrame, final: pd.DataFrame) -> None:
    """Update counters, breakdowns and the alerts stream."""
    resolution = final["resolution"].value_counts()
    attack = final["prediction"].to_numpy(dtype=bool)
    counters = {
        "samples": len(final), "flagged_attack": int(attack.sum()),
        "conflicts": int(final["conflict"].sum()),
        "advice:snort": int((final["counselor"] == "snort").sum()) if "counselor" in final else 0,
        **{f"resolution:{k}": int(v) for k, v in resolution.items()},
    }
    src, dst = _endpoints(frame)
    flagged_rows = final.index[attack]
    flagged_ids = frame.loc[flagged_rows, "record_id"].astype(int).tolist()
    if len(flagged_rows):  # so an analyst's verdict on these alarms can be learned from later
        keep = r.pipeline()
        feedback.remember_flows(keep, frame, flagged_rows)
        keep.execute()

    # Flows flagged by any detector, counted once: breakdowns grow only for flows
    # no other detector has flagged yet.
    if flagged_ids:
        pipe = r.pipeline()
        for record_id in flagged_ids:
            pipe.sadd(bus.FLAGGED_ML, record_id)
        new = [row for row, added in zip(flagged_rows, pipe.execute()) if added]
    else:
        new = []

    pipe = r.pipeline()
    for key, value in counters.items():
        pipe.hincrby(bus.stats(name), key, value)
    pipe.expire(bus.FLAGGED_ML, 3600)
    for row in new:
        if src is not None:
            pipe.hincrby(bus.ML_SOURCES, frame.at[row, "src_ip"], 1)

    now = time.time()
    for row in flagged_rows:
        result = final.loc[row]
        entry = {
            "detector": name, "record_id": int(frame.at[row, "record_id"]), "timestamp": float(result.timestamp),
            "time": now, "resolution": str(result.resolution), "counselor": result.counselor or "",
        }
        if src is not None:
            entry["src"] = src.at[row]
        if dst is not None:
            entry["dst"] = dst.at[row]
        pipe.xadd(bus.ALERTS, entry, maxlen=bus.ALERTS_KEPT, approximate=True)
    pipe.execute()


def run(
    r: redis.Redis,
    detector: Detector,
    sources: list[str],
    min_accuracy: float = 0.9,
    window: float = 0.0,
    cross_check: bool = False,
    retrain_every: int = 0,
    advice_wait: float = 2.0,
    exit_on_end: bool = False,
    max_history: int = 2_000_000,
    suppress_fallback: bool = False,
    snort_counselor: bool = False,
    model_path: Path | None = None,
) -> None:
    """``model_path``: watch this file and switch to a retrained model once one is
    installed there (learn_feedback.py), without a restart."""
    state = State(detector=detector)
    r.hset(bus.SUBSCRIPTIONS, detector.name, json.dumps(sources))
    threading.Thread(target=serve_advice, args=(r, detector.name, state, advice_wait), daemon=True).start()
    seen = model_path.stat().st_mtime if model_path else 0.0
    next_check = time.monotonic() + RELOAD_EVERY

    last = "0"
    try:
        while True:
            if model_path and time.monotonic() >= next_check:
                newer, seen = installed_model(model_path, seen)
                if newer is not None and newer.name == detector.name:
                    detector = state.detector = newer
                    r.hincrby(bus.stats(detector.name), "reloaded", 1)
                    print(f"{detector.name}: switched to the newly installed model", flush=True)
                next_check = time.monotonic() + RELOAD_EVERY
            bus.beat(r, f"detector:{detector.name}", snort_counselor=snort_counselor)
            for _, messages in r.xread({bus.inbox(detector.name): last}, block=1000, count=10) or []:
                for message_id, fields in messages:
                    last = message_id
                    if bus.field(fields, "kind") == bus.END:
                        state.ended = True
                        r.sadd(bus.ENDED, detector.name)
                        continue
                    frame = bus.decode_frame(bus.field(fields, "frame"))
                    process(r, detector, frame, state, min_accuracy, window, cross_check, suppress_fallback,
                            snort_counselor, learn=bool(retrain_every))
                    detector.trim_history(max_history)
                    pending = sum(len(y) for _, y in detector.new_signatures)
                    if retrain_every and pending >= retrain_every:
                        r.hincrby(bus.stats(detector.name), "retrained_on", detector.retrain())
            # Keep answering advice until every detector has finished the stream
            # and the Snort correlator (if running) no longer needs verdicts.
            if (exit_on_end and state.ended and r.scard(bus.ENDED) >= r.hlen(bus.SUBSCRIPTIONS)
                    and not r.exists(bus.SNORT_ACTIVE)):
                return
    finally:
        state.stop.set()


def process(r, detector, frame, state, min_accuracy, window, cross_check, suppress_fallback=False,
            snort_counselor=False, learn=False) -> pd.DataFrame:
    """Classify a batch and resolve its conflicts with the counselors. ``snort_counselor``:
    Snort advises on conflicts and a trusted "attack" advice wins (counselor/network.py).
    ``learn``: keep advised samples for retraining — only when the service retrains, or
    they would pile up in memory forever."""
    results = detector.detect(frame, frame["timestamp"])
    state.watermark = max(state.watermark, float(frame["timestamp"].max()))
    conflicts = results["conflict"].to_numpy(dtype=bool)
    if snort_counselor and conflicts.any() and "flow_end" in frame:
        # ask Snort only once it has seen these connections to the end
        wait_for_snort(r, float(frame.loc[conflicts, "flow_end"].max()))
    counselors = [RemoteCounselor(r, name.decode())
                  for name in r.hkeys(bus.SUBSCRIPTIONS) if name.decode() != detector.name]
    network = CounselorNetwork([detector, *counselors], min_accuracy, window,
                               cross_check_normal=cross_check, suppress_fallback=suppress_fallback,
                               advisors=[RedisSnortCounselor(r)] if snort_counselor else [],
                               attack_advice_wins=snort_counselor, learn_from_advice=learn)
    final = network.resolve(detector, frame, results)
    record(r, detector.name, frame, final)
    # how far this detector has analysed, so the Snort correlator knows when to ask
    r.set(f"{bus.PREFIX}:watermark:{detector.name}", state.watermark)
    return final
