"""Alert journal — a durable record of live monitoring, to measure false alarms.

The Redis alert streams are capped and cleared at every start, so they cannot answer "how
many false alarms does the system raise on my network over a week?". The journal appends,
one JSON object per line, to ``<dir>/<YYYY-MM-DD>.jsonl``:

    {"kind": "ml", ...}      every ML alert (one per detector that flagged the flow)
    {"kind": "snort", ...}   every Snort alert, with whether the ML agreed
    {"kind": "tick", ...}    every minute: flows analysed so far in this run, interface state

``report`` reads the journal back. On a network where you are not attacking anything, every
alert is a false alarm; pass the times you ran attack tests with ``exclude`` so those alerts
are left out (and counted separately).
"""

import json
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

import redis

from . import bus
from .snort_bridge import ALERTS as SNORT_ALERTS

DEFAULT_DIR = Path(__file__).resolve().parents[3] / "logs" / "journal"


def _decode(fields: dict) -> dict:
    return {bus.text(k): bus.text(v) for k, v in fields.items()}


def flows_analysed(r: redis.Redis) -> int:
    """Flows the ML has judged in this run: every live detector sees every flow, so the
    largest per-detector count."""
    counts = [int(r.hget(bus.stats(bus.text(n)), "samples") or 0) for n in r.hkeys(bus.SUBSCRIPTIONS)]
    return max(counts, default=0)


class Journal:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def write(self, entry: dict) -> None:
        entry.setdefault("time", time.time())
        day = datetime.fromtimestamp(float(entry["time"])).strftime("%Y-%m-%d")
        with open(self.directory / f"{day}.jsonl", "a") as f:
            f.write(json.dumps(entry) + "\n")


def run(r: redis.Redis, directory: Path = DEFAULT_DIR, tick: float = 60.0, block_ms: int = 2000,
        stop=lambda: False) -> None:
    """Append new alerts and a tick every ``tick`` seconds until ``stop()``."""
    journal = Journal(directory)
    # start after what is already there; "$" on every call would drop alerts written between calls
    last = {}
    for stream in (bus.ALERTS, SNORT_ALERTS):
        newest = r.xrevrange(stream, count=1)
        last[stream] = bus.text(newest[0][0]) if newest else "0-0"
    next_tick = 0.0
    while not stop():
        now = time.time()
        if now >= next_tick:
            live = _decode(r.hgetall(bus.LIVE))
            journal.write({"kind": "tick", "time": now, "run": live.get("started_at", ""),
                           "target": live.get("target", ""), "state": live.get("state", ""),
                           "flows": flows_analysed(r)})
            next_tick = now + tick
        for stream, entries in r.xread(last, block=block_ms) or []:
            stream = bus.text(stream)
            kind = "ml" if stream == bus.ALERTS else "snort"
            run_id = bus.text(r.hget(bus.LIVE, "started_at") or "")
            for entry_id, fields in entries:
                last[stream] = bus.text(entry_id)
                journal.write({"kind": kind, "run": run_id, **_decode(fields)})


def read(directory: Path = DEFAULT_DIR) -> list[dict]:
    entries = []
    for path in sorted(Path(directory).glob("*.jsonl")):
        for line in path.read_text().splitlines():
            if line.strip():
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:  # a line cut short by a crash
                    continue
    return entries


def _in(t: float, windows) -> bool:
    return any(start <= t <= end for start, end in windows)


def report(entries: list[dict], exclude=(), top: int = 10) -> dict:
    """False-alarm figures from journal entries; ``exclude`` lists (start, end) epoch
    windows when attacks were run on purpose."""
    ticks = sorted((e for e in entries if e["kind"] == "tick"), key=lambda e: float(e["time"]))
    # Flows analysed: the counters restart with every run, so add up each run's growth,
    # leaving out growth during excluded windows.
    flows, watched, last = 0, 0.0, {}
    for e in ticks:
        t, n = float(e["time"]), int(e["flows"])
        prev = last.get(e["run"])
        if prev is not None:
            gap = t - prev[0]
            if not _in(t, exclude) and gap < 600:  # a longer gap: the journal was not running
                flows += max(n - prev[1], 0)
                watched += gap
        last[e["run"]] = (t, n)

    def split(kind):
        rows = [e for e in entries if e["kind"] == kind]
        return ([e for e in rows if not _in(float(e["time"]), exclude)],
                [e for e in rows if _in(float(e["time"]), exclude)])

    ml, ml_tests = split("ml")
    snort, snort_tests = split("snort")
    flagged = {(e.get("run", ""), e["record_id"]) for e in ml}
    per_1k = lambda n: round(1000 * n / flows, 3) if flows else None  # noqa: E731
    pair = lambda e: f"{e.get('src', '?').rsplit(':', 1)[0]} -> {e.get('dst', '?')}"  # noqa: E731
    return {
        "hours_watched": round(watched / 3600, 2),
        "flows_analysed": flows,
        "ml": {
            "flagged_flows": len(flagged),
            "per_1000_flows": per_1k(len(flagged)),
            "per_hour": round(len(flagged) / (watched / 3600), 2) if watched else None,
            "by_detector": dict(Counter(e["detector"] for e in ml).most_common()),
            "top_connections": dict(Counter(pair(e) for e in ml).most_common(top)),
        },
        "snort": {
            "alerts": len(snort),
            "by_agreement": dict(Counter(e.get("agreement", "") for e in snort).most_common()),
            "top_rules": dict(Counter(e.get("msg", "") for e in snort).most_common(top)),
        },
        "excluded_test_alerts": {"ml": len(ml_tests), "snort": len(snort_tests)},
    }
