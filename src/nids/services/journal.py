"""Alert journal — a durable record of live monitoring, to measure false alarms.

The Redis alert streams are capped and cleared at every start, so they cannot answer "how
many false alarms does the system raise on my network over a week?". The journal appends,
one JSON object per line, to ``<dir>/<YYYY-MM-DD>.jsonl``:

    {"kind": "ml", ...}      every ML alert (one per detector that flagged the flow)
    {"kind": "snort", ...}   every Snort alert, with whether the ML agreed
    {"kind": "tick", ...}    every minute: flows analysed so far in this run, interface state

``report`` reads the journal back. On a network where you are not attacking anything, every
alert is a false alarm. Times when attacks were run on purpose are left out (and counted
separately): those saved in ``<dir>/tests.json`` — the dashboard's "I'm running an attack
test" button writes them — plus any passed as ``exclude``.
"""

import json
import os
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

import redis

from . import bus
from .snort_bridge import ALERTS as SNORT_ALERTS

DEFAULT_DIR = Path(os.environ.get("NIDS_JOURNAL_DIR",
                                  Path(__file__).resolve().parents[3] / "logs" / "journal"))
GAP = 600.0  # seconds between ticks beyond which the journal was not running


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


def read(directory: Path = DEFAULT_DIR, days: int | None = None) -> list[dict]:
    """Entries of the last ``days`` days (all when None)."""
    entries = []
    paths = sorted(Path(directory).glob("*.jsonl"))
    if days is not None:
        first = datetime.fromtimestamp(time.time() - (days - 1) * 86400).strftime("%Y-%m-%d")
        paths = [p for p in paths if p.stem >= first]
    for path in paths:
        for line in path.read_text().splitlines():
            if line.strip():
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:  # a line cut short by a crash
                    continue
    return entries


def read_tests(directory: Path = DEFAULT_DIR) -> list[dict]:
    """Saved attack-test windows: [{"start", "end" (None while running), "note"}]."""
    path = Path(directory) / "tests.json"
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def write_tests(tests: list[dict], directory: Path = DEFAULT_DIR) -> None:
    path = Path(directory) / "tests.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(tests, indent=1))
    tmp.replace(path)  # atomic: a crash never leaves half a file


def start_test(note: str = "", directory: Path = DEFAULT_DIR, now: float | None = None) -> list[dict]:
    tests = read_tests(directory)
    if not any(t["end"] is None for t in tests):
        tests.append({"start": now or time.time(), "end": None, "note": note[:200]})
        write_tests(tests, directory)
    return tests


def stop_test(directory: Path = DEFAULT_DIR, now: float | None = None) -> list[dict]:
    tests = read_tests(directory)
    for t in tests:
        if t["end"] is None:
            t["end"] = now or time.time()
    write_tests(tests, directory)
    return tests


def delete_test(index: int, directory: Path = DEFAULT_DIR) -> list[dict]:
    tests = read_tests(directory)
    if 0 <= index < len(tests):
        del tests[index]
        write_tests(tests, directory)
    return tests


def windows(tests: list[dict], now: float | None = None) -> list[tuple[float, float]]:
    """(start, end) of each test; a running test lasts until now."""
    now = now or time.time()
    return [(float(t["start"]), float(t["end"] if t["end"] is not None else now)) for t in tests]


def _in(t: float, windows) -> bool:
    return any(start <= t <= end for start, end in windows)


def _day(t: float) -> str:
    return datetime.fromtimestamp(t).strftime("%Y-%m-%d")


def report(entries: list[dict], exclude=(), top: int = 10) -> dict:
    """False-alarm figures from journal entries; ``exclude`` lists (start, end) epoch
    windows when attacks were run on purpose."""
    ticks = sorted((e for e in entries if e["kind"] == "tick"), key=lambda e: float(e["time"]))
    # Flows analysed: the counters restart with every run, so add up each run's growth,
    # leaving out growth during excluded windows.
    flows, watched, last = 0, 0.0, {}
    daily: dict[str, dict] = {}

    def on(day: str) -> dict:
        return daily.setdefault(day, {"flows": 0, "hours": 0.0, "ml_flagged": 0, "snort": 0})

    for e in ticks:
        t, n = float(e["time"]), int(e["flows"])
        prev = last.get(e["run"])
        if prev is not None:
            gap = t - prev[0]
            if not _in(t, exclude) and gap < GAP:
                grown = max(n - prev[1], 0)
                flows += grown
                watched += gap
                on(_day(t))["flows"] += grown
                on(_day(t))["hours"] += gap / 3600
        last[e["run"]] = (t, n)

    def split(kind):
        rows = [e for e in entries if e["kind"] == kind]
        return ([e for e in rows if not _in(float(e["time"]), exclude)],
                [e for e in rows if _in(float(e["time"]), exclude)])

    ml, ml_tests = split("ml")
    snort, snort_tests = split("snort")
    flagged = {(e.get("run", ""), e["record_id"]): float(e["time"]) for e in ml}
    for t in flagged.values():
        on(_day(t))["ml_flagged"] += 1
    for e in snort:
        on(_day(float(e["time"])))["snort"] += 1
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
        "daily": [{"day": day, **v, "hours": round(v["hours"], 2)} for day, v in sorted(daily.items())],
    }
