"""Analyst feedback: "Not an attack" / "Real attack" on the alarms the system raised.

Lab-trained detectors misjudge some ordinary traffic of a new network (on a home network:
long-lived HTTPS and push connections, which look like slow DoS). Snort's agreement can only
teach the AI about attacks Snort sees; this is the other half — the person watching the
dashboard says what an alarm really was, and the detectors learn from it
(scripts/live_detectors/learn_feedback.py, behind a safety gate).

Detector services keep the measurements of every connection they flag in Redis
(``nids:flow:<record id>``, 7 days), so a verdict given later can still be learned from.
Each verdict is appended to ``logs/feedback.jsonl`` together with those measurements —
durable, across runs — and held in ``nids:feedback`` for the current run, so the dashboard
can take the alarm out of its counts at once. A verdict on a connection Snort alerted on
also counts for or against each of those rules' trust.
"""

import json
import os
import time
from pathlib import Path

import pandas as pd
import redis

from . import bus
from . import snort_counselor as counsel

FLOW = f"{bus.PREFIX}:flow:"          # + record id -> the flagged flow's row (JSON)
FEEDBACK = f"{bus.PREFIX}:feedback"   # record id -> "normal" | "attack" (this run)
FLOW_TTL = 7 * 24 * 3600
VERDICTS = ("normal", "attack")
DEFAULT_FILE = Path(os.environ.get("NIDS_FEEDBACK_FILE",
                                   Path(__file__).resolve().parents[3] / "logs" / "feedback.jsonl"))


def remember_flows(pipe, frame: pd.DataFrame, rows) -> None:
    """Keep the measurements of flagged flows (first detector to flag one wins)."""
    for row in rows:
        record = frame.loc[[row]].to_json(orient="records")[1:-1]  # one JSON object
        pipe.set(f"{FLOW}{int(frame.at[row, 'record_id'])}", record, nx=True, ex=FLOW_TTL)


def mark(r: redis.Redis, record_id: int, verdict: str, note: str = "", path: Path = DEFAULT_FILE) -> dict:
    """Record a verdict on a flagged connection. Raises ValueError if the verdict is
    unknown; the entry is still recorded (without measurements) if the flow has expired."""
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {VERDICTS}")
    raw = r.get(f"{FLOW}{record_id}")
    flow = json.loads(raw) if raw else None
    run = bus.text(r.hget(bus.LIVE, "started_at") or "")
    entry = {"time": time.time(), "run": run, "record_id": int(record_id), "verdict": verdict,
             "note": note[:200], "flow": flow}
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")
    pipe = r.pipeline()
    pipe.hset(FEEDBACK, str(record_id), verdict)
    # the analyst's verdict also judges the Snort rules that fired on this connection
    for rule in r.smembers(f"{counsel.FLOW_RULES}{record_id}"):
        counsel.record_agreement(pipe, bus.text(rule), verdict == "attack")
    pipe.execute()
    return {k: v for k, v in entry.items() if k != "flow"} | {"learnable": flow is not None}


def verdicts(r: redis.Redis) -> dict[int, str]:
    """This run's verdicts: record id -> verdict."""
    return {int(bus.text(k)): bus.text(v) for k, v in r.hgetall(FEEDBACK).items()}


def read(path: Path = DEFAULT_FILE) -> list[dict]:
    """Every verdict, the latest one per connection (a connection can be re-marked)."""
    latest: dict[tuple, dict] = {}
    try:
        lines = path.read_text().splitlines()
    except FileNotFoundError:
        return []
    for line in lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        latest[(entry.get("run", ""), entry["record_id"])] = entry
    return sorted(latest.values(), key=lambda e: e["time"])


def summary(path: Path = DEFAULT_FILE) -> dict:
    entries = read(path)
    learnable = [e for e in entries if e.get("flow")]
    return {"total": len(entries),
            "normal": sum(e["verdict"] == "normal" for e in entries),
            "attack": sum(e["verdict"] == "attack" for e in entries),
            "learnable": len(learnable),
            "latest": [{k: v for k, v in e.items() if k != "flow"} for e in entries[-20:]][::-1]}
