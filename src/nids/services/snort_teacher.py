"""Snort teaches the AI: a Disputed alert becomes a labelled attack the detectors retrain on.

In the 2026-11-25 attack test, Snort's signatures caught brute force, SQL injection, XSS and the
rest while the ML detectors flagged almost nothing — they had learned the lab tools' flow shapes,
not the behaviour. A *Disputed* verdict (Snort fired, the AI said normal) is therefore a labelled
attack the AI got wrong, free of charge. This module records those flows, with their measurements,
in the same JSONL shape ``services/feedback`` uses, so the existing gated retrainer
(``scripts/live_detectors/learn_feedback.py``, run via ``learn_from_snort.py``) can learn from
them without forgetting the lab attacks.

Opt-in: the detector service persists every judged flow's measurements briefly only when
``NIDS_SNORT_TEACH=1`` (otherwise only flagged flows are kept, as before), and the Snort bridge
records disputes only then. Default off, so a deployment's behaviour is unchanged until asked for.
"""

import json
import os
import time
from pathlib import Path

import redis

from . import bus, feedback

ENABLED = os.environ.get("NIDS_SNORT_TEACH", "0") == "1"
DEFAULT_FILE = Path(os.environ.get("NIDS_SNORT_TEACH_FILE",
                                   Path(__file__).resolve().parents[3] / "logs" / "snort_teach.jsonl"))


def record_disputes(r: redis.Redis, record_ids: list[int], rule: str, path: Path = DEFAULT_FILE) -> int:
    """Append the disputed flows (Snort said attack, the AI said normal) as attack-labelled
    entries, taking each flow's measurements from the short-lived per-flow store. Returns how many
    were recorded (those whose measurements were still available)."""
    if not ENABLED or not record_ids:
        return 0
    run = bus.text(r.hget(bus.LIVE, "started_at") or "")
    path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with open(path, "a") as f:
        for rid in record_ids:
            raw = r.get(f"{feedback.FLOW}{int(rid)}")
            if not raw:
                continue
            entry = {"time": time.time(), "run": run, "record_id": int(rid), "verdict": "attack",
                     "note": f"snort:{rule}", "flow": json.loads(raw)}
            f.write(json.dumps(entry) + "\n")
            written += 1
    return written
