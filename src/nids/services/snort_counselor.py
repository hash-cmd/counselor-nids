"""Snort as a counselor in live mode, through Redis.

The Snort bridge links each alert to its connection as soon as the connection is known and
records the rule in ``nids:snort:flowrules:<record id>``. A detector service started with
``--snort-counselor`` uses ``RedisSnortCounselor`` as an advisor: when its classifiers
disagree on a connection Snort alerted on, Snort's advice is "attack", worth the trust of
the most trusted rule that fired (see counselor/snort.py).

Rule trust adapts as the system runs: the bridge counts, per rule, how often the AI agreed
(Confirmed) and disagreed (Disputed) — the AI's verdict there comes from each detector's own
confident decisions, never from Snort's advice — in ``nids:snort:trust``. A disagreement
counts only if the AI flagged nothing from the alert's source: otherwise the dispute is more
likely an AI blind spot than a Snort false alarm (without this, the rule that catches the
Slowloris connections the AI misses lost all its trust). In live mode the
counts are saved to a file, so trust survives restarts.
"""

import json
import time
from pathlib import Path

import numpy as np
import redis

from ..counselor.snort import RuleTrust
from . import bus

FLOW_RULES = f"{bus.PREFIX}:snort:flowrules:"  # + record id -> set of "gid:sid"
TRUST = f"{bus.PREFIX}:snort:trust"            # "agree:<rule>" / "disagree:<rule>" -> count
RULE_NAMES = f"{bus.PREFIX}:snort:rulenames"   # "gid:sid" -> message
PROGRESS = f"{bus.PREFIX}:snort:progress"      # packet time up to which alerts are linked
DONE = 1e18                                    # progress once Snort has read everything
TTL = 3600


def wait_for_snort(r: redis.Redis, until: float, timeout: float = 10.0, poll: float = 0.05) -> bool:
    """Wait until Snort's alerts are linked up to packet time ``until`` — so a detector
    asks Snort's advice on a connection only after Snort has seen all of it. Returns at
    once if Snort is not running; gives up after ``timeout`` seconds. True if caught up."""
    deadline = time.monotonic() + timeout
    while True:
        progress = r.get(PROGRESS)
        if progress is not None and float(progress) >= until:
            return True
        if not r.exists(bus.SNORT_ACTIVE) or time.monotonic() > deadline:
            return False
        time.sleep(poll)


def rule_key(alert: dict) -> str:
    return f"{alert.get('gid', 1)}:{alert.get('sid', 0)}"


def read_trust(r: redis.Redis, prior: float = 0.9, prior_weight: float = 20.0) -> RuleTrust:
    trust = RuleTrust(prior, prior_weight)
    for field, value in r.hgetall(TRUST).items():
        kind, _, rule = bus.text(field).partition(":")
        if kind == "agree":
            trust.update(rule, agree=int(value))
        elif kind == "disagree":
            trust.update(rule, disagree=int(value))
    return trust


def record_agreement(pipe, rule: str, agreed: bool) -> None:
    pipe.hincrby(TRUST, f"{'agree' if agreed else 'disagree'}:{rule}", 1)


def save_trust(r: redis.Redis, path: Path) -> None:
    data = {bus.text(k): int(v) for k, v in r.hgetall(TRUST).items()}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True))
    tmp.replace(path)


def load_trust(r: redis.Redis, path: Path) -> int:
    try:
        data = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return 0
    if data:
        r.hset(TRUST, mapping=data)
    return len(data)


class RedisSnortCounselor:
    """``advise_many`` over the rules the Snort bridge linked to each connection."""

    name = "snort"

    def __init__(self, r: redis.Redis, prior: float = 0.9, prior_weight: float = 20.0):
        self.r, self.prior, self.prior_weight = r, prior, prior_weight

    def advise_many(self, timestamps: np.ndarray, window: float = 0.0):
        timestamps = np.asarray(timestamps, dtype=float)
        n = len(timestamps)
        found, confidence = np.zeros(n, dtype=bool), np.zeros(n)
        if n == 0:
            return found, found.copy(), confidence
        pipe = self.r.pipeline()
        for t in timestamps:
            pipe.smembers(f"{FLOW_RULES}{int(t)}")
        rules = pipe.execute()
        if any(rules):
            trust = read_trust(self.r, self.prior, self.prior_weight)
            for i, members in enumerate(rules):
                if members:
                    found[i] = True
                    confidence[i] = max(trust.score(bus.text(m)) for m in members)
        return found, found.copy(), confidence


def trust_table(r: redis.Redis, limit: int = 20) -> list[dict]:
    """Rules the AI has judged, most-judged first: agreements, disagreements, trust."""
    trust = read_trust(r)
    names = {bus.text(k): bus.text(v) for k, v in r.hgetall(RULE_NAMES).items()}
    rows = [{"rule": rule, "msg": names.get(rule, ""), **stats} for rule, stats in trust.table().items()]
    rows.sort(key=lambda row: -(row["agree"] + row["disagree"]))
    return rows[:limit]
