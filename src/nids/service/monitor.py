"""Live view of every detector's counters."""

import time

import pandas as pd
import redis

from . import bus


def snapshot(r: redis.Redis) -> pd.DataFrame:
    rows = {}
    for name in sorted(n.decode() for n in r.hkeys(bus.SUBSCRIPTIONS)):
        raw = {k.decode(): int(v) for k, v in r.hgetall(bus.stats(name)).items()}
        samples = raw.get("samples", 0)
        row = {
            "samples": samples,
            "flagged": raw.get("flagged_attack", 0),
            "conflicts": raw.get("conflicts", 0),
            "advised": raw.get("resolution:advice", 0),
            "cross_checked": raw.get("resolution:cross_check", 0),
            "fallback": raw.get("resolution:fallback", 0),
            "retrained_on": raw.get("retrained_on", 0),
        }
        if "correct" in raw and samples:
            row["accuracy"] = f"{raw['correct'] / samples:.2%}"
            if raw.get("true_attacks"):
                row["detection_rate"] = f"{raw['detected_attacks'] / raw['true_attacks']:.2%}"
        rows[name] = row
    return pd.DataFrame(rows).T


def run(r: redis.Redis, interval: float = 2.0, once: bool = False) -> None:
    while True:
        table = snapshot(r)
        print(time.strftime("%H:%M:%S"), "\n" + (table.to_string() if len(table) else "no detectors yet"),
              flush=True)
        if once:
            return
        time.sleep(interval)
