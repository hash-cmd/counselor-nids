"""Live view of every detector's counters."""

import time

import pandas as pd
import redis

from . import bus


def read_stats(r: redis.Redis) -> dict[str, dict]:
    """Counters of every subscribed detector, with accuracy and detection rate as fractions
    (None when the replayed data carries no ground truth)."""
    stats = {}
    for name in sorted(bus.text(n) for n in r.hkeys(bus.SUBSCRIPTIONS)):
        raw = {bus.text(k): int(v) for k, v in r.hgetall(bus.stats(name)).items()}
        samples = raw.get("samples", 0)
        stats[name] = {
            "samples": samples,
            "flagged": raw.get("flagged_attack", 0),
            "conflicts": raw.get("conflicts", 0),
            "advised": raw.get("resolution:advice", 0),
            "cross_checked": raw.get("resolution:cross_check", 0),
            "fallback": raw.get("resolution:fallback", 0),
            "retrained_on": raw.get("retrained_on", 0),
            "accuracy": raw["correct"] / samples if "correct" in raw and samples else None,
            "detection_rate": (raw["detected_attacks"] / raw["true_attacks"]
                               if raw.get("true_attacks") else None),
        }
    return stats


def read_alerts(r: redis.Redis, count: int = 50, after: str | None = None) -> list[dict]:
    """Newest alerts first; with ``after``, only alerts newer than that stream id."""
    entries = r.xrevrange(bus.ALERTS, "+", f"({after}" if after else "-", count=count)
    alerts = []
    for entry_id, fields in entries:
        alert: dict = {bus.text(k): bus.text(v) for k, v in fields.items()}
        alert["id"] = bus.text(entry_id)
        alert["record_id"] = int(alert["record_id"])
        alert["timestamp"] = float(alert["timestamp"])
        alert["counselor"] = alert.get("counselor") or None
        alerts.append(alert)
    return alerts


def snapshot(r: redis.Redis) -> pd.DataFrame:
    rows = {}
    for name, s in read_stats(r).items():
        row: dict[str, object] = {k: v for k, v in s.items() if k not in ("accuracy", "detection_rate")}
        if s["accuracy"] is not None:
            row["accuracy"] = f"{s['accuracy']:.2%}"
        if s["detection_rate"] is not None:
            row["detection_rate"] = f"{s['detection_rate']:.2%}"
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
