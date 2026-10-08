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
        alert["time"] = float(alert["time"]) if alert.get("time") else None
        alert["counselor"] = alert.get("counselor") or None
        alert.setdefault("src", None)
        alert.setdefault("dst", None)
        alerts.append(alert)
    return alerts


def _top(r: redis.Redis, key: str, n: int) -> dict[str, int]:
    counts = {bus.text(k): int(v) for k, v in r.hgetall(key).items()}
    return dict(sorted(counts.items(), key=lambda kv: -kv[1])[:n])


def read_breakdown(r: redis.Redis, n: int = 8) -> dict:
    """What was flagged: ML-flagged flows by true label, Snort alerts by rule, and the
    sources behind both (packet captures only)."""
    ml_sources, snort_sources = _top(r, bus.ML_SOURCES, 50), _top(r, bus.SNORT_SOURCES, 50)
    sources = [
        {"ip": ip, "ml": ml_sources.get(ip, 0), "snort": snort_sources.get(ip, 0)}
        for ip in set(ml_sources) | set(snort_sources)
    ]
    sources.sort(key=lambda s: -(s["ml"] + s["snort"]))
    return {
        "ml_labels": _top(r, bus.ML_LABELS, n),
        "snort_rules": _top(r, bus.SNORT_RULES, n),
        "sources": sources[:n],
        "ml_flagged_flows": r.scard(bus.FLAGGED_ML),
    }


def read_live(r: redis.Redis) -> dict | None:
    """The interface being captured and since when, or None if no live capture runs."""
    live = {bus.text(k): bus.text(v) for k, v in r.hgetall(bus.LIVE).items()}
    if not live.get("target"):
        return None
    return {"target": live["target"], "started_at": float(live.get("started_at", 0)),
            "state": live.get("state", "capturing")}  # "waiting": the interface is down


def read_activity(r: redis.Redis) -> str:
    """"running" while detector services are processing a stream, "ended" once they all
    finished it, "idle" when none are running."""
    subscribed = r.hlen(bus.SUBSCRIPTIONS)
    if not subscribed:
        return "idle"
    return "ended" if r.scard(bus.ENDED) >= subscribed else "running"


def read_snort(r: redis.Redis) -> dict | None:
    """Snort alert counts and how they compare with the ML, or None if Snort is not running."""
    from . import snort_bridge as snort

    stats = {bus.text(k): int(v) for k, v in r.hgetall(snort.STATS).items()}
    if not stats:
        return None
    snort_flows = r.scard(snort.FLAGGED_SNORT)
    ml_flows = r.scard(snort.FLAGGED_ML)
    both = len(r.sinter(snort.FLAGGED_SNORT, snort.FLAGGED_ML)) if snort_flows and ml_flows else 0
    return {
        "alerts": stats.get("alerts", 0),
        "confirmed": stats.get("confirmed", 0),
        "disputed": stats.get("disputed", 0),
        "no_verdict": stats.get("no_verdict", 0),
        "unmatched": stats.get("unmatched", 0),
        "pending": stats.get("alerts", 0) - sum(stats.get(k, 0) for k in
                                                 ("confirmed", "disputed", "no_verdict", "unmatched")),
        "flows": {"both": both, "snort_only": snort_flows - both, "ml_only": ml_flows - both},
    }


def read_snort_alerts(r: redis.Redis, count: int = 50, after: str | None = None) -> list[dict]:
    """Newest correlated Snort alerts first."""
    from . import snort_bridge as snort

    alerts = []
    for entry_id, fields in r.xrevrange(snort.ALERTS, "+", f"({after}" if after else "-", count=count):
        a: dict = {bus.text(k): bus.text(v) for k, v in fields.items()}
        a["id"] = bus.text(entry_id)
        for key in ("seconds", "gid", "sid", "priority", "flows", "record_id"):
            a[key] = int(a[key])
        a["time"] = float(a["time"]) if a.get("time") else None
        for key in ("ml_share", "ml_confidence"):
            a[key] = float(a[key]) if a[key] else None
        a["ml_verdict"] = a["ml_verdict"] or None
        a["ml_detector"] = a["ml_detector"] or None
        alerts.append(a)
    return alerts


SOURCES = ("both", "ml", "snort")


def read_incidents(r: redis.Redis, source: str = "all", query: str = "", limit: int = 50,
                   offset: int = 0) -> dict:
    """Every flagged flow once, with what the ML and Snort said, newest first.

    Built from the whole ML and Snort alert streams, so nothing is missed because newer
    alerts crowded it out. A flow flagged by several detectors is one incident; a Snort
    alert the ML disputed stays "snort" (the ML looked and said normal).
    """
    incidents: dict[str, dict] = {}

    def get(key: str, record_id: int | None) -> dict:
        if key not in incidents:
            incidents[key] = {"key": key, "record_id": record_id, "time": None, "src": None, "dst": None,
                              "label": None, "ml": None, "snort": None}
        return incidents[key]

    for alert in reversed(read_alerts(r, bus.ALERTS_KEPT)):
        i = get(f"flow-{alert['record_id']}", alert["record_id"])
        ml = i["ml"] = i["ml"] or {"detectors": [], "resolutions": [], "counselors": []}
        for field, value in (("detectors", alert["detector"]), ("resolutions", alert["resolution"]),
                             ("counselors", alert["counselor"])):
            if value and value not in ml[field]:
                ml[field].append(value)
        i["time"] = max(i["time"] or 0, alert["time"] or 0) or None
        i["src"] = i["src"] or alert["src"]
        i["dst"] = i["dst"] or alert["dst"]
        i["label"] = i["label"] or alert.get("label")

    for alert in reversed(read_snort_alerts(r, bus.ALERTS_KEPT)):
        record_id = alert["record_id"] if alert["record_id"] >= 0 else None
        i = get(f"flow-{record_id}" if record_id is not None else f"snort-{alert['id']}", record_id)
        sn = i["snort"] = i["snort"] or {"rules": [], "ids": [], "flows": 0, "agreement": alert["agreement"],
                                         "ml_verdict": alert["ml_verdict"]}
        if alert["msg"] not in sn["rules"]:
            sn["rules"].append(alert["msg"])
        sn["ids"].append(f"{alert['gid']}:{alert['sid']}")
        sn["flows"] = max(sn["flows"], alert["flows"])
        if alert["agreement"] == "confirmed":
            sn["agreement"] = "confirmed"
        i["time"] = max(i["time"] or 0, alert["time"] or 0) or None
        i["src"] = i["src"] or alert["src"] or None
        i["dst"] = i["dst"] or alert["dst"] or None

    for i in incidents.values():
        i["source"] = "both" if i["ml"] and i["snort"] else "snort" if i["snort"] else "ml"

    everything = sorted(incidents.values(), key=lambda i: (-(i["time"] or 0), -(i["record_id"] or 0)))
    counts = {"all": len(everything), **{s: sum(i["source"] == s for i in everything) for s in SOURCES}}
    q = query.strip().lower()

    def matches(i: dict) -> bool:
        fields = [i["src"], i["dst"], i["label"], str(i["record_id"]),
                  *(i["snort"]["rules"] if i["snort"] else []), *(i["ml"]["detectors"] if i["ml"] else [])]
        return any(q in f.lower() for f in fields if f)

    chosen = [i for i in everything if (source == "all" or i["source"] == source) and (not q or matches(i))]
    return {"counts": counts, "total": len(chosen), "incidents": chosen[offset:offset + limit]}


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
        if (snort_stats := read_snort(r)) is not None:
            print("snort:", snort_stats, flush=True)
        if once:
            return
        time.sleep(interval)
