"""Live view of every detector's counters."""

import ipaddress
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor

import pandas as pd
import redis

from . import bus

_RDNS: dict[str, str | None] = {}  # ip -> hostname (None once a lookup failed); cached for the process


def _host(endpoint: str | None) -> str | None:
    """The IP part of an "ip:port" endpoint, or None when there is no routable address."""
    if not endpoint or endpoint.startswith("port "):
        return None
    ip = endpoint.rsplit(":", 1)[0]
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None
    return ip


def _resolve_names(endpoints, budget: float = 1.0) -> None:
    """Reverse-DNS the destinations we have not looked up yet, caching the result. Bounded
    to ``budget`` seconds total and done in a thread pool so a slow PTR never stalls the page;
    anything unresolved in time stays absent and is retried on the next poll. Private and
    link-local addresses are skipped (they do not resolve and would only leak to the resolver)."""
    todo = []
    for ep in {_host(e) for e in endpoints}:
        if ep and ep not in _RDNS and ipaddress.ip_address(ep).is_global:
            todo.append(ep)
    if not todo:
        return
    with ThreadPoolExecutor(max_workers=min(16, len(todo))) as pool:
        futures = {ip: pool.submit(socket.gethostbyaddr, ip) for ip in todo}
        deadline = time.monotonic() + budget
        for ip, fut in futures.items():
            try:
                _RDNS[ip] = fut.result(timeout=max(0.0, deadline - time.monotonic()))[0]
            except Exception:  # noqa: BLE001 - timeout, NXDOMAIN, no PTR: all mean "no name"
                _RDNS[ip] = None


def read_stats(r: redis.Redis) -> dict[str, dict]:
    """Counters of every subscribed detector."""
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
            "snort_advised": raw.get("advice:snort", 0),
        }
    return stats


def read_connections(r: redis.Redis, count: int = 200) -> dict:
    """The latest connections the system judged, flagged or not (populated only when the
    observer runs with NIDS_FEED_ALL=1). Each is marked flagged if any detector alerted on it."""
    entries = r.xrevrange(bus.CONNECTIONS, "+", "-", count=count)
    flagged = {bus.text(x) for x in r.smembers(bus.FLAGGED_ML)}
    rows = []
    for entry_id, fields in entries:
        d = {bus.text(k): bus.text(v) for k, v in fields.items()}
        rid = d.get("record_id", "")
        rows.append({"id": bus.text(entry_id), "record_id": rid, "src": d.get("src"),
                     "dst": d.get("dst"), "source": d.get("source"),
                     "proto": d.get("proto"),
                     "flags": d.get("flags") or None,
                     "packets": int(d["packets"]) if d.get("packets") else None,
                     "bytes": int(d["bytes"]) if d.get("bytes") else None,
                     "duration": float(d["duration"]) if d.get("duration") else None,
                     "time": float(d["time"]) if d.get("time") else None,
                     "flagged": rid in flagged})
    _resolve_names(row["dst"] for row in rows)  # reverse-DNS the destinations (cached, bounded)
    for row in rows:
        row["name"] = _RDNS.get(_host(row["dst"]) or "")
    total = r.xlen(bus.CONNECTIONS)
    return {"feed_on": bool(r.exists(bus.FEED_ALL)), "total_window": total, "connections": rows}


def set_feed(r: redis.Redis, on: bool) -> bool:
    """Turn the full-traffic feed on or off (the observer checks this each cycle)."""
    if on:
        r.set(bus.FEED_ALL, "1")
    else:
        r.delete(bus.FEED_ALL)
    return on


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
    """What was flagged: Snort alerts by rule, and the sources behind ML and Snort alerts."""
    ml_sources, snort_sources = _top(r, bus.ML_SOURCES, 50), _top(r, bus.SNORT_SOURCES, 50)
    sources = [
        {"ip": ip, "ml": ml_sources.get(ip, 0), "snort": snort_sources.get(ip, 0)}
        for ip in set(ml_sources) | set(snort_sources)
    ]
    sources.sort(key=lambda s: -(s["ml"] + s["snort"]))
    return {
        "snort_rules": _top(r, bus.SNORT_RULES, n),
        "sources": sources[:n],
        "ml_flagged_flows": r.scard(bus.FLAGGED_ML),
    }


STALE = 15.0  # seconds without a heartbeat before a service counts as down


def read_snort_trust(r: redis.Redis, limit: int = 20) -> list[dict]:
    """How much each Snort rule is trusted as a counselor, from the AI's agreement."""
    from .snort_counselor import trust_table
    return trust_table(r, limit)


def read_health(r: redis.Redis, now: float | None = None) -> list[dict]:
    """Every service that has reported since the last reset: {"service", "ok", "age", ...}.
    A service is down when its heartbeat is older than STALE seconds, or (Snort) when the
    Snort process it runs has exited."""
    now = now or time.time()
    out = []
    for name, raw in r.hgetall(bus.HEALTH).items():
        try:
            info = json.loads(bus.text(raw))
        except ValueError:
            continue
        age = max(0.0, now - float(info.pop("at", 0)))
        ok = age < STALE and info.get("running", True) is not False
        out.append({"service": bus.text(name), "ok": ok, "age": round(age, 1), **info})
    return sorted(out, key=lambda s: s["service"])


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
        ml = i["ml"] = i["ml"] or {"detectors": [], "resolutions": [], "counselors": [], "origins": []}
        # a cross-checked alarm belongs to the counselor that recognised the attack
        origin = alert["counselor"] if alert["resolution"] == "cross_check" and alert["counselor"] else alert["detector"]
        if origin not in ml["origins"]:
            ml["origins"].append(origin)
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

    from .feedback import verdicts
    marked = verdicts(r)
    for i in incidents.values():
        i["source"] = "both" if i["ml"] and i["snort"] else "snort" if i["snort"] else "ml"
        i["feedback"] = marked.get(i["record_id"]) if i["record_id"] is not None else None

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
    return pd.DataFrame(read_stats(r)).T


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
