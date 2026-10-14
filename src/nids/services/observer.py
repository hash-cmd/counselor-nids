"""Observer — publish/subscribe broker between Extractors and Detectors (Figure 1, 5-6).

Watches the Unknown Samples Repository and forwards each batch only to the
detectors subscribed to its data source, so detectors never process data they
do not analyse.
"""

import json
import os
import time

import redis

from . import bus


def _endpoint(ip, port) -> str:
    if ip:
        return f"{ip}:{port}" if port else str(ip)
    return f"port {port}" if port else "?"


def _feed(r: redis.Redis, fields, source: str) -> None:
    """Publish each connection in a flow batch to the live-traffic stream (flagged or not). The
    batch arrives as a JSON ``frame`` field (columns + rows), so one message is many connections."""
    raw = bus.field(fields, "frame")
    if not raw:
        return
    frame = json.loads(raw)
    idx = {c: i for i, c in enumerate(frame["columns"])}
    si, di, spi = idx.get("src_ip"), idx.get("dst_ip"), idx.get("src_port")
    dpi = idx.get("conn_dst_port", idx.get("Destination Port"))
    ri = idx.get("record_id")
    ti = idx.get("flow_end", idx.get("flow_start"))  # wall-clock time (the "timestamp" col is relative)
    proto_i, dur_i = idx.get("protocol"), idx.get("Flow Duration")
    fpk, bpk = idx.get("Total Fwd Packets"), idx.get("Total Backward Packets")
    fby, bby = idx.get("Total Length of Fwd Packets"), idx.get("Total Length of Bwd Packets")
    # TCP flags seen on the connection (SYN-only = a scan/half-open; SYN+ACK = established)
    flag_i = [(nm, idx.get(f"{nm} Flag Count")) for nm in ("SYN", "ACK", "FIN", "RST", "PSH", "URG")]
    now = time.time()
    PROTO = {6: "TCP", 17: "UDP", 1: "ICMP"}
    cell = lambda row, i: row[i] if i is not None else None  # noqa: E731
    num = lambda row, i: float(row[i]) if i is not None and row[i] is not None else 0.0  # noqa: E731
    pipe = r.pipeline()
    for row in frame["data"]:
        pipe.xadd(bus.CONNECTIONS, {
            "record_id": str(cell(row, ri)) if ri is not None else "",
            "src": _endpoint(cell(row, si), cell(row, spi)),
            "dst": _endpoint(cell(row, di), cell(row, dpi)),
            "proto": PROTO.get(int(num(row, proto_i)), str(cell(row, proto_i) or "")),
            "flags": " ".join(nm for nm, i in flag_i if i is not None and num(row, i) > 0),
            "packets": int(num(row, fpk) + num(row, bpk)),
            "bytes": int(num(row, fby) + num(row, bby)),
            "duration": repr(round(num(row, dur_i) / 1e6, 2)),  # microseconds -> seconds
            "source": source, "time": repr(float(cell(row, ti)) if ti is not None else now),
        }, maxlen=bus.CONNECTIONS_KEPT, approximate=True)
    pipe.execute()


def subscriptions(r: redis.Redis) -> dict[str, list[str]]:
    return {name.decode(): json.loads(sources) for name, sources in r.hgetall(bus.SUBSCRIPTIONS).items()}


def run(r: redis.Redis, exit_on_end: bool = False, block_ms: int = 1000) -> int:
    """Forward messages until stopped (or the first end-of-stream, with ``exit_on_end``)."""
    last, forwarded = "0", 0
    env_feed = bool(os.environ.get("NIDS_FEED_ALL"))  # forces the feed on from the environment
    while True:
        # publish every connection for the live-traffic page when the env var or the dashboard
        # toggle (a Redis flag) asks for it — checked each cycle so it turns on/off without a restart
        feed_all = env_feed or bool(r.exists(bus.FEED_ALL))
        bus.beat(r, "observer", forwarded=forwarded)
        for _, messages in r.xread({bus.UNKNOWN: last}, block=block_ms, count=100) or []:
            for message_id, fields in messages:
                last = message_id
                source = bus.field(fields, "source")
                is_end = bus.field(fields, "kind") == bus.END
                if feed_all and not is_end:
                    _feed(r, fields, source or "")
                for name, sources in subscriptions(r).items():
                    if source in sources:
                        r.xadd(bus.inbox(name), fields)
                        forwarded += 1
                if exit_on_end and is_end:
                    return forwarded
