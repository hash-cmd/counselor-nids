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
    """Publish one connection's summary to the live-traffic stream (flagged or not)."""
    dport = bus.field(fields, "conn_dst_port") or bus.field(fields, "Destination Port")
    r.xadd(bus.CONNECTIONS, {
        "record_id": bus.field(fields, "record_id") or "",
        "src": _endpoint(bus.field(fields, "src_ip"), bus.field(fields, "src_port")),
        "dst": _endpoint(bus.field(fields, "dst_ip"), dport),
        "source": source, "time": repr(time.time()),
    }, maxlen=bus.CONNECTIONS_KEPT, approximate=True)


def subscriptions(r: redis.Redis) -> dict[str, list[str]]:
    return {name.decode(): json.loads(sources) for name, sources in r.hgetall(bus.SUBSCRIPTIONS).items()}


def run(r: redis.Redis, exit_on_end: bool = False, block_ms: int = 1000) -> int:
    """Forward messages until stopped (or the first end-of-stream, with ``exit_on_end``)."""
    last, forwarded = "0", 0
    feed_all = bool(os.environ.get("NIDS_FEED_ALL"))  # publish every connection for the live-traffic page
    while True:
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
