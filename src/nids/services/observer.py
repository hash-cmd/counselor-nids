"""Observer — publish/subscribe broker between Extractors and Detectors (Figure 1, 5-6).

Watches the Unknown Samples Repository and forwards each batch only to the
detectors subscribed to its data source, so detectors never process data they
do not analyse.
"""

import json

import redis

from . import bus


def subscriptions(r: redis.Redis) -> dict[str, list[str]]:
    return {name.decode(): json.loads(sources) for name, sources in r.hgetall(bus.SUBSCRIPTIONS).items()}


def run(r: redis.Redis, exit_on_end: bool = False, block_ms: int = 1000) -> int:
    """Forward messages until stopped (or the first end-of-stream, with ``exit_on_end``)."""
    last, forwarded = "0", 0
    while True:
        for _, messages in r.xread({bus.UNKNOWN: last}, block=block_ms, count=100) or []:
            for message_id, fields in messages:
                last = message_id
                source = bus.field(fields, "source")
                for name, sources in subscriptions(r).items():
                    if source in sources:
                        r.xadd(bus.inbox(name), fields)
                        forwarded += 1
                if exit_on_end and bus.field(fields, "kind") == bus.END:
                    return forwarded
