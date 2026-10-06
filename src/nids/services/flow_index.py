"""Index captured flows by connection and time, so Snort alerts can be linked to them.

A flow is stored under its connection key — both endpoints and the protocol, in a
fixed order so either direction matches — in a sorted set scored by start time:

    nids:flows:<proto>|<ip:port>|<ip:port>   member "<record_id>|<start>|<end>"
    nids:hostflows:<proto>|<ip>|<ip>        same, per host pair (for host-level alerts)
"""

import pandas as pd
import redis

from . import bus

PROTOCOLS = {"TCP": 6, "UDP": 17, "ICMP": 1}
TTL = 3600  # seconds the index is kept

# Flow start times are stored to the second, so allow that much slack either side.
SLACK = 1.0


def proto_number(proto) -> int:
    if isinstance(proto, str):
        return PROTOCOLS.get(proto.upper(), -1) if not proto.isdigit() else int(proto)
    return int(proto)


def connection_key(proto, a_ip, a_port, b_ip, b_port) -> str:
    ends = sorted([f"{a_ip}:{int(a_port)}", f"{b_ip}:{int(b_port)}"])
    return f"{bus.PREFIX}:flows:{proto_number(proto)}|{ends[0]}|{ends[1]}"


def host_key(proto, a_ip, b_ip) -> str:
    ends = sorted([str(a_ip), str(b_ip)])
    return f"{bus.PREFIX}:hostflows:{proto_number(proto)}|{ends[0]}|{ends[1]}"


def index_flows(r: redis.Redis, flows: pd.DataFrame) -> None:
    """flows needs record_id, flow_start, flow_end, src_ip, src_port, dst_ip, dst_port, protocol."""
    pipe = r.pipeline()
    for f in flows.itertuples():
        member = f"{f.record_id}|{f.flow_start}|{f.flow_end}"
        for key in (connection_key(f.protocol, f.src_ip, f.src_port, f.dst_ip, f.dst_port),
                    host_key(f.protocol, f.src_ip, f.dst_ip)):
            pipe.zadd(key, {member: f.flow_start})
            pipe.expire(key, TTL)
    pipe.execute()


def _parse(members) -> list[tuple[int, float, float]]:
    out = []
    for m in members:
        record_id, start, end = bus.text(m).split("|")
        out.append((int(record_id), float(start), float(end)))
    return out


def find_flow(r: redis.Redis, proto, src_ip, src_port, dst_ip, dst_port, at: float) -> int | None:
    """record_id of the flow on this connection that was open at time ``at``."""
    key = connection_key(proto, src_ip, src_port, dst_ip, dst_port)
    candidates = _parse(r.zrangebyscore(key, "-inf", at + SLACK))
    matching = [c for c in candidates if c[1] - SLACK <= at <= c[2] + SLACK]
    # the latest flow that started before the alert (ports can be reused)
    return max(matching, key=lambda c: c[1])[0] if matching else None


def find_host_flows(r: redis.Redis, proto, a_ip, b_ip, at: float, window: float) -> list[int]:
    """record_ids of all flows between two hosts that overlap [at - window, at + window]."""
    key = host_key(proto, a_ip, b_ip)
    candidates = _parse(r.zrangebyscore(key, "-inf", at + window))
    return [c[0] for c in candidates if c[2] >= at - window]
