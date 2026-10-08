"""Run Snort on a recording and link its alerts to flows, offline.

Same matching as the live Snort bridge (services/snort_bridge.py, flow_index.py): a packet
alert belongs to the flow on its connection (both endpoints and the protocol, either
direction) that was open at the alert's time; a port-scan alert (gid 122) to every flow
between the two hosts within ±30 s. Used to build training and adaptation data where every
flow carries the Snort rules that fired on it.
"""

import json
import os
import subprocess
from bisect import bisect_right
from collections import defaultdict
from pathlib import Path

import pandas as pd

from ..services.flow_index import SLACK, connection_key, host_key
from ..services.snort_bridge import HOST_LEVEL_GIDS, HOST_WINDOW, snort_command


def run_snort(pcap: Path, work: Path, community: bool = True) -> list[dict]:
    """Snort's alerts on ``pcap`` (alert_json records), written under ``work``."""
    work.mkdir(parents=True, exist_ok=True)
    env = os.environ | {"NIDS_SNORT_COMMUNITY": "1" if community else "0"}
    subprocess.run(snort_command(str(pcap), str(work)), check=False, env=env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    path = work / "alert_json.txt"
    if not path.exists():
        return []
    alerts = []
    for line in path.read_text().splitlines():
        try:
            alerts.append(json.loads(line))
        except json.JSONDecodeError:  # Snort stopped mid-line
            continue
    return alerts


def rule_key(alert: dict) -> str:
    return f"{alert.get('gid', 1)}:{alert.get('sid', 0)}"


def link(flows: pd.DataFrame, alerts: list[dict]) -> pd.Series:
    """The Snort rules ("gid:sid") that fired on each flow, as a tuple (empty: none).

    ``flows`` needs flow_start, flow_end, src_ip, src_port, dst_ip, conn_dst_port, protocol.
    """
    by_conn, by_host = defaultdict(list), defaultdict(list)
    for row, f in enumerate(flows.itertuples(index=False)):
        item = (f.flow_start, f.flow_end, row)
        by_conn[connection_key(f.protocol, f.src_ip, f.src_port, f.dst_ip, f.conn_dst_port)].append(item)
        by_host[host_key(f.protocol, f.src_ip, f.dst_ip)].append(item)
    for index in (by_conn, by_host):
        for items in index.values():
            items.sort()
    starts = {k: [s for s, _, _ in v] for k, v in by_conn.items()}
    host_starts = {k: [s for s, _, _ in v] for k, v in by_host.items()}

    rules: list[set] = [set() for _ in range(len(flows))]
    for a in alerts:
        at, key = float(a.get("seconds", 0)), rule_key(a)
        if a.get("gid") in HOST_LEVEL_GIDS:
            hk = host_key(a.get("proto", ""), a.get("src_addr"), a.get("dst_addr"))
            items = by_host.get(hk, [])
            for start, end, row in items[:bisect_right(host_starts.get(hk, []), at + HOST_WINDOW)]:
                if end >= at - HOST_WINDOW:
                    rules[row].add(key)
        elif a.get("src_port") is not None and a.get("dst_port") is not None:
            ck = connection_key(a.get("proto", ""), a["src_addr"], a["src_port"], a["dst_addr"], a["dst_port"])
            items = by_conn.get(ck, [])
            # the latest flow on this connection that started before the alert and was open then
            candidates = items[:bisect_right(starts.get(ck, []), at + SLACK)]
            for start, end, row in reversed(candidates):
                if start - SLACK <= at <= end + SLACK:
                    rules[row].add(key)
                    break
    return pd.Series([tuple(sorted(r)) for r in rules], index=flows.index, dtype=object)


def rule_names(alerts: list[dict]) -> dict[str, str]:
    """"gid:sid" -> rule message."""
    return {rule_key(a): a.get("msg", "") for a in alerts}
