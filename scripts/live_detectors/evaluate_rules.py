"""Held-out test of the project's own Snort rules (snort/rules/nids.rules, sid 9000000+).

The project's web-attack rules (SQL injection, cross-site scripting, login brute force) were
written while looking at the CSE-CIC-IDS2018 web-attack capture, so their score on that capture
is not a fair test. This script scores them on traffic they were not written from: the CICIDS2017
Thursday web attacks (a different lab, attacker, victim server and web application).

Snort runs with the project rules only (community rules off) on all of the day's web traffic
(TCP port 80, every host), so the whole day's benign browsing is the false-alarm reference; alerts are linked to the labelled flows with the same matching
as live mode. Reports, per label, the share of flows and of sessions (host pair x minute) on
which a project rule fired. Writes results/live/rules_heldout_<name>.json.

    python scripts/live_detectors/evaluate_rules.py
"""

import argparse
import json
import sys
import tempfile
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))

import data_prep as dp  # noqa: E402

from nids.capture import snort_offline  # noqa: E402
from nids.datasets.paths import PROJECT_ROOT, RESULTS_DIR  # noqa: E402

PROJECT_SID = 9000000


def project_rule(rules: tuple) -> bool:
    """Whether any of the project's own rules (gid 1, sid >= 9000000) is among ``rules``."""
    return any(int(r.split(":")[1]) >= PROJECT_SID for r in rules if r.startswith("1:"))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pcap", type=Path,
                        default=PROJECT_ROOT / "data/raw/cicids2017-pcap/Thursday-WorkingHours.pcap")
    parser.add_argument("--flows", type=Path,
                        default=PROJECT_ROOT / "data/processed/live/cicids2017-Thursday-WorkingHours.pkl")
    parser.add_argument("--port", type=int, default=80, help="web port whose traffic is tested")
    parser.add_argument("--name", default="2017_web")
    args = parser.parse_args()

    flows = pd.read_pickle(args.flows)
    web = (flows["conn_dst_port"] == args.port) | (flows["src_port"] == args.port)
    flows = flows[web & (flows["protocol"] == 6)]  # TCP
    flows = flows.reset_index(drop=True)

    # Snort filters the capture itself while reading: an extracted copy can run to gigabytes
    with tempfile.TemporaryDirectory() as tmp:
        print(f"running Snort (project rules only) on TCP port {args.port} of {args.pcap.name} ...", flush=True)
        alerts = snort_offline.run_snort(args.pcap, Path(tmp) / "snort", community=False,
                                         bpf=f"tcp port {args.port}")

    fired = snort_offline.link(flows, alerts).map(project_rule).to_numpy()
    sessions = dp.session_ids(flows)
    rows = {}
    for label, g in flows.groupby("label"):
        i = g.index.to_numpy()
        s = pd.Series(fired[i]).groupby(sessions[i]).any()
        rows[label] = {"flows": len(i), "flows_alerted": int(fired[i].sum()), "flow_rate": float(fired[i].mean()),
                       "sessions": int(len(s)), "sessions_alerted": int(s.sum()), "session_rate": float(s.mean())}
    names = snort_offline.rule_names(alerts)
    by_rule = pd.Series([k for a in alerts for k in [snort_offline.rule_key(a)]]).value_counts()
    report = {"capture": args.pcap.name, "port": args.port, "by_label": rows,
              "alerts_by_rule": {f"{k} {names.get(k, '')}": int(v) for k, v in by_rule.items()}}
    print(pd.DataFrame(rows).T.to_string())
    print(json.dumps(report["alerts_by_rule"], indent=1))
    out = RESULTS_DIR / "live" / f"rules_heldout_{args.name}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=1))
    print("wrote", out)


if __name__ == "__main__":
    main()
