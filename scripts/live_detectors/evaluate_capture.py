"""Whole-system test on a labelled packet capture: flow meter, live detectors and Snort.

Runs what live mode runs, offline: the Python cicflowmeter computes flows; the ML (the live
detectors as a counselor network, cross-check on, fallback suppressed) judges the flows
that carry data, as live mode does; Snort runs with the project's configuration and each
alert is linked to its flows with the same index the Snort bridge uses (one flow per
packet alert; every flow between the two hosts within 30 s for a port-scan alert). Flows
are labelled by their attacker-victim pair (scripts/live_detectors/build_dataset.SOURCES).

Reports, per kind of traffic, the share of flows flagged by the ML, by Snort and by either;
the "Normal" row is the false-alarm rate. Writes results/live/system_<capture>.csv.

    python scripts/live_detectors/evaluate_capture.py [data/pcap/real-attacks-2018.pcap]
"""

import argparse
import sys
import tempfile
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))

from build_dataset import SOURCES, flowmeter  # noqa: E402

from nids.capture import snort_offline  # noqa: E402
from nids.counselor import CounselorNetwork, SnortCounselor  # noqa: E402
from nids.datasets.flow_features import CIC2018_TO_2017  # noqa: E402
from nids.datasets.paths import PROJECT_ROOT, RESULTS_DIR  # noqa: E402
from nids.services.live_capture import carries_payload  # noqa: E402

MODELS = PROJECT_ROOT / "models" / "live"
NAMES = {  # dataset label -> table row
    "Benign": "Normal", "FTP-BruteForce": "FTP brute force", "SSH-Bruteforce": "SSH brute force",
    "DoS-GoldenEye": "DoS GoldenEye", "DoS-Slowloris": "DoS Slowloris", "DoS-Hulk": "DoS Hulk",
    "DoS-SlowHTTPTest": "DoS SlowHTTPTest", "Web-attack": "Web attacks", "Bot": "Botnet",
}


def label(flows: pd.DataFrame) -> pd.Series:
    pairs = {frozenset((ip, s.victim)): lbl for s in SOURCES if s.victim for ip, lbl in s.attackers.items()}
    return pd.Series([pairs.get(frozenset((a, b)), "Benign") for a, b in zip(flows["src_ip"], flows["dst_ip"])],
                     index=flows.index)


def ml_flags(flows: pd.DataFrame, min_accuracy: float, snort_rules: pd.Series | None = None) -> np.ndarray:
    """The AI's verdicts, as live mode runs it; with ``snort_rules`` (the rules that fired on
    each flow), Snort advises on conflicts as in live mode with --snort-counselor."""
    features = list(CIC2018_TO_2017.values())
    judged = carries_payload(flows) & flows[features].replace([np.inf, -np.inf], np.nan).notna().all(axis=1)
    flagged = np.zeros(len(flows), dtype=bool)
    sample = flows[judged].reset_index()
    if sample.empty:
        return flagged
    detectors = [joblib.load(p) for p in sorted(MODELS.glob("*.joblib"))]
    advisors = []
    if snort_rules is not None:
        advisors = [SnortCounselor(dict(zip(sample["record_id"].astype(float), snort_rules[sample["index"]].to_numpy())))]
    finals = CounselorNetwork(detectors, min_accuracy, window=0, cross_check_normal=True, suppress_fallback=True,
                              advisors=advisors, attack_advice_wins=bool(advisors)).run(sample, sample["record_id"])
    hit = np.logical_or.reduce([f["prediction"].to_numpy(dtype=bool) for f in finals.values()])
    flagged[sample.loc[hit, "index"].to_numpy()] = True
    return flagged


def snort_flags(capture: Path, flows: pd.DataFrame, work: Path, community: bool = True):
    """(flagged by Snort, Snort alerts, rules that fired per flow)."""
    alerts = snort_offline.run_snort(capture, work / "snort", community)
    rules = snort_offline.link(flows, alerts)
    return rules.map(bool).to_numpy(), alerts, rules


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("capture", nargs="?", type=Path, default=PROJECT_ROOT / "data" / "pcap" / "real-attacks-2018.pcap")
    parser.add_argument("--min-accuracy", type=float, default=0.9)
    parser.add_argument("--no-community", action="store_true", help="Snort with the project's rules only")
    parser.add_argument("--snort-counselor", action="store_true", help="Snort advises the AI on conflicts (as live)")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="nids-evaluate-") as work:
        work = Path(work)
        flows = flowmeter(args.capture, work / "flows.csv").reset_index(drop=True)
        flows["record_id"] = np.arange(len(flows))
        flows["label"] = label(flows)
        snort, alerts, rules = snort_flags(args.capture, flows, work, community=not args.no_community)
        ml = ml_flags(flows, args.min_accuracy, rules if args.snort_counselor else None)

    rows = {}
    for lbl, g in flows.groupby("label"):
        i = g.index.to_numpy()
        rows[NAMES.get(lbl, lbl)] = {"flows": len(g), "ML": ml[i].mean(), "Snort": snort[i].mean(),
                                     "either": (ml | snort)[i].mean()}
    table = pd.DataFrame(rows).T.sort_index()
    table["flows"] = table["flows"].astype(int)
    print(table.to_string(formatters={k: "{:.1%}".format for k in ("ML", "Snort", "either")}))
    rules = pd.Series([a["msg"] for a in alerts]).value_counts()
    print(f"\n{len(alerts):,} Snort alerts; by rule:\n{rules.head(15).to_string()}")

    out = RESULTS_DIR / "live"
    out.mkdir(parents=True, exist_ok=True)
    suffix = ("_project_rules" if args.no_community else "") + ("_snort_counselor" if args.snort_counselor else "")
    path = out / f"system_{args.capture.stem.replace('-', '_')}{suffix}.csv"
    table.rename_axis("traffic").to_csv(path)
    print("written to", path)


if __name__ == "__main__":
    main()
