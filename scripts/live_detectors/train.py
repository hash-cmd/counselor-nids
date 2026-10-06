"""Train and test the LIVE detectors on flows computed by the Python cicflowmeter.

Input: data/processed/live/flows.pkl (scripts/live_detectors/build_dataset.py). Two counselor
detectors with different knowledge, as in the paper's Scenario 2:

    live_dos      DoS (GoldenEye, Slowloris, Hulk, SlowHTTPTest)
    live_access   brute force (FTP, SSH) and web attacks

Both learn from all benign flows. Split by TIME within each label (earliest 70% for
signatures, latest 30% for test), so test flows come from later in each attack than any
training flow — closer to meeting traffic live than a random split.

Saves models/live/*.joblib (used by `./start.sh live` and packet-capture replays) and
results/live/.

    python scripts/live_detectors/train.py
"""

import argparse
import json

import joblib
import numpy as np
import pandas as pd

from nids.counselor import CounselorNetwork
from nids.datasets.flow_features import CIC2018_TO_2017
from nids.datasets.paths import PROJECT_ROOT
from nids.detector.classifiers import SCENARIO2
from nids.evaluation import metrics
from nids.detector.training import build_detector
from nids.reporting import RESULTS_DIR

FLOWS = PROJECT_ROOT / "data" / "processed" / "live" / "flows.pkl"
MODELS = PROJECT_ROOT / "models" / "live"

KNOWLEDGE = {
    "live_dos": ["DoS-GoldenEye", "DoS-Slowloris", "DoS-Hulk", "DoS-SlowHTTPTest"],
    "live_access": ["FTP-BruteForce", "SSH-Bruteforce", "Web-attack"],
}


def time_split(flows: pd.DataFrame, share: float) -> tuple[pd.DataFrame, pd.DataFrame]:
    parts = [(g.iloc[: int(len(g) * share)], g.iloc[int(len(g) * share):])
             for _, g in flows.sort_values("flow_start").groupby(["label", "capture"])]
    return (pd.concat([a for a, _ in parts], ignore_index=True),
            pd.concat([b for _, b in parts], ignore_index=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--train-share", type=float, default=0.7)
    parser.add_argument("--min-accuracy", type=float, default=0.9)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--max-per-label", type=int, default=15_000,
                        help="cap each attack type's signature flows (benign is far scarcer)")
    args = parser.parse_args()

    features = list(CIC2018_TO_2017.values())

    flows = pd.read_pickle(FLOWS)
    flows = flows.replace([np.inf, -np.inf], np.nan).dropna(subset=features)
    signatures, test = time_split(flows, args.train_share)
    signatures = pd.concat(
        [g if label == "Benign" else g.sample(min(len(g), args.max_per_label), random_state=args.seed)
         for label, g in signatures.groupby("label")], ignore_index=True)
    test = test.sample(frac=1, random_state=args.seed).reset_index(drop=True)
    test["record_id"] = np.arange(len(test))
    print(f"{len(signatures):,} signature flows, {len(test):,} test flows")

    detectors = []
    for name, attacks in KNOWLEDGE.items():
        known = signatures[signatures["label"].isin(["Benign", *attacks])]
        detectors.append(build_detector(name, known, features, SCENARIO2, n_clusters=known["label"].nunique(),
                                        stratify="label", seed=args.seed))

    y = test["is_attack"].to_numpy()
    verdicts = {}
    for d in detectors:
        verdicts[f"{d.name} alone"] = d.detect(test, test["record_id"])["prediction"].to_numpy(dtype=bool)
        d.clear_history()
    finals = CounselorNetwork(detectors, args.min_accuracy, window=0, cross_check_normal=True).run(
        test, test["record_id"])
    verdicts["counselor network"] = np.logical_or.reduce([f["prediction"].to_numpy(dtype=bool)
                                                          for f in finals.values()])

    table = pd.DataFrame({
        label: {"flows": len(g), **{k: float(v[g.index].mean()) for k, v in verdicts.items()}}
        for label, g in test.groupby("label")
    }).T.sort_values("flows", ascending=False)
    summary = {k: metrics(y, v) for k, v in verdicts.items()}

    pct = lambda v: f"{v:.2%}"  # noqa: E731
    print("\nshare of test flows flagged as attack (Benign row = false alarms):")
    print(table.to_string(formatters={k: pct for k in verdicts} | {"flows": "{:,.0f}".format}))
    print(pd.DataFrame(summary).T.map(pct).to_string())

    MODELS.mkdir(parents=True, exist_ok=True)
    for d in detectors:
        d.clear_history()
        joblib.dump(d, MODELS / f"{d.name}.joblib", compress=3)
    out = RESULTS_DIR / "live"
    out.mkdir(parents=True, exist_ok=True)
    table.to_csv(out / "by_label.csv")
    (out / "summary.json").write_text(json.dumps({"metrics": summary, "args": vars(args),
                                                  "knowledge": KNOWLEDGE}, indent=2))
    print("\nsaved", ", ".join(str(MODELS / f"{d.name}.joblib") for d in detectors))


if __name__ == "__main__":
    main()
