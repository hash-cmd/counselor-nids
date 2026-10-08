"""Train and test the LIVE detectors on flows computed by the Python cicflowmeter.

Input: data/processed/live/flows.pkl (scripts/live_detectors/build_dataset.py). Three counselor
detectors with different knowledge, as in the paper's Scenario 2:

    live_dos      DoS (GoldenEye, Slowloris, Hulk, SlowHTTPTest)
    live_access   brute force (FTP, SSH) and web attacks
    live_bot      botnet (Ares hosts calling their command-and-control server)

Both learn from all benign flows. Split by TIME within each label (earliest 70% for
signatures, latest 30% for test), so test flows come from later in each attack than any
training flow — closer to meeting traffic live than a random split.

Promotion gate: new models replace the installed ones only if the whole system does not get
worse than the installed baseline (models/live/manifest.json) — no more false alarms, and no
attack type's detection drops by more than --max-drop. A bad retrain therefore never silently
reaches live monitoring; --force overrides. Promoted models are listed with their SHA-256 in
models/live/SHA256SUMS, which `./start.sh live` verifies before loading them.

Saves models/live/*.joblib (used by `./start.sh live` and packet-capture replays), the
manifest, and results/live/.

    python scripts/live_detectors/train.py
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone

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
MANIFEST = MODELS / "manifest.json"
SYSTEM = "counselor network"
# with no installed baseline, a candidate must at least meet these
FIRST_MAX_FALSE_ALARMS = 0.002
FIRST_MIN_DETECTION = 0.8

KNOWLEDGE = {
    "live_dos": ["DoS-GoldenEye", "DoS-Slowloris", "DoS-Hulk", "DoS-SlowHTTPTest"],
    "live_access": ["FTP-BruteForce", "SSH-Bruteforce", "Web-attack"],
    "live_bot": ["Bot"],
}


def time_split(flows: pd.DataFrame, share: float) -> tuple[pd.DataFrame, pd.DataFrame]:
    # stable sort: flow starts have one-second resolution, so thousands of flows tie; an unstable
    # sort ordered them differently whenever other captures were added, changing which flows
    # landed in training (false alarms swung between 0 and 921 on the same data)
    flows = flows.sort_values("flow_start", kind="stable")
    parts = [(g.iloc[: int(len(g) * share)], g.iloc[int(len(g) * share):])
             for _, g in flows.groupby(["label", "capture"], sort=True)]
    return (pd.concat([a for a, _ in parts], ignore_index=True),
            pd.concat([b for _, b in parts], ignore_index=True))


def gate(rates: pd.Series, baseline: dict | None, max_drop: float, max_fa_rise: float) -> list[str]:
    """Reasons the candidate must not replace the installed models (empty: promote it).
    ``rates`` is the system's share of test flows flagged per label (Benign = false alarms)."""
    problems = []
    if baseline is None:
        if rates.get("Benign", 0.0) > FIRST_MAX_FALSE_ALARMS:
            problems.append(f"false alarms {rates['Benign']:.3%} > {FIRST_MAX_FALSE_ALARMS:.3%}")
        problems += [f"{label} detected {r:.2%} < {FIRST_MIN_DETECTION:.0%}"
                     for label, r in rates.items() if label != "Benign" and r < FIRST_MIN_DETECTION]
        return problems
    before = baseline["by_label"]
    if rates.get("Benign", 0.0) > before.get("Benign", 0.0) + max_fa_rise:
        problems.append(f"false alarms {before.get('Benign', 0.0):.3%} -> {rates['Benign']:.3%}")
    for label, r in rates.items():
        if label == "Benign":
            continue
        if label in before and r < before[label] - max_drop:
            problems.append(f"{label} detection {before[label]:.2%} -> {r:.2%}")
        elif label not in before and r < FIRST_MIN_DETECTION:
            problems.append(f"{label} (new) detected {r:.2%} < {FIRST_MIN_DETECTION:.0%}")
    problems += [f"{label} no longer tested" for label in before if label not in rates]
    return problems


def sha256(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--train-share", type=float, default=0.7)
    parser.add_argument("--min-accuracy", type=float, default=0.9)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--max-per-label", type=int, default=15_000,
                        help="cap each attack type's signature flows (benign is far scarcer)")
    parser.add_argument("--only", nargs="+", choices=list(KNOWLEDGE), metavar="DETECTOR",
                        help="train only these detectors and keep the others' saved models; the whole "
                             "system is still evaluated (default: train all)")
    parser.add_argument("--max-drop", type=float, default=0.02,
                        help="largest drop in any attack type's detection rate the gate accepts")
    parser.add_argument("--max-fa-rise", type=float, default=0.0005,
                        help="largest rise in the false-alarm rate the gate accepts")
    parser.add_argument("--force", action="store_true", help="install the models even if the gate fails")
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

    # Adding a detector need not retrain the validated ones: the web-attack class is tiny (~150
    # signature flows) and retraining the break-in detector on a larger normal-traffic pool swung
    # its web-attack detection between 17% and 92% depending on sampling alone. --only keeps them.
    trained, detectors = [], []
    for name, attacks in KNOWLEDGE.items():
        if args.only and name not in args.only:
            detectors.append(joblib.load(MODELS / f"{name}.joblib"))
            print(f"{name}: kept the saved model")
            continue
        known = signatures[signatures["label"].isin(["Benign", *attacks])]
        detectors.append(build_detector(name, known, features, SCENARIO2, n_clusters=known["label"].nunique(),
                                        stratify="label", seed=args.seed))
        trained.append(detectors[-1])

    y = test["is_attack"].to_numpy()
    verdicts = {}
    for d in detectors:
        verdicts[f"{d.name} alone"] = d.detect(test, test["record_id"])["prediction"].to_numpy(dtype=bool)
        d.clear_history()
    # evaluated exactly as live mode runs: cross-check on, unresolved-conflict guesses suppressed
    finals = CounselorNetwork(detectors, args.min_accuracy, window=0, cross_check_normal=True,
                              suppress_fallback=True).run(
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

    out = RESULTS_DIR / "live"
    out.mkdir(parents=True, exist_ok=True)
    table.to_csv(out / "by_label.csv")
    (out / "summary.json").write_text(json.dumps({"metrics": summary, "args": vars(args),
                                                  "knowledge": KNOWLEDGE}, indent=2))

    rates = table[SYSTEM]
    baseline = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else None
    problems = gate(rates, baseline, args.max_drop, args.max_fa_rise)
    if problems:
        print("\npromotion gate FAILED against the", "installed models" if baseline else "minimum bar")
        for p in problems:
            print("  -", p)
        if not args.force:
            print("installed models left unchanged (--force to install anyway)")
            sys.exit(1)
        print("--force: installing anyway")

    MODELS.mkdir(parents=True, exist_ok=True)
    for d in detectors:
        d.clear_history()
    for d in trained:
        joblib.dump(d, MODELS / f"{d.name}.joblib", compress=3)
    files = sorted(MODELS / f"{name}.joblib" for name in KNOWLEDGE)
    sums = {p.name: sha256(p) for p in files}
    (MODELS / "SHA256SUMS").write_text("".join(f"{h}  {n}\n" for n, h in sums.items()))
    MANIFEST.write_text(json.dumps({
        "promoted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "knowledge": KNOWLEDGE,
        "metrics": summary[SYSTEM],
        "by_label": rates.to_dict(),
        "test_flows": table["flows"].astype(int).to_dict(),
        "sha256": sums,
        "args": vars(args),
    }, indent=2) + "\n")
    print("\ninstalled", ", ".join(str(MODELS / f"{d.name}.joblib") for d in trained) or "no new models",
          f"(manifest: {MANIFEST})")

if __name__ == "__main__":
    main()
