"""Train and test the LIVE detectors on flows computed by the Python cicflowmeter.

Input, from two labs: data/processed/live/flows.pkl (CSE-CIC-IDS2018, build_dataset.py) and
data/processed/live/cicids2017-*.pkl (CICIDS2017, build_cicids2017.py). Counselor detectors
with different knowledge, as in the paper's Scenario 2:

    live_dos      DoS (GoldenEye, Slowloris, Hulk, SlowHTTPTest) and DDoS
    live_access   brute force (FTP, SSH), web attacks and port scans
    live_bot      botnet (Ares hosts calling their command-and-control server)

All learn from all benign flows. Split by TIME within each label and capture (earliest 80%
for signatures, latest 20% for test), so test flows come from later in each attack than any
training flow — closer to meeting traffic live than a random split. ``--train-labs`` and
``--test-labs`` train on one lab and test on the other (with ``--evaluate-only``), to check
the detectors learned the attacks and not the lab.

Promotion gate: the installed models are tested on the same test flows, and the new ones
replace them only if the whole system does not get worse — no more false alarms, no attack
type's detection drops by more than --max-drop, and attack types the installed models never
learned reach FIRST_MIN_DETECTION. A bad retrain therefore never silently reaches live
monitoring; --force overrides. Promoted models are listed with their SHA-256 in
models/live/SHA256SUMS, which `./start.sh live` verifies before loading them, and their
results in models/live/manifest.json.

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
from nids.datasets.paths import PROJECT_ROOT, RESULTS_DIR
from nids.detector.classifiers import CLASSIFIERS
from nids.evaluation import metrics
from nids.detector.training import build_detector

PROCESSED = PROJECT_ROOT / "data" / "processed" / "live"
LABS = {"2018": [PROCESSED / "flows.pkl"], "2017": sorted(PROCESSED.glob("cicids2017-*.pkl"))}
MODELS = PROJECT_ROOT / "models" / "live"
MANIFEST = MODELS / "manifest.json"
SYSTEM = "counselor network"
# with no installed baseline, a candidate must at least meet these
FIRST_MAX_FALSE_ALARMS = 0.002
FIRST_MIN_DETECTION = 0.8

KNOWLEDGE = {
    "live_dos": ["DoS-GoldenEye", "DoS-Slowloris", "DoS-Hulk", "DoS-SlowHTTPTest", "DDoS"],
    "live_access": ["FTP-BruteForce", "SSH-Bruteforce", "Web-attack", "PortScan"],
    "live_bot": ["Bot"],
}


def load(labs: list[str]) -> pd.DataFrame:
    frames = [pd.read_pickle(path).assign(lab=lab) for lab in labs for path in LABS[lab] if path.exists()]
    if not frames:
        sys.exit(f"no flows for labs {labs} in {PROCESSED}")
    flows = pd.concat(frames, ignore_index=True)
    flows["is_attack"] = flows["label"] != "Benign"
    return flows


def time_split(flows: pd.DataFrame, share: float) -> tuple[pd.DataFrame, pd.DataFrame]:
    # stable sort: flow starts have one-second resolution, so thousands of flows tie; an unstable
    # sort ordered them differently whenever other captures were added, changing which flows
    # landed in training (false alarms swung between 0 and 921 on the same data)
    flows = flows.sort_values("flow_start", kind="stable")
    parts = [(g.iloc[: int(len(g) * share)], g.iloc[int(len(g) * share):])
             for _, g in flows.groupby(["label", "capture"], sort=True)]
    return (pd.concat([a for a, _ in parts], ignore_index=True),
            pd.concat([b for _, b in parts], ignore_index=True))


def evaluate(detectors, test: pd.DataFrame, min_accuracy: float) -> tuple[pd.DataFrame, dict]:
    """Share of each label's test flows flagged, per detector alone and for the whole system
    (Benign row = false alarms), and overall metrics."""
    verdicts = {}
    for d in detectors:
        d.clear_history()
        verdicts[f"{d.name} alone"] = d.detect(test, test["record_id"])["prediction"].to_numpy(dtype=bool)
        d.clear_history()
    # evaluated exactly as live mode runs: cross-check on, unresolved-conflict guesses suppressed
    finals = CounselorNetwork(detectors, min_accuracy, window=0, cross_check_normal=True,
                              suppress_fallback=True).run(test, test["record_id"])
    verdicts[SYSTEM] = np.logical_or.reduce([f["prediction"].to_numpy(dtype=bool) for f in finals.values()])
    for d in detectors:
        d.clear_history()
    table = pd.DataFrame({
        label: {"flows": len(g), **{k: float(v[g.index].mean()) for k, v in verdicts.items()}}
        for label, g in test.groupby("label")
    }).T.sort_values("flows", ascending=False)
    y = test["is_attack"].to_numpy()
    return table, {k: metrics(y, v) for k, v in verdicts.items()}


def show(table: pd.DataFrame, summary: dict) -> None:
    pct = lambda v: f"{v:.2%}"  # noqa: E731
    print("\nshare of test flows flagged as attack (Benign row = false alarms):")
    print(table.to_string(formatters={k: pct for k in table.columns if k != "flows"} | {"flows": "{:,.0f}".format}))
    print(pd.DataFrame(summary).T.map(pct).to_string())


def gate(rates: pd.Series, baseline: dict | None, max_drop: float, max_fa_rise: float) -> list[str]:
    """Reasons the candidate must not replace the installed models (empty: promote it).
    ``rates`` and ``baseline["by_label"]`` are the share of the same test flows flagged per
    label (Benign = false alarms) by the new and the installed system."""
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
    return problems


def sha256(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--train-share", type=float, default=0.8)
    parser.add_argument("--min-accuracy", type=float, default=0.9)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--labs", nargs="+", choices=list(LABS), default=list(LABS),
                        help="labs to train and test on (default: both)")
    parser.add_argument("--train-labs", nargs="+", choices=list(LABS), help="train on these labs only")
    parser.add_argument("--test-labs", nargs="+", choices=list(LABS), help="test on these labs only")
    parser.add_argument("--max-per-label", type=int,
                        help="cap each attack type's signature flows (default: use all of them)")
    parser.add_argument("--only", nargs="+", choices=list(KNOWLEDGE), metavar="DETECTOR",
                        help="train only these detectors and keep the others' saved models; the whole "
                             "system is still evaluated (default: train all)")
    parser.add_argument("--max-drop", type=float, default=0.02,
                        help="largest drop in any attack type's detection rate the gate accepts")
    parser.add_argument("--max-fa-rise", type=float, default=0.0005,
                        help="largest rise in the false-alarm rate the gate accepts")
    parser.add_argument("--force", action="store_true", help="install the models even if the gate fails")
    parser.add_argument("--evaluate-only", action="store_true", help="report results, install nothing")
    parser.add_argument("--results", default="live", help="folder under results/ for this run's tables")
    args = parser.parse_args()

    features = list(CIC2018_TO_2017.values())

    flows = load(sorted(set(args.labs) | set(args.train_labs or []) | set(args.test_labs or [])))
    flows = flows.replace([np.inf, -np.inf], np.nan).dropna(subset=features)
    signatures, test = time_split(flows, args.train_share)
    if args.train_labs:
        signatures = signatures[signatures["lab"].isin(args.train_labs)]
    if args.test_labs:
        test = test[test["lab"].isin(args.test_labs)]
    if args.max_per_label:
        signatures = pd.concat(
            [g if label == "Benign" else g.sample(min(len(g), args.max_per_label), random_state=args.seed)
             for label, g in signatures.groupby("label")], ignore_index=True)
    signatures = signatures.reset_index(drop=True)
    test = test.sample(frac=1, random_state=args.seed).reset_index(drop=True)
    test["record_id"] = np.arange(len(test))
    print(f"{len(signatures):,} signature flows, {len(test):,} test flows")
    print(pd.crosstab(flows["label"], flows["lab"]).to_string())

    trained, detectors = [], []
    for name, attacks in KNOWLEDGE.items():
        if args.only and name not in args.only:
            detectors.append(joblib.load(MODELS / f"{name}.joblib"))
            print(f"{name}: kept the saved model")
            continue
        known = signatures[signatures["label"].isin(["Benign", *attacks])]
        print(f"{name}: training on {len(known):,} flows", flush=True)
        detectors.append(build_detector(name, known, features, CLASSIFIERS, n_clusters=known["label"].nunique(),
                                        stratify="label", seed=args.seed))
        trained.append(detectors[-1])

    table, summary = evaluate(detectors, test, args.min_accuracy)
    show(table, summary)
    out = RESULTS_DIR / args.results
    out.mkdir(parents=True, exist_ok=True)
    table.to_csv(out / "by_label.csv")
    (out / "summary.json").write_text(json.dumps({"metrics": summary, "args": vars(args),
                                                  "knowledge": KNOWLEDGE}, indent=2))
    if args.evaluate_only:
        return

    # the installed models, tested on the same flows, are the bar the new ones must clear
    installed = sorted(MODELS.glob("*.joblib"))
    baseline = None
    if installed and MANIFEST.exists():
        print("\ninstalled models on the same test flows:")
        before, before_summary = evaluate([joblib.load(p) for p in installed], test, args.min_accuracy)
        show(before, before_summary)
        baseline = {"by_label": before[SYSTEM].to_dict()}

    rates = table[SYSTEM]
    problems = gate(rates, baseline, args.max_drop, args.max_fa_rise)
    rates.to_frame("new").assign(installed=pd.Series(baseline["by_label"]) if baseline else np.nan) \
        .to_csv(out / "gate.csv")
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
    for stale in set(MODELS.glob("*.joblib")) - set(files):
        stale.unlink()  # a detector no longer in KNOWLEDGE must not keep running live
    sums = {p.name: sha256(p) for p in files}
    (MODELS / "SHA256SUMS").write_text("".join(f"{h}  {n}\n" for n, h in sums.items()))
    MANIFEST.write_text(json.dumps({
        "promoted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "knowledge": KNOWLEDGE,
        "metrics": summary[SYSTEM],
        "by_label": rates.to_dict(),
        "test_flows": table["flows"].astype(int).to_dict(),
        "labs": args.labs,
        "sha256": sums,
        "args": vars(args),
    }, indent=2) + "\n")
    print("\ninstalled", ", ".join(str(MODELS / f"{d.name}.joblib") for d in trained) or "no new models",
          f"(manifest: {MANIFEST})")

if __name__ == "__main__":
    main()
