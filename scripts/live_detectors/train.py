"""Train and test the LIVE detectors on flows computed by the Python cicflowmeter.

Input, from two labs: data/processed/live/flows.pkl (CSE-CIC-IDS2018, build_dataset.py) and
data/processed/live/cicids2017-*.pkl (CICIDS2017, build_cicids2017.py). Counselor detectors
with different knowledge, as in the paper's Scenario 2:

    live_dos      DoS (GoldenEye, Slowloris, Hulk, SlowHTTPTest) and DDoS
    live_access   brute force (FTP, SSH), web attacks and port scans
    live_bot      botnet (Ares hosts calling their command-and-control server)

All learn from all benign flows. Flows are cleaned and de-duplicated, then split by TIME within
each label and capture (data_prep.py): earliest 60% training, next 20% validation, latest 20%
test. Classifier selection, novelty thresholds and the promotion gate use validation only; the
test split is evaluated once at the end, for reporting. ``--train-labs`` and
``--test-labs`` train on one lab and test on the other (with ``--evaluate-only``), to check
the detectors learned the attacks and not the lab.

Promotion gate: the installed models are tested on the same validation flows, and the new ones
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
from pathlib import Path
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd

from nids.counselor import LIVE, CounselorNetwork
from nids.datasets.paths import PROJECT_ROOT, RESULTS_DIR
from nids.detector.classifiers import CLASSIFIERS
from nids.evaluation import clustered_mcnemar, metrics, metrics_with_intervals, wilson
from nids.detector import novelty as nov
from nids.detector.training import build_detector

import data_prep as dp

PROCESSED = PROJECT_ROOT / "data" / "processed" / "live"
LABS = {"2018": [PROCESSED / "flows.pkl"], "2017": sorted(PROCESSED.glob("cicids2017-*.pkl"))}
MODELS = PROJECT_ROOT / "models" / "live"
MANIFEST = MODELS / "manifest.json"
SYSTEM = "counselor network"
# with no installed baseline, a candidate must at least meet these
FIRST_MAX_FALSE_ALARMS = 0.002
FIRST_MIN_DETECTION = 0.8
# identifies the split; installed models trained under another protocol have seen this run's
# validation/test flows, so they can't serve as the gate's baseline
PROTOCOL = "time-ordered 60/20/20 within (label, capture), deduplicated; selection+gate on validation"

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


def evaluate(detectors, test: pd.DataFrame, min_accuracy: float) -> tuple[pd.DataFrame, dict, np.ndarray]:
    """Share of each label's test flows flagged, per detector alone and for the whole system
    (Benign row = false alarms), overall metrics (the system's with 95% intervals), and the
    system's verdict per test flow."""
    verdicts = {}
    for d in detectors:
        d.clear_history()
        verdicts[f"{d.name} alone"] = d.detect(test, test["record_id"])["prediction"].to_numpy(dtype=bool)
        d.clear_history()
    # evaluated exactly as live mode runs (counselor.LIVE)
    finals = CounselorNetwork(detectors, min_accuracy, window=0, learn_from_advice=False,
                              **LIVE).run(test, test["record_id"])
    verdicts[SYSTEM] = np.logical_or.reduce([f["prediction"].to_numpy(dtype=bool) for f in finals.values()])
    for d in detectors:
        d.clear_history()
    table = pd.DataFrame({
        label: {"flows": len(g), **{k: float(v[g.index].mean()) for k, v in verdicts.items()}}
        for label, g in test.groupby("label")
    }).T.sort_values("flows", ascending=False)
    y = test["is_attack"].to_numpy()
    summary = {k: metrics(y, v) for k, v in verdicts.items()}
    summary[SYSTEM] = metrics_with_intervals(y, verdicts[SYSTEM])
    return table, summary, verdicts[SYSTEM]


CONFLICT_RULES = {
    "any detector alone": None,
    "previous live (normal advice + suppress)": dict(suppress_fallback=True),
    "paper (normal advice + best guess)": dict(),
    "live (no normal advice + best guess)": dict(conflict_normal_advice=False),
    "no normal advice + proba>=0.7": dict(conflict_normal_advice=False, fallback_threshold=0.7),
}


def conflict_ablation(detectors, test: pd.DataFrame, min_accuracy: float) -> pd.DataFrame:
    """Detection, false alarms and a session-clustered McNemar test against "any detector
    alone", per conflict-handling rule, on the same flows."""
    y, sessions, rid = test["is_attack"].to_numpy(), dp.session_ids(test), test["record_id"]
    verdicts = {}
    for name, kw in CONFLICT_RULES.items():
        if kw is None:
            verdicts[name] = np.logical_or.reduce([d.detect(test, rid)["prediction"].to_numpy(dtype=bool)
                                                   for d in detectors])
        else:
            out = CounselorNetwork(detectors, min_accuracy, window=0, cross_check_normal=True,
                                   learn_from_advice=False, **kw).run(test, rid)
            verdicts[name] = np.logical_or.reduce([f["prediction"].to_numpy(dtype=bool) for f in out.values()])
        for d in detectors:
            d.clear_history()
    base = verdicts["any detector alone"]
    rows = {}
    for name, v in verdicts.items():
        m = metrics(y, v)
        t = clustered_mcnemar(y, v, base, sessions)
        rows[name] = {"detection_rate": m["detection_rate"], "fp_per_1k": 1000 * m["false_alarm_rate"],
                      "flows_differ": t["b"] + t["c"], "sessions_differ": t["informative_clusters"],
                      "p_vs_alone": t["p_value"]}
    return pd.DataFrame(rows).T


def intervals(test: pd.DataFrame, verdict: np.ndarray) -> pd.DataFrame:
    """Per label: flows, flagged, the flagged share and its 95% Wilson interval."""
    rows = {}
    for label, g in test.groupby("label"):
        k, n = int(verdict[g.index].sum()), len(g)
        low, high = wilson(k, n)
        rows[label] = {"flows": n, "flagged": k, "rate": k / n, "low": low, "high": high}
    return pd.DataFrame(rows).T.sort_values("flows", ascending=False)


def show(table: pd.DataFrame, summary: dict) -> None:
    pct = lambda v: f"{v:.2%}"  # noqa: E731
    print("\nshare of test flows flagged as attack (Benign row = false alarms):")
    print(table.to_string(formatters={k: pct for k in table.columns if k != "flows"} | {"flows": "{:,.0f}".format}))
    print(pd.DataFrame({k: {m: v[m] for m in ("accuracy", "detection_rate", "false_alarm_rate")}
                        for k, v in summary.items()}).T.map(pct).to_string())
    s = summary[SYSTEM]
    print(f"system, 95% intervals: detection {s['detection_rate']:.2%} "
          f"({s['detection_rate_low']:.2%}-{s['detection_rate_high']:.2%}), false alarms "
          f"{s['false_alarm_rate']:.3%} ({s['false_alarm_rate_low']:.3%}-{s['false_alarm_rate_high']:.3%})")


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
    parser.add_argument("--train-share", type=float, default=0.6)
    parser.add_argument("--val-share", type=float, default=0.2,
                        help="validation share: classifier selection, novelty thresholds and the gate")
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
    parser.add_argument("--models-out", type=Path, default=MODELS,
                        help="where to write promoted models (default: models/live). Use a separate\n"
                             "folder to train a candidate set without touching the deployed models.")
    parser.add_argument("--ablation", action="store_true",
                        help="also compare conflict-handling rules on the test split (conflict_rules.csv)")
    parser.add_argument("--no-window", action="store_true",
                        help="omit the per-source window features (reproduce the single-flow baseline)")
    parser.add_argument("--drop-port", action="store_true",
                        help="train without Destination Port (port-shortcut sensitivity analysis)")
    args = parser.parse_args()

    models_dir = args.models_out
    manifest_path = models_dir / "manifest.json"
    features = dp.common_features(drop_port=args.drop_port, window=not args.no_window)
    installed_manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    comparable = installed_manifest.get("protocol") == PROTOCOL
    if args.only and not comparable:
        sys.exit("--only reuses installed models, but they were trained under a different split and "
                 "have seen this run's validation/test flows; retrain all detectors")

    flows = load(sorted(set(args.labs) | set(args.train_labs or []) | set(args.test_labs or [])))
    flows, cleaning = dp.prepare(flows, features)
    print("cleaning:", cleaning)
    signatures, val, test = dp.three_way_split(flows, args.train_share, args.val_share)
    if args.train_labs:
        signatures = signatures[signatures["lab"].isin(args.train_labs)]
        val = val[val["lab"].isin(args.train_labs)]
    if args.test_labs:
        test = test[test["lab"].isin(args.test_labs)]
    if args.max_per_label:
        signatures = pd.concat(
            [g if label == "Benign" else g.sample(min(len(g), args.max_per_label), random_state=args.seed)
             for label, g in signatures.groupby("label")], ignore_index=True)
    signatures = signatures.reset_index(drop=True)
    val, test = (part.sample(frac=1, random_state=args.seed).reset_index(drop=True) for part in (val, test))
    val["record_id"], test["record_id"] = np.arange(len(val)), np.arange(len(test))
    print(f"{len(signatures):,} training, {len(val):,} validation, {len(test):,} test flows")
    print(pd.crosstab(flows["label"], flows["lab"]).to_string())

    trained, detectors = [], []
    for name, attacks in KNOWLEDGE.items():
        if args.only and name not in args.only:
            detectors.append(joblib.load(models_dir / f"{name}.joblib"))
            print(f"{name}: kept the saved model")
            continue
        keep = ["Benign", *attacks]
        known = signatures[signatures["label"].isin(keep)]
        # classifiers are selected per cluster on the time-ordered validation slice, not on a
        # random half of training (near-duplicate flows of one session would sit on both sides)
        print(f"{name}: training on {len(known):,} flows", flush=True)
        detectors.append(build_detector(name, known, features, CLASSIFIERS, n_clusters=known["label"].nunique(),
                                        stratify="label", seed=args.seed,
                                        validation=val[val["label"].isin(keep)]))
        trained.append(detectors[-1])

    # every decision (gate, McNemar, novelty thresholds) is made on VALIDATION flows only
    print("\n== validation (used for the promotion decision) ==")
    val_table, val_summary, val_verdict = evaluate(detectors, val, args.min_accuracy)
    show(val_table, val_summary)
    rates = val_table[SYSTEM]
    taus = novelty_thresholds(detectors, val, features)

    baseline, tests = None, None
    installed = sorted(models_dir.glob("*.joblib"))
    if installed and comparable and not args.evaluate_only:
        print("\ninstalled models on the same validation flows:")
        before, before_summary, before_verdict = evaluate([joblib.load(p) for p in installed], val, args.min_accuracy)
        show(before, before_summary)
        baseline = {"by_label": before[SYSTEM].to_dict()}
        # sessions, not flows, are the unit: flows of one session are near-copies
        y, sessions = val["is_attack"].to_numpy(), dp.session_ids(val)
        tests = {"all": clustered_mcnemar(y, val_verdict, before_verdict, sessions)}
        for label, g in val.groupby("label"):
            i = g.index
            tests[label] = clustered_mcnemar(y[i], val_verdict[i], before_verdict[i], sessions[i])
        t = tests["all"]
        print(f"\nnew vs installed (McNemar, validation): new alone right on {t['b']:,} flows, installed "
              f"alone on {t['c']:,}; {t['informative_clusters']} of {t['clusters']} sessions differ; p = {t['p_value']:.3g}")
    elif installed and not comparable:
        print("\ninstalled models were trained under a different split (they have seen these flows): "
              "comparing against the minimum bar instead")

    problems = gate(rates, baseline, args.max_drop, args.max_fa_rise)

    # the test split is touched once, after every choice above is fixed, for reporting only
    print("\n== test (reported only; never used for a decision) ==")
    table, summary, verdict = evaluate(detectors, test, args.min_accuracy)
    show(table, summary)
    out = RESULTS_DIR / args.results
    out.mkdir(parents=True, exist_ok=True)
    intervals(test, verdict).to_csv(out / "intervals.csv")
    table.to_csv(out / "by_label.csv")
    (out / "summary.json").write_text(json.dumps({"protocol": PROTOCOL, "cleaning": cleaning, "metrics": summary,
                                                  "args": vars(args), "knowledge": KNOWLEDGE}, indent=2, default=str))
    rates.to_frame("new").assign(installed=pd.Series(baseline["by_label"]) if baseline else np.nan) \
        .to_csv(out / "gate.csv")
    if args.ablation:
        rules = conflict_ablation(detectors, test, args.min_accuracy)
        print("\nconflict-handling rules (test):\n" + rules.to_string())
        rules.to_csv(out / "conflict_rules.csv")
    if tests:
        (out / "mcnemar.json").write_text(json.dumps(
            {"a": "new", "b": "installed", "split": "validation",
             "note": "b = only the new system right, c = only the installed one right", "tests": tests}, indent=1))
    if args.evaluate_only:
        return

    if problems:
        print("\npromotion gate FAILED (validation) against the", "installed models" if baseline else "minimum bar")
        for p in problems:
            print("  -", p)
        if not args.force:
            print("installed models left unchanged (--force to install anyway)")
            sys.exit(1)
        print("--force: installing anyway")

    models_dir.mkdir(parents=True, exist_ok=True)
    for d in detectors:
        d.clear_history()
    for d in trained:
        joblib.dump(d, models_dir / f"{d.name}.joblib", compress=3)
    files = sorted(models_dir / f"{name}.joblib" for name in KNOWLEDGE)
    for stale in set(models_dir.glob("*.joblib")) - set(files):
        stale.unlink()  # a detector no longer in KNOWLEDGE must not keep running live
    (models_dir / "novelty.json").write_text(json.dumps(taus, indent=1) + "\n")
    sums = {p.name: sha256(p) for p in files}
    (models_dir / "SHA256SUMS").write_text("".join(f"{h}  {n}\n" for n, h in sums.items()))
    manifest_path.write_text(json.dumps({
        "promoted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "protocol": PROTOCOL,
        "knowledge": KNOWLEDGE,
        "metrics": summary[SYSTEM],
        "by_label": table[SYSTEM].to_dict(),
        "validation_by_label": rates.to_dict(),
        "test_flows": table["flows"].astype(int).to_dict(),
        "labs": args.labs,
        "sha256": sums,
        "args": vars(args),
    }, indent=2, default=str) + "\n")
    print("\ninstalled", ", ".join(str(models_dir / f"{d.name}.joblib") for d in trained) or "no new models",
          f"(manifest: {manifest_path})")


def novelty_thresholds(detectors, val: pd.DataFrame, features: list[str], keep_benign: float = 0.99) -> dict:
    """Per-detector novelty threshold tau: the 99th percentile of the detector's novelty score on
    benign VALIDATION flows (never test). Written to models/live/novelty.json for live mode."""
    benign = val.loc[~val["is_attack"], features]
    out = {"keep_benign": keep_benign, "split": "validation", "detectors": {}}
    for d in detectors:
        scores = nov.novelty_scores(d, benign)
        tau = float(nov.choose_threshold(scores, keep_benign))
        out["detectors"][d.name] = {"tau": round(tau, 4), "tau_alert": round(tau, 4),
                                    "median_benign": round(float(np.median(scores)), 4)}
    return out


if __name__ == "__main__":
    main()
