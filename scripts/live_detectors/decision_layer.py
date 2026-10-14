"""Formal decision layer: an alternative to the counselor voting, evaluated end to end.

On top of the trained detectors this applies, in order:
    1. calibration            so the detectors' scores are comparable (Platt / isotonic),
    2. trust-weighted          log-odds fusion of the calibrated detector probabilities and
       log-odds fusion         Snort (its rule trust), so one confident trusted source can
                               outweigh several weak ones,
    3. cost-sensitive          flag when the fused probability exceeds C_FP / (C_FP + C_FN),
       threshold
with Beta detector trust (the AI counselors' reputation, updated online from agreement with a
decay), and, with ``--stream``, importance-weighted self-learning and Page-Hinkley
drift-triggered retraining. It reports how this fused decision compares with the plain ensemble
vote, and the calibration quality (Brier score).

This is the home of the "formal decision layer" from the comparison with the base paper; it
does not change the deployed counselor voting.

    python scripts/live_detectors/decision_layer.py --labs 2018
    python scripts/live_detectors/decision_layer.py --labs 2017 --calibration isotonic --cost-fn 5
"""

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))  # reuse the training helpers
import train  # noqa: E402

from nids.counselor.decision import (  # noqa: E402
    Calibrator, DetectorTrust, PageHinkley, cost_threshold, detector_proba, fuse_noisy_or, importance_weights,
)
from nids.counselor.snort import RuleTrust  # noqa: E402
from nids.datasets.flow_features import CIC2018_TO_2017  # noqa: E402
from nids.datasets.paths import PROJECT_ROOT  # noqa: E402
from nids.evaluation import metrics, pr_auc  # noqa: E402

FEATURES = list(CIC2018_TO_2017.values())
MODELS = PROJECT_ROOT / "models" / "live"


def brier(p, y) -> float:
    return float(np.mean((np.asarray(p, float) - np.asarray(y, float)) ** 2))


def snort_trust_per_row(frame: pd.DataFrame, rule_trust: RuleTrust) -> np.ndarray:
    """For each connection, the trust of the most trusted Snort rule that fired on it (0 if
    Snort was silent)."""
    return np.array([max((rule_trust.score(r) for r in rules), default=0.0)
                     for rules in frame["snort_rules"].to_numpy()])


def fused_probability(detectors, frame, calibrators, det_trust, rule_trust) -> np.ndarray:
    """Trust-weighted noisy-OR of the calibrated per-family detector probabilities and Snort —
    the right fusion for disjoint specialists (attack if ANY family fires). Log-odds pooling is
    wrong here: it would let a specialist's "not my family" cancel another's detection."""
    probs = [calibrators[d.name].transform(detector_proba(d, frame)) for d in detectors]
    weights = [det_trust.score(d.name) for d in detectors]
    probs.append(snort_trust_per_row(frame, rule_trust))  # Snort: p = its rule trust where it fired, 0 else
    weights.append(1.0)
    return fuse_noisy_or(probs, weights)


def report(name: str, y, verdict) -> dict:
    m = metrics(y, verdict)
    print(f"  {name:20s} detection {m['detection_rate']:.2%}  false alarms {m['false_alarm_rate']:.3%}  "
          f"F1 {m['f1']:.3f}  MCC {m['mcc']:.3f}")
    return m


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--labs", nargs="+", default=["2018"], choices=list(train.LABS))
    p.add_argument("--calibration", choices=["platt", "isotonic"], default="platt")
    p.add_argument("--cost-fp", type=float, default=1.0, help="cost of a false alarm")
    p.add_argument("--cost-fn", type=float, default=1.0, help="cost of a missed attack")
    p.add_argument("--trust-prior", type=float, default=0.8)
    p.add_argument("--decay", type=float, default=1.0, help="forgetting factor for detector trust")
    p.add_argument("--train-share", type=float, default=0.8)
    p.add_argument("--max-test", type=int, default=200_000)
    p.add_argument("--stream", action="store_true",
                   help="demonstrate importance-weighted self-learning and drift-triggered retrain")
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args()

    paths = sorted(MODELS.glob("*.joblib"))
    if not paths:
        sys.exit("no live detectors in models/live/ (train them first)")
    detectors = [joblib.load(p) for p in paths]
    print("detectors:", ", ".join(d.name for d in detectors))

    flows = train.load(args.labs).replace([np.inf, -np.inf], np.nan).dropna(subset=FEATURES)
    flows["snort_rules"] = flows["snort_rules"].map(lambda r: tuple(r) if isinstance(r, (list, tuple)) else ())
    flows["is_attack"] = (flows["label"] != "Benign").to_numpy()
    fit, test = train.time_split(flows, args.train_share)
    if len(test) > args.max_test:
        test = test.sample(args.max_test, random_state=args.seed)
    fit, test = fit.reset_index(drop=True), test.reset_index(drop=True)
    y = test["is_attack"].to_numpy()
    print(f"calibrating on {len(fit):,} flows, testing on {len(test):,} ({int(y.sum()):,} attacks)")

    # each specialist is calibrated and judged against ITS OWN family (is this my kind of attack):
    # the detectors are not redundant, so fusing/calibrating them against the global label is unsound
    def family(labels, name):
        return labels.isin(train.KNOWLEDGE.get(name, [])).to_numpy()

    # 3. calibration: per detector, against its own family; Brier before/after
    calibrators, raw = {}, {}
    print("\ncalibration (Brier vs the detector's own family, lower is better):")
    for d in detectors:
        calibrators[d.name] = Calibrator(args.calibration).fit(detector_proba(d, fit), family(fit["label"], d.name))
        raw[d.name] = detector_proba(d, test)
        yf = family(test["label"], d.name)
        cal = calibrators[d.name].transform(raw[d.name])
        print(f"  {d.name:12s} raw {brier(raw[d.name], yf):.4f} -> calibrated {brier(cal, yf):.4f}")

    # 2. detector trust: Beta reputation from each specialist's accuracy on its own family
    det_trust = DetectorTrust(prior=args.trust_prior, decay=args.decay)
    for d in detectors:
        correct = int(((detector_proba(d, fit) > 0.5) == family(fit["label"], d.name)).sum())
        det_trust.update(d.name, agree=correct, disagree=len(fit) - correct)
    print("\ndetector trust (reliability on own family):",
          {d.name: round(det_trust.score(d.name), 3) for d in detectors})

    # 1 + 6: trust-weighted noisy-OR of calibrated specialists + Snort, then a cost threshold
    rule_trust = RuleTrust()
    fused = fused_probability(detectors, test, calibrators, det_trust, rule_trust)
    thr = cost_threshold(args.cost_fp, args.cost_fn)
    print(f"\ncost threshold = C_FP/(C_FP+C_FN) = {thr:.3f}  (C_FP={args.cost_fp}, C_FN={args.cost_fn})")
    print("comparison on the global attack label:")
    vote = np.logical_or.reduce([calibrators[d.name].transform(raw[d.name]) > 0.5 for d in detectors])
    report("calibrated OR (vote)", y, vote)
    report("noisy-OR fusion+cost", y, fused > thr)
    print(f"  fusion PR-AUC {pr_auc(y, fused):.3f}  (OR PR-AUC {pr_auc(y, vote.astype(float)):.3f})")

    if args.stream:
        stream_demo(detectors, fit, args)


def stream_demo(detectors, data, args):
    """Importance-weighted self-learning with Page-Hinkley drift detection over a stream."""
    print("\n--- streaming self-learning (importance weighting + drift) ---")
    df = data.sample(frac=1, random_state=args.seed).reset_index(drop=True)
    bounds = np.linspace(0, len(df), 11).astype(int)  # np.array_split no longer returns DataFrames
    chunks = [df.iloc[lo:hi].reset_index(drop=True) for lo, hi in zip(bounds[:-1], bounds[1:])]
    ph = {d.name: PageHinkley(delta=0.005, threshold=0.5, min_instances=100) for d in detectors}
    for step, chunk in enumerate(chunks, 1):
        y = chunk["is_attack"].to_numpy()
        for d in detectors:
            pred = detector_proba(d, chunk) > 0.5
            errors = (pred != y).astype(float)
            drifted = any(ph[d.name].update(e) for e in errors)
            # importance weighting: agreement labels over-represent easy cases
            selected = (pred == y)  # confident-correct samples a self-trainer would keep
            w = importance_weights(selected, y)
            if drifted:
                print(f"  step {step:2d}: drift on {d.name} (would retrain; "
                      f"importance weights span {w.min():.2f}-{w.max():.2f})")
    print("  (drift detector triggers a retrain instead of a fixed schedule; importance weights "
          "would be passed to that retrain)")


if __name__ == "__main__":
    main()
