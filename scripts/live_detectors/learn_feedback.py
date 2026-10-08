"""Teach the detectors from analyst feedback: the alarms marked "Not an attack" / "Real attack".

Reads logs/feedback.jsonl (the dashboard's buttons; services/feedback.py), which holds each
marked connection's measurements. Every detector learns from every verdict — a connection
marked normal is normal for all of them — with each marked connection repeated --weight
times, since a handful of verdicts would otherwise vanish among ~150,000 training flows.

A retrained detector replaces the installed one only if all hold:
  1. on the marked connections, it is right more often than before;
  2. it forgot nothing overall: on the lab evaluation data kept inside the model (labelled),
     attack detection drops by at most --max-drop and false alarms rise by at most
     --max-fa-rise;
  3. it forgot no kind of attack: inside every cluster of that data holding lab attacks, and
     (when the training flows are present) for every labelled attack type, detection drops
     by at most --max-drop. An overall check alone let a mistaken verdict — real DoS Hulk
     connections marked "not an attack" — through, since Hulk is a small share of all attacks.
Accepted models are written to models/live/ with SHA256SUMS and the manifest updated; running
detector services switch to them by themselves within a minute. Writes a report to
logs/feedback-learning.json (the dashboard shows it).

    python scripts/live_detectors/learn_feedback.py [--dry-run]
"""

import argparse
import copy
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from nids.datasets.flow_features import CIC2018_TO_2017
from nids.datasets.paths import PROJECT_ROOT
from nids.services import feedback

MODELS = PROJECT_ROOT / "models" / "live"
REPORT = PROJECT_ROOT / "logs" / "feedback-learning.json"
FEATURES = list(CIC2018_TO_2017.values())
KNOWLEDGE = {  # as in train.py: the attack types each detector learned
    "live_dos": ["DoS-GoldenEye", "DoS-Slowloris", "DoS-Hulk", "DoS-SlowHTTPTest", "DDoS"],
    "live_access": ["FTP-BruteForce", "SSH-Bruteforce", "Web-attack", "PortScan"],
    "live_bot": ["Bot"],
}


def sure_attack(detector, X: pd.DataFrame) -> np.ndarray:
    """The detector's own "attack" verdicts as live mode uses them (an unresolved conflict
    counts as normal)."""
    d = copy.copy(detector)
    d.clear_history()
    r = d.detect(X, np.arange(len(X), dtype=float))
    return (r["prediction"].astype(bool) & ~r["conflict"].astype(bool)).to_numpy()


def per_kind(detector, X: pd.DataFrame, y, kinds) -> dict:
    """Attack detection per kind (a cluster id or an attack label), for kinds with at
    least 30 attack samples."""
    p = sure_attack(detector, X)
    y = np.asarray(y, dtype=bool)
    kinds = np.asarray(kinds)
    return {str(k): float(p[(kinds == k) & y].mean()) for k in np.unique(kinds[y])
            if ((kinds == k) & y).sum() >= 30}


def forgot_kinds(old, new, X: pd.DataFrame, y, kinds, max_drop: float, what: str) -> list[str]:
    before, after = per_kind(old, X, y, kinds), per_kind(new, X, y, kinds)
    return [f"{what} {k}: {before[k]:.2%} -> {after.get(k, 0.0):.2%}"
            for k in before if after.get(k, 0.0) < before[k] - max_drop]


def lab_check(detector) -> tuple[float, float]:
    """(attack detection, false-alarm rate) on the lab evaluation data inside the model."""
    X, y = detector.model.eval_data
    y = np.asarray(y, dtype=bool)
    p = sure_attack(detector, pd.DataFrame(X, columns=detector.features) if not isinstance(X, pd.DataFrame) else X)
    return float(p[y].mean()) if y.any() else float("nan"), float(p[~y].mean()) if (~y).any() else float("nan")


def write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--feedback", type=Path, default=feedback.DEFAULT_FILE)
    parser.add_argument("--weight", type=int, default=20, help="times each marked connection is repeated")
    parser.add_argument("--max-drop", type=float, default=0.02)
    parser.add_argument("--max-fa-rise", type=float, default=0.001)
    parser.add_argument("--dry-run", action="store_true", help="report only, install nothing")
    parser.add_argument("--models", type=Path, default=MODELS, help="folder of installed detectors")
    parser.add_argument("--report", type=Path, default=REPORT)
    parser.add_argument("--labelled", type=Path, default=PROJECT_ROOT / "data" / "processed" / "live" / "flows.pkl",
                        help="training flows, for the per-attack-type check (skipped if absent)")
    args = parser.parse_args()

    entries = [e for e in feedback.read(args.feedback) if e.get("flow")]
    report = {"started": time.time(), "verdicts": len(entries), "detectors": {}, "installed": []}
    if not entries:
        report["message"] = "No marked connections with measurements yet: mark some alarms on the dashboard first."
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=1))
        sys.exit(report["message"])

    flows = pd.DataFrame([e["flow"] for e in entries])
    flows[FEATURES] = flows[FEATURES].astype(float).replace([np.inf, -np.inf], np.nan).fillna(0)
    y = np.array([e["verdict"] == "attack" for e in entries])
    print(f"{len(entries)} marked connections: {int((~y).sum())} not an attack, {int(y.sum())} real attacks")

    paths = sorted(args.models.glob("*.joblib"))
    labelled = None
    if args.labelled.exists():  # the training flows: a per-attack-type forgetting check
        labelled = pd.read_pickle(args.labelled).replace([np.inf, -np.inf], np.nan).dropna(subset=FEATURES)
        labelled = pd.concat([g.sample(min(len(g), 3000), random_state=0) for _, g in labelled.groupby("label")],
                             ignore_index=True)
    for path in paths:
        old = joblib.load(path)
        before = sure_attack(old, flows)
        candidate = copy.deepcopy(old)
        X = pd.concat([flows[candidate.features]] * args.weight, ignore_index=True)
        candidate.new_signatures = [(X, np.tile(y, args.weight))]
        print(f"retraining {old.name} on {len(X):,} feedback rows…", flush=True)
        candidate.retrain()
        after = sure_attack(candidate, flows)
        right_before, right_after = float((before == y).mean()), float((after == y).mean())
        det_before, fa_before = lab_check(old)
        det_after, fa_after = lab_check(candidate)
        problems = []
        # no kind of attack forgotten: per cluster of the lab evaluation data (always there)...
        X_eval, y_eval = old.model.eval_data
        X_eval = X_eval.reset_index(drop=True)
        clusters = old.model.assign_clusters(old.model.transform(X_eval[old.features]))
        problems += forgot_kinds(old, candidate, X_eval, y_eval, clusters, args.max_drop, "lab cluster")
        # ...and per labelled attack type, when the training flows are present
        if labelled is not None:
            mine = labelled[labelled["label"].isin(["Benign", *KNOWLEDGE.get(old.name, [])])].reset_index(drop=True)
            problems += forgot_kinds(old, candidate, mine, (mine["label"] != "Benign").to_numpy(),
                                     mine["label"].to_numpy(), args.max_drop, "attack type")
        if right_after < right_before:
            problems.append(f"right on marked connections {right_before:.0%} -> {right_after:.0%}")
        if det_after < det_before - args.max_drop:
            problems.append(f"lab attack detection {det_before:.2%} -> {det_after:.2%}")
        if fa_after > fa_before + args.max_fa_rise:
            problems.append(f"lab false alarms {fa_before:.3%} -> {fa_after:.3%}")
        accepted = not problems and right_after > right_before
        report["detectors"][old.name] = {
            "marked_flagged_before": int(before[~y].sum()), "marked_flagged_after": int(after[~y].sum()),
            "real_attacks_caught_before": int(before[y].sum()), "real_attacks_caught_after": int(after[y].sum()),
            "right_before": right_before, "right_after": right_after,
            "lab_detection": [det_before, det_after], "lab_false_alarms": [fa_before, fa_after],
            "accepted": accepted, "problems": problems or ([] if accepted else ["no improvement on the marked connections"]),
        }
        print(f"  {old.name}: still flags {int(before[~y].sum())} -> {int(after[~y].sum())} of the "
              f"{int((~y).sum())} marked not-an-attack; lab detection {det_before:.2%} -> {det_after:.2%}, "
              f"lab false alarms {fa_before:.3%} -> {fa_after:.3%} ({'accepted' if accepted else 'rejected'})")
        if accepted and not args.dry_run:
            candidate.clear_history()
            tmp = path.with_suffix(".joblib.tmp")
            joblib.dump(candidate, tmp, compress=3)
            os.replace(tmp, path)
            report["installed"].append(old.name)

    if report["installed"]:
        sums = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
        write_atomic(args.models / "SHA256SUMS", "".join(f"{h}  {n}\n" for n, h in sums.items()).encode())
        manifest_path = args.models / "manifest.json"
        manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
        manifest["sha256"] = sums
        manifest.setdefault("feedback", []).append({
            "learned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "verdicts": len(entries), "detectors": report["installed"]})
        write_atomic(manifest_path, (json.dumps(manifest, indent=2) + "\n").encode())
        print("installed:", ", ".join(report["installed"]), "— running detectors switch within a minute")
    else:
        print("nothing installed")
    report["finished"] = time.time()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
