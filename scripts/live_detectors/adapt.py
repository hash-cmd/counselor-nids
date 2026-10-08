"""Adapting the detectors to a network they never saw, without labels — the thesis experiment.

Detectors are trained on one lab (--source) and then watch another (--target), as in a real
deployment: the target's traffic streams through the system in time order, in chunks, and
nobody labels it. What each configuration may use to adapt:

    ai              the counselors network as deployed (cross-check on, fallback suppressed)
    +snort          Snort joins as a counselor: advice "attack" on connections it alerted on;
                    a trusted "attack" advice beats "normal" advice (attack_advice_wins)
    +rules          adaptive trust, Snort rules only: each rule's trust re-estimated from
                    how often the AI agrees with it
    +trust          adaptive trust: rules, and each detector's per-cluster advice confidence
    +trust-reselect as +trust, but detectors also re-select their classifiers per cluster
    +learn          self-learning from agreement: detectors retrain on agreement labels
                    behind a gate (see below)
    full            Snort counselor + rule trust + self-learning (the proposed system)
    full+trust      full, plus adaptive detector confidence (ablation)

Ablations show why adaptive trust is limited to Snort's rules: agreement labels are the easy
cases every classifier already gets right, so estimates of the AI's own accuracy from them
are biased upwards — re-selecting classifiers on them lets weaker ones vote (more false
alarms), and inflated detector confidence makes confident "normal" advice win cross-checks.

Agreement labels (pseudo-labels), from each chunk:
    attack   Snort alerted AND the AI says attack without Snort's advice
    normal   Snort silent AND every detector is unanimously sure it is normal
Everything else stays unlabelled. Ground truth of the target is used only to score.

Self-learning keeps each detector a specialist and stops it forgetting:
    - a detector learns "attack" labels only for connections it was involved in (it said
      attack, or its classifiers disagreed); every detector learns the "normal" labels
    - a retrain is accepted only if (1) its accuracy on held-out agreement labels does not
      fall, and (2) on the SOURCE lab's labelled test data — legitimately labelled, it is
      where the detector came from — no attack type it knew drops by more than --max-drop
      and false alarms rise by at most --max-fa-rise (learning without forgetting)

Scoring: the target's latest 20% of every attack type and capture is held out as a fixed
test set (as train.py splits) and scored before adaptation and after every --eval-every
chunks; the rest is the adaptation stream. Baselines: Snort alone, and AI-or-Snort.

Statistics: every rate comes with a 95% Wilson interval, and each configuration's final
verdicts are compared with McNemar's test (same test flows) against the deployed system
(``ai``) and the baselines, and ``full`` against every other configuration.

Writes results/adaptation/<source>_to_<target>/: curve.csv (per config and step: detection,
false alarms with intervals, per attack type), mcnemar.csv, pseudo_labels.csv (how many
agreement labels and how many were right, with intervals), rule_trust.json, summary.json.

    python scripts/live_detectors/adapt.py --source 2018 --target 2017
"""

import argparse
import copy
import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))

import train  # noqa: E402

from nids.counselor import CounselorNetwork, RuleTrust, SnortCounselor  # noqa: E402
from nids.datasets.flow_features import CIC2018_TO_2017  # noqa: E402
from nids.datasets.paths import RESULTS_DIR  # noqa: E402
from nids.detector.classifiers import CLASSIFIERS  # noqa: E402
from nids.detector.training import build_detector  # noqa: E402
from nids.evaluation import mcnemar, metrics_with_intervals, wilson  # noqa: E402

FEATURES = list(CIC2018_TO_2017.values())
CONFIGS = {  # name: (snort counselor, adaptive trust: None | "rules" | "confidence" | "reselect", self-learning)
    "ai": (False, None, False),
    "+snort": (True, None, False),
    "+rules": (True, "rules", False),
    "+trust": (True, "confidence", False),
    "+trust-reselect": (True, "reselect", False),
    "+learn": (True, None, True),
    "full": (True, "rules", True),
    "full+trust": (True, "confidence", True),
}


def source_detectors(flows: pd.DataFrame, source: str, share: float, seed: int, cache: Path) -> list:
    """Detectors trained on the source lab's earliest ``share`` of every attack (cached)."""
    paths = [cache / f"{name}.joblib" for name in train.KNOWLEDGE]
    if all(p.exists() for p in paths):
        return [joblib.load(p) for p in paths]
    signatures, _ = train.time_split(flows[flows["lab"] == source], share)
    cache.mkdir(parents=True, exist_ok=True)
    for name, attacks in train.KNOWLEDGE.items():
        known = signatures[signatures["label"].isin(["Benign", *attacks])]
        if known["label"].nunique() < 2:
            continue
        print(f"training {name} on {len(known):,} {source} flows", flush=True)
        d = build_detector(name, known, FEATURES, CLASSIFIERS, n_clusters=known["label"].nunique(),
                           stratify="label", seed=seed)
        d.clear_history()
        joblib.dump(d, cache / f"{name}.joblib", compress=3)
    return [joblib.load(p) for p in paths if p.exists()]


def per_label(frame: pd.DataFrame, cap, seed: int) -> pd.DataFrame:
    """At most ``cap(len(group))`` rows of every label, sampled; keeps every column."""
    return pd.concat([g.sample(min(len(g), cap(len(g))), random_state=seed) for _, g in frame.groupby("label")],
                     ignore_index=True)


def snort_map(frame: pd.DataFrame) -> dict:
    return dict(zip(frame["record_id"].astype(float), frame["snort_rules"]))


def judge(detectors, frame, snort, trust, min_accuracy):
    """Run the network on ``frame``: (finals per detector, system verdict)."""
    advisors = [SnortCounselor(snort_map(frame), trust)] if snort else []
    network = CounselorNetwork(detectors, min_accuracy, window=0, cross_check_normal=True,
                               suppress_fallback=True, advisors=advisors, learn_from_advice=False,
                               attack_advice_wins=snort)
    finals = network.run(frame, frame["record_id"])
    verdict = np.logical_or.reduce([f["prediction"].to_numpy(dtype=bool) for f in finals.values()])
    for d in detectors:
        d.clear_history()
    return finals, verdict


def agreement_labels(frame, finals):
    """(pseudo-attack, pseudo-normal, AI-attack-without-Snort, AI-unanimously-normal) masks."""
    snort = frame["snort_rules"].map(bool).to_numpy()
    own_attack = np.logical_or.reduce([
        (f["prediction"].to_numpy(dtype=bool) & (f["counselor"].fillna("") != "snort").to_numpy())
        for f in finals.values()])
    sure_normal = np.logical_and.reduce([
        ((f["resolution"] == "unanimous") & ~f["prediction"].astype(bool)).to_numpy() for f in finals.values()])
    return snort & own_attack, ~snort & sure_normal, own_attack, sure_normal


def score(frame, verdict) -> dict:
    y = frame["is_attack"].to_numpy()
    out = metrics_with_intervals(y, verdict)
    per = {lbl: float(verdict[g.index].mean()) for lbl, g in frame.groupby("label")}
    attacks = [v for k, v in per.items() if k != "Benign"]
    out["balanced"] = float(np.mean([*attacks, 1 - per.get("Benign", 0.0)])) if attacks else float("nan")
    return out | {f"label:{k}": v for k, v in per.items()}


def predict(detector, X) -> np.ndarray:
    """A detector's own "attack" verdicts as the system uses them: only when its classifiers
    agree (an unresolved conflict's best guess counts as normal, as with --suppress-fallback).
    Leaves its advice history untouched."""
    d = copy.copy(detector)
    d.clear_history()
    r = d.detect(X, np.arange(len(X), dtype=float))
    return (r["prediction"].astype(bool) & ~r["conflict"].astype(bool)).to_numpy()


def accuracy_on(detector, X, y) -> float:
    return float(np.mean(predict(detector, X) == y)) if len(y) else float("nan")


def forgetting(old, new, source_check: pd.DataFrame, args) -> list[str]:
    """What the retrained detector forgot on the source lab's labelled test data."""
    rows = source_check[source_check["label"].isin(["Benign", *train.KNOWLEDGE.get(old.name, [])])]
    rows = rows.reset_index(drop=True)
    before, after = predict(old, rows), predict(new, rows)
    problems = []
    for label, g in rows.groupby("label"):
        b, a = before[g.index].mean(), after[g.index].mean()
        if label == "Benign" and a > b + args.max_fa_rise:
            problems.append(f"false alarms {b:.2%} -> {a:.2%}")
        elif label != "Benign" and a < b - args.max_drop:
            problems.append(f"{label} {b:.2%} -> {a:.2%}")
    return problems


def run_config(name, base, stream_chunks, test, source_check, args):
    snort, adaptive, learn = CONFIGS[name]
    detectors = [copy.deepcopy(d) for d in base]
    trust = RuleTrust(prior=0.9, prior_weight=args.rule_prior)
    pools = {d.name: ([], []) for d in base}  # agreement labels each detector may learn from
    curve, labels_log = [], []
    final = run_config.last = {}

    def evaluate(step):
        _, verdict = judge(detectors, test, snort, trust, args.min_accuracy)
        final["verdict"] = verdict
        row = {"config": name, "step": step, **score(test, verdict)}
        curve.append(row)
        print(f"  {name:7s} step {step:2d}: detection {row['detection_rate']:.2%}  "
              f"false alarms {row['false_alarm_rate']:.3%}  balanced {row['balanced']:.2%}", flush=True)

    evaluate(0)
    for step, chunk in enumerate(stream_chunks, 1):
        finals, _ = judge(detectors, chunk, snort, trust, args.min_accuracy)
        p_attack, p_normal, own_attack, sure_normal = agreement_labels(chunk, finals)
        truth = chunk["is_attack"].to_numpy()
        a_right, n_right = int((p_attack & truth).sum()), int((p_normal & ~truth).sum())
        a_low, a_high = wilson(a_right, int(p_attack.sum()))
        n_low, n_high = wilson(n_right, int(p_normal.sum()))
        labels_log.append({"config": name, "step": step, "flows": len(chunk),
                           "attack_labels": int(p_attack.sum()), "attack_labels_right": a_right,
                           "attack_label_precision_low": a_low, "attack_label_precision_high": a_high,
                           "normal_labels": int(p_normal.sum()), "normal_labels_right": n_right,
                           "normal_label_precision_low": n_low, "normal_label_precision_high": n_high,
                           "true_attacks": int(truth.sum())})

        # agreement-labelled samples; normals capped so they don't swamp the attacks
        idx_a = np.flatnonzero(p_attack)
        idx_n = np.flatnonzero(p_normal)
        cap = max(args.normal_per_attack * len(idx_a), args.min_normals)
        if len(idx_n) > cap:
            idx_n = np.random.default_rng(step).choice(idx_n, cap, replace=False)
        idx = np.concatenate([idx_a, idx_n])
        X_new, y_new = chunk.iloc[idx], np.r_[np.ones(len(idx_a), bool), np.zeros(len(idx_n), bool)]

        if adaptive in ("confidence", "reselect"):
            for d in detectors:
                d.adapt(X_new, y_new, args.cluster_prior, reselect=adaptive == "reselect")
        if adaptive:
            snort_rules = chunk["snort_rules"].to_numpy()
            for i in np.flatnonzero(chunk["snort_rules"].map(bool).to_numpy()):
                for rule in snort_rules[i]:
                    trust.update(rule, agree=int(own_attack[i]), disagree=int(sure_normal[i]))

        if learn and len(idx):
            for d in detectors:  # specialists learn the attacks they were involved in
                f = finals[d.name]
                involved = ((f["resolution"] != "unanimous") | f["prediction"].astype(bool)).to_numpy()
                own = np.concatenate([idx_a[involved[idx_a]], idx_n])
                X_d, y_d = pools[d.name]
                X_d.append(chunk.iloc[own])
                y_d.append(np.r_[np.ones(int(involved[idx_a].sum()), bool), np.zeros(len(idx_n), bool)])
            if step % args.retrain_every == 0:
                for i, d in enumerate(detectors):
                    X_all = pd.concat(pools[d.name][0], ignore_index=True)
                    y_all = np.concatenate(pools[d.name][1])
                    if not y_all.any():
                        continue
                    order = np.random.default_rng(step).permutation(len(y_all))
                    hold = order[: len(order) // 5]  # held-out agreement labels
                    fit = order[len(order) // 5:]
                    before = accuracy_on(d, X_all.iloc[hold], y_all[hold])
                    candidate = copy.deepcopy(d)
                    candidate.new_signatures = [(X_all.iloc[fit][candidate.features], y_all[fit])]
                    candidate.retrain(eval_share=0.5)
                    after = accuracy_on(candidate, X_all.iloc[hold], y_all[hold])
                    forgot = forgetting(d, candidate, source_check, args)
                    kept = after >= before - args.gate_tolerance and not forgot
                    print(f"    retrain {d.name} on {len(fit):,} labels ({int(y_all[fit].sum()):,} attacks): "
                          f"agreement accuracy {before:.2%} -> {after:.2%}"
                          f"{'; forgot ' + ', '.join(forgot) if forgot else ''} "
                          f"({'accepted' if kept else 'rejected'})", flush=True)
                    if kept:
                        detectors[i] = candidate
                        if adaptive in ("confidence", "reselect"):  # retraining resets cluster statistics
                            candidate.adapt(X_all, y_all, args.cluster_prior, reselect=adaptive == "reselect")
        if step % args.eval_every == 0 or step == len(stream_chunks):
            evaluate(step)
    final["detectors"], final["trust"] = detectors, trust
    return curve, labels_log, trust.table() if adaptive else {}, final["verdict"]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", choices=list(train.LABS), required=True)
    parser.add_argument("--target", choices=list(train.LABS), required=True)
    parser.add_argument("--configs", nargs="+", choices=list(CONFIGS), default=list(CONFIGS))
    parser.add_argument("--chunks", type=int, default=10, help="adaptation stream split into this many chunks")
    parser.add_argument("--eval-every", type=int, default=1)
    parser.add_argument("--retrain-every", type=int, default=2, help="chunks between retrains (+learn)")
    parser.add_argument("--train-share", type=float, default=0.8)
    parser.add_argument("--min-accuracy", type=float, default=0.9)
    parser.add_argument("--cluster-prior", type=float, default=200.0, help="weight of the lab estimate (+trust)")
    parser.add_argument("--rule-prior", type=float, default=20.0, help="weight of a Snort rule's prior trust")
    parser.add_argument("--normal-per-attack", type=int, default=3)
    parser.add_argument("--min-normals", type=int, default=2000)
    parser.add_argument("--gate-tolerance", type=float, default=0.005)
    parser.add_argument("--max-drop", type=float, default=0.02, help="forgetting gate: largest drop per attack type")
    parser.add_argument("--max-fa-rise", type=float, default=0.001, help="forgetting gate: largest false-alarm rise")
    parser.add_argument("--max-test", type=int, default=200_000, help="cap the test set (stratified)")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--allow-same", action="store_true", help="development only: source == target")
    args = parser.parse_args()
    if args.source == args.target and not args.allow_same:
        parser.error("source and target must be different labs (--allow-same for a development run)")

    flows = train.load(sorted({args.source, args.target}))
    flows = flows.replace([np.inf, -np.inf], np.nan).dropna(subset=FEATURES)
    if "snort_rules" not in flows:
        sys.exit("flows have no snort_rules: rebuild them (build_dataset.py / build_cicids2017.py)")
    flows["snort_rules"] = flows["snort_rules"].map(lambda r: tuple(r) if isinstance(r, (list, tuple)) else ())

    out = RESULTS_DIR / "adaptation" / f"{args.source}_to_{args.target}"
    base = source_detectors(flows, args.source, args.train_share, args.seed, out / "source_models")
    print("source detectors:", ", ".join(d.name for d in base))

    target = flows[flows["lab"] == args.target]
    stream, test = train.time_split(target, args.train_share)
    if args.source == args.target:  # development: adapt and test on the held-out part only
        stream, test = train.time_split(test, 0.5)
    if len(test) > args.max_test:
        n = len(test)
        test = per_label(test, lambda size: max(50, int(args.max_test * size / n)), args.seed)
    stream = stream.sort_values("flow_start", kind="stable").reset_index(drop=True)
    stream["record_id"] = np.arange(len(stream))
    test = test.reset_index(drop=True)
    test["record_id"] = np.arange(len(test)) + 10_000_000
    bounds = np.linspace(0, len(stream), args.chunks + 1).astype(int)
    chunks = [stream.iloc[lo:hi].reset_index(drop=True) for lo, hi in zip(bounds[:-1], bounds[1:])]
    print(f"target {args.target}: {len(stream):,} stream flows in {args.chunks} chunks, {len(test):,} test flows")

    # the source lab's labelled test data, for the forgetting gate (development: the stream)
    source_check = stream if args.source == args.target else train.time_split(flows[flows["lab"] == args.source],
                                                                              args.train_share)[1]
    source_check = per_label(source_check, lambda size: 5000, args.seed)

    # baselines on the test set
    snort_alone = test["snort_rules"].map(bool).to_numpy()
    _, ai = judge([copy.deepcopy(d) for d in base], test, False, RuleTrust(), args.min_accuracy)
    baselines = {"snort alone": score(test, snort_alone), "ai or snort": score(test, ai | snort_alone)}
    verdicts = {"snort alone": snort_alone, "ai or snort": ai | snort_alone}

    curves, logs, trusts = [], [], {}
    for name in args.configs:
        started = time.time()
        print(f"\n{name}", flush=True)
        curve, log, trust, verdicts[name] = run_config(name, base, chunks, test, source_check, args)
        curves += curve
        logs += log
        trusts[name] = trust
        print(f"  ({time.time() - started:.0f} s)")

    # is each difference real? McNemar on the same test flows
    y = test["is_attack"].to_numpy()
    pairs = [(c, ref) for c in args.configs for ref in ("ai", "snort alone", "ai or snort") if c != ref and ref in verdicts]
    pairs += [("full", c) for c in args.configs if c not in ("full", "ai") and "full" in verdicts]
    comparisons = [{"system_a": a, "system_b": b, **mcnemar(y, verdicts[a], verdicts[b])} for a, b in pairs]

    out.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(comparisons).to_csv(out / "mcnemar.csv", index=False)
    pd.DataFrame(curves).to_csv(out / "curve.csv", index=False)
    pd.DataFrame(logs).to_csv(out / "pseudo_labels.csv", index=False)
    (out / "rule_trust.json").write_text(json.dumps(trusts, indent=1))
    final = {c["config"]: c for c in curves if c["step"] == max(x["step"] for x in curves if x["config"] == c["config"])}
    (out / "summary.json").write_text(json.dumps({"args": vars(args), "baselines": baselines, "final": final}, indent=1))

    pct = lambda v: f"{v:.2%}"  # noqa: E731
    table = pd.DataFrame({**baselines, **{f"{k} (start)": next(c for c in curves if c["config"] == k and c["step"] == 0)
                                          for k in args.configs}, **final}).T
    print("\n" + table[["detection_rate", "false_alarm_rate", "balanced"]].map(pct).to_string())
    print("\nMcNemar (b = only system A right, c = only system B right):")
    for c in comparisons:
        print(f"  {c['system_a']:12s} vs {c['system_b']:12s}  b={c['b']:>7,}  c={c['c']:>7,}  p={c['p_value']:.3g}"
              f"{'  *' if c['p_value'] < 0.05 else ''}")
    print("written to", out)


if __name__ == "__main__":
    main()
