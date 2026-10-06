"""Evaluate a scenario on the TEST set, averaged over several seeds.

Reports the paper's method, the cross-check extension, and the baselines.
Choose the thresholds with tune.py first (validation set only).

    python experiments/evaluate.py scenario2 --cross-check-alpha 0.001 --cross-check-min-accuracy 0.9
    python experiments/evaluate.py scenario1 --protocol holdout --cross-check-min-accuracy 0.99
"""

import argparse

import numpy as np
import pandas as pd

from nids import scenarios
from nids.counselor import CounselorNetwork
from nids.evaluation import compare, conflict_summary, metrics
from nids.reporting import print_comparison, save_report

PAPER = {"alpha": 0.001, "min_accuracy": 0.9}  # paper's alpha; min_accuracy unspecified


def evaluate(setup: scenarios.Setup, args) -> tuple[dict[str, pd.DataFrame], dict]:
    test, y = setup.test, setup.test["is_attack"]
    finals = {}
    for variant, alpha, min_accuracy, cross_check in [
        ("proposed", PAPER["alpha"], PAPER["min_accuracy"], False),
        ("proposed_cross_check", args.cross_check_alpha, args.cross_check_min_accuracy, True),
    ]:
        for d in setup.detectors:
            d.model.reselect(alpha)
        network = CounselorNetwork(setup.detectors, min_accuracy, window=0, cross_check_normal=cross_check)
        finals[variant] = network.run(test, test["record_id"])

    # Naive merge of the detectors (no counselor logic): attack if any detector says so.
    any_attack = np.logical_or.reduce([f["prediction"].to_numpy(dtype=bool)
                                       for f in finals["proposed"].values()])

    for d in setup.detectors:
        d.model.reselect(PAPER["alpha"])  # baselines use the paper's selection
    tables, summary = {}, {}
    for d in setup.detectors:
        per_variant = {variant: results[d.name] for variant, results in finals.items()}
        table = compare(d, test, per_variant, y)
        table.loc["any_detector_attack"] = metrics(y, any_attack)
        tables[d.name] = table
        summary[d.name] = {v: conflict_summary(r, y) for v, r in per_variant.items()}
    return tables, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("scenario", choices=["scenario1", "scenario2"])
    parser.add_argument("--protocol", default="kddtest", help="scenario 1: kddtest | holdout")
    parser.add_argument("--fraction", type=float, default=1.0, help="scenario 2: subsample for quick runs")
    parser.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    parser.add_argument("--cross-check-alpha", type=float, default=0.001)
    parser.add_argument("--cross-check-min-accuracy", type=float, default=0.9)
    args = parser.parse_args()

    per_seed, summaries = [], {}
    for seed in args.seeds:
        if args.scenario == "scenario1":
            setup = scenarios.scenario1(args.protocol, seed=seed)
        else:
            setup = scenarios.scenario2(args.fraction, seed=seed)
        print(f"seed {seed}: {len(setup.test):,} test samples")
        tables, summaries[seed] = evaluate(setup, args)
        per_seed.append(tables)

    names = list(per_seed[0])
    mean = {n: sum(t[n] for t in per_seed) / len(per_seed) for n in names}
    for n in names:
        print_comparison(n, mean[n], summaries[args.seeds[0]][n])
        acc = [t[n].loc[["proposed", "proposed_cross_check"], "accuracy"] for t in per_seed]
        print("accuracy per seed (paper / cross-check):",
              ", ".join(f"{a['proposed']:.2%} / {a['proposed_cross_check']:.2%}" for a in acc))

    name = args.scenario + (f"_{args.protocol}" if args.scenario == "scenario1" else "")
    out = save_report(name, mean, {"args": vars(args), "per_seed": summaries})
    print("\nmean over seeds written to", out)


if __name__ == "__main__":
    main()
