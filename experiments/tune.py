"""Tune alpha, the advice threshold and cross-checking on the VALIDATION set only.

    python experiments/tune.py scenario2 --fraction 0.2
    python experiments/tune.py scenario1 --protocol holdout

Prints every setting ranked by mean accuracy across detectors. The test set is never
touched; pass the winning settings to run.py to get test results.
"""

import argparse
import itertools

import pandas as pd

from nids import scenarios
from nids.counselor import CounselorNetwork
from nids.evaluation import metrics

ALPHAS = [0.001, 0.005, 0.01, 0.02]
MIN_ACCURACIES = [0.9, 0.95, 0.99, 0.999]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("scenario", choices=["scenario1", "scenario2"])
    parser.add_argument("--protocol", default="kddtest", help="scenario 1 only")
    parser.add_argument("--fraction", type=float, default=1.0, help="scenario 2 only")
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    if args.scenario == "scenario1":
        setup = scenarios.scenario1(args.protocol, seed=args.seed)
    else:
        setup = scenarios.scenario2(args.fraction, seed=args.seed)
    samples, y = setup.validation, setup.validation["is_attack"]
    print(f"tuning on {len(samples):,} validation samples")

    rows = []
    for alpha in ALPHAS:
        for d in setup.detectors:
            d.model.reselect(alpha)
            d.clear_history()
        raw = {d.name: d.detect(samples, samples["record_id"]) for d in setup.detectors}
        for min_accuracy, cross_check in itertools.product(MIN_ACCURACIES, [False, True]):
            network = CounselorNetwork(setup.detectors, min_accuracy, window=0,
                                       cross_check_normal=cross_check)
            row = {"alpha": alpha, "min_accuracy": min_accuracy, "cross_check": cross_check}
            for d in setup.detectors:
                final = network.resolve(d, samples, raw[d.name])
                d.new_signatures.clear()
                for metric, value in metrics(y, final["prediction"]).items():
                    row[f"{d.name}:{metric}"] = value
            rows.append(row)

    table = pd.DataFrame(rows)
    names = [d.name for d in setup.detectors]
    table["mean_accuracy"] = table[[f"{n}:accuracy" for n in names]].mean(axis=1)
    table = table.sort_values("mean_accuracy", ascending=False)
    shown = ["alpha", "min_accuracy", "cross_check", "mean_accuracy",
             *[f"{n}:{m}" for n in names for m in ("accuracy", "detection_rate")]]
    print(table[shown].head(15).to_string(index=False, float_format=lambda v: f"{v:.4f}"))


if __name__ == "__main__":
    main()
