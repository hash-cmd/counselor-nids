"""Scenario 2 — homogeneous cooperative network on CICIDS2017 (paper Section V-B).

Two detectors see the same flow features but know different attacks:
detector 1 is trained on DoS (slowloris, Slowhttptest, Hulk, GoldenEye),
detector 2 on DDoS and PortScan. Each gets 20% of its classes as signatures
(10% train + 10% evaluation); both are tested on the remaining 80% of all classes.

    python experiments/scenario2_cicids2017.py              # full run, ~1M test flows
    python experiments/scenario2_cicids2017.py --fraction 0.1   # quick run
"""

import argparse

from sklearn.model_selection import train_test_split

from nids.counselor import CounselorNetwork
from nids.data.cicids2017 import (
    BENIGN, DETECTOR1_ATTACKS, DETECTOR2_ATTACKS, SCENARIO2_FILES, feature_columns, load_cicids2017,
)
from nids.detector.classifiers import SCENARIO2
from nids.evaluation import compare, conflict_summary
from nids.experiments import build_detector, cluster_table, print_comparison, save_report

KNOWLEDGE = {"detector1": DETECTOR1_ATTACKS, "detector2": DETECTOR2_ATTACKS}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--fraction", type=float, default=1.0, help="subsample each class (for quick runs)")
    parser.add_argument("--signature-share", type=float, default=0.2, help="share of each class used as signatures")
    parser.add_argument("--min-accuracy", type=float, default=0.9, help="advice acceptance threshold")
    parser.add_argument("--alpha", type=float, default=0.001, help="classifier selection threshold")
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    flows = load_cicids2017(SCENARIO2_FILES, labels=[BENIGN, *DETECTOR1_ATTACKS, *DETECTOR2_ATTACKS])
    if args.fraction < 1:
        flows = flows.groupby("label").sample(frac=args.fraction, random_state=args.seed)
    features = feature_columns(flows)
    print(f"{len(flows):,} flows, {len(features)} features")

    signatures, unknown = train_test_split(
        flows, train_size=args.signature_share, stratify=flows["label"], random_state=args.seed)
    unknown = unknown.sort_values("record_id")

    detectors = []
    for name, attacks in KNOWLEDGE.items():
        known = signatures[signatures["label"].isin([BENIGN, *attacks])]
        detectors.append(build_detector(
            name, known, features, SCENARIO2, n_clusters=known["label"].nunique(),
            stratify="label", alpha=args.alpha, seed=args.seed))
        print(f"{name}: {len(known):,} signatures, {known['label'].nunique()} clusters")

    # Both detectors analyse the same flows, so advice must match the exact record_id.
    network = CounselorNetwork(detectors, min_accuracy=args.min_accuracy, window=0)
    results = network.run(unknown, unknown["record_id"])

    tables, summary = {}, {"args": vars(args), "test_flows": len(unknown), "detectors": {}}
    for detector in detectors:
        final = results[detector.name]
        tables[detector.name] = compare(detector, unknown, final, unknown["is_attack"])
        summary["detectors"][detector.name] = conflict_summary(final, unknown["is_attack"])
        print_comparison(detector.name, tables[detector.name], summary["detectors"][detector.name])
        print("\nclassifier accuracy per cluster (* = selected):")
        print(cluster_table(detector).to_string())

    print("\nresults written to", save_report("scenario2", tables, summary))


if __name__ == "__main__":
    main()
