"""Scenario 1 — heterogeneous cooperative network on NSL-KDD (paper Section V-A).

Three detectors, each seeing a different simulated data source (connection,
content, traffic features of the same records), advise each other on conflicts.

    python experiments/scenario1_nsl_kdd.py
"""

import argparse

from nids.counselor import CounselorNetwork
from nids.data.nsl_kdd import CATEGORICAL_FEATURES, SOURCES, load_nsl_kdd
from nids.detector.classifiers import SCENARIO1
from nids.evaluation import compare, conflict_summary
from nids.experiments import build_detector, cluster_table, print_comparison, save_report


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--samples", type=int, default=1000, help="unknown samples to analyse")
    parser.add_argument("--min-accuracy", type=float, default=0.9, help="advice acceptance threshold")
    parser.add_argument("--alpha", type=float, default=0.001, help="classifier selection threshold")
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    signatures = load_nsl_kdd("train_20")
    unknown = load_nsl_kdd("test").sample(args.samples, random_state=args.seed).sort_values("record_id")
    n_clusters = signatures["category"].nunique()

    detectors = [
        build_detector(source, signatures, features, SCENARIO1, n_clusters, stratify="category",
                       categorical=CATEGORICAL_FEATURES, alpha=args.alpha, seed=args.seed)
        for source, features in SOURCES.items()
    ]
    # Every detector views the same records, so advice must match the exact record_id.
    network = CounselorNetwork(detectors, min_accuracy=args.min_accuracy, window=0)
    results = network.run(unknown, unknown["record_id"])

    tables, summary = {}, {"args": vars(args), "n_clusters": n_clusters, "detectors": {}}
    for detector in detectors:
        final = results[detector.name]
        tables[detector.name] = compare(detector, unknown, final, unknown["is_attack"])
        summary["detectors"][detector.name] = conflict_summary(final, unknown["is_attack"])
        print_comparison(detector.name, tables[detector.name], summary["detectors"][detector.name])
        print("\nclassifier accuracy per cluster (* = selected):")
        print(cluster_table(detector).to_string())

    show_example(detectors, results, unknown)
    print("\nresults written to", save_report("scenario1", tables, summary))


def show_example(detectors, results, unknown):
    """Print one conflict resolved by advice, like the paper's teardrop case (Tables II-III)."""
    for detector in detectors:
        final = results[detector.name]
        advised = final[final["resolution"] == "advice"].join(unknown[["label", "is_attack"]])
        if advised.empty:
            continue
        teardrop = advised[advised["label"] == "teardrop"]
        row = (teardrop if len(teardrop) else advised).iloc[0]
        profile = detector.model.clusters[int(row["cluster"])]
        print(f"\nexample: {detector.name} conflicted on a '{row['label']}' sample in cluster "
              f"{int(row['cluster'])} (selected: {', '.join(profile.selected)}); "
              f"{row['counselor']} advised {'attack' if row['prediction'] else 'normal'} "
              f"-> {'correct' if row['prediction'] == row['is_attack'] else 'wrong'}")
        return
    print("\nno conflict was resolved by advice")


if __name__ == "__main__":
    main()
