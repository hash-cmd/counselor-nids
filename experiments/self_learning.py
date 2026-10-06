"""Self-learning: do detectors absorb their counselors' knowledge? (Figure 1, steps 8.A-C)

Streams the Scenario 2 test flows in time order, in chunks. After each chunk, every
detector retrains on the samples it was advised on. Each detector's *standalone*
accuracy (its own verdict, before any advice) is compared with a copy that never
retrains — if self-learning works, detector 1 should start catching PortScan on its
own after detector 2 has advised it about PortScan flows.

    python experiments/self_learning.py --fraction 0.2
"""

import argparse
import copy

import numpy as np
import pandas as pd

from nids import scenarios
from nids.counselor import CounselorNetwork
from nids.evaluation import metrics
from nids.experiments import RESULTS_DIR


def stream(detectors, chunks, args, retrain: bool) -> list[dict]:
    network = CounselorNetwork(detectors, args.min_accuracy, window=0,
                               cross_check_normal=args.cross_check)
    rows = []
    for i, chunk in enumerate(chunks):
        y = chunk["is_attack"]
        for d in detectors:
            d.clear_history()
        raw = {d.name: d.detect(chunk, chunk["record_id"]) for d in detectors}
        for d in detectors:
            final = network.resolve(d, chunk, raw[d.name])
            learned = sum(len(labels) for _, labels in d.new_signatures)
            rows.append({
                "chunk": i, "detector": d.name, "retrain": retrain,
                "labels": ", ".join(sorted(chunk["label"].unique())),
                "standalone_accuracy": metrics(y, raw[d.name]["prediction"])["accuracy"],
                "final_accuracy": metrics(y, final["prediction"])["accuracy"],
                "learned": learned,
            })
        for d in detectors:
            if retrain:
                d.retrain()
            else:
                d.new_signatures.clear()
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--fraction", type=float, default=1.0)
    parser.add_argument("--chunks", type=int, default=10)
    parser.add_argument("--min-accuracy", type=float, default=0.9)
    parser.add_argument("--cross-check", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    setup = scenarios.scenario2(args.fraction, seed=args.seed)
    # test is sorted by record_id, i.e. time order
    bounds = np.linspace(0, len(setup.test), args.chunks + 1).astype(int)
    chunks = [setup.test.iloc[a:b] for a, b in zip(bounds[:-1], bounds[1:])]
    frozen = copy.deepcopy(setup.detectors)

    rows = stream(setup.detectors, chunks, args, retrain=True)
    rows += stream(frozen, chunks, args, retrain=False)
    table = pd.DataFrame(rows)

    for name in table["detector"].unique():
        own = table[table["detector"] == name].pivot_table(
            index=["chunk", "labels"], columns="retrain",
            values=["standalone_accuracy", "final_accuracy"])
        own.columns = [f"{metric.split('_')[0]} ({'self-learning' if r else 'frozen'})"
                       for metric, r in own.columns]
        learned = table[(table["detector"] == name) & table["retrain"]].set_index("chunk")["learned"]
        own["learned"] = learned.to_numpy()
        print(f"\n=== {name} ===")
        print(own.to_string(float_format=lambda v: f"{v:.2%}"))

    out = RESULTS_DIR / "self_learning"
    out.mkdir(parents=True, exist_ok=True)
    path = out / ("chunks.csv" if args.cross_check else "chunks_conflicts_only.csv")
    table.to_csv(path, index=False)
    print("\nwritten to", path)


if __name__ == "__main__":
    main()
