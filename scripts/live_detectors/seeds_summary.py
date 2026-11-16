"""Combine train.py runs made with different seeds: how much do the results depend on chance?

The split is time-ordered, so it is the same for every seed; the seed changes the random parts
of training (K-Means initialisation, the random forest, the random tree). Spread across seeds is
therefore the model's own variability on fixed data.

Reads results/live/ (the installed run, seed 0) and results/seeds/seed_*/ (made with
``train.py --evaluate-only --ablation --seed N --results seeds/seed_N``). Prints and writes
results/seeds/summary.csv (system detection and false alarms, and each attack type's detection:
mean, standard deviation, min, max over seeds) and, where the runs have one,
results/seeds/conflict_rules.csv (each conflict rule's detection and false alarms per seed).

    python scripts/live_detectors/seeds_summary.py
"""

import json

import pandas as pd

from nids.datasets.paths import RESULTS_DIR

SYSTEM = "counselor network"


def runs() -> dict[int, object]:
    found = {}
    for folder in [RESULTS_DIR / "live", *sorted((RESULTS_DIR / "seeds").glob("seed_*"))]:
        summary = folder / "summary.json"
        if summary.exists():
            found[json.loads(summary.read_text())["args"]["seed"]] = folder
    return found


def main():
    folders = runs()
    if not folders:
        raise SystemExit("no runs found")
    rows = {}
    for seed, folder in sorted(folders.items()):
        s = json.loads((folder / "summary.json").read_text())
        m = s["metrics"][SYSTEM]
        row = {"system detection": m["detection_rate"], "system false alarms": m["false_alarm_rate"]}
        by_label = pd.read_csv(folder / "by_label.csv", index_col=0)[SYSTEM]
        row |= {f"{label}": rate for label, rate in by_label.items() if label != "Benign"}
        rows[seed] = row
    per_seed = pd.DataFrame(rows)
    table = pd.DataFrame({"mean": per_seed.mean(axis=1), "sd": per_seed.std(axis=1, ddof=1),
                          "min": per_seed.min(axis=1), "max": per_seed.max(axis=1)})
    print(f"seeds: {sorted(folders)}")
    print(table.to_string(float_format=lambda v: f"{v:.4%}"))
    out = RESULTS_DIR / "seeds"
    out.mkdir(parents=True, exist_ok=True)
    table.join(per_seed.add_prefix("seed ")).to_csv(out / "summary.csv")

    rules = {seed: pd.read_csv(f / "conflict_rules.csv", index_col=0)
             for seed, f in folders.items() if (f / "conflict_rules.csv").exists()}
    if rules:
        long = pd.concat(rules, names=["seed", "rule"])[["detection_rate", "fp_per_1k", "p_vs_alone"]]
        print("\nconflict rules (test split), per seed:")
        print(long.to_string(float_format=lambda v: f"{v:.4f}"))
        print("\nmean over seeds:")
        print(long.groupby("rule")[["detection_rate", "fp_per_1k"]].agg(["mean", "std"]).to_string(
            float_format=lambda v: f"{v:.4f}"))
        long.to_csv(out / "conflict_rules.csv")
    print("\nwritten to", out)


if __name__ == "__main__":
    main()
