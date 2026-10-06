"""Shared helpers for the scenario scripts in experiments/."""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

from .data.paths import PROJECT_ROOT  # noqa: E402
from .detector.classifiers import make_classifiers  # noqa: E402
from .detector.detector import Detector  # noqa: E402
from .detector.model import DetectorModel, split_signatures  # noqa: E402

RESULTS_DIR = PROJECT_ROOT / "results"

# Approaches shown in the paper's Figures 3 and 4, in order.
FIGURE_ROWS = {
    "proposed_cross_check": "Proposed + cross-check (ours)",
    "proposed": "Proposed solution (paper)",
    "any_detector_attack": "Any detector says attack",
    "best_local": "Best local",
    "majority_voting": "Majority voting",
    "weighted_voting": "Weighted voting",
    "single_classifier_mean": "Single classifier (avg)",
    "single_classifier_max": "Single classifier (max)",
    "single_classifier_min": "Single classifier (min)",
}


def build_detector(
    name: str,
    signatures: pd.DataFrame,
    features: list[str],
    classifiers: list[str],
    n_clusters: int,
    stratify: str,
    categorical: list[str] = (),
    alpha: float = 0.001,
    seed: int = 0,
) -> Detector:
    """Split signatures 50/50, then train and evaluate a detector (Algorithm 1)."""
    train, evaluation = split_signatures(signatures, stratify=stratify, seed=seed)
    model = DetectorModel(
        make_classifiers(classifiers, seed), n_clusters, alpha,
        [c for c in categorical if c in features], seed,
    ).fit(train[features], train["is_attack"], evaluation[features], evaluation["is_attack"])
    return Detector(name, model, features)


def cluster_table(detector: Detector) -> pd.DataFrame:
    """Per-cluster accuracy of every classifier, selected ones marked with '*'."""
    rows = {}
    for k, profile in enumerate(detector.model.clusters):
        rows[f"cluster {k} (n={profile.size})"] = {
            name: f"{acc:.2%}{'*' if name in profile.selected else ''}"
            for name, acc in profile.accuracy.items()
        }
    return pd.DataFrame(rows).T


def save_report(scenario: str, tables: dict[str, pd.DataFrame], summary: dict) -> Path:
    """Write per-detector comparison CSVs, summary.json and the Figure 3/4 style chart."""
    out = RESULTS_DIR / scenario
    out.mkdir(parents=True, exist_ok=True)
    for name, table in tables.items():
        table.to_csv(out / f"{name}_comparison.csv")
    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str))

    fig, axes = plt.subplots(1, 2, figsize=(13, 4.5), sharey=True)
    labels = list(FIGURE_ROWS.values())
    height = 0.8 / len(tables)
    for ax, metric, title in zip(axes, ["accuracy", "detection_rate"], ["Accuracy", "Detection rate"]):
        for i, (name, table) in enumerate(tables.items()):
            values = table.loc[list(FIGURE_ROWS), metric]
            positions = [y + i * height for y in range(len(labels))]
            bars = ax.barh(positions, values, height=height, label=name)
            ax.bar_label(bars, labels=[f"{v:.2%}" for v in values], fontsize=7, padding=2)
        ax.set_title(title)
        ax.set_xlim(0, 1.1)
        ax.set_yticks([y + height * (len(tables) - 1) / 2 for y in range(len(labels))], labels)
        ax.invert_yaxis()
    axes[0].legend(loc="lower left")
    fig.tight_layout()
    fig.savefig(out / "comparison.png", dpi=150)
    plt.close(fig)
    return out


def print_comparison(name: str, table: pd.DataFrame, summary: dict) -> None:
    print(f"\n=== {name} ===")
    print("conflicts:", summary)
    shown = table.loc[list(FIGURE_ROWS), ["accuracy", "detection_rate", "false_alarm_rate"]]
    print(shown.rename(index=FIGURE_ROWS).map(lambda v: f"{v:.2%}").to_string())
