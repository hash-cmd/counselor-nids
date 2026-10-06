"""Metrics and the baselines the paper compares against (Figures 3 and 4)."""

import numpy as np
import pandas as pd

from .detector.detector import Detector


def metrics(y_true, y_pred) -> dict[str, float]:
    y_true, y_pred = np.asarray(y_true, dtype=bool), np.asarray(y_pred, dtype=bool)
    return {
        "accuracy": float(np.mean(y_true == y_pred)),
        "detection_rate": float(np.mean(y_pred[y_true])) if y_true.any() else float("nan"),
        "false_alarm_rate": float(np.mean(y_pred[~y_true])) if (~y_true).any() else float("nan"),
    }


def baseline_predictions(detector: Detector, samples: pd.DataFrame) -> dict[str, np.ndarray]:
    """Predictions of every classifier alone, plus Best Local, Majority and Weighted Voting.

    Voting ties count as attacks.
    """
    model = detector.model
    Xt = model.transform(samples[detector.features])
    clusters = model.assign_clusters(Xt)
    single = {name: c.predict(Xt).astype(bool) for name, c in model.classifiers.items()}
    votes = np.column_stack(list(single.values()))

    best_local = np.zeros(len(samples), dtype=bool)
    for k in np.unique(clusters):
        rows = clusters == k
        best_local[rows] = single[model.clusters[k].best][rows]

    weights = np.array([model.overall_accuracy[name] for name in single])
    return {
        "best_local": best_local,
        "majority_voting": votes.mean(axis=1) >= 0.5,
        "weighted_voting": votes @ weights / weights.sum() >= 0.5,
        **{f"single:{name}": p for name, p in single.items()},
    }


def compare(detector: Detector, samples: pd.DataFrame, finals: dict[str, pd.DataFrame], y_true) -> pd.DataFrame:
    """Metrics of each proposed variant (``finals``: name -> results) vs. every baseline."""
    rows = {name: metrics(y_true, final["prediction"]) for name, final in finals.items()}
    rows |= {name: metrics(y_true, p) for name, p in baseline_predictions(detector, samples).items()}
    table = pd.DataFrame(rows).T

    single = table[table.index.str.startswith("single:")]
    for stat in ("mean", "max", "min"):
        table.loc[f"single_classifier_{stat}"] = getattr(single, stat)()
    return table


def conflict_summary(final: pd.DataFrame, y_true=None) -> dict[str, int]:
    """Conflict counts; with ``y_true``, also how many advised/fallback decisions were right."""
    counts = final["resolution"].value_counts()
    summary = {
        "samples": len(final),
        "conflicts": int(final["conflict"].sum()),
        "resolved_by_advice": int(counts.get("advice", 0)),
        "fallback": int(counts.get("fallback", 0)),
        "cross_check_overrides": int(counts.get("cross_check", 0)),
    }
    if y_true is not None:
        correct = final["prediction"].to_numpy(dtype=bool) == np.asarray(y_true, dtype=bool)
        for resolution in ("advice", "fallback", "cross_check"):
            summary[f"{resolution}_correct"] = int(correct[final["resolution"] == resolution].sum())
    return summary
