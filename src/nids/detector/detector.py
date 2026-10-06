"""Online detection — Algorithm 2 of the paper (without the counselors phase).

Each unknown sample is assigned to its nearest cluster and classified only by that
cluster's selected classifiers. If at least two were selected and they disagree,
the sample is a conflict and needs advice from the counselors network.
"""

from dataclasses import dataclass

import numpy as np
import pandas as pd

from .model import DetectorModel


@dataclass(frozen=True)
class Advice:
    counselor: str
    prediction: bool
    accuracy: float  # counselor's historical accuracy for similar samples


class Detector:
    def __init__(self, name: str, model: DetectorModel, features: list[str]):
        self.name = name
        self.model = model
        self.features = list(features)
        self._history = pd.DataFrame(
            {"timestamp": [], "prediction": [], "confidence": []}
        ).astype({"timestamp": float, "prediction": bool, "confidence": float})
        self.new_signatures: list[tuple[pd.DataFrame, np.ndarray]] = []

    def detect(self, samples: pd.DataFrame, timestamps) -> pd.DataFrame:
        """Classify samples; one result row per sample, in the same order.

        Columns: timestamp, cluster, prediction, conflict, confidence, resolution.
        For conflicts, ``prediction`` holds the best local classifier's output until
        the counselors network replaces it.
        """
        Xt = self.model.transform(samples[self.features])
        clusters = self.model.assign_clusters(Xt)
        n = len(samples)
        prediction = np.zeros(n, dtype=bool)
        conflict = np.zeros(n, dtype=bool)
        confidence = np.zeros(n)

        for k in np.unique(clusters):
            rows = np.flatnonzero(clusters == k)
            profile = self.model.clusters[k]
            votes = np.column_stack(
                [self.model.classifiers[name].predict(Xt[rows]) for name in profile.selected]
            ).astype(bool)
            prediction[rows] = votes[:, profile.selected.index(profile.best)]
            conflict[rows] = (votes != votes[:, :1]).any(axis=1)
            confidence[rows] = profile.accuracy[profile.best]

        results = pd.DataFrame({
            "timestamp": np.asarray(timestamps, dtype=float),
            "cluster": clusters,
            "prediction": prediction,
            "conflict": conflict,
            "confidence": confidence,
            "resolution": np.where(conflict, "fallback", "unanimous"),
        }, index=samples.index)
        self._remember(results[~results["conflict"]])
        return results

    def _remember(self, decided: pd.DataFrame) -> None:
        """Keep unambiguous decisions so this detector can advise others."""
        entries = decided[["timestamp", "prediction", "confidence"]]
        self._history = (
            pd.concat([self._history, entries], ignore_index=True)
            .sort_values("timestamp", kind="stable", ignore_index=True)
        )

    def advise(self, timestamp: float, window: float) -> Advice | None:
        """Answer an advice request from this detector's own past decisions.

        Looks at unambiguous decisions in ``[timestamp - window, timestamp]`` and
        returns the one backed by the highest historical accuracy (latest on ties).
        """
        ts = self._history["timestamp"].to_numpy()
        lo = np.searchsorted(ts, timestamp - window, side="left")
        hi = np.searchsorted(ts, timestamp, side="right")
        if lo == hi:
            return None
        candidates = self._history.iloc[lo:hi]
        best = candidates.iloc[::-1]["confidence"].idxmax()
        return Advice(self.name, bool(candidates.at[best, "prediction"]),
                      float(candidates.at[best, "confidence"]))

    def learn(self, samples: pd.DataFrame, labels) -> None:
        """Store advised samples as new signatures (Figure 1, steps 8.A-C)."""
        if len(samples):
            self.new_signatures.append((samples[self.features], np.asarray(labels, dtype=bool)))

    def retrain(self) -> int:
        """Rebuild the model with the learned signatures; returns how many were added."""
        if not self.new_signatures:
            return 0
        X = pd.concat([x for x, _ in self.new_signatures], ignore_index=True)
        y = np.concatenate([y for _, y in self.new_signatures])
        self.model.refit(X, y)
        self.new_signatures.clear()
        return len(y)
