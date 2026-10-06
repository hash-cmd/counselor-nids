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
        found, prediction, confidence = self.advise_many(np.array([timestamp], dtype=float), window)
        if not found[0]:
            return None
        return Advice(self.name, bool(prediction[0]), float(confidence[0]))

    def advise_many(self, timestamps: np.ndarray, window: float):
        """Vectorised ``advise``: returns (found, prediction, confidence) arrays."""
        history = self._history  # snapshot: detect() may replace it from another thread
        ts = history["timestamp"].to_numpy()
        predictions = history["prediction"].to_numpy(dtype=bool)
        confidences = history["confidence"].to_numpy()
        lo = np.searchsorted(ts, timestamps - window, side="left")
        hi = np.searchsorted(ts, timestamps, side="right")
        found = hi > lo

        # Fast path: the latest entry in the window (exact when it holds one entry).
        pick = np.where(found, hi - 1, 0)
        for i in np.flatnonzero(hi - lo > 1):
            span = confidences[lo[i]:hi[i]]
            pick[i] = hi[i] - 1 - np.argmax(span[::-1])  # highest confidence, latest on ties

        prediction = np.where(found, predictions[pick] if len(ts) else False, False)
        confidence = np.where(found, confidences[pick] if len(ts) else 0.0, 0.0)
        return found, prediction, confidence

    def clear_history(self) -> None:
        self._history = self._history.iloc[0:0]

    def trim_history(self, max_entries: int) -> None:
        """Keep only the most recent decisions (bounds memory in a long-running service)."""
        if len(self._history) > max_entries:
            self._history = self._history.iloc[-max_entries:].reset_index(drop=True)

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
