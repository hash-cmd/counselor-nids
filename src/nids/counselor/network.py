"""Counselors network — conflict resolution between detectors (Section III-D).

When a detector's selected classifiers disagree on a sample, it asks the other
detectors for advice. A counselor answers from its own unambiguous decisions in a
look-back time window, together with its historical accuracy; advice below
``min_accuracy`` is ignored. Accepted advice becomes the final decision and the
sample is stored as a new signature for retraining.

``cross_check_normal`` (an extension, off by default) also covers the paper's second
situation — a detector with limited vision of attacks it was never trained on. Each
"normal" verdict is checked with the counselors, and an acceptable "attack" advice
overrides it. A detector cannot raise a conflict about an attack class it has never
seen, so without this such attacks are confidently missed.
"""

import numpy as np
import pandas as pd

from ..detector.detector import Advice, Detector


class CounselorNetwork:
    def __init__(
        self,
        detectors: list[Detector],
        min_accuracy: float = 0.9,
        window: float = 2.0,
        cross_check_normal: bool = False,
    ):
        """window: look-back in timestamp units; the paper uses 2 seconds."""
        self.detectors = detectors
        self.min_accuracy = min_accuracy
        self.window = window
        self.cross_check_normal = cross_check_normal

    def request_advice(self, requester: Detector, timestamp: float) -> Advice | None:
        """Ask every other detector; return the most accurate acceptable advice."""
        answers = (d.advise(timestamp, self.window) for d in self.detectors if d is not requester)
        acceptable = [a for a in answers if a is not None and a.accuracy >= self.min_accuracy]
        return max(acceptable, key=lambda a: a.accuracy, default=None)

    def _best_advice(self, requester: Detector, timestamps: np.ndarray):
        """Vectorised ``request_advice``: (found, prediction, counselor name) arrays."""
        counselors = [d for d in self.detectors if d is not requester]
        n = len(timestamps)
        best_confidence = np.full(n, -np.inf)
        prediction = np.zeros(n, dtype=bool)
        counselor = np.full(n, None, dtype=object)
        for other in counselors:
            found, pred, confidence = other.advise_many(timestamps, self.window)
            better = found & (confidence >= self.min_accuracy) & (confidence > best_confidence)
            best_confidence[better] = confidence[better]
            prediction[better] = pred[better]
            counselor[better] = other.name
        return np.isfinite(best_confidence), prediction, counselor

    def resolve(self, requester: Detector, samples: pd.DataFrame, results: pd.DataFrame) -> pd.DataFrame:
        """Resolve the conflicts in ``results`` (from ``requester.detect(samples, ...)``).

        Returns a copy with ``prediction``, ``resolution`` and ``counselor`` updated;
        advised samples are handed to the requester as new signatures.
        """
        results = results.copy()
        results["counselor"] = None
        conflict = results["conflict"].to_numpy()
        ask = conflict | (self.cross_check_normal & ~results["prediction"].to_numpy(dtype=bool))
        rows = np.flatnonzero(ask)
        found, prediction, counselor = self._best_advice(
            requester, results["timestamp"].to_numpy()[rows])

        # Conflicts take any acceptable advice; cross-checked normals only flip to attack.
        use = found & (conflict[rows] | prediction)
        rows, prediction, counselor = rows[use], prediction[use], counselor[use]
        resolution = np.where(conflict[rows], "advice", "cross_check")

        results.iloc[rows, results.columns.get_loc("prediction")] = prediction
        results.iloc[rows, results.columns.get_loc("resolution")] = resolution
        results.iloc[rows, results.columns.get_loc("counselor")] = counselor

        requester.learn(samples.iloc[rows], prediction)
        return results

    def run(self, samples: pd.DataFrame, timestamps) -> dict[str, pd.DataFrame]:
        """Run every detector on the same samples, then resolve each one's conflicts.

        All detectors analyse first (as if running in parallel), so every counselor's
        history is populated before advice is requested. Histories from earlier runs
        are cleared.
        """
        timestamps = np.asarray(timestamps, dtype=float)
        for d in self.detectors:
            d.clear_history()
        raw = {d.name: d.detect(samples, timestamps) for d in self.detectors}
        return {d.name: self.resolve(d, samples, raw[d.name]) for d in self.detectors}
