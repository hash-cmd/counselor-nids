"""Counselors network — conflict resolution between detectors (Section III-D).

When a detector's selected classifiers disagree on a sample, it asks the other
detectors for advice. A counselor answers from its own unambiguous decisions in a
look-back time window, together with its historical accuracy; advice below
``min_accuracy`` is ignored. Accepted advice becomes the final decision and the
sample is stored as a new signature for retraining.
"""

import numpy as np
import pandas as pd

from ..detector.detector import Advice, Detector


class CounselorNetwork:
    def __init__(self, detectors: list[Detector], min_accuracy: float = 0.9, window: float = 2.0):
        """window: look-back in timestamp units; the paper uses 2 seconds."""
        self.detectors = detectors
        self.min_accuracy = min_accuracy
        self.window = window

    def request_advice(self, requester: Detector, timestamp: float) -> Advice | None:
        """Ask every other detector; return the most accurate acceptable advice."""
        answers = (d.advise(timestamp, self.window) for d in self.detectors if d is not requester)
        acceptable = [a for a in answers if a is not None and a.accuracy >= self.min_accuracy]
        return max(acceptable, key=lambda a: a.accuracy, default=None)

    def resolve(self, requester: Detector, samples: pd.DataFrame, results: pd.DataFrame) -> pd.DataFrame:
        """Resolve the conflicts in ``results`` (from ``requester.detect(samples, ...)``).

        Returns a copy with ``prediction``, ``resolution`` and ``counselor`` updated;
        advised samples are handed to the requester as new signatures.
        """
        results = results.copy()
        results["counselor"] = None
        advised = []
        for index in results.index[results["conflict"]]:
            advice = self.request_advice(requester, results.at[index, "timestamp"])
            if advice is None:
                continue
            results.loc[index, ["prediction", "resolution", "counselor"]] = (
                advice.prediction, "advice", advice.counselor)
            advised.append(index)

        requester.learn(samples.loc[advised], results.loc[advised, "prediction"].to_numpy(dtype=bool))
        return results

    def run(self, samples: pd.DataFrame, timestamps) -> dict[str, pd.DataFrame]:
        """Run every detector on the same samples, then resolve each one's conflicts.

        All detectors analyse first (as if running in parallel), so every counselor's
        history is populated before advice is requested.
        """
        timestamps = np.asarray(timestamps, dtype=float)
        raw = {d.name: d.detect(samples, timestamps) for d in self.detectors}
        return {d.name: self.resolve(d, samples, raw[d.name]) for d in self.detectors}
