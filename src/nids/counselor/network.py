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

``attack_advice_wins`` (an extension, off by default): when acceptable advice on a conflict
disagrees, the most trusted "attack" advice is taken over any "normal" advice. Same reasoning as the
cross-check: a counselor that never learned an attack type is not unsure about it but
confidently wrong, so its "normal" says little, while a trusted "attack" (a specialist that
knows the attack, or a Snort rule) says a lot. Without it, the most confident counselor wins,
which lets e.g. the flood detector overrule Snort on a website attack.

``advisors`` (an extension) are counselors that only give advice and classify nothing
themselves, e.g. Snort (``SnortCounselor``): anything with a ``name`` and an
``advise_many(timestamps, window)`` returning (found, prediction, confidence) arrays.
Advisors are asked about conflicts only — they break ties when a detector is unsure. Asking
them to cross-check every confident "normal" verdict too would turn the system into "AI or
Snort", inheriting every Snort false alarm (27% of normal flows in the 2018 lab, mostly
policy rules). ``attack_advice_wins`` likewise applies to conflicts only.
"""

import numpy as np
import pandas as pd

from ..detector.detector import Detector


class CounselorNetwork:
    def __init__(
        self,
        detectors: list[Detector],
        min_accuracy: float = 0.9,
        window: float = 2.0,
        cross_check_normal: bool = False,
        suppress_fallback: bool = False,
        advisors=(),
        learn_from_advice: bool = True,
        attack_advice_wins: bool = False,
    ):
        """window: look-back in timestamp units; the paper uses 2 seconds.

        ``suppress_fallback`` (off by default, so the paper's experiments are unchanged)
        downgrades an unresolved conflict's "attack" guess to normal. When a detector's
        classifiers disagree and no counselor can advise, the fallback is the best local
        classifier's bet; on out-of-distribution live traffic that bet is the main source
        of false alarms, while it accounts for almost none of the real detections.
        """
        self.detectors = detectors
        self.min_accuracy = min_accuracy
        self.window = window
        self.cross_check_normal = cross_check_normal
        self.suppress_fallback = suppress_fallback
        self.advisors = list(advisors)
        self.learn_from_advice = learn_from_advice  # the paper's steps 8.A-C
        self.attack_advice_wins = attack_advice_wins

    def _best_advice(self, requester: Detector, timestamps: np.ndarray, conflict: np.ndarray | None = None):
        """Best acceptable advice per timestamp: (found, prediction, counselor name) arrays.
        ``conflict`` marks the timestamps that are conflicts: only those also hear the
        advisors and use attack_advice_wins (default: all)."""
        n = len(timestamps)
        conflict = np.ones(n, dtype=bool) if conflict is None else np.asarray(conflict, dtype=bool)
        counselors = [(d, False) for d in self.detectors if d is not requester] + [(a, True) for a in self.advisors]
        best_confidence = np.full(n, -np.inf)
        prediction = np.zeros(n, dtype=bool)
        counselor = np.full(n, None, dtype=object)
        for other, advisor in counselors:
            found, pred, confidence = other.advise_many(timestamps, self.window)
            acceptable = found & (confidence >= self.min_accuracy)
            if advisor:
                acceptable &= conflict
            more_confident = confidence > best_confidence
            if self.attack_advice_wins:
                # on conflicts an attack advice beats any normal advice; within a kind, the most confident
                attack_first = (pred & ~prediction) | ((pred == prediction) & more_confident)
                better = acceptable & np.where(conflict, attack_first, more_confident)
            else:
                better = acceptable & more_confident
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
            requester, results["timestamp"].to_numpy()[rows], conflict[rows])

        # Conflicts take any acceptable advice; cross-checked normals only flip to attack.
        use = found & (conflict[rows] | prediction)
        rows, prediction, counselor = rows[use], prediction[use], counselor[use]
        resolution = np.where(conflict[rows], "advice", "cross_check")

        results.iloc[rows, results.columns.get_loc("prediction")] = prediction
        results.iloc[rows, results.columns.get_loc("resolution")] = resolution
        results.iloc[rows, results.columns.get_loc("counselor")] = counselor

        if self.suppress_fallback:
            guess = (results["resolution"] == "fallback").to_numpy() & results["prediction"].to_numpy(dtype=bool)
            results.iloc[np.flatnonzero(guess), results.columns.get_loc("prediction")] = False

        if self.learn_from_advice:
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
