"""A formal decision layer for the counselor network (optional, opt-in).

The deployed network resolves a conflict by taking the most trusted counselor's advice. This
module adds a principled alternative and the pieces the comparison with the base paper claims,
each as a small, testable unit. None of it replaces the counselor voting; it is wired into the
experiment (adapt.py) as extra configurations so the data can say whether it helps.

Pieces (and the formula each implements):

- ``detector_proba``   a calibrated attack probability per detector (mean of the selected
                       classifiers' predict_proba, then a calibrator).
- ``Calibrator``       Platt scaling  p = 1 / (1 + e^(A s + B))  or isotonic regression, so
                       scores from different detectors are comparable before they are combined.
- ``fuse_log_odds``    trust-weighted log-odds pooling  logit(P) = Σ wᵢ logit(pᵢ)  — one
                       confident, trusted detector can outweigh several weak ones.
- ``cost_threshold``   the cost-minimising decision threshold  p* = C_FP / (C_FP + C_FN).
- ``DetectorTrust``    Beta reputation per detector, updated online from agreement, with decay
                       (same estimator as RuleTrust, for the AI counselors).
- ``importance_weights`` 1 / P(selected) weights, to undo the easy-case bias of agreement labels.
- ``PageHinkley``      a drift detector, to trigger retraining instead of a fixed schedule.
"""

from collections import defaultdict

import numpy as np


# --------------------------------------------------------------- calibration
class Calibrator:
    """Map raw scores to calibrated probabilities. ``method="platt"`` fits a sigmoid
    p = 1/(1+e^(A s + B)); ``method="isotonic"`` fits a monotone step function. An unfitted
    calibrator is the identity, so it is safe to apply before fitting."""

    def __init__(self, method: str = "platt"):
        self.method = method
        self.model = None

    def fit(self, scores, labels) -> "Calibrator":
        s = np.asarray(scores, dtype=float).reshape(-1, 1)
        y = np.asarray(labels, dtype=bool)
        if len(np.unique(y)) < 2:  # nothing to calibrate against
            return self
        if self.method == "isotonic":
            from sklearn.isotonic import IsotonicRegression
            self.model = IsotonicRegression(out_of_bounds="clip").fit(s.ravel(), y.astype(float))
        else:
            from sklearn.linear_model import LogisticRegression
            self.model = LogisticRegression().fit(s, y)
        return self

    def transform(self, scores) -> np.ndarray:
        s = np.asarray(scores, dtype=float)
        if self.model is None:
            return np.clip(s, 1e-6, 1 - 1e-6)
        if self.method == "isotonic":
            return np.clip(self.model.predict(s.ravel()), 1e-6, 1 - 1e-6)
        return np.clip(self.model.predict_proba(s.reshape(-1, 1))[:, 1], 1e-6, 1 - 1e-6)


def _attack_proba(clf, X) -> np.ndarray:
    """Probability of the attack class. A classifier trained on benign traffic only (its
    detector's sole attack family was withheld, as in leave-one-family-out) has no attack class in
    ``predict_proba`` and so contributes a probability of 0."""
    proba = clf.predict_proba(X)
    classes = list(clf.classes_)
    for attack in (True, 1):
        if attack in classes:
            return proba[:, classes.index(attack)]
    return np.zeros(len(X))


def detector_proba(detector, X) -> np.ndarray:
    """A single attack probability per row from one detector: the mean of the selected
    classifiers' ``predict_proba`` in that row's cluster (a softer signal than the binary vote)."""
    m = detector.model
    Xt = m.transform(X[detector.features])
    clusters = m.assign_clusters(Xt)
    out = np.zeros(len(X))
    for k in np.unique(clusters):
        rows = np.flatnonzero(clusters == k)
        names = m.clusters[k].selected
        probs = np.column_stack([_attack_proba(m.classifiers[n], Xt[rows]) for n in names])
        out[rows] = probs.mean(axis=1)
    return out


# --------------------------------------------------------------- fusion + threshold
def _logit(p):
    p = np.clip(np.asarray(p, dtype=float), 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p))


def fuse_log_odds(probs: list[np.ndarray], weights: list[float], prior: float = 0.5) -> np.ndarray:
    """Trust-weighted log-odds pooling: logit(P) = logit(prior) + Σ wᵢ (logit(pᵢ) - logit(prior)).
    ``probs`` are per-source attack probabilities (already calibrated), ``weights`` their trust.
    Returns the pooled probability. A source with weight 0 has no say."""
    base = _logit(prior)
    acc = np.full_like(np.asarray(probs[0], dtype=float), base)
    for p, w in zip(probs, weights):
        acc = acc + float(w) * (_logit(p) - base)
    return 1.0 / (1.0 + np.exp(-acc))


def fuse_noisy_or(probs: list[np.ndarray], weights: list[float] | None = None) -> np.ndarray:
    """Noisy-OR fusion: P(attack) = 1 - Π(1 - wᵢ pᵢ). The right combination when each source
    detects a DIFFERENT attack family (any one firing means an attack) — as the specialist
    detectors do — unlike log-odds pooling, which suits redundant sources predicting the same
    event and here would let one specialist's "not my family" cancel another's detection."""
    probs = [np.clip(np.asarray(p, dtype=float), 0.0, 1.0) for p in probs]
    weights = weights if weights is not None else [1.0] * len(probs)
    keep = np.ones_like(probs[0])
    for p, w in zip(probs, weights):
        keep = keep * (1.0 - np.asarray(w, dtype=float) * p)
    return 1.0 - keep


def cost_threshold(c_fp: float, c_fn: float) -> float:
    """The probability threshold that minimises expected cost: flag when p > C_FP/(C_FP+C_FN).
    Equal costs give 0.5; a costlier miss (C_FN large) lowers the threshold, catching more."""
    total = c_fp + c_fn
    return c_fp / total if total > 0 else 0.5


# --------------------------------------------------------------- counselor trust (Beta)
class DetectorTrust:
    """Beta reputation per detector, the same estimator as RuleTrust but for the AI counselors:
    trust = (prior·w + agree) / (w + agree + disagree), updated online from agreement, with an
    optional forgetting factor ``decay`` (α ← λα + agree, β ← λβ + disagree)."""

    def __init__(self, prior: float = 0.8, prior_weight: float = 20.0, decay: float = 1.0):
        self.prior, self.prior_weight, self.decay = prior, prior_weight, decay
        self.agree: dict[str, float] = defaultdict(float)
        self.disagree: dict[str, float] = defaultdict(float)

    def update(self, name: str, agree: int = 0, disagree: int = 0) -> None:
        if self.decay != 1.0:
            self.agree[name] *= self.decay
            self.disagree[name] *= self.decay
        self.agree[name] += agree
        self.disagree[name] += disagree

    def score(self, name: str) -> float:
        a, d = self.agree.get(name, 0.0), self.disagree.get(name, 0.0)
        return (self.prior * self.prior_weight + a) / (self.prior_weight + a + d)


# --------------------------------------------------------------- self-learning bias
def importance_weights(selected: np.ndarray, labels: np.ndarray) -> np.ndarray:
    """Importance weights 1/P(selected) for self-training samples, to undo the easy-case bias:
    agreement labels over-represent easy connections, so each selected sample is up-weighted by
    the inverse of how often its class was selected. Returns weights that average to 1."""
    selected = np.asarray(selected, dtype=bool)
    labels = np.asarray(labels, dtype=bool)
    w = np.ones(len(labels), dtype=float)
    for cls in (False, True):
        inclass = labels == cls
        p = selected[inclass].mean() if inclass.any() else 0.0
        w[inclass] = 1.0 / p if p > 0 else 1.0
    return w / w.mean() if w.mean() else w


# --------------------------------------------------------------- drift detection
class PageHinkley:
    """Page-Hinkley drift test on a stream of errors. It tracks the cumulative deviation of the
    running error from its mean minus a tolerance ``delta``; drift is flagged when that deviation
    exceeds ``threshold``. Use it to trigger retraining instead of a fixed schedule."""

    def __init__(self, delta: float = 0.005, threshold: float = 0.5, min_instances: int = 30):
        self.delta, self.threshold, self.min_instances = delta, threshold, min_instances
        self.reset()

    def reset(self) -> None:
        self.n = 0
        self.mean = 0.0
        self.cum = 0.0
        self.min_cum = 0.0

    def update(self, error: float) -> bool:
        """Feed one error (e.g. 0/1 per connection). Returns True when drift is detected."""
        self.n += 1
        self.mean += (error - self.mean) / self.n
        self.cum += error - self.mean - self.delta
        self.min_cum = min(self.min_cum, self.cum)
        drift = self.n >= self.min_instances and (self.cum - self.min_cum) > self.threshold
        if drift:
            self.reset()
        return drift
