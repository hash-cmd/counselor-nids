"""Novelty score — how unlike anything a detector learned a flow is.

Each specialist detector groups its training traffic into K-Means clusters. A flow that sits far
from *every* cluster centre is unlike anything the detector was trained on, and so is a candidate
for an **unseen** attack — one of no known family, for which there is also no Snort rule. The
novelty score ``n_d(x)`` is the Euclidean distance from ``x``, in the detector's own (scaled)
feature space, to its nearest cluster centre. A flow is flagged *novel* when ``n_d(x) > tau``,
where ``tau`` is chosen on benign validation data (not on attacks, and never on the test set).

This directly addresses RQ3 ("how well do the novelty score and the 'AI only' outcome identify
flows belonging to unseen attacks?") and H3 (the score separates unseen attacks from benign better
than chance, AUROC > 0.5). The distance-to-centroid approach is an established way to flag samples
that drift from the known classes (Yang et al., 2021).
"""

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score


def novelty_scores(detector, samples: pd.DataFrame) -> np.ndarray:
    """``n_d(x)`` for each sample: the distance to the detector's nearest K-Means centre."""
    xt = detector.model.transform(samples[detector.features])
    return detector.model.kmeans.transform(xt).min(axis=1).astype(float)


def choose_threshold(benign_scores, keep_benign: float = 0.99) -> float:
    """A threshold ``tau`` that keeps ``keep_benign`` of benign *validation* flows below it, so
    about ``1 - keep_benign`` of benign traffic is flagged novel. The default 0.99 (the 99th
    percentile, ~1% of familiar traffic flagged) is the value set in Chapter 3. Set on benign
    validation only, so the novelty flag's benign false-positive budget is fixed before any
    attack is seen."""
    benign_scores = np.asarray(benign_scores, dtype=float)
    benign_scores = benign_scores[np.isfinite(benign_scores)]
    if not len(benign_scores):
        return float("inf")
    return float(np.quantile(benign_scores, keep_benign))


def is_novel(scores, tau: float) -> np.ndarray:
    """Whether each flow is novel: its score exceeds the validation-set threshold ``tau``."""
    return np.asarray(scores, dtype=float) > tau


def novelty_auroc(scores, is_unseen_attack) -> float:
    """AUROC of the novelty score at separating unseen attacks (1) from benign (0).

    A value above 0.5 means the score ranks unseen attacks as more novel than benign traffic
    better than chance — the evidence for H3. Flows of *seen* attack families should be excluded
    from ``is_unseen_attack`` (they are expected to sit near a cluster, so low novelty is correct).
    Returns NaN when only one class is present.
    """
    y = np.asarray(is_unseen_attack, dtype=bool)
    s = np.asarray(scores, dtype=float)
    ok = np.isfinite(s)
    y, s = y[ok], s[ok]
    if not y.any() or y.all():
        return float("nan")
    return float(roc_auc_score(y, s))
