"""Train a detector from labelled signatures (the paper's Algorithm 1)."""

import pandas as pd

from .classifiers import make_classifiers
from .detector import Detector
from .model import DetectorModel, split_signatures


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
    validation: pd.DataFrame | None = None,
) -> Detector:
    """Train and evaluate a detector (Algorithm 1). With an explicit ``validation`` set, that set
    is used for clustering and classifier selection (the three-way train/validation/test protocol);
    otherwise ``signatures`` is split 50/50 into training and evaluation."""
    if validation is None:
        train, evaluation = split_signatures(signatures, stratify=stratify, seed=seed)
    else:
        train, evaluation = signatures, validation
    model = DetectorModel(
        make_classifiers(classifiers, seed), n_clusters, alpha,
        [c for c in categorical if c in features], seed,
    ).fit(train[features], train["is_attack"], evaluation[features], evaluation["is_attack"])
    return Detector(name, model, features)
