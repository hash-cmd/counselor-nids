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
) -> Detector:
    """Split signatures 50/50, then train and evaluate a detector (Algorithm 1)."""
    train, evaluation = split_signatures(signatures, stratify=stratify, seed=seed)
    model = DetectorModel(
        make_classifiers(classifiers, seed), n_clusters, alpha,
        [c for c in categorical if c in features], seed,
    ).fit(train[features], train["is_attack"], evaluation[features], evaluation["is_attack"])
    return Detector(name, model, features)
