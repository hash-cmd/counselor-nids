"""Offline model building — Algorithm 1 of the paper.

Train every classifier on the training signatures, cluster the evaluation signatures
with K-Means, measure each classifier's accuracy per cluster, and keep the most
accurate classifier plus any within ``alpha`` of it.
"""

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.base import ClassifierMixin
from sklearn.cluster import KMeans
from sklearn.model_selection import train_test_split

from .preprocessing import build_preprocessor


@dataclass
class ClusterProfile:
    accuracy: dict[str, float]  # evaluation accuracy of every classifier in this cluster
    selected: list[str]  # classifiers within alpha of the best
    size: int  # evaluation samples in this cluster

    @property
    def best(self) -> str:
        return max(self.selected, key=self.accuracy.__getitem__)


class DetectorModel:
    def __init__(
        self,
        classifiers: dict[str, ClassifierMixin],
        n_clusters: int,
        alpha: float = 0.001,
        categorical: list[str] = (),
        seed: int = 0,
    ):
        self.classifiers = classifiers
        self.n_clusters = n_clusters
        self.alpha = alpha
        self.categorical = list(categorical)
        self.seed = seed

    def fit(self, X_train: pd.DataFrame, y_train, X_eval: pd.DataFrame, y_eval) -> "DetectorModel":
        y_train, y_eval = np.asarray(y_train), np.asarray(y_eval)
        self.train_data, self.eval_data = (X_train, y_train), (X_eval, y_eval)

        # Training phase (Algorithm 1, lines 1-3)
        self.preprocessor = build_preprocessor(self.categorical).fit(X_train)
        Xt_train = self.transform(X_train)
        for classifier in self.classifiers.values():
            classifier.fit(Xt_train, y_train)

        # Evaluation phase (lines 4-16)
        Xt_eval = self.transform(X_eval)
        self.kmeans = KMeans(self.n_clusters, n_init=10, random_state=self.seed).fit(Xt_eval)
        predictions = {name: c.predict(Xt_eval) for name, c in self.classifiers.items()}
        self.overall_accuracy = {name: float(np.mean(p == y_eval)) for name, p in predictions.items()}

        self.clusters = []
        for k in range(self.n_clusters):
            in_cluster = self.kmeans.labels_ == k
            accuracy = {
                name: float(np.mean(p[in_cluster] == y_eval[in_cluster]))
                for name, p in predictions.items()
            }
            self.clusters.append(ClusterProfile(accuracy, [], int(in_cluster.sum())))
        return self.reselect(self.alpha)

    def reselect(self, alpha: float) -> "DetectorModel":
        """Re-run classifier selection with a new alpha; no retraining needed."""
        self.alpha = alpha
        for profile in self.clusters:
            best = max(profile.accuracy.values())
            profile.selected = [n for n, a in profile.accuracy.items() if a >= best - alpha - 1e-12]
        return self

    def refit(self, X_extra: pd.DataFrame, y_extra) -> "DetectorModel":
        """Rebuild the model with extra training signatures (self-learning)."""
        X_train, y_train = self.train_data
        return self.fit(
            pd.concat([X_train, X_extra], ignore_index=True),
            np.concatenate([y_train, np.asarray(y_extra)]),
            *self.eval_data,
        )

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        # One dtype for training and serving: K-Means rejects inputs whose dtype
        # differs from its fitted centres (JSON-decoded frames arrive as float64).
        return np.asarray(self.preprocessor.transform(X), dtype=np.float32)

    def assign_clusters(self, Xt: np.ndarray) -> np.ndarray:
        """Nearest centroid by Euclidean distance."""
        return self.kmeans.predict(Xt)


def split_signatures(signatures: pd.DataFrame, stratify: str, seed: int = 0):
    """Split signatures 50/50 into training and evaluation sets with equal class proportions."""
    return train_test_split(
        signatures, test_size=0.5, stratify=signatures[stratify], random_state=seed
    )
