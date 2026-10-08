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

    def refit(self, X_extra: pd.DataFrame, y_extra, eval_share: float = 0.0) -> "DetectorModel":
        """Rebuild the model with extra training signatures (self-learning).

        ``eval_share`` of the extra signatures go to the evaluation set instead, so cluster
        accuracies (and with them classifier selection and advice confidence) also reflect
        the traffic the extras came from — e.g. a new network the model is adapting to."""
        X_train, y_train = self.train_data
        X_eval, y_eval = self.eval_data
        y_extra = np.asarray(y_extra)
        n_eval = int(len(y_extra) * eval_share)
        if n_eval:
            order = np.random.default_rng(self.seed).permutation(len(y_extra))
            to_eval, to_train = order[:n_eval], order[n_eval:]
            X_eval = pd.concat([X_eval, X_extra.iloc[to_eval]], ignore_index=True)
            y_eval = np.concatenate([y_eval, y_extra[to_eval]])
            X_extra, y_extra = X_extra.iloc[to_train], y_extra[to_train]
        return self.fit(
            pd.concat([X_train, X_extra], ignore_index=True),
            np.concatenate([y_train, y_extra]),
            X_eval, y_eval,
        )

    def adapt(self, X: pd.DataFrame, y, prior_weight: float = 200.0, reselect: bool = False) -> int:
        """Re-estimate every classifier's accuracy per cluster from new labelled samples
        (adaptive trust).

        By default only the cluster's advice confidence changes (``profile.confidence``):
        the accuracy of the classifier the cluster already relies on. With ``reselect``,
        all accuracies are replaced and classifier selection re-run — but agreement labels
        are the easy cases every classifier gets right, so they cannot tell good classifiers
        from bad ones, and re-selection then lets weaker classifiers vote.

        The lab estimate is the prior, worth ``prior_weight`` samples (or the cluster's
        evaluation size, if smaller); each new sample moves it towards the accuracy seen on
        the new traffic. A detector's advice confidence is its cluster accuracy, so this
        also adapts how much the counselors trust it. Statistics accumulate across calls
        and are reset by ``fit``/``refit``. Returns how many samples were used."""
        y = np.asarray(y, dtype=bool)
        if not len(y):
            return 0
        Xt = self.transform(X)
        clusters = self.assign_clusters(Xt)
        predictions = {name: c.predict(Xt).astype(bool) for name, c in self.classifiers.items()}
        for k in np.unique(clusters):
            rows = clusters == k
            profile = self.clusters[k]
            if not hasattr(profile, "lab_accuracy"):
                profile.lab_accuracy, profile.new_seen = dict(profile.accuracy), 0
                profile.new_correct = dict.fromkeys(profile.accuracy, 0)
            profile.new_seen += int(rows.sum())
            prior = min(prior_weight, max(profile.size, 1))
            adapted = {}
            for name, p in predictions.items():
                profile.new_correct[name] += int((p[rows] == y[rows]).sum())
                adapted[name] = ((prior * profile.lab_accuracy[name] + profile.new_correct[name])
                                 / (prior + profile.new_seen))
            if reselect:
                profile.accuracy.update(adapted)
            profile.confidence = adapted[profile.best]
        if reselect:
            self.reselect(self.alpha)
            for profile in self.clusters:
                if hasattr(profile, "confidence"):
                    profile.confidence = profile.accuracy[profile.best]
        return len(y)

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
