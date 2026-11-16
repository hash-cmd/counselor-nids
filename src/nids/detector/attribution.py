"""Feature attributions for the decision a detector actually makes.

A detector's attack probability for a flow is the mean ``predict_proba`` of the classifiers
selected for the flow's cluster — trees and naive Bayes alike. Explaining a single tree from that
set (the earlier approach) explains a different function from the one that raised the alert, and
silently explains nothing when only naive Bayes was selected.

Here the explained function is that ensemble mean itself, and the attributions are Shapley values
estimated by SHAP's model-agnostic permutation explainer against one reference flow: the training
mean (the zero vector in the standardised feature space). Two properties follow:

- every selected classifier is covered, whatever its type;
- the attributions add up exactly: ``sum(values) == p(x) - p(reference)``, and the reference is
  the same "neutral" value the faithfulness test (``faithfulness.py``) substitutes, so the
  explanation and its faithfulness check measure the same thing.
"""

import numpy as np


def attack_proba(clf, xt) -> np.ndarray:
    """Probability of the attack class; 0 for a classifier that never saw an attack."""
    proba = clf.predict_proba(xt)
    classes = list(clf.classes_)
    for attack in (True, 1):
        if attack in classes:
            return proba[:, classes.index(attack)]
    return np.zeros(len(xt))


def ensemble_proba(model, cluster: int):
    """The detector's attack probability within ``cluster``: the mean over its selected classifiers."""
    names = model.clusters[cluster].selected

    def f(xt):
        xt = np.asarray(xt, dtype=np.float32)
        return np.mean([attack_proba(model.classifiers[n], xt) for n in names], axis=0)

    return f


def attributions(model, xt: np.ndarray, cluster: int, n_permutations: int = 10, seed: int = 0) -> np.ndarray:
    """Per-feature contributions (rows x features) to the ensemble attack probability of flows
    ``xt`` (already transformed, all in ``cluster``), relative to the training-mean reference.
    Needs the ``shap`` package (imported lazily: it is heavy)."""
    import shap

    xt = np.atleast_2d(np.asarray(xt, dtype=np.float32))
    n_features = xt.shape[1]
    reference = np.zeros((1, n_features), dtype=np.float32)  # training mean, standardised space
    explainer = shap.explainers.Permutation(ensemble_proba(model, cluster), reference, seed=seed)
    return np.asarray(explainer(xt, max_evals=2 * n_features * n_permutations + 1, silent=True).values)


def feature_names(model) -> list[str]:
    """Names of the model's transformed features (the original flow feature names)."""
    return [n.split("__", 1)[-1] for n in model.preprocessor.get_feature_names_out()]
