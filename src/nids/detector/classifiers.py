"""The classifiers each detector trains and chooses between, per cluster (scikit-learn
stand-ins for the Weka classifiers in Quincozes et al., 2019)."""

from sklearn.base import ClassifierMixin
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier

FACTORIES = {
    # Weka J48 (C4.5): entropy splits, at least 2 samples per leaf
    "decision_tree": lambda seed: DecisionTreeClassifier(
        criterion="entropy", min_samples_leaf=2, random_state=seed),
    # Weka REPTree: pruned tree; cost-complexity pruning approximates reduced-error pruning
    "rep_tree": lambda seed: DecisionTreeClassifier(
        criterion="entropy", ccp_alpha=5e-4, random_state=seed),
    # Weka RandomTree: unpruned tree over a random log2-sized feature subset per split
    "random_tree": lambda seed: DecisionTreeClassifier(max_features="log2", random_state=seed),
    "random_forest": lambda seed: RandomForestClassifier(
        n_estimators=100, n_jobs=-1, random_state=seed),
    "naive_bayes": lambda seed: GaussianNB(),
}

# k-NN is left out: predicting ~1M flows against ~100k neighbours is too slow.
CLASSIFIERS = ["naive_bayes", "random_tree", "rep_tree", "random_forest", "decision_tree"]


def make_classifiers(names: list[str], seed: int = 0) -> dict[str, ClassifierMixin]:
    return {name: FACTORIES[name](seed) for name in names}
