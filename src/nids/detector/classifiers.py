"""scikit-learn stand-ins for the Weka classifiers used in the paper.

NBTree, ADTree and KStar have no scikit-learn equivalent and are left out.
"""

from sklearn.base import ClassifierMixin
from sklearn.ensemble import AdaBoostClassifier, RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier

FACTORIES = {
    # Weka IBk (default k=1)
    "knn": lambda seed: KNeighborsClassifier(n_neighbors=1, n_jobs=-1),
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
    # Weka AdaBoostM1 (decision stumps by default, as here)
    "adaboost": lambda seed: AdaBoostClassifier(random_state=seed),
}

# Scenario 1 (Table II) minus NBTree, ADTree and KStar.
SCENARIO1 = ["knn", "decision_tree", "naive_bayes", "adaboost", "rep_tree", "random_forest"]
# Scenario 2 (Section IV-B), with J48 standing in for NBTree. k-NN is left out:
# predicting ~1M flows against ~100k neighbours is too slow.
SCENARIO2 = ["naive_bayes", "random_tree", "rep_tree", "random_forest", "decision_tree"]


def make_classifiers(names: list[str], seed: int = 0) -> dict[str, ClassifierMixin]:
    return {name: FACTORIES[name](seed) for name in names}
