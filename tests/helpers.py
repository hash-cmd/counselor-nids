"""Small detectors with known behaviour, shared by the tests."""

from sklearn.dummy import DummyClassifier
from sklearn.tree import DecisionTreeClassifier

from nids.detector.detector import Detector
from nids.detector.model import DetectorModel, split_signatures

FEATURES = [f"f{i}" for i in range(6)]


def make_detector(df, name, classifiers, alpha=0.001):
    train, evaluation = split_signatures(df, stratify="is_attack")
    model = DetectorModel(classifiers, n_clusters=1, alpha=alpha).fit(
        train[FEATURES], train["is_attack"], evaluation[FEATURES], evaluation["is_attack"]
    )
    return Detector(name, model, FEATURES)


def accurate(df, name="accurate"):
    return make_detector(df, name, {"tree": DecisionTreeClassifier(random_state=0)})


def split_brain(df, name="split_brain"):
    """Two constant classifiers with equal accuracy: both get selected, always disagree."""
    return make_detector(df, name, {
        "yes": DummyClassifier(strategy="constant", constant=True),
        "no": DummyClassifier(strategy="constant", constant=False),
    }, alpha=1.0)


def always(df, name, attack):
    """Detector that is never conflicted and always says attack (or normal)."""
    return make_detector(df, name, {"c": DummyClassifier(strategy="constant", constant=attack)})
