import numpy as np
import pandas as pd
import pytest
from sklearn.dummy import DummyClassifier
from sklearn.tree import DecisionTreeClassifier

from nids.detector.detector import Detector
from nids.detector.model import DetectorModel, split_signatures

from .conftest import FEATURES


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


def test_single_selected_classifier_never_conflicts(blobs):
    results = accurate(blobs).detect(blobs, blobs["record_id"])
    assert not results["conflict"].any()
    assert (results["resolution"] == "unanimous").all()
    assert (results["prediction"] == blobs["is_attack"]).mean() > 0.9
    assert results.index.equals(blobs.index)


def test_disagreeing_classifiers_flag_conflicts(blobs):
    results = split_brain(blobs).detect(blobs, blobs["record_id"])
    assert results["conflict"].all()
    assert (results["resolution"] == "fallback").all()


def test_advise_uses_unambiguous_history_within_window(blobs):
    detector = accurate(blobs)
    results = detector.detect(blobs, blobs["record_id"])

    advice = detector.advise(timestamp=10, window=0)
    assert advice.prediction == results.loc[10, "prediction"]
    assert advice.counselor == "accurate"
    assert detector.advise(timestamp=10_000, window=2) is None


def test_advise_ignores_conflicting_decisions(blobs):
    detector = split_brain(blobs)
    detector.detect(blobs, blobs["record_id"])
    assert detector.advise(timestamp=10, window=5) is None


def test_advise_window_looks_back_not_forward(blobs):
    detector = accurate(blobs)
    detector.detect(blobs.iloc[[5]], [5.0])
    assert detector.advise(timestamp=6.5, window=2) is not None
    assert detector.advise(timestamp=4.0, window=2) is None


@pytest.mark.parametrize("n", [0, 20])
def test_retrain_with_learned_signatures(blobs, n):
    detector = accurate(blobs)
    rows = blobs.head(n)
    detector.learn(rows, rows["is_attack"])
    assert detector.retrain() == n
    assert len(detector.model.train_data[0]) == 300 + n
    assert detector.new_signatures == []


def test_advise_picks_most_confident_entry_in_window(blobs):
    detector = accurate(blobs)
    detector._remember(pd.DataFrame({
        "timestamp": [1.0, 2.0, 3.0], "prediction": [True, False, True], "confidence": [0.7, 0.99, 0.8]}))
    found, prediction, confidence = detector.advise_many(np.array([3.0, 0.5, 1.0]), window=2)
    assert list(found) == [True, False, True]
    assert prediction[0] == False and confidence[0] == 0.99  # noqa: E712
    assert prediction[2] == True and confidence[2] == 0.7  # noqa: E712


def test_clear_history(blobs):
    detector = accurate(blobs)
    detector.detect(blobs, blobs["record_id"])
    detector.clear_history()
    assert detector.advise(timestamp=10, window=0) is None
