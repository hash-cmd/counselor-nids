import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.tree import DecisionTreeClassifier

from nids.detector.model import DetectorModel, split_signatures
from nids.detector.preprocessing import build_preprocessor

from .conftest import FEATURES


def fit_model(df, alpha, n_clusters=1):
    train, evaluation = split_signatures(df, stratify="is_attack")
    classifiers = {
        "tree": DecisionTreeClassifier(random_state=0),
        "always_attack": DummyClassifier(strategy="constant", constant=True),
    }
    model = DetectorModel(classifiers, n_clusters=n_clusters, alpha=alpha)
    return model.fit(train[FEATURES], train["is_attack"], evaluation[FEATURES], evaluation["is_attack"])


def test_split_is_even_and_stratified(blobs):
    train, evaluation = split_signatures(blobs, stratify="is_attack")
    assert len(train) == len(evaluation) == 300
    assert train["is_attack"].mean() == evaluation["is_attack"].mean()


def test_selects_only_classifiers_within_alpha(blobs):
    profile = fit_model(blobs, alpha=0.001).clusters[0]
    assert profile.accuracy["tree"] > 0.9
    assert profile.accuracy["always_attack"] < 0.6
    assert profile.selected == ["tree"]
    assert profile.best == "tree"


def test_wide_alpha_selects_everything(blobs):
    profile = fit_model(blobs, alpha=1.0).clusters[0]
    assert profile.selected == ["tree", "always_attack"]
    assert profile.best == "tree"


def test_cluster_profiles_cover_all_evaluation_samples(blobs):
    model = fit_model(blobs, alpha=0.001, n_clusters=3)
    assert len(model.clusters) == 3
    assert sum(p.size for p in model.clusters) == 300
    assert all(p.selected for p in model.clusters)


def test_refit_adds_training_signatures(blobs):
    model = fit_model(blobs, alpha=0.001)
    extra = blobs[FEATURES].head(10)
    model.refit(extra, blobs["is_attack"].head(10))
    assert len(model.train_data[0]) == 310


def test_preprocessor_one_hot_encodes_and_drops_constant_columns():
    df = pd.DataFrame({"proto": ["tcp", "udp", "tcp"], "bytes": [1.0, 5.0, 9.0], "zero": [0.0, 0.0, 0.0]})
    Xt = build_preprocessor(categorical=["proto"]).fit_transform(df)
    assert Xt.shape == (3, 3)  # tcp, udp, bytes — "zero" dropped


def test_reselect_changes_selection_without_retraining(blobs):
    model = fit_model(blobs, alpha=0.001)
    tree = model.classifiers["tree"]
    assert model.reselect(1.0).clusters[0].selected == ["tree", "always_attack"]
    assert model.reselect(0.0).clusters[0].selected == ["tree"]
    assert model.classifiers["tree"] is tree
