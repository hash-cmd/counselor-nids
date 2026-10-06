"""The paper's two evaluation scenarios, with a held-out validation set for tuning.

Each setup returns trained detectors plus disjoint ``validation`` and ``test`` sample
sets. Thresholds are tuned on validation only; test is reported once.
"""

from dataclasses import dataclass

import pandas as pd
from sklearn.model_selection import train_test_split

from .datasets import cicids2017 as cic
from .datasets import nsl_kdd as kdd
from .detector.classifiers import SCENARIO1, SCENARIO2
from .detector.detector import Detector
from .detector.training import build_detector


@dataclass
class Setup:
    detectors: list[Detector]
    validation: pd.DataFrame
    test: pd.DataFrame


def _split_unknown(unknown: pd.DataFrame, validation_share: float, stratify: str, seed: int):
    validation, test = train_test_split(
        unknown, train_size=validation_share, stratify=unknown[stratify], random_state=seed)
    return validation.sort_values("record_id"), test.sort_values("record_id")


def scenario1(protocol: str = "kddtest", samples: int = 1000, seed: int = 0) -> Setup:
    """Three heterogeneous NSL-KDD detectors (connection / content / traffic features).

    protocol:
      "kddtest" — signatures from KDDTrain+_20Percent, unknown samples from KDDTest+
                  (includes attack types never seen in training).
      "holdout" — signatures and unknown samples both drawn, disjoint, from KDDTrain+.
    ``samples`` unknown samples go to validation and another ``samples`` to test.
    """
    if protocol == "kddtest":
        signatures, pool = kdd.load_nsl_kdd("train_20"), kdd.load_nsl_kdd("test")
    elif protocol == "holdout":
        full = kdd.load_nsl_kdd("train")
        signatures, pool = train_test_split(
            full, train_size=len(kdd.load_nsl_kdd("train_20")), stratify=full["category"],
            random_state=seed)
    else:
        raise ValueError(f"unknown protocol {protocol!r}")

    unknown = pool.sample(2 * samples, random_state=seed)
    validation, test = _split_unknown(unknown, 0.5, "category", seed)
    n_clusters = signatures["category"].nunique()
    detectors = [
        build_detector(source, signatures, features, SCENARIO1, n_clusters, stratify="category",
                       categorical=kdd.CATEGORICAL_FEATURES, seed=seed)
        for source, features in kdd.SOURCES.items()
    ]
    return Setup(detectors, validation, test)


KNOWLEDGE = {"detector1": cic.DETECTOR1_ATTACKS, "detector2": cic.DETECTOR2_ATTACKS}


def scenario2(
    fraction: float = 1.0,
    signature_share: float = 0.2,
    validation_share: float = 0.125,
    seed: int = 0,
) -> Setup:
    """Two homogeneous CICIDS2017 detectors with different attack knowledge.

    ``signature_share`` of each class becomes signatures (split 50/50 train/eval); the
    rest is unknown traffic, of which ``validation_share`` is held out for tuning.
    Defaults: 20% signatures, 10% validation, 70% test.
    """
    flows = cic.load_cicids2017(
        cic.SCENARIO2_FILES, labels=[cic.BENIGN, *cic.DETECTOR1_ATTACKS, *cic.DETECTOR2_ATTACKS])
    if fraction < 1:
        flows = flows.groupby("label").sample(frac=fraction, random_state=seed)
    features = cic.feature_columns(flows)

    signatures, unknown = train_test_split(
        flows, train_size=signature_share, stratify=flows["label"], random_state=seed)
    validation, test = _split_unknown(unknown, validation_share, "label", seed)

    detectors = []
    for name, attacks in KNOWLEDGE.items():
        known = signatures[signatures["label"].isin([cic.BENIGN, *attacks])]
        detectors.append(build_detector(
            name, known, features, SCENARIO2, n_clusters=known["label"].nunique(),
            stratify="label", seed=seed))
    return Setup(detectors, validation, test)
