import numpy as np
import pytest

from nids.counselor import CounselorNetwork
from nids.evaluation import compare, conflict_summary, metrics

from tests.helpers import accurate, split_brain


def test_metrics():
    m = metrics([True, True, False, False], [True, False, True, False])
    assert m == {"accuracy": 0.5, "detection_rate": 0.5, "false_alarm_rate": 0.5}


def test_metrics_without_attacks_has_nan_detection_rate():
    assert np.isnan(metrics([False], [False])["detection_rate"])


def test_compare_and_summary(blobs):
    confused, counselor = split_brain(blobs), accurate(blobs)
    final = CounselorNetwork([confused, counselor], min_accuracy=0.8, window=0).run(
        blobs, blobs["record_id"])["split_brain"]

    table = compare(confused, blobs, {"proposed": final}, blobs["is_attack"])

    assert table.loc["proposed", "accuracy"] > 0.9
    # constant classifiers: majority/weighted voting tie -> attack, so everything is flagged
    assert table.loc["majority_voting", "detection_rate"] == 1.0
    assert table.loc["single_classifier_max", "accuracy"] == pytest.approx(
        max(table.loc["single:yes", "accuracy"], table.loc["single:no", "accuracy"]))
    assert conflict_summary(final) == {"samples": 600, "conflicts": 600, "resolved_by_advice": 600,
                                       "fallback": 0, "cross_check_overrides": 0}
    summary = conflict_summary(final, blobs["is_attack"])
    assert summary["advice_correct"] == (final["prediction"] == blobs["is_attack"]).sum()
    assert summary["fallback_correct"] == 0
