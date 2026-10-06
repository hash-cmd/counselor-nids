from nids.counselor import CounselorNetwork
from tests.helpers import accurate, always, split_brain


def test_conflicts_resolved_by_counselor_advice(blobs):
    confused, counselor = split_brain(blobs), accurate(blobs, name="counselor")
    network = CounselorNetwork([confused, counselor], min_accuracy=0.8, window=0)

    results = network.run(blobs, blobs["record_id"])
    mine, theirs = results["split_brain"], results["counselor"]

    assert (mine["resolution"] == "advice").all()
    assert (mine["counselor"] == "counselor").all()
    assert (mine["prediction"] == theirs["prediction"]).all()
    assert (theirs["resolution"] == "unanimous").all()


def test_advised_samples_become_new_signatures(blobs):
    confused = split_brain(blobs)
    CounselorNetwork([confused, accurate(blobs)], min_accuracy=0.8, window=0).run(
        blobs, blobs["record_id"])
    assert confused.retrain() == len(blobs)


def test_low_accuracy_advice_is_ignored(blobs):
    confused = split_brain(blobs)
    network = CounselorNetwork([confused, accurate(blobs)], min_accuracy=1.01, window=0)

    results = network.run(blobs, blobs["record_id"])["split_brain"]

    assert (results["resolution"] == "fallback").all()
    assert results["counselor"].isna().all()
    assert confused.retrain() == 0


def test_no_counselor_history_in_window_means_fallback(blobs):
    confused, counselor = split_brain(blobs), accurate(blobs)
    counselor.detect(blobs, blobs["record_id"] + 1_000)  # history far in the future
    network = CounselorNetwork([confused, counselor], min_accuracy=0.5, window=2)

    results = network.resolve(confused, blobs, confused.detect(blobs, blobs["record_id"]))

    assert (results["resolution"] == "fallback").all()


def test_conflicted_counselor_gives_no_advice(blobs):
    confused = split_brain(blobs)
    good, bad = accurate(blobs, name="good"), split_brain(blobs, name="bad")
    network = CounselorNetwork([confused, bad, good], min_accuracy=0.0, window=0)

    results = network.run(blobs, blobs["record_id"])["split_brain"]

    # "bad" conflicts on everything, so it has no unambiguous history to advise from
    assert (results["counselor"] == "good").all()



def test_cross_check_flips_normal_verdicts_to_attack_only(blobs):
    blind, alarm = always(blobs, "blind", False), always(blobs, "alarm", True)
    network = CounselorNetwork([blind, alarm], min_accuracy=0.0, window=0, cross_check_normal=True)

    results = network.run(blobs, blobs["record_id"])

    assert (results["blind"]["resolution"] == "cross_check").all()
    assert results["blind"]["prediction"].all()
    # attack verdicts are never cross-checked, so "alarm" keeps its own answers
    assert (results["alarm"]["resolution"] == "unanimous").all()


def test_cross_check_is_off_by_default(blobs):
    blind, alarm = always(blobs, "blind", False), always(blobs, "alarm", True)
    results = CounselorNetwork([blind, alarm], min_accuracy=0.0, window=0).run(blobs, blobs["record_id"])
    assert not results["blind"]["prediction"].any()


def test_cross_check_respects_min_accuracy(blobs):
    blind, alarm = always(blobs, "blind", False), always(blobs, "alarm", True)
    network = CounselorNetwork([blind, alarm], min_accuracy=0.99, window=0, cross_check_normal=True)
    assert not network.run(blobs, blobs["record_id"])["blind"]["prediction"].any()
