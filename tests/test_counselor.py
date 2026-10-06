from nids.counselor import CounselorNetwork

from .test_detector import accurate, split_brain


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
