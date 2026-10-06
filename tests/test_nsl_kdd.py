import pytest

from nids.data import nsl_kdd
from nids.data.nsl_kdd import FEATURES, SOURCES, load_nsl_kdd
from nids.data.paths import raw_data_dir


def write_rows(tmp_path, labels):
    folder = tmp_path / "nsl-kdd"
    folder.mkdir()
    row = ["0", "tcp", "http", "SF"] + ["0"] * 37
    lines = [",".join(row + [label, "20"]) for label in labels]
    (folder / "KDDTrain+.txt").write_text("\n".join(lines) + "\n")
    return tmp_path


def test_sources_partition_all_features():
    combined = [f for cols in SOURCES.values() for f in cols]
    assert sorted(combined) == sorted(FEATURES)
    assert len(FEATURES) == 41


def test_load_adds_category_and_record_id(tmp_path):
    df = load_nsl_kdd("train", data_dir=write_rows(tmp_path, ["normal", "teardrop", "satan"]))
    assert list(df["category"]) == ["normal", "DoS", "Probe"]
    assert list(df["is_attack"]) == [False, True, True]
    assert list(df["record_id"]) == [0, 1, 2]
    assert df["protocol_type"].iloc[0] == "tcp"


def test_unknown_label_raises(tmp_path):
    with pytest.raises(ValueError, match="made_up_attack"):
        load_nsl_kdd("train", data_dir=write_rows(tmp_path, ["made_up_attack"]))


requires_data = pytest.mark.skipif(
    not (raw_data_dir() / "nsl-kdd" / "KDDTrain+.txt").exists(),
    reason="NSL-KDD not downloaded",
)


@requires_data
@pytest.mark.parametrize(
    "split, rows", [("train", 125_973), ("train_20", 25_192), ("test", 22_544), ("test_21", 11_850)]
)
def test_real_split_sizes(split, rows):
    df = load_nsl_kdd(split)
    assert len(df) == rows
    assert df[nsl_kdd.FEATURES].notna().all().all()


@requires_data
def test_real_train_has_teardrop():
    df = load_nsl_kdd("train")
    assert (df["label"] == "teardrop").sum() == 892
