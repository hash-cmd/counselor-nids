import numpy as np
import pytest

from nids.data.cicids2017 import BENIGN, FILES, feature_columns, load_cicids2017
from nids.data.paths import raw_data_dir

HEADER = " Destination Port, Flow Bytes/s, Fwd Header Length, Fwd Header Length, Label"


def write_csv(tmp_path, rows, encoding="utf-8"):
    folder = tmp_path / "cicids2017"
    folder.mkdir()
    text = "\n".join([HEADER, *rows]) + "\n"
    (folder / FILES["friday_ddos"]).write_bytes(text.encode(encoding, errors="replace"))
    return tmp_path


def test_cleans_columns_and_drops_infinite_rows(tmp_path):
    data_dir = write_csv(tmp_path, [
        "80,100.5,20,20,BENIGN",
        "80,Infinity,20,20,DDoS",
        "443,NaN,20,20,DDoS",
        "443,7.0,40,40,DDoS",
    ])
    df = load_cicids2017(["friday_ddos"], data_dir=data_dir)

    assert feature_columns(df) == ["Destination Port", "Flow Bytes/s", "Fwd Header Length"]
    assert list(df["label"]) == [BENIGN, "DDoS"]
    assert list(df["is_attack"]) == [False, True]
    assert list(df["record_id"]) == [0, 1]
    assert df["source_file"].eq("friday_ddos").all()
    assert df["Flow Bytes/s"].dtype == np.float32


def test_label_filter(tmp_path):
    data_dir = write_csv(tmp_path, ["80,1,1,1,BENIGN", "80,1,1,1,DDoS", "80,1,1,1,PortScan"])
    df = load_cicids2017(["friday_ddos"], labels=["DDoS"], data_dir=data_dir)
    assert list(df["label"]) == ["DDoS"]
    assert list(df["record_id"]) == [0]


@pytest.mark.parametrize("encoding", ["cp1252", "utf-8"])
def test_fixes_broken_dash_in_web_attack_labels(tmp_path, encoding):
    # cp1252 writes the raw 0x96 byte (official files); utf-8 keeps U+FFFD (mirrors)
    dash = "–" if encoding == "cp1252" else "�"
    data_dir = write_csv(tmp_path, [f"80,1,1,1,Web Attack {dash} XSS"], encoding=encoding)
    df = load_cicids2017(["friday_ddos"], data_dir=data_dir)
    assert df["label"].iloc[0] == "Web Attack - XSS"


@pytest.mark.skipif(
    not (raw_data_dir() / "cicids2017" / FILES["friday_portscan"]).exists(),
    reason="CICIDS2017 not downloaded",
)
def test_real_portscan_file():
    df = load_cicids2017(["friday_portscan"])
    assert len(feature_columns(df)) == 77
    assert set(df["label"]) == {BENIGN, "PortScan"}
    assert df[feature_columns(df)].notna().all().all()
    assert np.isfinite(df[feature_columns(df)].to_numpy()).all()
