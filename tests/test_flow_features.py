import numpy as np
import pandas as pd
import pytest

from nids.data.cse_cic_ids2018 import FILES, load_cse_cic_ids2018
from nids.data.flow_features import (
    CIC2018_TO_2017, PYTHON_TO_2017, TIME_FEATURES_2017, python_flows_to_2017, snake,
)
from nids.data.paths import raw_data_dir

FEATURES_2017 = list(CIC2018_TO_2017.values())


def test_mapping_is_one_to_one_over_77_features():
    assert len(CIC2018_TO_2017) == len(set(FEATURES_2017)) == 77


def test_snake_case_names():
    assert snake("Flow Byts/s") == "flow_byts_s"
    assert PYTHON_TO_2017["tot_fwd_pkts"] == "Total Fwd Packets"
    assert PYTHON_TO_2017["init_fwd_win_byts"] == "Init_Win_bytes_forward"


def test_python_flows_converted_to_2017_names_and_microseconds():
    produced = [k for k in PYTHON_TO_2017 if not k.startswith(("subflow", "cwe")) and "seg_size_avg" not in k]
    flows = pd.DataFrame([dict.fromkeys(produced, 1.0)]).assign(
        flow_duration=0.05, flow_byts_s=np.inf, src_ip="10.0.0.1")

    out = python_flows_to_2017(flows)

    assert set(FEATURES_2017) <= set(out.columns)
    assert out.loc[0, "Flow Duration"] == pytest.approx(50_000)  # seconds -> microseconds
    assert out.loc[0, "Flow Bytes/s"] == 0  # infinity cleaned
    assert out.loc[0, "Subflow Fwd Packets"] == out.loc[0, "Total Fwd Packets"]
    assert out.loc[0, "CWE Flag Count"] == 0
    assert out.loc[0, "src_ip"] == "10.0.0.1"
    assert "Flow Duration" in TIME_FEATURES_2017 and "Flow Bytes/s" not in TIME_FEATURES_2017


def write_2018(tmp_path):
    folder = tmp_path / "cse-cic-ids2018"
    folder.mkdir()
    header = ["Dst Port", "Protocol", "Timestamp", *list(CIC2018_TO_2017)[1:], "Label"]
    row = lambda ts, label: ["80", "6", ts, *["1"] * 76, label]  # noqa: E731
    rows = [row("01/03/2018 10:00:05", "Benign"), header,  # repeated header mid-file
            row("01/03/2018 10:00:01", "Infilteration"), row("01/03/2018 10:00:03", "Benign")]
    rows[3][header.index("Flow Byts/s")] = "Infinity"
    text = "\n".join(",".join(r) for r in [header, *rows]) + "\n"
    (folder / FILES["Thursday-01-03-2018"]).write_text(text)
    return tmp_path


def test_2018_loader_cleans_and_orders_by_time(tmp_path):
    df = load_cse_cic_ids2018(["Thursday-01-03-2018"], data_dir=write_2018(tmp_path))

    assert list(df["label"]) == ["Infilteration", "Benign"]  # header row and Infinity row dropped
    assert list(df["is_attack"]) == [True, False]
    assert df["timestamp"].is_monotonic_increasing
    assert list(df["record_id"]) == [0, 1]
    assert set(FEATURES_2017) <= set(df.columns)
    assert df["Destination Port"].dtype == np.float32


def test_2018_loader_can_keep_original_names(tmp_path):
    df = load_cse_cic_ids2018(["Thursday-01-03-2018"], rename_to_2017=False,
                              data_dir=write_2018(tmp_path))
    assert "Tot Fwd Pkts" in df.columns


@pytest.mark.skipif(
    not (raw_data_dir() / "cse-cic-ids2018" / FILES["Thursday-01-03-2018"]).exists(),
    reason="CSE-CIC-IDS2018 not downloaded",
)
def test_real_2018_file():
    df = load_cse_cic_ids2018(["Thursday-01-03-2018"], nrows=50_000)
    assert (df["label"] != "Label").all()
    assert set(df["label"]) <= {"Benign", "Infilteration"}
    assert np.isfinite(df[FEATURES_2017].to_numpy()).all()
