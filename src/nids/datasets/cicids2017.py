"""CICIDS2017 loader (Scenario 2: homogeneous detectors).

Reads the MachineLearningCSV files and fixes their known quirks:
leading spaces in column names, a duplicated ``Fwd Header Length`` column,
``Infinity``/``NaN`` values in the rate columns, and a broken dash character in
the web-attack labels.
"""

from pathlib import Path

import numpy as np
import pandas as pd

from .paths import raw_data_dir

FILES = {
    "monday": "Monday-WorkingHours.pcap_ISCX.csv",
    "tuesday": "Tuesday-WorkingHours.pcap_ISCX.csv",
    "wednesday": "Wednesday-workingHours.pcap_ISCX.csv",
    "thursday_web": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "thursday_infiltration": "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "friday_bot": "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "friday_portscan": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "friday_ddos": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
}

BENIGN = "BENIGN"

# Attack classes each detector is trained on in the paper's Scenario 2.
DETECTOR1_ATTACKS = ["DoS slowloris", "DoS Slowhttptest", "DoS Hulk", "DoS GoldenEye"]
DETECTOR2_ATTACKS = ["DDoS", "PortScan"]
SCENARIO2_FILES = ["wednesday", "friday_ddos", "friday_portscan"]

META_COLUMNS = ["label", "is_attack", "source_file", "record_id"]


def load_cicids2017(
    files: list[str] | None = None,
    labels: list[str] | None = None,
    data_dir: Path | None = None,
) -> pd.DataFrame:
    """Load and clean CICIDS2017 CSVs.

    files:  keys of ``FILES`` to load (default: all eight days).
    labels: keep only rows with these labels (e.g. ``[BENIGN, *DETECTOR1_ATTACKS]``).

    Rows containing NaN/Infinity are dropped. Features are stored as float32.
    The ML CSVs carry no timestamps, so ``record_id`` (row order across the loaded
    files) stands in for one when matching advice between detectors.
    """
    data_dir = (Path(data_dir) if data_dir else raw_data_dir()) / "cicids2017"
    frames = []
    for key in files or list(FILES):
        frame = pd.read_csv(data_dir / FILES[key], encoding_errors="replace", low_memory=False)
        frame["source_file"] = key
        frames.append(frame)
    df = pd.concat(frames, ignore_index=True)

    df.columns = df.columns.str.strip()
    df = df.drop(columns=["Fwd Header Length.1"], errors="ignore")
    df = df.rename(columns={"Label": "label"})
    # Web-attack labels hold a broken dash: raw 0x96 in the official files, U+FFFD in
    # re-encoded mirrors (and after encoding_errors="replace" above).
    df["label"] = df["label"].str.replace("�", "-", regex=False).str.strip()

    if labels is not None:
        df = df[df["label"].isin(labels)]

    features = feature_columns(df)
    df[features] = df[features].replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=features)
    df[features] = df[features].astype(np.float32)

    df["is_attack"] = df["label"] != BENIGN
    df = df.reset_index(drop=True)
    df["record_id"] = range(len(df))
    return df


def feature_columns(df: pd.DataFrame) -> list[str]:
    """All CICFlowMeter feature columns (everything except the metadata columns)."""
    return [c for c in df.columns if c not in META_COLUMNS]
