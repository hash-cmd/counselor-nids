"""CSE-CIC-IDS2018 loader (reserved for later work; not used by the paper's scenarios).

Fixes the dataset's quirks: header rows repeated inside some files, four extra
identifier columns in the 20-02-2018 file, and NaN/Infinity values. Columns are
renamed to the CICIDS2017 names by default, so 2017-trained detectors can read it.
"""

from pathlib import Path

import numpy as np
import pandas as pd

from .flow_features import CIC2018_TO_2017
from .paths import raw_data_dir

FILES = {
    day: f"{day}_TrafficForML_CICFlowMeter.csv"
    for day in [
        "Wednesday-14-02-2018", "Thursday-15-02-2018", "Friday-16-02-2018",
        "Thuesday-20-02-2018", "Wednesday-21-02-2018", "Thursday-22-02-2018",
        "Friday-23-02-2018", "Wednesday-28-02-2018", "Thursday-01-03-2018",
        "Friday-02-03-2018",
    ]
}
BENIGN = "Benign"
USECOLS = [*CIC2018_TO_2017, "Protocol", "Timestamp", "Label"]


def load_cse_cic_ids2018(
    files: list[str] | None = None,
    labels: list[str] | None = None,
    rename_to_2017: bool = True,
    nrows: int | None = None,
    data_dir: Path | None = None,
) -> pd.DataFrame:
    """Load and clean CSE-CIC-IDS2018 CSVs.

    files: keys of ``FILES`` (default: all — about 16M rows, load selectively).
    Adds ``label``, ``is_attack``, ``timestamp`` (Unix seconds), ``source_file`` and
    ``record_id`` (time order).
    """
    data_dir = (Path(data_dir) if data_dir else raw_data_dir()) / "cse-cic-ids2018"
    frames = []
    for key in files or list(FILES):
        frame = pd.read_csv(data_dir / FILES[key], usecols=USECOLS, nrows=nrows,
                            dtype=str, low_memory=False)
        frame["source_file"] = key
        frames.append(frame)
    df = pd.concat(frames, ignore_index=True)

    df = df[df["Label"] != "Label"]  # header rows repeated mid-file
    df = df.rename(columns={"Label": "label"})
    if labels is not None:
        df = df[df["label"].isin(labels)]

    features = [*CIC2018_TO_2017, "Protocol"]
    df[features] = df[features].apply(pd.to_numeric, errors="coerce")
    df[features] = df[features].replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=features)
    df[features] = df[features].astype(np.float32)

    df["timestamp"] = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S").astype("int64") / 1e9
    df = df.drop(columns="Timestamp").sort_values("timestamp", kind="stable", ignore_index=True)
    df["is_attack"] = df["label"] != BENIGN
    df["record_id"] = range(len(df))
    if rename_to_2017:
        df = df.rename(columns=CIC2018_TO_2017)
    return df
