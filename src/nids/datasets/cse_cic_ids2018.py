"""CSE-CIC-IDS2018 loader. Used for detectors covering attacks the CICIDS2017 models never
saw; the paper's scenarios stay on NSL-KDD and CICIDS2017.

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
CHUNK_ROWS = 200_000

# Attack types the CICIDS2017 detectors (DoS, DDoS, PortScan) do not cover, and the days
# they were recorded on. Web attacks are rare (about 930 flows over two days).
NEW_ATTACKS = {
    "brute_force": (["Wednesday-14-02-2018"], ["FTP-BruteForce", "SSH-Bruteforce"]),
    "bot": (["Friday-02-03-2018"], ["Bot"]),
    "web": (["Thursday-22-02-2018", "Friday-23-02-2018"], ["Brute Force -Web", "Brute Force -XSS", "SQL Injection"]),
    "infiltration": (["Wednesday-28-02-2018", "Thursday-01-03-2018"], ["Infilteration"]),
}


def load_cse_cic_ids2018(
    files: list[str] | None = None,
    labels: list[str] | None = None,
    rename_to_2017: bool = True,
    nrows: int | None = None,
    data_dir: Path | None = None,
    benign_fraction: float = 1.0,
    seed: int = 0,
) -> pd.DataFrame:
    """Load and clean CSE-CIC-IDS2018 CSVs.

    files: keys of ``FILES`` (default: all — about 16M rows, load selectively).
    benign_fraction: keep this share of benign flows (sampled), to fit in memory.
    Files are read in chunks and cleaned as they go, so only kept rows are held.
    Adds ``label``, ``is_attack``, ``timestamp`` (Unix seconds), ``source_file`` and
    ``record_id`` (time order).
    """
    data_dir = (Path(data_dir) if data_dir else raw_data_dir()) / "cse-cic-ids2018"
    rng = np.random.default_rng(seed)
    wanted = set(labels) if labels is not None else None
    frames = []
    for key in files or list(FILES):
        reader = pd.read_csv(data_dir / FILES[key], usecols=USECOLS, nrows=nrows, dtype=str,
                             chunksize=CHUNK_ROWS)
        for chunk in reader:
            chunk = chunk[chunk["Label"] != "Label"]  # header rows repeated mid-file
            if wanted is not None:
                chunk = chunk[chunk["Label"].isin(wanted)]
            if benign_fraction < 1:
                benign = chunk["Label"].to_numpy() == BENIGN
                chunk = chunk[~benign | (rng.random(len(chunk)) < benign_fraction)]
            frames.append(_clean(chunk).assign(source_file=key))
    df = pd.concat(frames, ignore_index=True).rename(columns={"Label": "label"})

    stamps = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S")
    df["timestamp"] = (stamps - pd.Timestamp(0)) / pd.Timedelta(seconds=1)  # unit-safe (pandas 3)
    df = df.drop(columns="Timestamp").sort_values("timestamp", kind="stable", ignore_index=True)
    df["is_attack"] = df["label"] != BENIGN
    df["record_id"] = range(len(df))
    if rename_to_2017:
        df = df.rename(columns=CIC2018_TO_2017)
    return df


def _clean(chunk: pd.DataFrame) -> pd.DataFrame:
    features = [*CIC2018_TO_2017, "Protocol"]
    numeric = chunk[features].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    keep = numeric.notna().all(axis=1).to_numpy()
    out = numeric[keep].astype(np.float32)
    out["Timestamp"] = chunk.loc[keep, "Timestamp"].to_numpy()
    out["Label"] = chunk.loc[keep, "Label"].to_numpy()
    return out


def load_new_attacks(benign_fraction: float = 0.1, seed: int = 0, data_dir: Path | None = None) -> pd.DataFrame:
    """Benign traffic plus the attack types in ``NEW_ATTACKS``, from the days they occur."""
    days = sorted({day for files, _ in NEW_ATTACKS.values() for day in files})
    labels = [BENIGN, *(label for _, attacks in NEW_ATTACKS.values() for label in attacks)]
    return load_cse_cic_ids2018(days, labels=labels, benign_fraction=benign_fraction, seed=seed,
                                data_dir=data_dir)
