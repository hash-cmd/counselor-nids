"""NSL-KDD loader (Scenario 1: heterogeneous detectors).

The paper simulates three heterogeneous data sources from NSL-KDD but does not say
which features each one gets. We follow the dataset's own feature groups
(Tavallaee et al., 2009):

    connection : basic features of individual TCP connections   (features 1-9)
    content    : content features, the "application logs" view  (features 10-22)
    traffic    : time- and host-based traffic statistics        (features 23-41)
"""

from pathlib import Path

import pandas as pd

from .paths import raw_data_dir

BASIC_FEATURES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent",
]
CONTENT_FEATURES = [
    "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
]
TIME_TRAFFIC_FEATURES = [
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
]
HOST_TRAFFIC_FEATURES = [
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]

FEATURES = BASIC_FEATURES + CONTENT_FEATURES + TIME_TRAFFIC_FEATURES + HOST_TRAFFIC_FEATURES
COLUMNS = FEATURES + ["label", "difficulty"]
CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]

SOURCES = {
    "connection": BASIC_FEATURES,
    "content": CONTENT_FEATURES,
    "traffic": TIME_TRAFFIC_FEATURES + HOST_TRAFFIC_FEATURES,
}

# Attack name -> category, covering the attacks in both KDDTrain+ and KDDTest+.
ATTACK_CATEGORIES = {
    **dict.fromkeys(
        ["back", "land", "neptune", "pod", "smurf", "teardrop", "apache2",
         "mailbomb", "processtable", "udpstorm"], "DoS"),
    **dict.fromkeys(
        ["ipsweep", "nmap", "portsweep", "satan", "mscan", "saint"], "Probe"),
    **dict.fromkeys(
        ["ftp_write", "guess_passwd", "imap", "multihop", "phf", "spy",
         "warezclient", "warezmaster", "httptunnel", "named", "sendmail",
         "snmpgetattack", "snmpguess", "worm", "xlock", "xsnoop"], "R2L"),
    **dict.fromkeys(
        ["buffer_overflow", "loadmodule", "perl", "rootkit", "ps", "sqlattack",
         "xterm"], "U2R"),
}

SPLIT_FILES = {
    "train": "KDDTrain+.txt",
    "train_20": "KDDTrain+_20Percent.txt",
    "test": "KDDTest+.txt",
    "test_21": "KDDTest-21.txt",
}


def load_nsl_kdd(split: str = "train", data_dir: Path | None = None) -> pd.DataFrame:
    """Load one NSL-KDD split with named columns.

    Adds ``category`` (normal/DoS/Probe/R2L/U2R), ``is_attack`` and ``record_id``.
    NSL-KDD has no timestamps; ``record_id`` (row order) stands in for one when
    matching advice between detectors that view the same record.
    """
    data_dir = Path(data_dir) if data_dir else raw_data_dir()
    df = pd.read_csv(data_dir / "nsl-kdd" / SPLIT_FILES[split], header=None, names=COLUMNS)

    unknown = set(df["label"]) - set(ATTACK_CATEGORIES) - {"normal"}
    if unknown:
        raise ValueError(f"Unmapped NSL-KDD labels: {sorted(unknown)}")

    df["category"] = df["label"].map(ATTACK_CATEGORIES).fillna("normal")
    df["is_attack"] = df["label"] != "normal"
    df["record_id"] = range(len(df))
    return df


def source_features(source: str) -> list[str]:
    """Feature columns seen by the detector of the given data source."""
    return list(SOURCES[source])
