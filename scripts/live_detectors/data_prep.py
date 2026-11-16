"""Data preparation for the thesis experiments: cleaning, de-duplication and the three-way,
time-ordered train / validation / test split.

The split is the backbone of a leakage-free evaluation (Arp et al., 2022):

    training    60%   fit K-Means, the classifiers and the scaler
    validation  20%   select classifiers per cluster and set the thresholds theta, tau, c
    test        20%   report results only, used once after every choice is fixed

It is made chronologically *within each (label, capture) group*, so a model never trains on
traffic recorded after the traffic it is tested on, while every attack family still appears in all
three partitions. Exact-duplicate flows are removed before splitting, so one flow can never land in
two partitions. The scaler is fit on training only (handled inside ``DetectorModel.fit``).
"""

import numpy as np
import pandas as pd

from nids.datasets.flow_features import CIC2018_TO_2017

DEST_PORT = "Destination Port"


def common_features(drop_port: bool = False) -> list[str]:
    """The shared flow features used as model input. ``drop_port=True`` omits the destination
    port for the port-shortcut sensitivity analysis (Section 3.4.3)."""
    feats = list(CIC2018_TO_2017.values())
    return [f for f in feats if f != DEST_PORT] if drop_port else feats


def prepare(flows: pd.DataFrame, features: list[str]) -> tuple[pd.DataFrame, dict]:
    """Clean and de-duplicate flows, and add the binary ``is_attack`` target. Returns the prepared
    frame and a report of how many rows were dropped and why."""
    n0 = len(flows)
    flows = flows.replace([np.inf, -np.inf], np.nan).dropna(subset=features)
    n_invalid = n0 - len(flows)
    flows = flows.drop_duplicates(subset=features).reset_index(drop=True)
    n_dup = n0 - n_invalid - len(flows)
    flows["is_attack"] = flows["label"] != "Benign"
    return flows, {"rows_in": n0, "removed_invalid": n_invalid, "removed_duplicate": n_dup,
                   "rows_out": len(flows)}


def three_way_split(flows: pd.DataFrame, train_share: float = 0.6, val_share: float = 0.2
                    ) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Chronological 60/20/20 split within each (label, capture) group (train, validation, test)."""
    flows = flows.sort_values("flow_start", kind="stable")
    train, val, test = [], [], []
    for _, g in flows.groupby(["label", "capture"], sort=True):
        n = len(g)
        a, b = int(n * train_share), int(n * (train_share + val_share))
        train.append(g.iloc[:a])
        val.append(g.iloc[a:b])
        test.append(g.iloc[b:])
    cat = lambda parts: pd.concat(parts, ignore_index=True)  # noqa: E731
    return cat(train), cat(val), cat(test)


def session_ids(flows: pd.DataFrame, minutes: float = 1.0) -> np.ndarray:
    """A session id per flow: (label, capture, unordered host pair, time bucket of ``minutes``).
    Flows of one session are near-copies of each other, so statistical tests use the session —
    not the flow — as the unit (``nids.evaluation.clustered_mcnemar`` / ``cluster_bootstrap``)."""
    a, b = flows["src_ip"].astype(str), flows["dst_ip"].astype(str)
    pair = np.where(a < b, a + "|" + b, b + "|" + a)
    bucket = (flows["flow_start"].astype(float) // (minutes * 60)).astype("int64").astype(str)  # epoch seconds
    key = flows["label"].astype(str) + "/" + flows["capture"].astype(str) + "/" + pair + "/" + bucket
    return pd.factorize(key)[0]
