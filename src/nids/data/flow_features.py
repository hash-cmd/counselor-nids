"""Map CICFlowMeter feature names between tool versions.

CICIDS2017 (CICFlowMeter v3) uses long names ("Total Fwd Packets"); CSE-CIC-IDS2018
and the Python ``cicflowmeter`` package use short ones ("Tot Fwd Pkts" /
"tot_fwd_pkts"). Models are trained on CICIDS2017, so everything is converted to the
2017 names.
"""

import numpy as np
import pandas as pd

# CSE-CIC-IDS2018 name -> CICIDS2017 name, for all 77 CICIDS2017 features.
CIC2018_TO_2017 = {
    "Dst Port": "Destination Port",
    "Flow Duration": "Flow Duration",
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets",
    "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    **{f"Fwd Pkt Len {s}": f"Fwd Packet Length {s}" for s in ("Max", "Min", "Mean", "Std")},
    **{f"Bwd Pkt Len {s}": f"Bwd Packet Length {s}" for s in ("Max", "Min", "Mean", "Std")},
    "Flow Byts/s": "Flow Bytes/s",
    "Flow Pkts/s": "Flow Packets/s",
    **{f"Flow IAT {s}": f"Flow IAT {s}" for s in ("Mean", "Std", "Max", "Min")},
    "Fwd IAT Tot": "Fwd IAT Total",
    **{f"Fwd IAT {s}": f"Fwd IAT {s}" for s in ("Mean", "Std", "Max", "Min")},
    "Bwd IAT Tot": "Bwd IAT Total",
    **{f"Bwd IAT {s}": f"Bwd IAT {s}" for s in ("Mean", "Std", "Max", "Min")},
    **{f: f for f in ("Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags")},
    "Fwd Header Len": "Fwd Header Length",
    "Bwd Header Len": "Bwd Header Length",
    "Fwd Pkts/s": "Fwd Packets/s",
    "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Min": "Min Packet Length",
    "Pkt Len Max": "Max Packet Length",
    "Pkt Len Mean": "Packet Length Mean",
    "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance",
    **{f"{f} Flag Cnt": f"{f} Flag Count" for f in ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE")},
    "CWE Flag Count": "CWE Flag Count",
    "Down/Up Ratio": "Down/Up Ratio",
    "Pkt Size Avg": "Average Packet Size",
    "Fwd Seg Size Avg": "Avg Fwd Segment Size",
    "Bwd Seg Size Avg": "Avg Bwd Segment Size",
    "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
    "Subflow Fwd Pkts": "Subflow Fwd Packets",
    "Subflow Fwd Byts": "Subflow Fwd Bytes",
    "Subflow Bwd Pkts": "Subflow Bwd Packets",
    "Subflow Bwd Byts": "Subflow Bwd Bytes",
    "Init Fwd Win Byts": "Init_Win_bytes_forward",
    "Init Bwd Win Byts": "Init_Win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd",
    "Fwd Seg Size Min": "min_seg_size_forward",
    **{f"Active {s}": f"Active {s}" for s in ("Mean", "Std", "Max", "Min")},
    **{f"Idle {s}": f"Idle {s}" for s in ("Mean", "Std", "Max", "Min")},
}


def snake(name: str) -> str:
    """CSE-CIC-IDS2018 name -> Python cicflowmeter name ("Flow Byts/s" -> "flow_byts_s")."""
    return name.lower().replace(" ", "_").replace("/", "_")


PYTHON_TO_2017 = {snake(k): v for k, v in CIC2018_TO_2017.items()}

# The Python cicflowmeter reports times in seconds; CICFlowMeter (Java) in microseconds.
TIME_FEATURES_2017 = [
    v for v in CIC2018_TO_2017.values()
    if v == "Flow Duration" or any(t in v for t in ("IAT", "Active", "Idle"))
]

# Features the Python cicflowmeter does not produce, derived the way CICFlowMeter
# v3 effectively computes them in CICIDS2017.
DERIVED_2017 = {
    "Avg Fwd Segment Size": "Fwd Packet Length Mean",
    "Avg Bwd Segment Size": "Bwd Packet Length Mean",
    "Subflow Fwd Packets": "Total Fwd Packets",
    "Subflow Fwd Bytes": "Total Length of Fwd Packets",
    "Subflow Bwd Packets": "Total Backward Packets",
    "Subflow Bwd Bytes": "Total Length of Bwd Packets",
}


def python_flows_to_2017(flows: pd.DataFrame) -> pd.DataFrame:
    """Convert Python cicflowmeter output to CICIDS2017 feature names and units.

    Keeps ``src_ip``/``dst_ip``/``src_port``/``timestamp`` alongside the features.
    """
    out = flows.rename(columns=PYTHON_TO_2017)
    for target, source in DERIVED_2017.items():
        if target not in out:
            out[target] = out[source]
    if "CWE Flag Count" not in out:
        out["CWE Flag Count"] = 0
    out[TIME_FEATURES_2017] = out[TIME_FEATURES_2017].astype(float) * 1e6
    features = list(CIC2018_TO_2017.values())
    out[features] = out[features].replace([np.inf, -np.inf], np.nan).fillna(0).astype(np.float32)
    return out
