import pandas as pd

from nids.services.live_capture import carries_payload


def test_carries_payload_keeps_flows_with_data():
    flows = pd.DataFrame({
        "Total Length of Fwd Packets": [0, 120, 0, 44],
        "Total Length of Bwd Packets": [0, 0, 300, 0],
    })
    # row 0: empty (scan/failed connection); 1: fwd data; 2: bwd data; 3: fwd data
    assert carries_payload(flows).tolist() == [False, True, True, True]


def test_carries_payload_handles_missing_and_nonnumeric_columns():
    # a bare SYN flood: no backward column, no forward payload -> dropped
    flows = pd.DataFrame({"Total Length of Fwd Packets": ["0", "0", "80"]})
    assert carries_payload(flows).tolist() == [False, False, True]
