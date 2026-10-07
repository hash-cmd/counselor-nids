"""Live Extractor — capture traffic with the Python ``cicflowmeter`` and publish flows.

Runs the Python cicflowmeter on an interface (or a .pcap) in the background,
follows the CSV it writes, converts each new flow to CICIDS2017 feature names/units,
and publishes batches to the Unknown Samples Repository.

Capturing needs raw-socket rights, e.g. ``sudo`` or
``sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python)``.

Caveat: the detectors were trained on flows from the Java CICFlowMeter used to build
CICIDS2017. The Python port computes some features slightly differently, so accuracy on
live traffic is not the accuracy measured in the experiments.
"""

import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime

import pandas as pd
import redis

from ..datasets.flow_features import python_flows_to_2017
from . import extractor, flow_index


def _numeric(df: pd.DataFrame) -> pd.DataFrame:
    """Convert every column that parses as numbers (IPs and dates stay text)."""
    for column in df:
        converted = pd.to_numeric(df[column], errors="coerce")
        if converted.notna().all():
            df[column] = converted
    return df


def connection_columns(flows: pd.DataFrame) -> pd.DataFrame:
    """Keep each flow's connection and time window (Unix seconds) next to its features,
    so Snort alerts can be linked to it."""
    # cicflowmeter writes local time to the second; datetime.timestamp() reads a naive
    # time as local, daylight saving included
    start = pd.Series([datetime.strptime(t, "%Y-%m-%d %H:%M:%S").timestamp() for t in flows["timestamp"]],
                      index=flows.index)
    return flows.assign(
        flow_start=start,
        flow_end=start + flows["flow_duration"].astype(float),  # seconds, before unit conversion
        conn_dst_port=flows["dst_port"],
    )


# Features that reveal whether any application-layer data was exchanged.
_FWD_LEN, _BWD_LEN = "Total Length of Fwd Packets", "Total Length of Bwd Packets"


def carries_payload(flows: pd.DataFrame) -> pd.Series:
    """True for flows that exchanged data in either direction.

    Connection-only flows — a port scan's SYN/RST, failed connections, a bare SYN
    flood — carry no payload. The live detectors were trained only on flows that
    exchange data (every attack *and* benign flow in the training set does), so asking
    them to classify empty flows yields best-guess false alarms: a single port scan
    produces tens of thousands. Empty flows are still indexed for Snort, which detects
    scans itself, so no detection is lost by keeping them out of the ML.
    """
    def total(column: str) -> pd.Series:
        if column in flows:
            return pd.to_numeric(flows[column], errors="coerce").fillna(0)
        return pd.Series(0, index=flows.index)

    return (total(_FWD_LEN) > 0) | (total(_BWD_LEN) > 0)


def _follow_csv(path: str, process: subprocess.Popen, poll: float = 0.5):
    """Yield DataFrames of new rows appended to a CSV until the process exits."""
    header, offset, buffer = None, 0, ""
    while True:
        alive = process.poll() is None
        if os.path.exists(path):
            with open(path) as f:
                f.seek(offset)
                buffer += f.read()
                offset = f.tell()
            *lines, buffer = buffer.split("\n")  # keep a partial last line for later
            if lines and header is None:
                header, lines = lines[0].split(","), lines[1:]
            rows = [line.split(",") for line in lines if line]
            if rows:
                yield _numeric(pd.DataFrame(rows, columns=header))
        if not alive:
            return
        time.sleep(poll)


def capture(r: redis.Redis, interface_or_pcap: str, source: str, batch_size: int = 100,
            drop_empty_flows: bool = True) -> int:
    """Capture from an interface (or read a .pcap file) and publish flows. Returns flows sent.

    ``drop_empty_flows`` keeps connection-only flows (scans, failed connections) out of
    the ML detectors — they carry no signal the detectors learned and only add false
    alarms. Such flows are still indexed so Snort's alerts can be linked to them.
    """
    try:
        import cicflowmeter  # noqa: F401
    except ImportError:
        raise RuntimeError("cicflowmeter not installed: pip install -e '.[live]'") from None
    mode = "--file" if interface_or_pcap.endswith((".pcap", ".pcapng")) else "--interface"
    out = os.path.join(tempfile.mkdtemp(prefix="nids-live-"), "flows.csv")
    process = subprocess.Popen(
        [sys.executable, "-m", "nids.capture.flowmeter", mode, interface_or_pcap, out])

    sent, next_id, pending = 0, 0, []
    try:
        for flows in _follow_csv(out, process):
            flows = python_flows_to_2017(connection_columns(flows))
            flows["record_id"] = range(next_id, next_id + len(flows))
            flow_index.index_flows(r, flows.rename(columns={"conn_dst_port": "dst_port"}))
            next_id += len(flows)
            if drop_empty_flows:
                flows = flows[carries_payload(flows)]
            if len(flows):
                pending.append(flows)
            if pending and (sum(map(len, pending)) >= batch_size or process.poll() is not None):
                batch = pd.concat(pending, ignore_index=True)
                # every detector sees this same flow stream, so advice matches on record_id
                extractor.publish(r, batch, source)
                sent += len(batch)
                pending = []
        if pending:
            batch = pd.concat(pending, ignore_index=True)
            extractor.publish(r, batch, source)
            sent += len(batch)
    finally:
        process.terminate()
        extractor.end(r, source)
    return sent
