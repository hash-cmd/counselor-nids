"""CSV recorder — a durable, spreadsheet-friendly record of everything the system sees.

The Redis streams are capped and cleared at every start, so a long run (for example, monitoring
a network over a week) would lose older alerts and connections. This service tails the live
streams and appends each new entry to a dated CSV file, one per kind:

    <dir>/connections-<YYYY-MM-DD>.csv   every connection judged (only while the feed is on)
    <dir>/alerts-<YYYY-MM-DD>.csv        every ML alert (one per detector that flagged the flow)
    <dir>/snort-<YYYY-MM-DD>.csv         every Snort alert, with whether the ML agreed

Nothing is lost beyond the rolling window, and the files open directly in a spreadsheet. Join
the alerts to the connections on ``record_id`` to see which connections were flagged, and why.

Connections are only recorded while the full-traffic feed is on (the dashboard toggle, or
NIDS_FEED_ALL=1); alerts and Snort alerts are always recorded.
"""

import csv
import os
import time
from datetime import datetime
from pathlib import Path

import redis

from . import bus
from .snort_bridge import ALERTS as SNORT_ALERTS

DEFAULT_DIR = Path(os.environ.get("NIDS_RECORD_DIR",
                                  Path(__file__).resolve().parents[3] / "logs" / "records"))

# the columns written for each kind of stream; fields the stream does not carry are left blank
COLUMNS = {
    "connections": ["time_iso", "time", "record_id", "source", "src", "dst", "proto", "flags",
                    "packets", "bytes", "duration"],
    "alerts": ["time_iso", "time", "record_id", "detector", "resolution", "counselor", "novel",
               "src", "dst", "label"],
    "snort": ["time_iso", "time", "record_id", "gid", "sid", "priority", "msg", "agreement",
              "ml_verdict", "ml_detector", "ml_share", "ml_confidence", "src", "dst", "seconds",
              "flows"],
}


class Recorder:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def write(self, kind: str, row: dict) -> None:
        t = float(row.get("time") or time.time())
        row = {"time_iso": datetime.fromtimestamp(t).isoformat(timespec="seconds"), **row}
        day = datetime.fromtimestamp(t).strftime("%Y-%m-%d")
        path = self.directory / f"{kind}-{day}.csv"
        new = not path.exists()
        with open(path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=COLUMNS[kind], extrasaction="ignore")
            if new:
                writer.writeheader()
            writer.writerow(row)


def run(r: redis.Redis, directory: Path = DEFAULT_DIR, block_ms: int = 2000,
        stop=lambda: False) -> None:
    """Append every new connection and alert to its dated CSV file until ``stop()``."""
    recorder = Recorder(directory)
    streams = {bus.CONNECTIONS: "connections", bus.ALERTS: "alerts", SNORT_ALERTS: "snort"}
    # start after what is already there; "$" on every call would drop entries written between calls
    last = {}
    for stream in streams:
        newest = r.xrevrange(stream, count=1)
        last[stream] = bus.text(newest[0][0]) if newest else "0-0"
    while not stop():
        bus.beat(r, "recorder")
        for stream, entries in r.xread(last, block=block_ms) or []:
            kind = streams[bus.text(stream)]
            for entry_id, fields in entries:
                last[bus.text(stream)] = bus.text(entry_id)
                recorder.write(kind, {bus.text(k): bus.text(v) for k, v in fields.items()})
