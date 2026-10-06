"""Extractor — publishes flow records to the Unknown Samples Repository (Figure 1, 3-4)."""

import time

import pandas as pd
import redis

from . import bus


def wait_for_subscribers(r: redis.Redis, count: int, timeout: float = 120) -> None:
    deadline = time.monotonic() + timeout
    while r.hlen(bus.SUBSCRIPTIONS) < count:
        if time.monotonic() > deadline:
            raise TimeoutError(f"only {r.hlen(bus.SUBSCRIPTIONS)} of {count} detectors subscribed")
        time.sleep(0.2)


def publish(r: redis.Redis, frame: pd.DataFrame, source: str, timestamp_column: str = "record_id") -> None:
    frame = frame.assign(timestamp=frame[timestamp_column].astype(float))
    r.xadd(bus.UNKNOWN, {"kind": bus.BATCH, "source": source, "frame": bus.encode_frame(frame)})


def end(r: redis.Redis, source: str) -> None:
    r.xadd(bus.UNKNOWN, {"kind": bus.END, "source": source})


def replay(
    r: redis.Redis,
    path: str,
    source: str,
    batch_size: int = 500,
    rate: float | None = None,
    timestamp_column: str = "record_id",
    max_rows: int | None = None,
) -> int:
    """Replay a flow CSV as a stream; ``rate`` caps rows per second. Returns rows sent."""
    sent = 0
    for chunk in pd.read_csv(path, chunksize=batch_size, nrows=max_rows):
        publish(r, chunk, source, timestamp_column)
        sent += len(chunk)
        if rate:
            time.sleep(len(chunk) / rate)
    end(r, source)
    return sent
