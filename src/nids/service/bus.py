"""Redis keys and message encoding shared by the services.

    nids:unknown              stream   Unknown Samples Repository (Extractor -> Observer)
    nids:inbox:<detector>     stream   samples routed to one detector (Observer -> Detector)
    nids:subscriptions        hash     detector -> JSON list of data sources it subscribes to
    nids:ended                set      detectors that have seen the end of the stream
    nids:advice:req:<name>    list     advice requests to one counselor
    nids:advice:reply:<uuid>  list     one advice reply
    nids:stats:<detector>     hash     running counters
    nids:alerts               stream   attack decisions
"""

import io
import os

import pandas as pd
import redis

PREFIX = "nids"
UNKNOWN = f"{PREFIX}:unknown"
SUBSCRIPTIONS = f"{PREFIX}:subscriptions"
ENDED = f"{PREFIX}:ended"
ALERTS = f"{PREFIX}:alerts"

BATCH, END = "batch", "end"


def inbox(name: str) -> str:
    return f"{PREFIX}:inbox:{name}"


def advice_requests(name: str) -> str:
    return f"{PREFIX}:advice:req:{name}"


def advice_reply(request_id: str) -> str:
    return f"{PREFIX}:advice:reply:{request_id}"


def stats(name: str) -> str:
    return f"{PREFIX}:stats:{name}"


def connect(url: str | None = None) -> redis.Redis:
    return redis.Redis.from_url(url or os.environ.get("NIDS_REDIS_URL", "redis://localhost:6379/0"))


def encode_frame(df: pd.DataFrame) -> str:
    return df.to_json(orient="split", index=False)


def decode_frame(raw: bytes | str) -> pd.DataFrame:
    text = raw.decode() if isinstance(raw, bytes) else raw
    return pd.read_json(io.StringIO(text), orient="split", dtype=False, convert_dates=False)


def field(fields: dict, key: str) -> str | None:
    value = fields.get(key.encode(), fields.get(key))
    return value.decode() if isinstance(value, bytes) else value


def reset(r: redis.Redis) -> int:
    """Delete every nids:* key (start a fresh run)."""
    keys = list(r.scan_iter(f"{PREFIX}:*"))
    return r.delete(*keys) if keys else 0
