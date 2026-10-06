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
ALERTS_KEPT = 50_000  # entries kept per alert stream (ML and Snort)
SNORT_ACTIVE = f"{PREFIX}:snort:active"  # set while the Snort correlator still needs advice

# Running counts behind the dashboard's breakdowns (hashes: name -> count).
FLAGGED_ML = f"{PREFIX}:flagged:ml"                   # set of flows any detector flagged
ML_LABELS = f"{PREFIX}:breakdown:ml:labels"           # flagged flows by true label (replays)
ML_SOURCES = f"{PREFIX}:breakdown:ml:sources"         # flagged flows by source IP (captures)
SNORT_RULES = f"{PREFIX}:breakdown:snort:rules"       # Snort alerts by rule
SNORT_SOURCES = f"{PREFIX}:breakdown:snort:sources"   # Snort alerts by source IP

BATCH, END = "batch", "end"


def inbox(name: str) -> str:
    return f"{PREFIX}:inbox:{name}"


def advice_requests(name: str) -> str:
    return f"{PREFIX}:advice:req:{name}"


def advice_reply(request_id: str) -> str:
    return f"{PREFIX}:advice:reply:{request_id}"


def stats(name: str) -> str:
    return f"{PREFIX}:stats:{name}"


# redis-py 8 gives connections a 5 s socket timeout by default, which races any
# blocking read (BLPOP) that waits 5 s or more. Every blocking wait here is shorter.
SOCKET_TIMEOUT = 30


def connect(url: str | None = None) -> redis.Redis:
    return redis.Redis.from_url(url or os.environ.get("NIDS_REDIS_URL", "redis://localhost:6379/0"),
                                socket_timeout=SOCKET_TIMEOUT)


def encode_frame(df: pd.DataFrame) -> str:
    return df.to_json(orient="split", index=False)


def decode_frame(raw: bytes | str) -> pd.DataFrame:
    text = raw.decode() if isinstance(raw, bytes) else raw
    return pd.read_json(io.StringIO(text), orient="split", dtype=False, convert_dates=False)


def text(value) -> str:
    """Redis returns bytes unless the client uses decode_responses=True."""
    return value.decode() if isinstance(value, bytes) else value


def field(fields: dict, key: str) -> str | None:
    value = fields.get(key.encode(), fields.get(key))
    return value.decode() if isinstance(value, bytes) else value


def reset(r: redis.Redis) -> int:
    """Delete every nids:* key (start a fresh run)."""
    keys = list(r.scan_iter(f"{PREFIX}:*"))
    return r.delete(*keys) if keys else 0
