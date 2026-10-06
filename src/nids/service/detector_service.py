"""Detector service — one detector as an independent process (Figure 1, 6-8).

The main loop classifies the samples the Observer routes to it and asks the other
detectors for advice over Redis. A background thread answers their advice requests
from this detector's own decisions.
"""

import json
import threading
import time
import uuid
from dataclasses import dataclass, field

import numpy as np
import pandas as pd
import redis

from ..counselor import CounselorNetwork
from ..detector.detector import Detector
from . import bus


class RemoteCounselor:
    """Another detector service, reached through Redis.

    Exposes the same ``advise_many`` as a local Detector, so CounselorNetwork can use
    it unchanged.
    """

    def __init__(self, r: redis.Redis, name: str, timeout: float = 5.0):
        self.r, self.name, self.timeout = r, name, timeout

    def advise_many(self, timestamps: np.ndarray, window: float):
        n = len(timestamps)
        none = (np.zeros(n, dtype=bool), np.zeros(n, dtype=bool), np.zeros(n))
        if n == 0:
            return none
        request_id = uuid.uuid4().hex
        self.r.rpush(bus.advice_requests(self.name), json.dumps({
            "timestamps": np.asarray(timestamps, dtype=float).tolist(),
            "window": window,
            "reply_to": bus.advice_reply(request_id),
        }))
        try:
            reply = self.r.blpop(bus.advice_reply(request_id), timeout=self.timeout)
        except redis.TimeoutError:
            reply = None
        if reply is None:
            return none
        answer = json.loads(reply[1])
        return (np.array(answer["found"], dtype=bool), np.array(answer["prediction"], dtype=bool),
                np.array(answer["confidence"], dtype=float))


@dataclass
class State:
    watermark: float = -np.inf  # latest timestamp this detector has analysed
    ended: bool = False
    stop: threading.Event = field(default_factory=threading.Event)


def serve_advice(r: redis.Redis, detector: Detector, state: State, wait: float) -> None:
    """Answer advice requests. Waits (up to ``wait`` s) until this detector has analysed
    the requested timestamps, since detectors run concurrently."""
    while not state.stop.is_set():
        request = r.blpop(bus.advice_requests(detector.name), timeout=1)
        if request is None:
            continue
        request = json.loads(request[1])
        timestamps = np.array(request["timestamps"], dtype=float)
        deadline = time.monotonic() + wait
        while (state.watermark < timestamps.max() and not state.ended
               and time.monotonic() < deadline):
            time.sleep(0.02)
        found, prediction, confidence = detector.advise_many(timestamps, request["window"])
        r.rpush(request["reply_to"], json.dumps({
            "found": found.tolist(), "prediction": prediction.tolist(),
            "confidence": confidence.tolist()}))
        r.expire(request["reply_to"], 60)


def record(r: redis.Redis, name: str, frame: pd.DataFrame, final: pd.DataFrame) -> None:
    """Update counters and publish attack alerts."""
    resolution = final["resolution"].value_counts()
    attack = final["prediction"].to_numpy(dtype=bool)
    counters = {
        "samples": len(final), "flagged_attack": int(attack.sum()),
        "conflicts": int(final["conflict"].sum()),
        **{f"resolution:{k}": int(v) for k, v in resolution.items()},
    }
    if "is_attack" in frame:
        truth = frame["is_attack"].to_numpy(dtype=bool)
        counters |= {"correct": int((attack == truth).sum()), "true_attacks": int(truth.sum()),
                     "detected_attacks": int((attack & truth).sum())}
    pipe = r.pipeline()
    for key, value in counters.items():
        pipe.hincrby(bus.stats(name), key, value)
    flagged_ids = frame.loc[final.index[attack], "record_id"].astype(int).tolist()
    if flagged_ids:  # for comparing with Snort: flows the ML flagged
        pipe.sadd(f"{bus.PREFIX}:flagged:ml", *flagged_ids)
        pipe.expire(f"{bus.PREFIX}:flagged:ml", 3600)
    flagged = final[attack].join(frame[["record_id"] + (["label"] if "label" in frame else [])])
    for row in flagged.itertuples():
        pipe.xadd(bus.ALERTS, {
            "detector": name, "record_id": int(row.record_id), "timestamp": row.timestamp,
            "resolution": row.resolution, "counselor": row.counselor or "",
            **({"label": row.label} if "label" in frame else {}),
        }, maxlen=10_000, approximate=True)
    pipe.execute()


def run(
    r: redis.Redis,
    detector: Detector,
    sources: list[str],
    min_accuracy: float = 0.9,
    window: float = 0.0,
    cross_check: bool = False,
    retrain_every: int = 0,
    advice_wait: float = 2.0,
    exit_on_end: bool = False,
    max_history: int = 2_000_000,
) -> None:
    state = State()
    r.hset(bus.SUBSCRIPTIONS, detector.name, json.dumps(sources))
    threading.Thread(target=serve_advice, args=(r, detector, state, advice_wait), daemon=True).start()

    last = "0"
    try:
        while True:
            for _, messages in r.xread({bus.inbox(detector.name): last}, block=1000, count=10) or []:
                for message_id, fields in messages:
                    last = message_id
                    if bus.field(fields, "kind") == bus.END:
                        state.ended = True
                        r.sadd(bus.ENDED, detector.name)
                        continue
                    frame = bus.decode_frame(bus.field(fields, "frame"))
                    process(r, detector, frame, state, min_accuracy, window, cross_check)
                    detector.trim_history(max_history)
                    pending = sum(len(y) for _, y in detector.new_signatures)
                    if retrain_every and pending >= retrain_every:
                        r.hincrby(bus.stats(detector.name), "retrained_on", detector.retrain())
            # Keep answering advice until every detector has finished the stream
            # and the Snort correlator (if running) no longer needs verdicts.
            if (exit_on_end and state.ended and r.scard(bus.ENDED) >= r.hlen(bus.SUBSCRIPTIONS)
                    and not r.exists(bus.SNORT_ACTIVE)):
                return
    finally:
        state.stop.set()


def process(r, detector, frame, state, min_accuracy, window, cross_check) -> pd.DataFrame:
    results = detector.detect(frame, frame["timestamp"])
    state.watermark = max(state.watermark, float(frame["timestamp"].max()))
    counselors = [RemoteCounselor(r, name.decode())
                  for name in r.hkeys(bus.SUBSCRIPTIONS) if name.decode() != detector.name]
    network = CounselorNetwork([detector, *counselors], min_accuracy, window,
                               cross_check_normal=cross_check)
    final = network.resolve(detector, frame, results)
    record(r, detector.name, frame, final)
    # how far this detector has analysed, so the Snort correlator knows when to ask
    r.set(f"{bus.PREFIX}:watermark:{detector.name}", state.watermark)
    return final
