"""Rate alarm for connection-only flows — the floods and scans the ML never sees.

Port scans and bare SYN floods carry no payload, so ``live_capture.carries_payload`` keeps them
out of the ML detectors (they would only guess, and a single scan once produced ~50,000 false
alarms). Snort's scan inspector catches scans, but in the 2026-11-25 attack test it missed SYN /
connection floods: nothing flagged them. This fills that gap with a cheap, behaviour-based rule
that needs no model.

It counts each source's connection-only flows in a short sliding window and raises one alert when
a source crosses ``threshold`` within ``window`` seconds — the defining shape of a flood or a
fast scan (many payloadless connections from one source in little time), whatever tool makes it.
A per-source cooldown stops one flood from raising thousands of alerts.

``RateAlarm.feed(frame, now)`` takes the full flow batch (before empties are dropped) and returns
alert dicts in the ``nids:alerts`` stream's shape, so the journal, recorder and dashboard treat
them like any other alert.
"""

from collections import deque

import numpy as np
import pandas as pd

DETECTOR = "rate"
DEFAULT_WINDOW = 10.0
DEFAULT_THRESHOLD = 100   # connection-only flows from one source within the window
DEFAULT_COOLDOWN = 30.0   # seconds a source stays quiet after an alert
_CONNONLY_MAX_PACKETS = 3


def _payload_packets(df: pd.DataFrame) -> np.ndarray:
    fwd = df["Total Fwd Packets"].to_numpy(dtype=float) if "Total Fwd Packets" in df else np.zeros(len(df))
    bwd = df["Total Backward Packets"].to_numpy(dtype=float) if "Total Backward Packets" in df else np.zeros(len(df))
    return fwd + bwd


class RateAlarm:
    def __init__(self, window: float = DEFAULT_WINDOW, threshold: int = DEFAULT_THRESHOLD,
                 cooldown: float = DEFAULT_COOLDOWN):
        self.window = window
        self.threshold = threshold
        self.cooldown = cooldown
        self._events: dict[str, deque] = {}   # src_ip -> deque of connection-only flow times
        self._muted_until: dict[str, float] = {}

    def feed(self, frame: pd.DataFrame, now: float | None = None) -> list[dict]:
        """Return rate alerts for ``frame`` (the full batch, empties included)."""
        if frame.empty or "src_ip" not in frame:
            return []
        connonly = _payload_packets(frame) <= _CONNONLY_MAX_PACKETS
        if not connonly.any():
            return []
        sub = frame[connonly]
        src = sub["src_ip"].astype(str).to_numpy()
        start = sub["flow_start"].astype(float).to_numpy() if "flow_start" in sub \
            else sub["timestamp"].astype(float).to_numpy()
        dst = sub["dst_ip"].astype(str).to_numpy() if "dst_ip" in sub else np.array([""] * len(sub))
        dport = sub["conn_dst_port"].to_numpy() if "conn_dst_port" in sub else np.array([""] * len(sub))
        rid = sub["record_id"].to_numpy() if "record_id" in sub else np.arange(len(sub))

        alerts = []
        for i in range(len(sub)):
            s, t = src[i], start[i]
            events = self._events.setdefault(s, deque())
            events.append(t)
            cutoff = t - self.window
            while events and events[0] < cutoff:
                events.popleft()
            if len(events) >= self.threshold and t >= self._muted_until.get(s, 0.0):
                distinct_ports = sub[src == s]["conn_dst_port"].nunique() if "conn_dst_port" in sub else 0
                kind = "port scan" if distinct_ports >= 20 else "connection flood"
                alerts.append({
                    "detector": DETECTOR, "record_id": int(rid[i]), "timestamp": float(t),
                    "resolution": "rate", "counselor": "",
                    "msg": f"{kind}: {len(events)} connection-only flows from {s} in {self.window:.0f}s",
                    "src": f"{s}", "dst": f"{dst[i]}:{dport[i]}".rstrip(":"),
                })
                self._muted_until[s] = t + self.cooldown
        return alerts

    def trim(self, max_sources: int = 100_000) -> None:
        for s in [s for s, ev in self._events.items() if not ev]:
            self._events.pop(s, None)
            self._muted_until.pop(s, None)
        if len(self._events) > max_sources:
            for s in list(self._events)[: len(self._events) - max_sources]:
                del self._events[s]
