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
DEFAULT_THRESHOLD = 100       # connection-only flows from one source within the window (scan / SYN flood)
DEFAULT_PORT_THRESHOLD = 100  # connections from one source to one port within the window (HTTP flood / Slowloris)
DEFAULT_COOLDOWN = 30.0       # seconds a source stays quiet after an alert
_CONNONLY_MAX_PACKETS = 3


def _payload_packets(df: pd.DataFrame) -> np.ndarray:
    fwd = df["Total Fwd Packets"].to_numpy(dtype=float) if "Total Fwd Packets" in df else np.zeros(len(df))
    bwd = df["Total Backward Packets"].to_numpy(dtype=float) if "Total Backward Packets" in df else np.zeros(len(df))
    return fwd + bwd


class RateAlarm:
    """Two behaviour-based alarms the per-flow ML cannot raise:

    - connection-only rate: many empty flows (SYN/RST) from one source — a scan or SYN flood;
    - same-port rate: many connections from one source to one port — an HTTP flood (Hulk) or a
      Slowloris holding hundreds of slow connections. Slowloris connections carry partial headers
      (not connection-only), so only this second alarm catches them. A very slow, low-fan-out
      Slowloris that stays under ``port_threshold`` is at the detection floor and is Snort's job
      (incomplete-header timeout).
    """

    def __init__(self, window: float = DEFAULT_WINDOW, threshold: int = DEFAULT_THRESHOLD,
                 port_threshold: int = DEFAULT_PORT_THRESHOLD, cooldown: float = DEFAULT_COOLDOWN):
        self.window = window
        self.threshold = threshold
        self.port_threshold = port_threshold
        self.cooldown = cooldown
        self._connonly: dict[str, deque] = {}        # src_ip -> times of connection-only flows
        self._per_port: dict[tuple, deque] = {}       # (src_ip, dport) -> times of all its connections
        self._muted_until: dict[str, float] = {}      # src_ip -> time until which scan/flood alerts are muted
        self._muted_port: dict[tuple, float] = {}      # (src, dport) -> muted until

    def feed(self, frame: pd.DataFrame, now: float | None = None) -> list[dict]:
        """Return rate alerts for ``frame`` (the full batch, empties included)."""
        if frame.empty or "src_ip" not in frame:
            return []
        connonly = _payload_packets(frame) <= _CONNONLY_MAX_PACKETS
        src = frame["src_ip"].astype(str).to_numpy()
        start = frame["flow_start"].astype(float).to_numpy() if "flow_start" in frame \
            else frame["timestamp"].astype(float).to_numpy()
        dst = frame["dst_ip"].astype(str).to_numpy() if "dst_ip" in frame else np.array([""] * len(frame))
        dport = frame["conn_dst_port"].to_numpy() if "conn_dst_port" in frame else np.array([""] * len(frame))
        rid = frame["record_id"].to_numpy() if "record_id" in frame else np.arange(len(frame))

        def recent(events: deque, t: float) -> int:
            events.append(t)
            cutoff = t - self.window
            while events and events[0] < cutoff:
                events.popleft()
            return len(events)

        alerts = []
        for i in range(len(frame)):
            s, t, p = src[i], start[i], dport[i]
            # same-port rate: HTTP flood / Slowloris (connections to one port, payload or not)
            key = (s, p)
            n_port = recent(self._per_port.setdefault(key, deque()), t)
            if n_port >= self.port_threshold and t >= self._muted_port.get(key, 0.0):
                alerts.append(self._alert(rid[i], t, s, dst[i], p,
                                          f"service flood (possible DoS): {n_port} connections from {s} "
                                          f"to port {p} in {self.window:.0f}s"))
                self._muted_port[key] = t + self.cooldown
            # connection-only rate: scan / SYN flood
            if connonly[i]:
                n = recent(self._connonly.setdefault(s, deque()), t)
                if n >= self.threshold and t >= self._muted_until.get(s, 0.0):
                    ports = len({k[1] for k in self._per_port if k[0] == s})
                    kind = "port scan" if ports >= 20 else "connection flood"
                    alerts.append(self._alert(rid[i], t, s, dst[i], p,
                                              f"{kind}: {n} connection-only flows from {s} in {self.window:.0f}s"))
                    self._muted_until[s] = t + self.cooldown
        return alerts

    def _alert(self, rid, t, s, d, p, msg) -> dict:
        return {"detector": DETECTOR, "record_id": int(rid), "timestamp": float(t),
                "resolution": "rate", "counselor": "", "msg": msg,
                "src": f"{s}", "dst": f"{d}:{p}".rstrip(":")}

    def trim(self, max_sources: int = 100_000) -> None:
        for s in [s for s, ev in self._connonly.items() if not ev]:
            self._connonly.pop(s, None)
            self._muted_until.pop(s, None)
        for k in [k for k, ev in self._per_port.items() if not ev]:
            self._per_port.pop(k, None)
            self._muted_port.pop(k, None)
        if len(self._per_port) > max_sources:
            for k in list(self._per_port)[: len(self._per_port) - max_sources]:
                del self._per_port[k]
