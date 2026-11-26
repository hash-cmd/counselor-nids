"""Per-source rolling-window features — the behaviour a single flow cannot show on its own.

A brute-force attempt, a port scan and a flood each look harmless as one flow: one short
connection. What gives them away is the *pattern across many flows from the same source in a
short time* — many connections, to many ports, mostly empty. The per-flow detectors could never
see that, which is why live brute force and scans slipped past them while Snort's rate rules
caught them.

This module adds, to each flow, a few features describing its source's recent behaviour, so the
pattern travels inside the single flow vector the detector already classifies:

    src_conn_rate       connections from this source in the last ``window`` seconds
    src_distinct_dports distinct destination ports the source touched in the window
    src_distinct_dhosts distinct destination hosts the source touched in the window
    src_same_dport_rate connections from the source to *this* flow's destination port (brute
                        force / flood against one service)
    src_connonly_ratio  share of the source's recent flows that carry no payload (scan / SYN flood)

The features are tool-agnostic: they describe what the attacker *does*, not which tool did it, so
they generalise to tools the models never trained on.

``WINDOW_FEATURES`` is the column list. ``add_window_features`` computes them over a whole
time-ordered frame (training). ``RollingWindow`` computes the same values incrementally over a
live stream of batches (``services/extractor``), so training and live produce identical values —
the project's rule that the same code measures both.
"""

from collections import deque

import numpy as np
import pandas as pd

WINDOW_FEATURES = [
    "src_conn_rate",
    "src_distinct_dports",
    "src_distinct_dhosts",
    "src_same_dport_rate",
    "src_connonly_ratio",
]

DEFAULT_WINDOW = 60.0
# A flow with no payload: a bare handshake / scan probe (SYN, maybe RST/FIN), no data exchanged.
_CONNONLY_MAX_PACKETS = 3


def _payload_packets(df: pd.DataFrame) -> np.ndarray:
    fwd = df["Total Fwd Packets"].to_numpy(dtype=float) if "Total Fwd Packets" in df else np.zeros(len(df))
    bwd = df["Total Backward Packets"].to_numpy(dtype=float) if "Total Backward Packets" in df else np.zeros(len(df))
    return fwd + bwd


class RollingWindow:
    """Incremental per-source window features over a time-ordered stream.

    ``update(batch)`` returns the window feature columns for every flow in ``batch`` (a frame with
    ``src_ip``, ``dst_ip``, ``conn_dst_port``, ``flow_start`` and the packet-count features), and
    folds the batch into the state for later batches. Flows must arrive in non-decreasing
    ``flow_start`` order across calls, which the live flow meter and the training frame both give.
    """

    def __init__(self, window: float = DEFAULT_WINDOW):
        self.window = window
        self._events: dict[str, deque] = {}  # src_ip -> deque of (flow_start, dst_ip, dport, connonly)

    def _evict(self, events: deque, now: float) -> None:
        cutoff = now - self.window
        while events and events[0][0] < cutoff:
            events.popleft()

    def update(self, batch: pd.DataFrame) -> pd.DataFrame:
        if batch.empty:
            return pd.DataFrame(columns=WINDOW_FEATURES, index=batch.index, dtype=float)
        src = batch["src_ip"].astype(str).to_numpy()
        dst = batch["dst_ip"].astype(str).to_numpy()
        dport = batch["conn_dst_port"].to_numpy()
        start = batch["flow_start"].astype(float).to_numpy()
        connonly = _payload_packets(batch) <= _CONNONLY_MAX_PACKETS

        rows = np.empty((len(batch), len(WINDOW_FEATURES)), dtype=float)
        for i in range(len(batch)):
            s, now = src[i], start[i]
            events = self._events.setdefault(s, deque())
            self._evict(events, now)
            # the window counts the source's earlier flows (this flow is added after measuring),
            # so a lone first connection reads as rate 1, not inflated by itself
            n = len(events) + 1
            dports = {e[2] for e in events}
            dports.add(dport[i])
            dhosts = {e[1] for e in events}
            dhosts.add(dst[i])
            same_dport = 1 + sum(1 for e in events if e[2] == dport[i])
            connonly_n = int(connonly[i]) + sum(1 for e in events if e[3])
            rows[i] = (n, len(dports), len(dhosts), same_dport, connonly_n / n)
            events.append((now, dst[i], dport[i], bool(connonly[i])))
        return pd.DataFrame(rows, columns=WINDOW_FEATURES, index=batch.index)

    def trim(self, max_sources: int = 100_000) -> None:
        """Drop empty/oldest source deques so a long-running service stays bounded."""
        for s in [s for s, ev in self._events.items() if not ev]:
            del self._events[s]
        if len(self._events) > max_sources:
            for s in list(self._events)[: len(self._events) - max_sources]:
                del self._events[s]


def add_window_features(flows: pd.DataFrame, window: float = DEFAULT_WINDOW) -> pd.DataFrame:
    """Add ``WINDOW_FEATURES`` to a whole frame at once (training). Sorts by ``flow_start`` to put
    the stream in time order, computes the features, and returns the frame in its original order."""
    if flows.empty:
        for c in WINDOW_FEATURES:
            flows[c] = pd.Series(dtype=float)
        return flows
    flows = flows.drop(columns=[c for c in WINDOW_FEATURES if c in flows.columns])  # idempotent
    order = flows["flow_start"].astype(float).sort_values(kind="stable").index
    feats = RollingWindow(window).update(flows.loc[order])
    return flows.join(feats)
