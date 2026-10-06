"""Fast, dependency-free tools for classic pcap files (not pcapng).

Used to build training data for the live detectors from the CSE-CIC-IDS2018 raw captures:
find who attacked a victim and when (``scan``), and cut out the packets to analyse
(``slice_pcap``). Reading is done with ``struct`` only, so a 1 GB capture takes seconds,
not the minutes a full packet parser needs.
"""

import struct
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

MAGIC_US, MAGIC_NS = 0xA1B2C3D4, 0xA1B23C4D


@dataclass(frozen=True)
class Packet:
    time: float
    src: str | None  # IPv4 only; None for anything else
    dst: str | None
    proto: int | None  # 6 TCP, 17 UDP
    sport: int | None
    dport: int | None
    syn_only: bool  # TCP SYN without ACK: a connection attempt


def _ip(b: bytes) -> str:
    return f"{b[0]}.{b[1]}.{b[2]}.{b[3]}"


def iter_raw(path: Path) -> Iterator[tuple[float, bytes, bytes]]:
    """(time, 16-byte record header, packet bytes) for every packet."""
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            return
        magic = struct.unpack("<I", header[:4])[0]
        if magic not in (MAGIC_US, MAGIC_NS):
            raise ValueError(f"{path}: not a little-endian classic pcap (pcapng is not supported)")
        scale = 1e9 if magic == MAGIC_NS else 1e6
        while True:
            record = f.read(16)
            if len(record) < 16:
                return
            sec, frac, incl, _ = struct.unpack("<IIII", record)
            yield sec + frac / scale, record, f.read(incl)


def pcap_header(path: Path) -> bytes:
    with open(path, "rb") as f:
        return f.read(24)


def parse(time: float, data: bytes) -> Packet:
    """Addresses and ports of an Ethernet/IPv4 packet (VLAN tags are not handled)."""
    if len(data) < 34 or data[12:14] != b"\x08\x00":
        return Packet(time, None, None, None, None, None, False)
    ihl = (data[14] & 0x0F) * 4
    proto = data[23]
    src, dst = _ip(data[26:30]), _ip(data[30:34])
    l4 = data[14 + ihl:]
    if proto in (6, 17) and len(l4) >= 4:
        sport, dport = struct.unpack("!HH", l4[:4])
        syn_only = proto == 6 and len(l4) >= 14 and bool(l4[13] & 0x02) and not l4[13] & 0x10
        return Packet(time, src, dst, proto, sport, dport, syn_only)
    return Packet(time, src, dst, proto, None, None, False)


def scan(path: Path, victim: str, bucket: float = 60.0) -> pd.DataFrame:
    """Packets sent to ``victim`` per source and time bucket (Unix seconds, bucket start).

    Columns: src, bucket, packets, syns, ports (most common destination port).
    """
    packets, syns, ports = Counter(), Counter(), {}
    for time, _, data in iter_raw(path):
        p = parse(time, data)
        if p.dst != victim or p.src is None:
            continue
        key = (p.src, int(time // bucket) * bucket)
        packets[key] += 1
        syns[key] += p.syn_only
        if p.dport is not None:
            ports.setdefault(key, Counter())[p.dport] += 1
    rows = [{"src": src, "bucket": b, "packets": n, "syns": syns[(src, b)],
             "port": ports[(src, b)].most_common(1)[0][0] if (src, b) in ports else None}
            for (src, b), n in packets.items()]
    return pd.DataFrame(rows, columns=["src", "bucket", "packets", "syns", "port"])


def attack_windows(scanned: pd.DataFrame, min_packets: int, gap: float = 180.0,
                   bucket: float = 60.0) -> pd.DataFrame:
    """Contiguous periods in which a source sent at least ``min_packets`` per bucket.

    Columns: src, start, end, packets, port — one row per period, busiest first.
    """
    busy = scanned[scanned["packets"] >= min_packets].sort_values(["src", "bucket"])
    windows = []
    for src, group in busy.groupby("src"):
        start = end = None
        total, ports = 0, Counter()
        for row in group.itertuples():
            if start is not None and row.bucket - end > gap:
                windows.append((src, start, end + bucket, total, ports.most_common(1)[0][0]))
                start, total, ports = None, 0, Counter()
            start = row.bucket if start is None else start
            end = row.bucket
            total += row.packets
            ports[row.port] += row.packets
        windows.append((src, start, end + bucket, total, ports.most_common(1)[0][0]))
    return (pd.DataFrame(windows, columns=["src", "start", "end", "packets", "port"])
            .sort_values("packets", ascending=False, ignore_index=True))


def slice_pcap(path: Path, out: Path, keep: Callable[[Packet], bool], max_packets: int | None = None) -> int:
    """Write the packets ``keep`` accepts to ``out``; returns how many were written."""
    written = 0
    with open(out, "wb") as f:
        f.write(pcap_header(path))
        for time, record, data in iter_raw(path):
            if keep(parse(time, data)):
                f.write(record)
                f.write(data)
                written += 1
                if max_packets and written >= max_packets:
                    break
    return written
