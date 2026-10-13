"""Fast, dependency-free tools for classic pcap and pcapng files.

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
PCAPNG_MAGIC = 0x0A0D0D0A  # pcapng Section Header Block type (reads the same either endianness)


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
    """(time, 16-byte classic-pcap record header, packet bytes) for every packet.

    Reads both classic pcap and pcapng (the CICIDS2017 captures are pcapng); the record
    header is always synthesised in classic little-endian microsecond form.
    """
    with open(path, "rb") as f:
        head = f.read(4)
        if len(head) < 4:
            return
        magic = struct.unpack("<I", head)[0]
        if magic == PCAPNG_MAGIC:
            yield from _iter_pcapng(f)
            return
        if magic not in (MAGIC_US, MAGIC_NS):
            raise ValueError(f"{path}: not a little-endian classic pcap or pcapng")
        f.read(20)  # rest of the 24-byte global header
        scale = 1e9 if magic == MAGIC_NS else 1e6
        while True:
            record = f.read(16)
            if len(record) < 16:
                return
            sec, frac, incl, _ = struct.unpack("<IIII", record)
            yield sec + frac / scale, record, f.read(incl)


def _iter_pcapng(f) -> Iterator[tuple[float, bytes, bytes]]:
    """Packets from a pcapng file: Enhanced Packet Blocks, honouring each interface's
    timestamp resolution. ``f`` may be anywhere — we re-read from the start."""
    f.seek(0)
    if f.read(4) != b"\x0a\x0d\x0d\x0a":
        return
    raw_len = f.read(4)
    bom = f.read(4)
    endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else None
    if endian is None:
        raise ValueError("pcapng: unknown byte-order magic")
    f.seek(struct.unpack(endian + "I", raw_len)[0])  # past the Section Header Block
    tsresol: list[int] = []  # ticks per second, per interface id
    while True:
        hdr = f.read(8)
        if len(hdr) < 8:
            return
        btype, blen = struct.unpack(endian + "II", hdr)
        if blen < 12:
            return
        body = f.read(blen - 12)
        f.read(4)  # trailing block length
        if btype == 1:  # Interface Description Block
            div = 1_000_000
            opts, i = body[8:], 0  # skip linktype, reserved, snaplen
            while i + 4 <= len(opts):
                code, olen = struct.unpack(endian + "HH", opts[i:i + 4])
                i += 4
                val = opts[i:i + olen]
                i += (olen + 3) & ~3
                if code == 0:
                    break
                if code == 9 and olen >= 1:  # if_tsresol
                    v = val[0]
                    div = (1 << (v & 0x7F)) if v & 0x80 else 10 ** v
            tsresol.append(div)
        elif btype == 6 and len(body) >= 20:  # Enhanced Packet Block
            iface, ts_hi, ts_lo, cap_len, _orig = struct.unpack(endian + "IIIII", body[:20])
            div = tsresol[iface] if iface < len(tsresol) else 1_000_000
            ts = ((ts_hi << 32) | ts_lo) / div
            data = body[20:20 + cap_len]
            sec = int(ts)
            rec = struct.pack("<IIII", sec, int(round((ts - sec) * 1e6)), cap_len, _orig)
            yield ts, rec, data


def pcap_header(path: Path) -> bytes:
    with open(path, "rb") as f:
        return f.read(24)


def parse(time: float, data: bytes) -> Packet:
    """Addresses and ports of an Ethernet/IPv4 packet (802.1Q/QinQ VLAN tags are skipped)."""
    if len(data) < 14:
        return Packet(time, None, None, None, None, None, False)
    off = 12  # EtherType field; advance past any VLAN tags
    while data[off:off + 2] in (b"\x81\x00", b"\x88\xa8") and len(data) >= off + 6:
        off += 4
    if data[off:off + 2] != b"\x08\x00":  # not IPv4
        return Packet(time, None, None, None, None, None, False)
    ip = off + 2  # start of the IP header
    if len(data) < ip + 20:
        return Packet(time, None, None, None, None, None, False)
    ihl = (data[ip] & 0x0F) * 4
    proto = data[ip + 9]
    src, dst = _ip(data[ip + 12:ip + 16]), _ip(data[ip + 16:ip + 20])
    l4 = data[ip + ihl:]
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
