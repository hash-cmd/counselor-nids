import pytest
from scapy.all import IP, TCP, UDP, Ether, wrpcap

from nids.data import pcap_tools


@pytest.fixture
def capture(tmp_path):
    pkts = []
    t = 1_000_000_020.0
    for i in range(300):  # attacker: 300 SYNs to port 22 within ~3 minutes
        p = Ether() / IP(src="13.58.98.64", dst="172.31.69.25") / TCP(sport=40000 + i, dport=22, flags="S")
        p.time = t + i * 0.5
        pkts.append(p)
    for i in range(5):  # a few benign packets, both directions
        for p in (Ether() / IP(src="172.31.64.34", dst="172.31.69.25") / TCP(sport=5000, dport=80, flags="PA"),
                  Ether() / IP(src="172.31.69.25", dst="8.8.8.8") / UDP(sport=5353, dport=53)):
            p.time = t + 600 + i
            pkts.append(p)
    path = tmp_path / "c.pcap"
    wrpcap(str(path), pkts)
    return path


def test_parse_and_scan(capture):
    first = next(pcap_tools.iter_raw(capture))
    p = pcap_tools.parse(first[0], first[2])
    assert (p.src, p.dst, p.proto, p.dport, p.syn_only) == ("13.58.98.64", "172.31.69.25", 6, 22, True)

    scanned = pcap_tools.scan(capture, "172.31.69.25")
    attacker = scanned[scanned.src == "13.58.98.64"]
    assert attacker.packets.sum() == 300 and attacker.syns.sum() == 300
    assert set(attacker.port) == {22}


def test_attack_windows(capture):
    windows = pcap_tools.attack_windows(pcap_tools.scan(capture, "172.31.69.25"), min_packets=50)
    assert list(windows.src) == ["13.58.98.64"]
    w = windows.iloc[0]
    assert w.packets == 300 and w.port == 22
    assert w.start <= 1_000_000_020 and w.end >= 1_000_000_020 + 150


def test_slice(capture, tmp_path):
    out = tmp_path / "attack.pcap"
    n = pcap_tools.slice_pcap(capture, out, lambda p: p.src == "13.58.98.64", max_packets=100)
    assert n == 100
    assert sum(1 for _ in pcap_tools.iter_raw(out)) == 100
