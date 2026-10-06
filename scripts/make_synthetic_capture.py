"""Write a test capture with known traffic for the Snort + ML pipeline.

    python scripts/make_synthetic_capture.py data/pcap/demo-attacks.pcap

Contains complete TCP sessions so Snort's stream and HTTP inspectors work:
normal web browsing, then a port scan, web attacks (SQL injection, XSS, path
traversal), a SYN flood and an SSH brute force. Prints the time range of each part.
Needs scapy (installed with the ``live`` extra).
"""

import argparse
import random
from pathlib import Path

from scapy.all import IP, TCP, Ether, wrpcap

CLIENT, SERVER, ATTACKER = "10.0.0.10", "10.0.0.80", "10.0.0.66"


class Capture:
    def __init__(self, start: float):
        self.time, self.packets = start, []

    def add(self, packet, gap: float):
        packet.time = self.time
        self.packets.append(packet)
        self.time += gap

    def http(self, src, sport, path, gap=0.002, response_size=1200):
        """One full HTTP/1.1 request-response over a TCP session."""
        dst, dport = SERVER, 80
        c, s = random.randint(1, 2**31), random.randint(1, 2**31)
        fwd = lambda flags, seq, ack, load=b"": Ether() / IP(src=src, dst=dst) / TCP(  # noqa: E731
            sport=sport, dport=dport, flags=flags, seq=seq, ack=ack) / load
        bwd = lambda flags, seq, ack, load=b"": Ether() / IP(src=dst, dst=src) / TCP(  # noqa: E731
            sport=dport, dport=sport, flags=flags, seq=seq, ack=ack) / load
        request = f"GET {path} HTTP/1.1\r\nHost: shop.local\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode()
        body = b"x" * response_size
        response = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body
        self.add(fwd("S", c, 0), gap)
        self.add(bwd("SA", s, c + 1), gap)
        self.add(fwd("A", c + 1, s + 1), gap)
        self.add(fwd("PA", c + 1, s + 1, request), gap)
        self.add(bwd("PA", s + 1, c + 1 + len(request), response), gap)
        self.add(fwd("FA", c + 1 + len(request), s + 1 + len(response)), gap)
        self.add(bwd("FA", s + 1 + len(response), c + 2 + len(request)), gap)
        self.add(fwd("A", c + 2 + len(request), s + 2 + len(response)), gap)

    def probe(self, src, sport, dport, open_port: bool, gap: float):
        """SYN probe answered by SYN-ACK (open) or RST (closed); scanner resets."""
        self.add(Ether() / IP(src=src, dst=SERVER) / TCP(sport=sport, dport=dport, flags="S", seq=1000), gap)
        if open_port:
            self.add(Ether() / IP(src=SERVER, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=5000, ack=1001), gap)
            self.add(Ether() / IP(src=src, dst=SERVER) / TCP(sport=sport, dport=dport, flags="R", seq=1001), gap)
        else:
            self.add(Ether() / IP(src=SERVER, dst=src) / TCP(sport=dport, dport=sport, flags="RA", seq=0, ack=1001), gap)


def build(seed: int = 0) -> tuple[list, dict]:
    random.seed(seed)
    cap, parts = Capture(start=1_790_000_000.0), {}
    pages = ["/", "/products", "/cart", "/products/42", "/search?q=shoes", "/about", "/img/logo.png"]

    def section(name, fn):
        begin = cap.time
        fn()
        parts[name] = (begin, cap.time)

    section("normal browsing", lambda: [cap.http(CLIENT, 40000 + i, random.choice(pages), gap=0.01) for i in range(60)])
    section("port scan", lambda: [cap.probe(ATTACKER, 50000 + p, p, p in (22, 80, 443), gap=0.001) for p in range(1, 1025)])
    section("web attacks", lambda: [cap.http(ATTACKER, 41000 + i, path, gap=0.01) for i, path in enumerate([
        "/search?q=1'%20UNION%20SELECT%20username,password%20FROM%20users--",
        "/login?user=admin'%20or%201=1--",
        "/search?q=<script>alert(document.cookie)</script>",
        "/download?file=../../../../etc/passwd",
    ] * 5)])
    section("SYN flood", lambda: [cap.add(Ether() / IP(src=f"172.16.{random.randint(0, 255)}.{random.randint(1, 254)}", dst=SERVER)
                                          / TCP(sport=random.randint(1024, 65535), dport=80, flags="S", seq=random.randint(1, 2**31)), 0.0005)
                                  for _ in range(3000)])
    section("SSH brute force", lambda: [cap.probe(ATTACKER, 52000 + i, 22, True, gap=0.05) for i in range(60)])
    section("normal browsing (after)", lambda: [cap.http(CLIENT, 43000 + i, random.choice(pages), gap=0.01) for i in range(40)])
    return cap.packets, parts


DESCRIPTION = ("Synthetic: generated packets (port scan, web attacks, SYN flood, SSH brute force). "
               "Snort catches these; the ML, trained on real traffic, does not recognise them.")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("output", type=Path)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    packets, parts = build(args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(args.output), packets)
    args.output.with_name(args.output.name + ".txt").write_text(DESCRIPTION + "\n")  # shown in the dashboard
    print(f"wrote {len(packets):,} packets to {args.output}")
    for name, (begin, end) in parts.items():
        print(f"  {name:24s} {begin:.3f} - {end:.3f}")


if __name__ == "__main__":
    main()
