"""Offline IP reputation from downloaded public blocklists.

Checks an address against known-bad IP/CIDR lists kept in ``data/blocklists/``
(fetch them with ``scripts/fetch_blocklists.py``). Everything is local: looking an
address up never contacts a third party, so no information about the network leaves
the machine. Absence of lists is fine — reputation just reports nothing.

IPv4 only; IPv6 lines and comments are ignored.
"""

import bisect
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Blocklist:
    """Known-bad IPv4 ranges from one or more lists, as sorted [start, end] intervals."""

    starts: list[int] = field(default_factory=list)
    ends: list[int] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def add(self, network: ipaddress.IPv4Network, source: str) -> None:
        self.starts.append(int(network.network_address))
        self.ends.append(int(network.broadcast_address))
        self.sources.append(source)

    def finalize(self) -> "Blocklist":
        order = sorted(range(len(self.starts)), key=self.starts.__getitem__)
        self.starts = [self.starts[i] for i in order]
        self.ends = [self.ends[i] for i in order]
        self.sources = [self.sources[i] for i in order]
        return self

    def check(self, ip: str) -> str | None:
        """Name of the list the address is on, or None. Overlapping ranges are handled."""
        try:
            n = int(ipaddress.ip_address(ip))
        except ValueError:
            return None
        if isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address):
            return None
        # every interval starting at or before n is a candidate; the widest cover any address.
        i = bisect.bisect_right(self.starts, n) - 1
        while i >= 0:
            if n <= self.ends[i]:
                return self.sources[i]
            # a non-covering interval can still sit before a wider one that started earlier
            if self.starts[i] < n - 0xFFFFFFFF:  # nothing wider than /0 can reach
                break
            i -= 1
        return None

    def __len__(self) -> int:
        return len(self.starts)


def _parse(line: str) -> ipaddress.IPv4Network | None:
    token = line.split("#", 1)[0].split(";", 1)[0].strip()
    if not token:
        return None
    try:
        return ipaddress.ip_network(token, strict=False)  # type: ignore[return-value]
    except ValueError:
        return None


def load_blocklists(directory: Path) -> Blocklist:
    """Load every *.netset / *.txt / *.ipset file in ``directory`` into one Blocklist."""
    blocklist = Blocklist()
    if not directory.is_dir():
        return blocklist
    for path in sorted(directory.glob("*")):
        if path.suffix.lower() not in (".netset", ".txt", ".ipset", ".list"):
            continue
        source = path.stem
        for line in path.read_text(errors="ignore").splitlines():
            network = _parse(line)
            if isinstance(network, ipaddress.IPv4Network):
                blocklist.add(network, source)
    return blocklist.finalize()
