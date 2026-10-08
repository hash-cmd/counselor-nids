"""Build live-detector training flows from ALL of CICIDS2017's raw captures.

CICIDS2017 is a second lab (different network, hosts and attack runs) next to
CSE-CIC-IDS2018, so detectors trained on both learn the attacks rather than one lab. Every
packet of every day goes through the Python cicflowmeter, exactly as live capture computes
flows. Unlike the 2018 per-host captures, each day is one capture of the whole network:

  1. each day is split into PARTS packet files by a hash of its connection (addresses and
     ports, the same in both directions), so every connection stays whole in one part
  2. the flow meter runs on the parts in parallel, and each part is deleted once metered
  3. flows are labelled from CIC's published attack schedule (attacker, victim, window).
     In the captures the outside attacker appears as the firewall's inside address,
     172.16.0.1 (NAT); the botnet's C2 server keeps its public address. Windows are
     padded by PAD seconds; attacker-victim traffic outside every window is ambiguous and
     dropped, as are Heartbleed (a handful of flows) and infiltration (looks normal).
  4. Snort runs on the whole day; the rules that fired on each flow are kept in
     ``snort_rules`` (linked before empty flows are dropped, so scans link as live)
  5. connection-only flows are dropped, as live mode drops them before the ML

Writes data/processed/live/cicids2017-<day>.pkl, one per day (kept, so a rerun skips
finished days). ``--check`` prints the attacker's busiest minutes next to the schedule,
to confirm the time zone before labelling.

    python scripts/live_detectors/build_cicids2017.py [--workers 4] [--check]
"""

import argparse
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from nids.capture import pcap, snort_offline
from nids.datasets.paths import PROJECT_ROOT
from nids.services.live_capture import carries_payload

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_dataset import flowmeter  # noqa: E402

PCAPS = PROJECT_ROOT / "data" / "raw" / "cicids2017-pcap"
OUT = PROJECT_ROOT / "data" / "processed" / "live"
WORK = OUT / "work"  # not /tmp: parts of a 13 GB day do not fit in a RAM-backed /tmp
PARTS = 32
PAD = 120.0

LAB = timezone(timedelta(hours=-3))  # New Brunswick summer time (ADT); verified with --check
ATTACKER = "172.16.0.1"              # Kali (205.174.165.73) behind the firewall's NAT
C2 = "205.174.165.73"                # Ares C2 server, contacted by the bots directly
WEB_SERVER = "192.168.10.50"
BOTS = ["192.168.10.15", "192.168.10.9", "192.168.10.14", "192.168.10.5", "192.168.10.8"]


@dataclass(frozen=True)
class Window:
    label: str          # "Drop": leave these flows out of the data
    a: str              # the two endpoints, either direction
    b: str | None       # None: any address talking to ``a``
    start: str          # local lab time "HH:MM"
    end: str


DAYS = {  # capture -> (date, windows), from https://www.unb.ca/cic/datasets/ids-2017.html
    "Monday-WorkingHours": ("2017-07-03", []),
    "Tuesday-WorkingHours": ("2017-07-04", [
        Window("FTP-BruteForce", ATTACKER, WEB_SERVER, "09:20", "10:20"),
        Window("SSH-Bruteforce", ATTACKER, WEB_SERVER, "14:00", "15:00"),
    ]),
    "Wednesday-workingHours": ("2017-07-05", [
        Window("DoS-Slowloris", ATTACKER, WEB_SERVER, "09:47", "10:10"),
        Window("DoS-SlowHTTPTest", ATTACKER, WEB_SERVER, "10:14", "10:35"),
        Window("DoS-Hulk", ATTACKER, WEB_SERVER, "10:43", "11:00"),
        Window("DoS-GoldenEye", ATTACKER, WEB_SERVER, "11:10", "11:23"),
        Window("Drop", ATTACKER, "192.168.10.51", "15:12", "15:32"),  # Heartbleed: ~10 flows
    ]),
    "Thursday-WorkingHours": ("2017-07-06", [
        Window("Web-attack", ATTACKER, WEB_SERVER, "09:20", "10:00"),   # brute force
        Window("Web-attack", ATTACKER, WEB_SERVER, "10:15", "10:35"),   # XSS
        Window("Web-attack", ATTACKER, WEB_SERVER, "10:40", "10:42"),   # SQL injection
        # infiltration: the victims' traffic in the afternoon looks normal and is unlabeled
        Window("Drop", "192.168.10.8", None, "14:15", "15:50"),
        Window("Drop", "192.168.10.25", None, "14:50", "15:05"),
        Window("Drop", C2, None, "14:15", "15:50"),
    ]),
    "Friday-WorkingHours": ("2017-07-07", [
        *[Window("Bot", bot, C2, "09:55", "11:10") for bot in BOTS],
        Window("PortScan", ATTACKER, WEB_SERVER, "13:55", "15:29"),
        Window("DDoS", ATTACKER, WEB_SERVER, "15:56", "16:16"),
    ]),
}


def epoch(date: str, hhmm: str) -> float:
    return datetime.fromisoformat(f"{date}T{hhmm}").replace(tzinfo=LAB).timestamp()


def connection_hash_filter(k: int, parts: int) -> str:
    """BPF for IPv4 TCP/UDP packets whose connection hashes to part ``k``. The sum of
    both addresses' last bytes and both ports is the same in either direction."""
    l4 = "((ip[0] & 0xf) << 2)"
    key = f"ip[15] + ip[19] + ip[{l4}:2] + ip[{l4} + 2:2]"
    return f"ip and (tcp or udp) and not (ip[6:2] & 0x1fff != 0) and (({key}) % {parts}) == {k}"


def meter_part(day_pcap: Path, k: int, parts: int, work: Path) -> pd.DataFrame:
    part = work / f"part{k:02d}.pcap"
    subprocess.run(["tcpdump", "-r", str(day_pcap), "-w", str(part), connection_hash_filter(k, parts)],
                   check=True, stderr=subprocess.DEVNULL)
    try:
        flows = flowmeter(part, work / f"part{k:02d}.csv")
    finally:
        part.unlink(missing_ok=True)
        (work / f"part{k:02d}.csv").unlink(missing_ok=True)
    print(f"  part {k + 1}/{parts}: {len(flows):,} flows", flush=True)
    return flows


def label(flows: pd.DataFrame, date: str, windows: list[Window]) -> pd.Series:
    labels = pd.Series("Benign", index=flows.index, dtype=object)
    t = flows["flow_start"]
    for w in windows:  # an attacker-victim pair outside all its windows is ambiguous
        pair = (flows["src_ip"].eq(w.a) | flows["dst_ip"].eq(w.a))
        if w.b is not None:
            pair &= flows["src_ip"].eq(w.b) | flows["dst_ip"].eq(w.b)
        inside = t.between(epoch(date, w.start) - PAD, epoch(date, w.end) + PAD)
        labels[pair & inside] = w.label
        if w.label != "Drop":
            labels[pair & ~inside & labels.eq("Benign")] = "Drop"
    return labels


def check(capture: str) -> None:
    date, windows = DAYS[capture]
    scanned = pcap.scan(PCAPS / f"{capture}.pcap", WEB_SERVER)
    busy = scanned[scanned["src"] == ATTACKER].sort_values("bucket")
    print(f"{capture}: minutes in which {ATTACKER} sent > 200 packets to {WEB_SERVER} (lab time)")
    for row in busy[busy["packets"] > 200].itertuples():
        print(f"  {datetime.fromtimestamp(row.bucket, LAB):%H:%M}  {row.packets:>8,} packets  port {row.port}")
    print("schedule:", ", ".join(f"{w.label} {w.start}-{w.end}" for w in windows if w.label != "Drop"))


def build(capture: str, workers: int, parts: int) -> pd.DataFrame:
    date, windows = DAYS[capture]
    WORK.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=WORK, prefix=f"{capture}-") as work:
        with ThreadPoolExecutor(workers) as pool:
            frames = list(pool.map(lambda k: meter_part(PCAPS / f"{capture}.pcap", k, parts, Path(work)),
                                   range(parts)))
    flows = pd.concat([f for f in frames if not f.empty], ignore_index=True)
    total = len(flows)
    with tempfile.TemporaryDirectory(dir=WORK, prefix=f"{capture}-snort-") as work:
        alerts = snort_offline.run_snort(PCAPS / f"{capture}.pcap", Path(work))
    flows["snort_rules"] = snort_offline.link(flows, alerts)
    print(f"  Snort: {len(alerts):,} alerts on {flows['snort_rules'].map(bool).sum():,} flows", flush=True)
    flows = flows[carries_payload(flows)].reset_index(drop=True)
    flows["label"] = label(flows, date, windows)
    flows = flows[flows["label"] != "Drop"].reset_index(drop=True)
    flows["capture"] = f"cicids2017-{capture}"
    print(f"  {total:,} flows, {len(flows):,} kept (with payload, unambiguous)")
    return flows


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--days", nargs="+", choices=list(DAYS), default=list(DAYS))
    parser.add_argument("--workers", type=int, default=4, help="flow meters run at once (each needs ~1 GB)")
    parser.add_argument("--parts", type=int, default=PARTS)
    parser.add_argument("--check", action="store_true", help="print attack minutes vs the schedule, then stop")
    args = parser.parse_args()
    if not shutil.which("tcpdump"):
        sys.exit("tcpdump is needed to split the captures")

    OUT.mkdir(parents=True, exist_ok=True)
    for capture in args.days:
        path = PCAPS / f"{capture}.pcap"
        if not path.exists():
            print(f"skipping {capture}: not downloaded")
            continue
        if args.check:
            check(capture)
            continue
        cached = OUT / f"cicids2017-{capture}.pkl"
        if cached.exists():
            print(f"have {capture}")
            continue
        print(capture, flush=True)
        flows = build(capture, args.workers, args.parts)
        flows.to_pickle(cached)
        print(flows["label"].value_counts().to_string(), flush=True)


if __name__ == "__main__":
    main()
