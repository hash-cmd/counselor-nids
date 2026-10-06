"""Download the CSE-CIC-IDS2018 raw captures the live detectors are trained on (~1.3 GB).

Only single hosts' captures are fetched out of each day's 40-60 GB archive, with HTTP
range requests. Files land in data/raw/cse-cic-ids2018-pcap/; existing ones are skipped.

    python experiments/fetch_live_captures.py
"""

import subprocess

from nids.data.paths import raw_data_dir
from nids.data.remote_zip import fetch_member

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def to_classic_pcap(path):
    """Some captures are pcapng; nids.data.pcap_tools reads classic pcap. tcpdump converts."""
    with open(path, "rb") as f:
        if f.read(4) != PCAPNG_MAGIC:
            return
    converted = path.with_suffix(".classic")
    subprocess.run(["tcpdump", "-r", str(path), "-w", str(converted)], check=True, stderr=subprocess.DEVNULL)
    converted.replace(path)

BUCKET = "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Original%20Network%20Traffic%20and%20Log%20data/"
CAPTURES = [  # (day, member in that day's pcap.zip)
    ("Wednesday-14-02-2018", "pcap/UCAP172.31.69.25"),         # FTP + SSH brute force victim
    ("Wednesday-14-02-2018", "pcap/capPC1-172.31.64.34"),      # an ordinary workstation (benign)
    ("Thursday-15-02-2018", "pcap/UCAP172.31.69.25"),          # DoS GoldenEye, Slowloris victim
    ("Friday-16-02-2018", "pcap/UCAP172.31.69.25-part1.pcap"),  # DoS Hulk, SlowHTTPTest victim
    ("Thursday-22-02-2018", "pcap/UCAP172.31.69.28"),          # web attacks victim
]


def main():
    folder = raw_data_dir() / "cse-cic-ids2018-pcap"
    for day, member in CAPTURES:
        dest = folder / f"{day}_{member.split('/')[-1].removesuffix('.pcap')}.pcap"
        if dest.exists():
            print("have", dest.name)
            continue
        print("fetching", day, member, "…", flush=True)
        fetch_member(f"{BUCKET}{day}/pcap.zip", member, dest)
        to_classic_pcap(dest)
        print("  saved", dest.name, f"({dest.stat().st_size / 1e6:.0f} MB)", flush=True)


if __name__ == "__main__":
    main()
