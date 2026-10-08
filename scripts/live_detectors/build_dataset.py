"""Build training flows for the LIVE detectors from CSE-CIC-IDS2018 raw captures.

Live mode computes flow features with the Python cicflowmeter, which differs from the
Java CICFlowMeter behind the published CSVs in 71 of 154 feature medians (packet lengths
include headers, flags and windows are counted differently, flows are split differently).
Models trained on the CSVs flag 0% of brute-force flows computed the live way. So the
live detectors are trained on flows computed the live way:

  1. victim-server captures from the dataset's raw traffic (data/raw/cse-cic-ids2018-pcap/)
  2. each attacker's packets in evenly spread minutes of its attack windows, found in the
     packets themselves (the CSV timestamps are a 12-hour clock without AM/PM)
  3. all other traffic of the victim, plus an ordinary workstation, as benign
  4. the Python cicflowmeter on each slice; flows labelled by attacker address

Writes data/processed/live/flows.pkl.

    python scripts/live_detectors/build_dataset.py
"""

import argparse
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from nids.capture import pcap
from nids.datasets.flow_features import python_flows_to_2017
from nids.datasets.paths import PROJECT_ROOT
from nids.services.live_capture import connection_columns

PCAPS = PROJECT_ROOT / "data" / "raw" / "cse-cic-ids2018-pcap"
OUT = PROJECT_ROOT / "data" / "processed" / "live"


@dataclass
class Source:
    capture: str
    victim: str | None  # None: the whole capture is benign
    attackers: dict[str, str] = field(default_factory=dict)  # ip -> label
    benign_packets: int | None = -1  # -1: the --benign-packets default; None: all


# Attacker addresses verified in each capture with pcap.scan / attack_windows.
SOURCES = [
    Source("Wednesday-14-02-2018_UCAP172.31.69.25", "172.31.69.25",
           {"18.221.219.4": "FTP-BruteForce", "13.58.98.64": "SSH-Bruteforce"}),
    Source("Thursday-15-02-2018_UCAP172.31.69.25", "172.31.69.25",
           {"18.219.211.138": "DoS-GoldenEye", "18.217.165.70": "DoS-Slowloris"}),
    Source("Friday-16-02-2018_UCAP172.31.69.25-part1", "172.31.69.25",
           {"13.59.126.31": "DoS-SlowHTTPTest", "18.219.193.20": "DoS-Hulk"}),
    Source("Thursday-22-02-2018_UCAP172.31.69.28", "172.31.69.28",
           {"18.218.115.60": "Web-attack"}),
    # Botnet: the infected Windows host is the "victim" and the Ares C2 server the "attacker"
    # (verified: 18.219.211.138 is each infected host's top talker all afternoon).
    Source("Friday-02-03-2018_capEC2AMAZ-O4EL3NG-172.31.69.26", "172.31.69.26", {"18.219.211.138": "Bot"}),
    Source("Friday-02-03-2018_capEC2AMAZ-O4EL3NG-172.31.69.12", "172.31.69.12", {"18.219.211.138": "Bot"}),
    Source("Wednesday-14-02-2018_capPC1-172.31.64.34", None, benign_packets=None),  # all of it
]


def spread_minutes(scanned: pd.DataFrame, src: str, budget: int, picks: int = 12) -> dict[float, float]:
    """Minutes of an attacker's activity, evenly spread over time, within a packet budget.

    Returns {minute start: seconds to keep from that minute}. A flood can send more
    packets in one minute than the whole budget (DoS Hulk: ~700k/min), so each picked
    minute is trimmed to its share of the budget.
    """
    minutes = scanned[scanned["src"] == src].sort_values("bucket")
    if minutes.empty:
        return {}
    picked = minutes.iloc[[round(i) for i in
                           pd.Series(range(picks)) * (len(minutes) - 1) / max(picks - 1, 1)]].drop_duplicates("bucket")
    if minutes["packets"].sum() <= budget:
        picked = minutes  # small attack: take all of it
    share = budget / len(picked)
    return {row.bucket: min(60.0, 60.0 * share / row.packets) for row in picked.itertuples()}


def flowmeter(pcap: Path, out_csv: Path) -> pd.DataFrame:
    log = out_csv.with_suffix(".log")
    with open(log, "w") as f:
        done = subprocess.run([sys.executable, "-m", "nids.capture.flowmeter", "--file", str(pcap), str(out_csv)],
                              stdout=f, stderr=subprocess.STDOUT)
    if done.returncode != 0:
        raise RuntimeError(f"flow meter failed on {pcap.name}:\n{log.read_text()[-3000:]}")
    if not out_csv.exists() or out_csv.stat().st_size == 0:
        return pd.DataFrame()
    return python_flows_to_2017(connection_columns(pd.read_csv(out_csv)))


def build(source: Source, attack_budget: int, benign_budget: int, work: Path) -> pd.DataFrame:
    path = PCAPS / f"{source.capture}.pcap"
    frames = []

    if source.victim is not None and source.attackers:
        scanned = pcap.scan(path, source.victim)
        minutes = {ip: spread_minutes(scanned, ip, attack_budget) for ip in source.attackers}
        for ip, label in source.attackers.items():
            print(f"  {label}: {len(minutes[ip])} minutes of {ip}", flush=True)

        def is_attack(p) -> bool:
            for ip, chosen in minutes.items():
                if ip in (p.src, p.dst) and source.victim in (p.src, p.dst):
                    minute = int(p.time // 60) * 60
                    return minute in chosen and p.time - minute < chosen[minute]
            return False

        sliced = work / f"{source.capture}-attack.pcap"
        n = pcap.slice_pcap(path, sliced, is_attack)
        print(f"  attack slice: {n:,} packets → flowmeter", flush=True)
        flows = flowmeter(sliced, work / f"{source.capture}-attack.csv")
        pair = lambda r: next((lbl for ip, lbl in source.attackers.items() if ip in (r.src_ip, r.dst_ip)), "Benign")
        flows["label"] = [pair(r) for r in flows.itertuples()]
        frames.append(flows)

    attackers = set(source.attackers)
    sliced = work / f"{source.capture}-benign.pcap"
    budget = benign_budget if source.benign_packets == -1 else source.benign_packets
    n = pcap.slice_pcap(path, sliced, lambda p: p.src not in attackers and p.dst not in attackers,
                              max_packets=budget)
    print(f"  benign slice: {n:,} packets → flowmeter", flush=True)
    flows = flowmeter(sliced, work / f"{source.capture}-benign.csv")
    flows["label"] = "Benign"
    frames.append(flows)

    out = pd.concat(frames, ignore_index=True)
    out["capture"] = source.capture
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--attack-packets", type=int, default=120_000, help="per attacker")
    parser.add_argument("--benign-packets", type=int, default=150_000, help="per capture")
    args = parser.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    frames = []
    for source in SOURCES:
        cached = OUT / f"{source.capture}.pkl"  # each capture's flows are kept once built
        if cached.exists():
            print(f"have {source.capture}")
            frames.append(pd.read_pickle(cached))
            continue
        if not (PCAPS / f"{source.capture}.pcap").exists():
            print(f"skipping {source.capture}: capture not downloaded")
            continue
        print(source.capture, flush=True)
        with tempfile.TemporaryDirectory(prefix="nids-live-data-") as work:
            flows = build(source, args.attack_packets, args.benign_packets, Path(work))
        flows.to_pickle(cached)
        frames.append(flows)
    flows = pd.concat(frames, ignore_index=True)
    flows["is_attack"] = flows["label"] != "Benign"
    flows.to_pickle(OUT / "flows.pkl")
    print("\nflows by label:\n" + flows.groupby(["label", "capture"]).size().to_string())
    print("written to", OUT / "flows.pkl")


if __name__ == "__main__":
    main()
