"""Build data/pcap/real-attacks-2018.pcap: real CSE-CIC-IDS2018 traffic for the dashboard demo.

Takes the LAST minutes of every attack in scripts/live_detectors/build_dataset.SOURCES — after
the 70% point the live detectors were trained on, so the demo shows them on traffic they
never saw — plus the workstation's normal traffic from the same late part of its day.
Floods are trimmed to a few seconds per minute. Packets keep their original times, ordered
by capture day.

    python scripts/live_detectors/make_demo_capture.py
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from build_dataset import PCAPS, SOURCES  # noqa: E402

from nids.capture import pcap  # noqa: E402
from nids.datasets.paths import PROJECT_ROOT  # noqa: E402

OUT = PROJECT_ROOT / "data" / "pcap" / "real-attacks-2018.pcap"
PER_ATTACKER = 6_000  # packets
BENIGN = 25_000


def late_minutes(scanned, src: str, keep: int = 3) -> dict[float, float]:
    """The last ``keep`` active minutes after the 70% point, trimmed to the packet budget."""
    minutes = scanned[scanned["src"] == src].sort_values("bucket")
    late = minutes.iloc[int(len(minutes) * 0.7):].tail(keep)
    share = PER_ATTACKER / max(len(late), 1)
    return {row.bucket: min(60.0, 60.0 * share / row.packets) for row in late.itertuples()}


def main():
    argparse.ArgumentParser(description=__doc__.splitlines()[0]).parse_args()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    header = None
    written = 0
    with open(OUT, "wb") as out:
        # one capture day after another, so packet times never go backwards
        by_day = sorted(SOURCES, key=lambda s: datetime.strptime(s.capture.split("_")[0].split("-", 1)[1], "%d-%m-%Y"))
        for source in by_day:
            path = PCAPS / f"{source.capture}.pcap"
            if not path.exists():
                print("skipping", source.capture)
                continue
            if header is None:
                header = pcap.pcap_header(path)
                out.write(header)
            if source.victim is None:  # workstation: normal traffic from late in its day
                times = [t for t, _, _ in pcap.iter_raw(path)]
                start = times[int(len(times) * 0.7)]
                keep = lambda p, start=start: p.time >= start  # noqa: E731
                budget = BENIGN
            else:
                scanned = pcap.scan(path, source.victim)
                chosen = {ip: late_minutes(scanned, ip) for ip in source.attackers}

                def keep(p, chosen=chosen, victim=source.victim):
                    for ip, minutes in chosen.items():
                        if ip in (p.src, p.dst) and victim in (p.src, p.dst):
                            minute = int(p.time // 60) * 60
                            return minute in minutes and p.time - minute < minutes[minute]
                    return False
                budget = None
            n = 0
            for time, record, data in pcap.iter_raw(path):
                if keep(pcap.parse(time, data)):
                    out.write(record)
                    out.write(data)
                    n += 1
                    if budget and n >= budget:
                        break
            written += n
            print(f"{source.capture}: {n:,} packets", flush=True)
    OUT.with_name(OUT.name + ".txt").write_text(
        "Real attacks recorded in a test lab in 2018 (CSE-CIC-IDS2018), from moments the AI never learned from: "
        "flooding attacks, password guessing and website attacks, mixed with normal office traffic. "
        "A fair test of what the system catches.\n")  # shown in the dashboard
    print(f"wrote {written:,} packets to {OUT}")


if __name__ == "__main__":
    main()
