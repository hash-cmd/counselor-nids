"""Cross-host test for the live botnet detector: a botnet-infected machine it never saw.

train.py tests on the later part of each attack on the SAME hosts it learned from. That can
reward memorising a machine's habits rather than recognising the botnet. Here the live
detectors — run as the counselor network exactly as in live mode (cross-check on, fallback
suppressed) — classify every flow of a different infected host (172.31.69.14 by default):
its traffic with the Ares C2 server should be flagged, everything else should not.

Needs the capture (scripts/live_detectors/fetch_captures.py) and trained models (train.py).
Writes results/live/cross_host.json.

    python scripts/live_detectors/cross_host.py
"""

import argparse
import json
import sys
import tempfile
from pathlib import Path

import joblib
import numpy as np

sys.path.insert(0, str(Path(__file__).parent))

from build_dataset import PCAPS, Source, build  # noqa: E402

from nids.counselor import CounselorNetwork  # noqa: E402
from nids.datasets.flow_features import CIC2018_TO_2017  # noqa: E402
from nids.datasets.paths import PROJECT_ROOT, RESULTS_DIR  # noqa: E402
from nids.evaluation import metrics  # noqa: E402
from nids.services.live_capture import carries_payload  # noqa: E402

MODELS = PROJECT_ROOT / "models" / "live"
C2 = "18.219.211.138"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="172.31.69.14", help="held-out infected host")
    parser.add_argument("--min-accuracy", type=float, default=0.9)
    args = parser.parse_args()

    capture = f"Friday-02-03-2018_capEC2AMAZ-O4EL3NG-{args.host}"
    if not (PCAPS / f"{capture}.pcap").exists():
        sys.exit(f"missing {capture}.pcap — run fetch_captures.py first")
    with tempfile.TemporaryDirectory(prefix="nids-crosshost-") as work:
        flows = build(Source(capture, args.host, {C2: "Bot"}), attack_budget=10**9,
                      benign_budget=150_000, work=Path(work))

    features = list(CIC2018_TO_2017.values())
    flows = flows.replace([np.inf, -np.inf], np.nan).dropna(subset=features)
    flows = flows[carries_payload(flows)].reset_index(drop=True)  # live drops connection-only flows
    flows["record_id"] = np.arange(len(flows))
    y = (flows["label"] != "Benign").to_numpy()

    detectors = [joblib.load(p) for p in sorted(MODELS.glob("*.joblib"))]
    # each detector's own verdict, before any counselling (run() below clears this history)
    alone = {d.name: d.detect(flows, flows["record_id"])["prediction"].to_numpy(dtype=bool) for d in detectors}
    finals = CounselorNetwork(detectors, args.min_accuracy, window=0, cross_check_normal=True,
                              suppress_fallback=True).run(flows, flows["record_id"])
    flagged = np.logical_or.reduce([f["prediction"].to_numpy(dtype=bool) for f in finals.values()])

    report = {
        "host": args.host,
        "bot_flows": int(y.sum()),
        "benign_flows": int((~y).sum()),
        "system": metrics(y, flagged),
        "detectors_alone": {name: metrics(y, p) for name, p in alone.items()},
    }
    pct = lambda v: f"{v:.2%}"  # noqa: E731
    print(f"\nheld-out infected host {args.host}: {report['bot_flows']:,} botnet flows, "
          f"{report['benign_flows']:,} other flows")
    print(f"  botnet flows flagged (system):  {pct(flagged[y].mean())}")
    print(f"  other flows flagged (false alarms): {pct(flagged[~y].mean())}")
    for name, p in alone.items():
        print(f"    {name:12s} alone: bot {pct(p[y].mean())}  ·  false alarms {pct(p[~y].mean())}")

    out = RESULTS_DIR / "live"
    out.mkdir(parents=True, exist_ok=True)
    (out / "cross_host.json").write_text(json.dumps(report, indent=2))
    print("\nwritten to", out / "cross_host.json")


if __name__ == "__main__":
    main()
