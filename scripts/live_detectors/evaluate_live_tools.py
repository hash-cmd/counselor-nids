"""Score a model set on the live-tool attack flows (capture_attacks.py) — the generalisation test.

These flows come from nmap, curl and slowhttptest, not the lab tools the detectors trained on, so
they measure whether the detectors catch attacks by *behaviour* rather than by a memorised tool
fingerprint. Window features are computed exactly as live mode computes them. Reports, per attack
type, the share of flows the whole counsellor network flags (as deployed, ``counselor.LIVE``).

    python scripts/live_detectors/evaluate_live_tools.py --models models/live
"""

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))

import data_prep as dp  # noqa: E402
from nids.counselor import LIVE, CounselorNetwork  # noqa: E402
from nids.datasets.paths import PROJECT_ROOT  # noqa: E402


def score(models_dir: Path, flows: pd.DataFrame, min_accuracy: float = 0.9) -> pd.Series:
    detectors = [joblib.load(p) for p in sorted(Path(models_dir).glob("*.joblib"))]
    rid = np.arange(len(flows))
    out = CounselorNetwork(detectors, min_accuracy, window=0, learn_from_advice=False, **LIVE).run(flows, rid)
    flagged = np.logical_or.reduce([f["prediction"].to_numpy(dtype=bool) for f in out.values()])
    return pd.Series(flagged, index=flows.index)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--models", type=Path, default=PROJECT_ROOT / "models/live")
    ap.add_argument("--flows", type=Path, default=PROJECT_ROOT / "data/processed/live/live_tool_attacks.pkl")
    ap.add_argument("--compare", type=Path, help="a second model set to compare against (before/after)")
    args = ap.parse_args()

    flows = pd.read_pickle(args.flows)
    flows, _ = dp.prepare(flows, dp.common_features())  # adds window features in flow-start order
    flows = flows.reset_index(drop=True)

    def table(models: Path) -> pd.Series:
        flagged = score(models, flows)
        return flows.assign(flagged=flagged).groupby("label")["flagged"].mean()

    result = pd.DataFrame({str(args.models): table(args.models)})
    if args.compare:
        result[str(args.compare)] = table(args.compare)
    result["flows"] = flows.groupby("label").size()
    print("\nshare of live-tool attack flows detected (whole system):")
    print(result.to_string(float_format=lambda v: f"{v:.1%}"))


if __name__ == "__main__":
    main()
