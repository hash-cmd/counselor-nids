"""Make slim inference models for deployment: drop the training data the live detector never uses.

train.py embeds each detector's training and evaluation flows in its .joblib (needed by the
feedback/Snort-teacher retrainers). For a running sensor that only classifies traffic, those are
dead weight — about 99% of the file. Dropping them cuts each model from ~130 MB to ~1 MB, which
makes deployment transfers reliable and, more importantly, cuts a running detector's memory from
~600 MB to ~210 MB (the 4 GB VPSes went from ~3.0 GB to ~1.4 GB of the 3 GB cap).

The slim models detect identically; they only cannot be retrained in place. Retraining regenerates
full models with train.py (optionally ``--extra-flows`` for collected Snort-teacher labels), then
this script slims them again for deployment.

    python scripts/live_detectors/slim_models.py models/window models/window_slim
"""

import hashlib
import shutil
import sys
from pathlib import Path

import joblib


def main() -> None:
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("models/live")
    dst = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("models/live_slim")
    dst.mkdir(parents=True, exist_ok=True)
    for p in sorted(src.glob("*.joblib")):
        d = joblib.load(p)
        d.model.train_data = None
        d.model.eval_data = None
        d.clear_history()
        joblib.dump(d, dst / p.name, compress=6)
        print(f"{p.name}: {p.stat().st_size/1e6:.0f}MB -> {(dst/p.name).stat().st_size/1e6:.1f}MB")
    for meta in ("novelty.json", "manifest.json"):
        if (src / meta).exists():
            shutil.copy(src / meta, dst / meta)
    sums = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(dst.glob("*.joblib"))}
    (dst / "SHA256SUMS").write_text("".join(f"{h}  {n}\n" for n, h in sums.items()))
    print("wrote", dst, "— deploy these; keep the full models for retraining")


if __name__ == "__main__":
    main()
