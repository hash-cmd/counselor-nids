"""Retrain the detectors on the attacks Snort caught but the AI missed (Snort-as-teacher).

While the system runs with ``NIDS_SNORT_TEACH=1``, every Disputed alert — Snort fired, the AI said
normal — is written to ``logs/snort_teach.jsonl`` as an attack-labelled flow with its measurements
(``services/snort_teacher``). This script feeds that file to the same gated retrainer the analyst
"Teach the AI" button uses (``learn_feedback``): each detector learns the missed attacks, and a
retrain is kept only if it forgets no lab attack type and does not raise false alarms. Run it
periodically (e.g. a daily timer) so the AI converges, on this network, toward what Snort catches.

    python scripts/live_detectors/learn_from_snort.py [--dry-run]

It is exactly ``learn_feedback`` pointed at the Snort-teach file, with a smaller default repeat
weight because Snort supplies many labels, not a handful of analyst clicks.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import learn_feedback  # noqa: E402
from nids.services import snort_teacher  # noqa: E402


def main() -> None:
    argv = sys.argv[1:]
    if not any(a.startswith("--feedback") for a in argv):
        argv += ["--feedback", str(snort_teacher.DEFAULT_FILE)]
    if not any(a.startswith("--weight") for a in argv):
        argv += ["--weight", "5"]
    if not any(a.startswith("--report") for a in argv):
        argv += ["--report", str(Path(learn_feedback.REPORT).with_name("snort-learning.json"))]
    sys.argv = [sys.argv[0], *argv]
    learn_feedback.main()


if __name__ == "__main__":
    main()
