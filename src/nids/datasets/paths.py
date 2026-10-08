import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
RESULTS_DIR = PROJECT_ROOT / "results"


def raw_data_dir() -> Path:
    """Directory holding the raw captures; override with the NIDS_DATA_DIR env var."""
    return Path(os.environ.get("NIDS_DATA_DIR", PROJECT_ROOT / "data" / "raw"))
