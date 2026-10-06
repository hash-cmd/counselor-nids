import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def raw_data_dir() -> Path:
    """Directory holding the raw datasets; override with the NIDS_DATA_DIR env var."""
    return Path(os.environ.get("NIDS_DATA_DIR", PROJECT_ROOT / "data" / "raw"))
