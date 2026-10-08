"""Test results of the live detectors, written by scripts/live_detectors/train.py."""

import json
import math

import pandas as pd
from django.conf import settings


def _clean(value):
    return None if isinstance(value, float) and math.isnan(value) else value


# Per-attack-type results: share of each label's test flows flagged as attack, per detector
# and for the whole system. (file, (summary file, key in it)) per table.
BY_LABEL = {
    "live": ("live/by_label.csv", ("live/summary.json", "metrics")),
}


def by_label() -> dict:
    """{name: {series: [...], rows: [{label, flows, flagged: {series: share}}], summary: {series: metrics}}}"""
    root = settings.NIDS_ROOT / "results"
    out = {}
    for name, (table_file, (summary_file, key)) in BY_LABEL.items():
        if not (root / table_file).exists():
            continue
        table = pd.read_csv(root / table_file, index_col=0)
        series = [c for c in table.columns if c != "flows"]
        summary = {}
        if (root / summary_file).exists():
            summary = json.loads((root / summary_file).read_text()).get(key, {})
        out[name] = {
            "series": series,
            "rows": [{"label": label, "flows": int(row["flows"]),
                      "flagged": {s: _clean(float(row[s])) for s in series}}
                     for label, row in table.iterrows()],
            "summary": summary,
        }
    return out
