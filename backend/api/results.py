"""Experiment results written by the scripts in experiments/."""

import json
import math

import pandas as pd
from django.conf import settings

from nids.reporting import FIGURE_ROWS


def _clean(value):
    return None if isinstance(value, float) and math.isnan(value) else value


def comparisons() -> dict:
    """{scenario: {detector: [{approach, label, accuracy, detection_rate, false_alarm_rate}]}}"""
    out = {}
    for folder in sorted((settings.NIDS_ROOT / "results").glob("*")):
        tables = sorted(folder.glob("*_comparison.csv"))
        if not tables:
            continue
        scenario = {}
        for path in tables:
            table = pd.read_csv(path, index_col=0)
            rows = [r for r in FIGURE_ROWS if r in table.index]
            scenario[path.stem.removesuffix("_comparison")] = [
                {"approach": r, "label": FIGURE_ROWS[r],
                 **{k: _clean(float(table.loc[r, k]))
                    for k in ("accuracy", "detection_rate", "false_alarm_rate")}}
                for r in rows
            ]
        summary = folder / "summary.json"
        out[folder.name] = {
            "detectors": scenario,
            "args": json.loads(summary.read_text()).get("args") if summary.exists() else None,
        }
    return out


def self_learning() -> dict:
    """{variant: [{chunk, detector, retrain, labels, standalone_accuracy, final_accuracy, learned}]}"""
    folder = settings.NIDS_ROOT / "results" / "self_learning"
    variants = {"cross_check": "chunks.csv", "conflicts_only": "chunks_conflicts_only.csv"}
    return {
        name: pd.read_csv(folder / file).to_dict(orient="records")
        for name, file in variants.items() if (folder / file).exists()
    }


# Per-attack-type results: share of each label's test flows flagged as attack, for each
# detector set. (file, key in summary.json) per table.
BY_LABEL = {
    "coverage_cse2018": ("coverage/cse2018_by_label.csv", ("coverage/summary.json", "cse2018")),
    "coverage_cicids2017": ("coverage/cicids2017_by_label.csv", ("coverage/summary.json", "cicids2017")),
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
