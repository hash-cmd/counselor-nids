"""Experiment results written by experiments/run.py and experiments/self_learning.py."""

import json
import math

import pandas as pd
from django.conf import settings

from nids.experiments import FIGURE_ROWS


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
