"""Results for the dashboard: the live detectors' test (train.py), the whole-system test on a
held-out recording (evaluate_capture.py), the unseen botnet machine (cross_host.py) and the
thesis experiments (adapt.py)."""

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
        system = "counselor network" if "counselor network" in series else None
        out[name] = {
            "series": series,
            "rows": [{"label": label, "flows": int(row["flows"]),
                      "flagged": {s: _clean(float(row[s])) for s in series},
                      # 95% interval for the whole system's share flagged
                      "interval": _wilson(round(float(row[system]) * row["flows"]), row["flows"]) if system else None}
                     for label, row in table.iterrows()],
            "summary": summary,
        }
    return out


def _wilson(k: int, n: int) -> dict:
    from nids.evaluation import wilson
    low, high = wilson(int(k), int(n))
    return {"low": _clean(low), "high": _clean(high)}


def _read_csv(path):
    return pd.read_csv(path) if path.exists() else None


def system_tests() -> dict:
    """The whole system (flow meter, AI, Snort, alert linking) on the held-out recording,
    with and without the community rules and Snort as a counselor:
    {variant: [{traffic, flows, ai, snort, either}]}."""
    root = settings.NIDS_ROOT / "results" / "live"
    variants = {
        "project_rules": "system_real_attacks_2018_project_rules.csv",
        "project_rules_snort_counselor": "system_real_attacks_2018_project_rules_snort_counselor.csv",
        "community_rules": "system_real_attacks_2018.csv",
        "community_rules_snort_counselor": "system_real_attacks_2018_snort_counselor.csv",
    }
    out = {}
    for name, file in variants.items():
        table = _read_csv(root / file)
        if table is not None:
            out[name] = [{"traffic": r.traffic, "flows": int(r.flows), "ai": float(r.ML),
                          "snort": float(r.Snort), "either": float(r.either)} for r in table.itertuples()]
    return out


def cross_host() -> dict | None:
    """The botnet test on an infected machine the detectors never trained on."""
    path = settings.NIDS_ROOT / "results" / "live" / "cross_host.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    system = data["system"]
    return {"host": data["host"], "bot_flows": data["bot_flows"], "benign_flows": data["benign_flows"],
            "detection_rate": system["detection_rate"], "false_alarm_rate": system["false_alarm_rate"],
            "detection_interval": _wilson(round(system["detection_rate"] * data["bot_flows"]), data["bot_flows"]),
            "false_alarm_interval": _wilson(round(system["false_alarm_rate"] * data["benign_flows"]),
                                            data["benign_flows"])}


_RULE = None


def rule_names() -> dict[str, str]:
    """"gid:sid" -> message, from the Snort rule files (cached)."""
    global _RULE
    if _RULE is None:
        import re
        _RULE = {}
        pattern = re.compile(r'msg:"([^"]*)".*?\bsid:(\d+)')
        for path in (settings.NIDS_ROOT / "snort" / "rules").rglob("*.rules"):
            for line in path.read_text(errors="ignore").splitlines():
                m = pattern.search(line)
                if m and not line.lstrip().startswith("#"):
                    gid = re.search(r"\bgid:(\d+)", line)
                    _RULE[f"{gid.group(1) if gid else 1}:{m.group(2)}"] = m.group(1)
    return _RULE


def adaptation() -> list[dict]:
    """Thesis experiments (scripts/live_detectors/adapt.py), one per source -> target."""
    root = settings.NIDS_ROOT / "results" / "adaptation"
    out = []
    for folder in sorted(p for p in root.glob("*") if (p / "summary.json").exists()):
        summary = json.loads((folder / "summary.json").read_text())
        args = summary.get("args", {})
        curve = _read_csv(folder / "curve.csv")
        mcnemar = _read_csv(folder / "mcnemar.csv")
        labels = _read_csv(folder / "pseudo_labels.csv")
        trust = json.loads((folder / "rule_trust.json").read_text()) if (folder / "rule_trust.json").exists() else {}
        per_label = sorted(c[len("label:"):] for c in curve.columns if c.startswith("label:"))

        def row(r) -> dict:
            return {k: _clean(float(r[k])) for k in
                    ("detection_rate", "detection_rate_low", "detection_rate_high", "false_alarm_rate",
                     "false_alarm_rate_low", "false_alarm_rate_high", "balanced") if k in r} | {
                "labels": {lbl: _clean(float(r[f"label:{lbl}"])) for lbl in per_label}}

        final = {name: row(r) for name, r in summary.get("final", {}).items()}
        baselines = {name: row(r) for name, r in summary.get("baselines", {}).items()}
        agreement = []
        if labels is not None:
            sums = labels.groupby("config")[["attack_labels", "attack_labels_right", "normal_labels",
                                             "normal_labels_right"]].sum()
            for config, s in sums.iterrows():
                agreement.append({
                    "config": config, "attack_labels": int(s.attack_labels), "normal_labels": int(s.normal_labels),
                    "attack_precision": _clean(s.attack_labels_right / s.attack_labels) if s.attack_labels else None,
                    "normal_precision": _clean(s.normal_labels_right / s.normal_labels) if s.normal_labels else None,
                    "attack_interval": _wilson(s.attack_labels_right, s.attack_labels),
                    "normal_interval": _wilson(s.normal_labels_right, s.normal_labels)})
        names = rule_names()
        rules = [{"rule": rule, "msg": names.get(rule, ""), **stats}
                 for rule, stats in trust.get("full", next(iter(v for v in trust.values() if v), {})).items()]
        rules.sort(key=lambda r: -(r["agree"] + r["disagree"]))
        out.append({
            "name": folder.name, "source": args.get("source"), "target": args.get("target"),
            "development": args.get("source") == args.get("target"),
            "chunks": args.get("chunks"),
            "curve": [{"config": r.config, "step": int(r.step), "detection_rate": float(r.detection_rate),
                       "false_alarm_rate": float(r.false_alarm_rate), "balanced": _clean(float(r.balanced))}
                      for r in curve.itertuples()] if curve is not None else [],
            "final": final, "baselines": baselines,
            "mcnemar": mcnemar.where(mcnemar.notna(), None).to_dict(orient="records") if mcnemar is not None else [],
            "agreement": agreement, "rule_trust": rules[:15],
        })
    return out
