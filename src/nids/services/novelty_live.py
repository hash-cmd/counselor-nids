"""Live novelty for the dashboard — is a flagged connection a *familiar* kind of attack, or
something *unfamiliar* the system has never seen before (a possible new or unknown attack)?

For a flagged connection whose measurements are still stored (``nids:flow:<record id>``, kept for
seven days), we measure how far the connection sits from each detector's learned clusters (the
novelty score) relative to that detector's threshold ``tau`` (``models/live/novelty.json``, set on
benign validation). A connection close to some detector's clusters is a *familiar* pattern; one far
from *every* detector's clusters is unlike anything the system learned, so it is flagged as a
possible unseen attack. This is the dashboard-facing view of the novelty score (answers RQ3); it
needs no change to the live detectors, since it reads the stored flow on demand.
"""

import json
from pathlib import Path

import pandas as pd

from ..detector import novelty as nov
from . import bus, feedback


def load_taus(models_dir) -> dict:
    """Per-detector novelty thresholds written at training time, or {} if not present."""
    path = Path(models_dir) / "novelty.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text()).get("detectors", {})
    except (OSError, ValueError):
        return {}


def familiarity(r, record_id, detectors: dict, taus: dict) -> dict | None:
    """How familiar a flagged connection is. Returns ``None`` when the flow is no longer stored.

    ``ratio`` is the novelty score divided by the threshold for the nearest detector: below 1 the
    connection matches a known pattern, above 1 it is unlike anything learned. ``novel`` is the
    plain verdict; ``label`` is a word for the dashboard."""
    raw = r.get(f"{feedback.FLOW}{record_id}")
    if not raw:
        return None
    try:
        flow = pd.DataFrame([json.loads(bus.text(raw))])
    except ValueError:
        return None
    ratios = {}
    for name, det in detectors.items():
        tau = taus.get(name, {}).get("tau")
        if not tau:
            continue
        try:
            score = float(nov.novelty_scores(det, flow)[0])
        except Exception:  # noqa: BLE001 - a stored flow missing a feature just skips that detector
            continue
        ratios[name] = score / tau
    if not ratios:
        return None
    nearest = min(ratios, key=ratios.get)   # smallest ratio = the detector it most resembles
    ratio = round(ratios[nearest], 2)
    novel = ratio > 1.0
    return {"ratio": ratio, "novel": novel,
            "label": "unfamiliar" if novel else "familiar",
            "nearest_detector": nearest}


def enrich(r, incidents, detectors: dict, taus: dict):
    """Attach a ``novelty`` field to each incident that still has a stored flow."""
    if not detectors or not taus:
        return incidents
    for inc in incidents:
        rid = inc.get("record_id")
        inc["novelty"] = familiarity(r, rid, detectors, taus) if rid is not None else None
    return incidents
