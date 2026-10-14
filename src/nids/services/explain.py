"""A structured, human-readable reason for every alert — the explainability layer.

A black-box classifier says "attack" and stops. This architecture makes the reason part of
every alert, from its structure: which specialist detector recognised the connection (so,
the kind of attack), how that detector reached its verdict (on its own, by taking a
counselor's advice, or because another detector double-checked it), which Snort rule matched,
and whether Snort and the AI agreed (Confirmed / Disputed / AI only).

``explain`` turns a raw alert (an ML alert or a Snort alert, as the journal and the live feed
carry them) into that reason. ``coverage`` measures explanation coverage: the share of alerts
that carry a valid reason — the metric the thesis reports for the explainability objective.
"""

# detector id -> the attack family it recognises, in plain words
ATTACK_NAME = {
    "live_dos": "flooding attack (DoS)",
    "live_access": "break-in (password guessing or website attack)",
    "live_bot": "infected machine (botnet)",
}
# how a detector reached its verdict (the "resolution" field)
HOW = {
    "unanimous": "its checks agreed",
    "advice": "it took a counselor's advice",
    "cross_check": "another detector double-checked it",
    "fallback": "a best guess when its checks disagreed",
    "conflict": "its checks disagreed",
}


def explain(alert: dict) -> dict:
    """A structured reason for one alert. ``explained`` is True when it carries a valid reason
    (a recognised detector for an AI alert, or a matched rule for a Snort alert)."""
    if alert.get("kind") == "snort" or "agreement" in alert:
        rule = alert.get("msg", "") or ""
        agreement = alert.get("agreement", "") or ""
        reason = f"Snort rule matched: {rule}" if rule else "Snort alert"
        if agreement:
            reason += f" ({agreement})"
        return {"source": "rule checker", "snort_rule": rule, "agreement": agreement,
                "reason": reason, "explained": bool(rule)}
    detector = alert.get("detector", "") or ""
    attack = ATTACK_NAME.get(detector, detector)
    how = HOW.get(alert.get("resolution", ""), "")
    counselor = alert.get("counselor", "") or ""
    reason = attack + (f", {how}" if how else "")
    if counselor:
        reason += f" (confirmed by the {ATTACK_NAME.get(counselor, counselor)})"
    return {"source": "AI", "detector": detector, "attack": attack,
            "how": alert.get("resolution", ""), "counselor": counselor,
            "reason": reason, "explained": bool(detector)}


def feature_contributions(detector, flow, top: int = 6) -> list[dict]:
    """Model-internal explanation: the features that drove one detector's verdict on one
    connection, via SHAP (on-demand; needs the ``shap`` package, imported lazily). ``flow`` is a
    one-row DataFrame holding the detector's features. Returns the top features by impact, each
    pushing the verdict toward "attack" (positive) or "normal" (negative).

    The detector picks, per cluster, the classifiers that vote; we explain the best tree-based
    one for this connection's cluster (TreeExplainer is exact and fast). Values are in the
    model's transformed feature space but keep the original feature names, so the direction
    ("this feature pushed toward attack") is what an analyst reads.
    """
    import numpy as np
    import shap  # heavy (numba); only loaded when a model-internal explanation is requested

    m = detector.model
    Xt = m.transform(flow[detector.features])
    profile = m.clusters[int(m.assign_clusters(Xt)[0])]
    trees = ("DecisionTreeClassifier", "RandomForestClassifier", "ExtraTreesClassifier")
    name = next((n for n in [profile.best, *profile.selected] if type(m.classifiers[n]).__name__ in trees), None)
    if name is None:  # only a non-tree classifier (e.g. naive Bayes) was selected here
        return []
    sv = np.asarray(shap.TreeExplainer(m.classifiers[name]).shap_values(Xt))
    vals = sv[0, :, 1] if sv.ndim == 3 else sv[0]  # contributions toward class 1 ("attack")
    names = [n.split("__", 1)[-1] for n in m.preprocessor.get_feature_names_out()]
    ranked = sorted(zip(names, vals), key=lambda kv: -abs(float(kv[1])))[:top]
    return [{"feature": f, "contribution": float(v), "toward": "attack" if v > 0 else "normal"}
            for f, v in ranked]


def coverage(alerts) -> dict:
    """Explanation coverage over a list of alerts: how many carry a valid reason, and from
    which source. By design every ML alert names a detector and every Snort alert a rule, so
    the architecture's coverage is total — unlike an opaque classifier."""
    exps = [explain(a) for a in alerts]
    total = len(exps)
    explained = sum(e["explained"] for e in exps)
    return {
        "alerts": total,
        "explained": explained,
        "explanation_coverage": round(explained / total, 4) if total else None,
        "with_snort_rule": sum(bool(e.get("snort_rule")) for e in exps),
        "with_ai_detector": sum(bool(e.get("detector")) for e in exps),
    }
