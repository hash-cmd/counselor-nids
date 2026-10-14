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
