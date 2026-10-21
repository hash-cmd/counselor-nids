"""CVE enrichment for Snort alerts.

A fired Snort rule carries a ``reference:cve,YYYY-NNNN`` in its definition, so an alert's ``sid``
maps to one or more CVE identifiers. This module builds that ``sid -> CVE`` index once from the
rule files, then looks the CVEs up on the online NVD API (https://services.nvd.nist.gov), caching
each result in Redis so the same CVE is never fetched twice.

The lookup is best-effort and bounded: a slow, rate-limited, or unreachable NVD never blocks an
alert — an unresolved CVE is shown with just its id and a link, and its details fill in on a later
poll (the same pattern as the live-traffic reverse-DNS lookup). Only a public CVE id ever leaves
the machine; no traffic, addresses, or flow data are sent. An NVD API key (``NVD_API_KEY`` in
``backend/.env``) raises the rate limit from 5 to 50 requests per 30 seconds.
"""

import json
import re
import time
from pathlib import Path

import requests

from . import bus

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE = f"{bus.PREFIX}:cve:"          # nids:cve:<CVE-ID> -> JSON details, or "" when NVD has none
FOUND_TTL = 30 * 24 * 3600           # CVE records change rarely; cache a month
MISS_TTL = 6 * 3600                  # re-check "not found" occasionally (a new CVE may appear)

_SID_RE = re.compile(r"\bsid:\s*(\d+)")
_CVE_RE = re.compile(r"reference:\s*cve,([0-9]{4}-[0-9]+)", re.IGNORECASE)
_RULE_CVES: dict[int, list[str]] | None = None  # sid -> [CVE-ID, ...], built once from the rules


def rule_cves(rules_dir) -> dict[int, list[str]]:
    """Map each Snort ``sid`` to the CVE ids its rule references (parsed once, then cached)."""
    global _RULE_CVES
    if _RULE_CVES is not None:
        return _RULE_CVES
    index: dict[int, list[str]] = {}
    root = Path(rules_dir)
    for path in root.rglob("*.rules") if root.exists() else []:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            if "reference:cve" not in line.lower():
                continue
            sid = _SID_RE.search(line)
            cves = _CVE_RE.findall(line)
            if sid and cves:
                index[int(sid.group(1))] = sorted({f"CVE-{c}" for c in cves})
    _RULE_CVES = index
    return index


def _severity(metrics: dict) -> tuple[str | None, float | None]:
    """Base severity and score from the best available CVSS metric (v3.1 -> v3.0 -> v4 -> v2)."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
            return severity, data.get("baseScore")
    return None, None


def _fetch_one(cve_id: str, api_key: str, timeout: float):
    """Query NVD for one CVE. Returns a details dict (found), ``""`` (NVD has no such record), or
    ``None`` (transient error — do not cache, retry later)."""
    headers = {"apiKey": api_key} if api_key else {}
    try:
        resp = requests.get(NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=timeout)
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    vulns = resp.json().get("vulnerabilities", [])
    if not vulns:
        return ""
    cve = vulns[0]["cve"]
    severity, score = _severity(cve.get("metrics", {}))
    description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    return {"id": cve["id"], "severity": severity, "score": score,
            "description": description[:300],
            "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"}


def cached(r: "bus.redis.Redis", cve_id: str):
    """Cached details for a CVE: a dict (found), ``{}`` (known not-found), or ``None`` (uncached)."""
    raw = r.get(CACHE + cve_id)
    if raw is None:
        return None
    raw = bus.text(raw)
    return json.loads(raw) if raw else {}


def lookup(r: "bus.redis.Redis", cve_ids, api_key: str = "", budget: float = 1.5) -> dict[str, dict]:
    """Details for each CVE id, from the Redis cache, fetching the uncached ones from NVD within
    ``budget`` seconds total. Ids left unfetched this call resolve on a later poll from the cache."""
    out: dict[str, dict] = {}
    missing = []
    for cve_id in dict.fromkeys(cve_ids):  # de-duplicate, keep order
        hit = cached(r, cve_id)
        if hit is None:
            missing.append(cve_id)
        elif hit:
            out[cve_id] = hit
    deadline = time.monotonic() + budget
    for cve_id in missing:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        info = _fetch_one(cve_id, api_key, timeout=max(0.4, remaining))
        if info is None:
            continue  # transient error: leave uncached so it is retried next poll
        r.setex(CACHE + cve_id, FOUND_TTL if info else MISS_TTL, json.dumps(info) if info else "")
        if info:
            out[cve_id] = info
    return out


def enrich_alerts(r: "bus.redis.Redis", alerts: list[dict], rules_dir, api_key: str = "",
                  budget: float = 1.5) -> list[dict]:
    """Attach a ``cves`` list to each alert: the CVE ids its rule references, with NVD details
    where known. An alert whose rule references no CVE gets an empty list."""
    index = rule_cves(rules_dir)
    wanted = [cid for a in alerts for cid in index.get(a.get("sid"), [])]
    details = lookup(r, wanted, api_key, budget) if wanted else {}
    for alert in alerts:
        alert["cves"] = [
            details.get(cid, {"id": cid, "severity": None, "score": None,
                              "url": f"https://nvd.nist.gov/vuln/detail/{cid}"})
            for cid in index.get(alert.get("sid"), [])
        ]
    return alerts
