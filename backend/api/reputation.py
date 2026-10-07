"""Offline IP-reputation endpoint, backed by local blocklists in data/blocklists/.

Loads the lists once per process (reloading only if the directory changes), so lookups
are fast and nothing about the queried addresses ever leaves the machine.
"""

from django.conf import settings

from nids.services.reputation import Blocklist, load_blocklists

_cache: dict[str, object] = {}


def _blocklist() -> Blocklist:
    directory = settings.NIDS_ROOT / "data" / "blocklists"
    stamp = 0.0
    if directory.is_dir():
        stamp = max((p.stat().st_mtime for p in directory.glob("*")), default=0.0)
    key = f"{directory}:{stamp}"
    if _cache.get("key") != key:
        _cache["blocklist"] = load_blocklists(directory)
        _cache["key"] = key
    return _cache["blocklist"]  # type: ignore[return-value]


def check(ips: list[str]) -> dict:
    """{ip: {"listed": bool, "source": str|None}} for each requested address."""
    blocklist = _blocklist()
    out = {}
    for ip in ips:
        source = blocklist.check(ip)
        out[ip] = {"listed": source is not None, "source": source}
    return {"reputation": out, "lists_loaded": len(blocklist)}
