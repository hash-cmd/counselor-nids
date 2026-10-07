"""Download public IP blocklists for offline reputation checks.

Fetches a few well-known, freely-redistributable lists of known-bad IPs/CIDRs into
data/blocklists/. This downloads *public lists only* — it never uploads anything, so
no information about your own network leaves the machine. Reputation lookups then
happen locally (src/nids/services/reputation.py, GET /api/reputation/).

    python scripts/fetch_blocklists.py

Re-run to refresh. Lists are not committed to git (see .gitignore).
"""

import argparse
import urllib.request

from nids.datasets.paths import PROJECT_ROOT

# name -> URL. All are public and redistributable; pick conservative, low-false-positive lists.
LISTS = {
    "firehol_level1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "spamhaus_drop": "https://www.spamhaus.org/drop/drop.txt",
    "dshield_top": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield.netset",
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()

    out = PROJECT_ROOT / "data" / "blocklists"
    out.mkdir(parents=True, exist_ok=True)
    for name, url in LISTS.items():
        target = out / f"{name}.netset"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "nids-blocklist-fetch"})
            with urllib.request.urlopen(req, timeout=args.timeout) as response:  # noqa: S310 (fixed, trusted URLs)
                target.write_bytes(response.read())
            print(f"{name}: {target.stat().st_size:,} bytes")
        except Exception as error:  # a single list failing should not abort the rest
            print(f"{name}: skipped ({error})")
    print(f"\nblocklists in {out} — reputation is now active in the dashboard")


if __name__ == "__main__":
    main()
