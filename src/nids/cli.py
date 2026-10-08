"""``nids`` command line: run the distributed services.

    nids observe                             # Observer
    nids detect models/live/live_dos.joblib --sources live --cross-check --suppress-fallback
    nids extract --live wlan0 --source live --wait-for 3     # or --live capture.pcap
    nids monitor
    nids snort --pcap capture.pcap           # Snort + link its alerts to flows and ML verdicts
    nids health                              # which services are alive (exit 1 if any is down)
    nids journal                             # keep every live alert in logs/journal/
    nids journal-report --exclude 2026-10-08T14:00 2026-10-08T15:00   # false alarms

All services talk to Redis at $NIDS_REDIS_URL (default redis://localhost:6379/0).
"""

import argparse
import signal
import sys
from pathlib import Path

import joblib

from .datasets.paths import PROJECT_ROOT


def extract(args) -> None:
    from .services import bus, extractor

    r = bus.connect(args.redis)
    if args.wait_for:
        extractor.wait_for_subscribers(r, args.wait_for)
    from .services import live_capture
    if not args.live.endswith((".pcap", ".pcapng")):
        # start.sh stops services with SIGTERM; exit through the normal path so the
        # flow meter is stopped and the dashboard stops showing live monitoring.
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    sent = live_capture.capture(r, args.live, args.source, args.batch_size,
                                drop_empty_flows=not args.keep_empty_flows)
    print(f"published {sent:,} flows from {args.live}")


def observe(args) -> None:
    from .services import bus, observer

    print("observer forwarded", observer.run(bus.connect(args.redis), exit_on_end=args.exit_on_end))


def detect(args) -> None:
    from .services import bus, detector as detector_service

    detector = joblib.load(args.model)
    print(f"{detector.name}: subscribed to {args.sources}", flush=True)
    detector_service.run(
        bus.connect(args.redis), detector, args.sources, args.min_accuracy, args.window,
        args.cross_check, args.retrain_every, args.advice_wait, args.exit_on_end,
        suppress_fallback=args.suppress_fallback, snort_counselor=args.snort_counselor, model_path=args.model)


def monitor(args) -> None:
    from .services import bus
    from .services import monitor as mon

    mon.run(bus.connect(args.redis), args.interval, args.once)


def snort(args) -> None:
    from .services import bus
    from .services import snort_bridge as bridge

    # live: Snort rule trust persists across restarts (a recording's verdicts must not change it)
    trust_file = args.trust_file if args.interface else None
    stats = bridge.run(bus.connect(args.redis), target=args.pcap or args.interface, follow=args.follow,
                       min_accuracy=args.min_accuracy, wait=args.wait,
                       config=args.config, include_path=args.include_path, trust_file=trust_file)
    print("snort:", stats)


def health(args) -> None:
    from .services import bus, monitor

    try:
        services = monitor.read_health(bus.connect(args.redis))
    except Exception as e:  # Redis itself is down
        print(f"redis: DOWN ({e})")
        sys.exit(2)
    if not services:
        print("no services have reported (nothing running?)")
        sys.exit(1)
    for s in services:
        extra = " ".join(f"{k}={v}" for k, v in s.items() if k not in ("service", "ok", "age"))
        print(f"{s['service']:24s} {'ok  ' if s['ok'] else 'DOWN'}  last seen {s['age']:>6.1f}s ago  {extra}")
    sys.exit(0 if all(s["ok"] for s in services) else 1)


def journal(args) -> None:
    from .services import bus
    from .services import journal as j

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    print(f"journal: writing to {args.dir}", flush=True)
    j.run(bus.connect(args.redis), args.dir, keep_days=args.keep_days)


def journal_report(args) -> None:
    import json
    from datetime import datetime

    from .services import journal as j

    windows = [(datetime.fromisoformat(a).timestamp(), datetime.fromisoformat(b).timestamp())
               for a, b in args.exclude or []] + j.windows(j.read_tests(args.dir))
    print(json.dumps(j.report(j.read(args.dir, args.days), windows), indent=2))


def reset(args) -> None:
    from .services import bus

    print("deleted", bus.reset(bus.connect(args.redis)), "keys")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(prog="nids", description=__doc__.splitlines()[0])
    parser.add_argument("--redis", help="Redis URL (default $NIDS_REDIS_URL)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("extract", help="capture traffic and publish its flows to the detectors")
    p.add_argument("--live", metavar="INTERFACE_OR_PCAP", required=True,
                   help="network interface to capture (needs root or CAP_NET_RAW), or a .pcap to read")
    p.add_argument("--source", required=True, help="data source name detectors subscribe to")
    p.add_argument("--batch-size", type=int, default=500)
    p.add_argument("--wait-for", type=int, default=0, help="wait until N detectors subscribed")
    p.add_argument("--keep-empty-flows", action="store_true",
                   help="live: also send connection-only flows (scans) to the ML (noisier)")
    p.set_defaults(func=extract)

    p = sub.add_parser("observe", help="run the Observer")
    p.add_argument("--exit-on-end", action="store_true")
    p.set_defaults(func=observe)

    p = sub.add_parser("detect", help="run one detector service")
    p.add_argument("model", type=Path)
    p.add_argument("--sources", nargs="+", required=True)
    p.add_argument("--min-accuracy", type=float, default=0.9)
    p.add_argument("--window", type=float, default=0.0, help="advice look-back (0 = exact record match)")
    p.add_argument("--cross-check", action="store_true", help="cross-check normal verdicts")
    p.add_argument("--suppress-fallback", action="store_true",
                   help="treat unresolved-conflict guesses as normal (fewer false alarms on live traffic)")
    p.add_argument("--snort-counselor", action="store_true",
                   help="take Snort's advice on conflicts (trusted attack advice wins); needs `nids snort`")
    p.add_argument("--retrain-every", type=int, default=0, help="retrain after N learned signatures")
    p.add_argument("--advice-wait", type=float, default=2.0)
    p.add_argument("--exit-on-end", action="store_true")
    p.set_defaults(func=detect)

    p = sub.add_parser("monitor", help="print detector counters")
    p.add_argument("--interval", type=float, default=2.0)
    p.add_argument("--once", action="store_true")
    p.set_defaults(func=monitor)

    p = sub.add_parser("snort", help="run Snort next to the detectors and link its alerts to flows")
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("--pcap", help="run Snort on this capture (same file as `extract --live`)")
    target.add_argument("--interface", help="run Snort live on this interface (needs root)")
    target.add_argument("--follow", type=Path, help="follow an existing Snort alert_json file instead")
    p.add_argument("--min-accuracy", type=float, default=0.9, help="accept ML verdicts at least this accurate")
    p.add_argument("--wait", type=float, default=120.0, help="seconds an alert may wait for its flow")
    p.add_argument("--config", type=Path, default=PROJECT_ROOT / "snort" / "nids.lua")
    p.add_argument("--include-path", default="/etc/snort", help="where snort_defaults.lua lives")
    p.add_argument("--trust-file", type=Path, default=PROJECT_ROOT / "logs" / "snort-trust.json",
                   help="live: where Snort rule trust is kept between runs")
    p.set_defaults(func=snort)

    p = sub.add_parser("health", help="which services are alive; exit 1 if any is down, 2 if Redis is")
    p.set_defaults(func=health)

    p = sub.add_parser("journal", help="keep every live alert on disk, to measure false alarms")
    p.add_argument("--dir", type=Path, default=PROJECT_ROOT / "logs" / "journal")
    p.add_argument("--keep-days", type=int, default=365, help="delete day files older than this")
    p.set_defaults(func=journal)

    p = sub.add_parser("journal-report", help="false alarms recorded by the journal")
    p.add_argument("--dir", type=Path, default=PROJECT_ROOT / "logs" / "journal")
    p.add_argument("--exclude", nargs=2, action="append", metavar=("START", "END"),
                   help="leave out a time you ran attacks on purpose (local ISO times); repeatable. "
                        "Tests marked on the dashboard are left out too")
    p.add_argument("--days", type=int, help="only the last N days (default: everything)")
    p.set_defaults(func=journal_report)

    p = sub.add_parser("reset", help="delete all nids:* keys in Redis")
    p.set_defaults(func=reset)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
