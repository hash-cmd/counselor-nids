"""``nids`` command line: train detectors and run the distributed services.

    nids train scenario2 --fraction 0.05     # models/*.joblib + data/replay/scenario2.csv
    nids observe                             # Observer
    nids detect models/detector1.joblib --sources cicids2017 --cross-check
    nids extract data/replay/scenario2.csv --source cicids2017 --wait-for 2
    nids monitor

All services talk to Redis at $NIDS_REDIS_URL (default redis://localhost:6379/0).
"""

import argparse
from pathlib import Path

import joblib

from .data.paths import PROJECT_ROOT


def train(args) -> None:
    from . import scenarios

    if args.scenario == "scenario1":
        setup = scenarios.scenario1(args.protocol, seed=args.seed)
    else:
        setup = scenarios.scenario2(args.fraction, seed=args.seed)
    args.models.mkdir(parents=True, exist_ok=True)
    for detector in setup.detectors:
        joblib.dump(detector, args.models / f"{detector.name}.joblib", compress=3)
        print("saved", args.models / f"{detector.name}.joblib")
    replay = args.replay or PROJECT_ROOT / "data" / "replay" / f"{args.scenario}.csv"
    replay.parent.mkdir(parents=True, exist_ok=True)
    setup.test.to_csv(replay, index=False)
    print(f"saved {len(setup.test):,} unseen test flows to {replay}")


def extract(args) -> None:
    from .service import bus, extractor

    r = bus.connect(args.redis)
    if args.wait_for:
        extractor.wait_for_subscribers(r, args.wait_for)
    if args.live:
        from .service import live
        sent = live.capture(r, args.live, args.source, args.batch_size)
    else:
        sent = extractor.replay(r, args.csv, args.source, args.batch_size, args.rate,
                                args.timestamp_column, args.max_rows)
    print(f"published {sent:,} flows from {args.live or args.csv}")


def observe(args) -> None:
    from .service import bus, observer

    print("observer forwarded", observer.run(bus.connect(args.redis), exit_on_end=args.exit_on_end))


def detect(args) -> None:
    from .service import bus, detector_service

    detector = joblib.load(args.model)
    print(f"{detector.name}: subscribed to {args.sources}", flush=True)
    detector_service.run(
        bus.connect(args.redis), detector, args.sources, args.min_accuracy, args.window,
        args.cross_check, args.retrain_every, args.advice_wait, args.exit_on_end)


def monitor(args) -> None:
    from .service import bus
    from .service import monitor as mon

    mon.run(bus.connect(args.redis), args.interval, args.once)


def reset(args) -> None:
    from .service import bus

    print("deleted", bus.reset(bus.connect(args.redis)), "keys")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(prog="nids", description=__doc__.splitlines()[0])
    parser.add_argument("--redis", help="Redis URL (default $NIDS_REDIS_URL)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("train", help="train detectors and write a replay file of unseen flows")
    p.add_argument("scenario", choices=["scenario1", "scenario2"])
    p.add_argument("--protocol", default="holdout", help="scenario 1 only")
    p.add_argument("--fraction", type=float, default=0.05, help="scenario 2 only")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--models", type=Path, default=PROJECT_ROOT / "models")
    p.add_argument("--replay", type=Path)
    p.set_defaults(func=train)

    p = sub.add_parser("extract", help="publish flows to the Unknown Samples Repository")
    p.add_argument("csv", nargs="?", help="flow CSV to replay")
    p.add_argument("--live", metavar="INTERFACE", help="capture live traffic instead (needs cicflowmeter)")
    p.add_argument("--source", required=True, help="data source name detectors subscribe to")
    p.add_argument("--batch-size", type=int, default=500)
    p.add_argument("--rate", type=float, help="max flows per second")
    p.add_argument("--timestamp-column", default="record_id")
    p.add_argument("--max-rows", type=int)
    p.add_argument("--wait-for", type=int, default=0, help="wait until N detectors subscribed")
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
    p.add_argument("--retrain-every", type=int, default=0, help="retrain after N learned signatures")
    p.add_argument("--advice-wait", type=float, default=2.0)
    p.add_argument("--exit-on-end", action="store_true")
    p.set_defaults(func=detect)

    p = sub.add_parser("monitor", help="print detector counters")
    p.add_argument("--interval", type=float, default=2.0)
    p.add_argument("--once", action="store_true")
    p.set_defaults(func=monitor)

    p = sub.add_parser("reset", help="delete all nids:* keys in Redis")
    p.set_defaults(func=reset)

    args = parser.parse_args(argv)
    if args.command == "extract" and not (args.csv or args.live):
        parser.error("extract needs a CSV path or --live INTERFACE")
    args.func(args)


if __name__ == "__main__":
    main()
