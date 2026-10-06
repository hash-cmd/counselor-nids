"""Run the Python cicflowmeter, writing flows to a CSV.

    python -m nids.service.flowmeter (--interface IFACE | --file PCAP) OUTPUT.csv

Replaces the package's own CLI, which in cicflowmeter 0.5.0 passes its arguments to
``create_sniffer`` in the wrong positions and crashes ("'bool' object has no
attribute 'split'").
"""

import argparse

from cicflowmeter.sniffer import create_sniffer


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--interface")
    source.add_argument("--file")
    parser.add_argument("output")
    args = parser.parse_args()

    sniffer, session = create_sniffer(
        input_file=args.file, input_interface=args.interface,
        output_mode="csv", output=args.output)
    sniffer.start()
    try:
        sniffer.join()
    except KeyboardInterrupt:
        sniffer.stop()
    finally:
        if hasattr(session, "_gc_stop"):
            session._gc_stop.set()
            session._gc_thread.join(timeout=2.0)
        sniffer.join()
        session.flush_flows()  # flows still open when capture ends


if __name__ == "__main__":
    main()
