"""Run the Python cicflowmeter, writing flows to a CSV.

    python -m nids.service.flowmeter (--interface IFACE | --file PCAP) OUTPUT.csv

Replaces the package's own CLI, which in cicflowmeter 0.5.0 passes its arguments to
``create_sniffer`` in the wrong positions and crashes ("'bool' object has no
attribute 'split'"). Also patches a crash in the package itself (see ``patch_cicflowmeter``).
"""

import argparse

from cicflowmeter.features.flow_bytes import FlowBytes
from cicflowmeter.features.packet_length import PacketLength
from cicflowmeter.sniffer import create_sniffer


def _min_or_zero(values) -> int:
    return min(values, default=0)


def patch_cicflowmeter() -> None:
    """cicflowmeter 0.5.0 calls min() on an empty list for a flow without forward packets
    (seen in real captures). The exception kills its flow-writing thread, so a live
    capture silently stops producing flows. Report 0 instead, as the package already does
    for the other empty min/max features."""
    from cicflowmeter.features.context import PacketDirection

    def min_forward_header_bytes(self) -> int:
        return _min_or_zero(self._header_size(packet) for packet, direction in self.flow.packets
                            if direction == PacketDirection.FORWARD)

    def min_header(self, packet_direction=None) -> int:
        return _min_or_zero(self.get_header_length(packet_direction))

    FlowBytes.get_min_forward_header_bytes = min_forward_header_bytes
    PacketLength.get_min_header = min_header


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--interface")
    source.add_argument("--file")
    parser.add_argument("output")
    args = parser.parse_args()

    patch_cicflowmeter()
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
