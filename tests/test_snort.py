import json

import fakeredis
import numpy as np
import pandas as pd
import pytest

from nids.service import bus, flowindex, monitor, snort


@pytest.fixture
def r():
    return fakeredis.FakeRedis()


def flows(*rows):
    return pd.DataFrame(rows, columns=["record_id", "flow_start", "flow_end", "src_ip", "src_port",
                                       "dst_ip", "dst_port", "protocol"])


def alert(**overrides):
    return {"seconds": 105, "proto": "TCP", "src_addr": "10.0.0.1", "src_port": 4000,
            "dst_addr": "10.0.0.2", "dst_port": 80, "gid": 1, "sid": 9000001, "msg": "test", **overrides}


class FakeDetectors:
    """Stand-in for detector services: answers advice requests from fixed verdicts."""

    def __init__(self, r, verdicts: dict[str, dict[int, tuple[bool, float]]]):
        self.verdicts = verdicts
        for name in verdicts:
            r.hset(bus.SUBSCRIPTIONS, name, '["live"]')
            r.set(snort.watermark_key(name), 10_000)

    def patch(self, monkeypatch):
        verdicts = self.verdicts

        class Counselor:
            def __init__(self, r, name, timeout=5.0):
                self.name = name

            def advise_many(self, timestamps, window):
                rows = [verdicts[self.name].get(int(t)) for t in timestamps]
                return (np.array([v is not None for v in rows]),
                        np.array([bool(v and v[0]) for v in rows]),
                        np.array([v[1] if v else 0.0 for v in rows]))

        monkeypatch.setattr(snort, "RemoteCounselor", Counselor)


def test_flow_found_in_either_direction_within_its_time_window(r):
    flowindex.index_flows(r, flows((7, 100.0, 110.0, "10.0.0.1", 4000, "10.0.0.2", 80, 6)))
    assert flowindex.find_flow(r, "TCP", "10.0.0.2", 80, "10.0.0.1", 4000, 105) == 7  # reply direction
    assert flowindex.find_flow(r, 6, "10.0.0.1", 4000, "10.0.0.2", 80, 99.5) == 7  # within slack
    assert flowindex.find_flow(r, "TCP", "10.0.0.1", 4000, "10.0.0.2", 80, 120) is None
    assert flowindex.find_flow(r, "UDP", "10.0.0.1", 4000, "10.0.0.2", 80, 105) is None


def test_reused_ports_pick_the_flow_open_at_alert_time(r):
    flowindex.index_flows(r, flows((1, 100.0, 101.0, "a", 1, "b", 2, 6), (2, 200.0, 201.0, "a", 1, "b", 2, 6)))
    assert flowindex.find_flow(r, "TCP", "a", 1, "b", 2, 200.5) == 2
    assert flowindex.find_flow(r, "TCP", "a", 1, "b", 2, 100.5) == 1


def test_host_flows_window(r):
    flowindex.index_flows(r, flows((1, 100.0, 101.0, "a", 1, "b", 22, 6), (2, 105.0, 106.0, "a", 2, "b", 23, 6),
                                   (3, 500.0, 501.0, "a", 3, "b", 24, 6)))
    assert sorted(flowindex.find_host_flows(r, "TCP", "b", "a", 103, window=30)) == [1, 2]


def test_alert_confirmed_when_any_detector_says_attack(r, monkeypatch):
    flowindex.index_flows(r, flows((7, 100.0, 110.0, "10.0.0.1", 4000, "10.0.0.2", 80, 6)))
    # a specialist that never saw this attack says normal; the other says attack
    FakeDetectors(r, {"d1": {7: (False, 1.0)}, "d2": {7: (True, 0.95)}}).patch(monkeypatch)
    correlator = snort.Correlator(r)
    correlator.add(alert())
    assert correlator.process() == 1

    published = monitor.read_snort_alerts(r)[0]
    assert published["agreement"] == "confirmed"
    assert published["ml_detector"] == "d2"
    assert published["record_id"] == 7
    assert r.sismember(snort.FLAGGED_SNORT, 7)


def test_alert_disputed_and_low_accuracy_advice_ignored(r, monkeypatch):
    flowindex.index_flows(r, flows((7, 100.0, 110.0, "10.0.0.1", 4000, "10.0.0.2", 80, 6)))
    FakeDetectors(r, {"d1": {7: (False, 0.99)}, "d2": {7: (True, 0.5)}}).patch(monkeypatch)
    correlator = snort.Correlator(r, min_accuracy=0.9)
    correlator.add(alert())
    correlator.process()
    assert monitor.read_snort_alerts(r)[0]["agreement"] == "disputed"


def test_alert_waits_for_its_flow_then_unmatched_when_final(r, monkeypatch):
    FakeDetectors(r, {"d1": {}}).patch(monkeypatch)
    correlator = snort.Correlator(r)
    correlator.add(alert())
    assert correlator.process() == 0 and len(correlator.pending) == 1  # flow not captured yet
    correlator.process(final=True)
    assert monitor.read_snort_alerts(r)[0]["agreement"] == "unmatched"


def test_alert_waits_until_detectors_have_analysed_the_flow(r, monkeypatch):
    flowindex.index_flows(r, flows((7, 100.0, 110.0, "10.0.0.1", 4000, "10.0.0.2", 80, 6)))
    FakeDetectors(r, {"d1": {7: (True, 1.0)}}).patch(monkeypatch)
    r.set(snort.watermark_key("d1"), 5)  # detector still behind
    correlator = snort.Correlator(r)
    correlator.add(alert())
    assert correlator.process() == 0
    r.set(snort.watermark_key("d1"), 7)
    assert correlator.process() == 1


def test_port_scan_alert_covers_all_flows_between_the_hosts(r, monkeypatch):
    rows = [(i, 100.0 + i, 100.5 + i, "10.0.0.66", 50000 + i, "10.0.0.80", i, 6) for i in range(10)]
    flowindex.index_flows(r, flows(*rows))
    FakeDetectors(r, {"d1": {i: (i < 8, 1.0) for i in range(10)}}).patch(monkeypatch)
    r.hset(bus.SUBSCRIPTIONS, "d1", '["live"]')
    r.sadd(bus.ENDED, "d1")  # stream over: the whole window is captured
    correlator = snort.Correlator(r)
    correlator.add(alert(gid=122, sid=1, src_addr="10.0.0.66", dst_addr="10.0.0.80",
                         src_port=None, dst_port=None, seconds=104))
    correlator.process()

    published = monitor.read_snort_alerts(r)[0]
    assert published["flows"] == 10
    assert published["agreement"] == "confirmed"  # ML flags 8 of the 10
    assert published["ml_share"] == pytest.approx(0.8)


def test_snort_vs_ml_flow_counts(r):
    r.hset(snort.STATS, "alerts", 3)
    r.sadd(snort.FLAGGED_SNORT, 1, 2, 3)
    r.sadd(snort.FLAGGED_ML, 2, 3, 4, 5)
    assert monitor.read_snort(r)["flows"] == {"both": 2, "snort_only": 1, "ml_only": 2}
    assert monitor.read_snort(fakeredis.FakeRedis()) is None


def test_follow_alerts_reads_appended_lines_and_heartbeats(tmp_path):
    path = tmp_path / "alert_json.txt"
    path.write_text(json.dumps(alert()) + "\n" + json.dumps(alert(sid=2)) + "\n")
    items = list(snort.follow_alerts(path, done=lambda: True, poll=0))
    assert [a["sid"] for a in items if a] == [9000001, 2]


def test_snort_command():
    assert snort.snort_command("x.pcap", "/tmp/l")[-5:] == ["-r", "x.pcap", "-l", "/tmp/l", "-q"]
    assert "-i" in snort.snort_command("eth0", "/tmp/l")
