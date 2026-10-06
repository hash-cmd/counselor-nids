"""End-to-end test of the distributed services against an in-memory Redis."""

import threading

import fakeredis
import numpy as np
import pytest
from sklearn.dummy import DummyClassifier

from nids.service import bus, detector_service, extractor, monitor, observer

from tests.helpers import accurate, make_detector, split_brain


@pytest.fixture
def server():
    return fakeredis.FakeServer()


def client(server):
    return fakeredis.FakeRedis(server=server)


def start(target, *args, **kwargs):
    thread = threading.Thread(target=target, args=args, kwargs=kwargs, daemon=True)
    thread.start()
    return thread


def run_pipeline(server, blobs, detectors, cross_check=False, min_accuracy=0.8, batch_size=100):
    threads = [start(observer.run, client(server), exit_on_end=True, block_ms=100)]
    for d in detectors:
        threads.append(start(detector_service.run, client(server), d, ["blobs"],
                             min_accuracy=min_accuracy, cross_check=cross_check, exit_on_end=True))
    r = client(server)
    extractor.wait_for_subscribers(r, len(detectors), timeout=10)
    for start_row in range(0, len(blobs), batch_size):
        extractor.publish(r, blobs.iloc[start_row:start_row + batch_size], "blobs")
    extractor.end(r, "blobs")
    for t in threads:
        t.join(timeout=60)
        assert not t.is_alive(), "service did not finish"
    return r


def test_frame_round_trip(blobs):
    frame = blobs.head(5).assign(label="x")
    decoded = bus.decode_frame(bus.encode_frame(frame))
    assert decoded.columns.tolist() == frame.columns.tolist()
    assert np.allclose(decoded["f0"], frame["f0"])
    assert decoded["is_attack"].tolist() == frame["is_attack"].tolist()


def test_conflicts_resolved_by_remote_counselor(server, blobs):
    r = run_pipeline(server, blobs, [split_brain(blobs), accurate(blobs, name="counselor")])

    stats = monitor.snapshot(r)
    assert stats.loc["split_brain", "samples"] == 600
    assert stats.loc["split_brain", "conflicts"] == 600
    assert stats.loc["split_brain", "advised"] == 600
    assert stats.loc["split_brain", "fallback"] == 0
    assert float(stats.loc["split_brain", "accuracy"].rstrip("%")) > 90
    assert r.xlen(bus.ALERTS) > 0


def test_cross_check_over_redis(server, blobs):
    blind = make_detector(blobs, "blind", {"c": DummyClassifier(strategy="constant", constant=False)})
    alarm = make_detector(blobs, "alarm", {"c": DummyClassifier(strategy="constant", constant=True)})
    # constant classifiers are ~50% accurate, so accept any advice
    r = run_pipeline(server, blobs, [blind, alarm], cross_check=True, min_accuracy=0.0)

    stats = monitor.snapshot(r)
    assert stats.loc["blind", "cross_checked"] == 600
    assert stats.loc["blind", "flagged"] == 600


def test_observer_routes_only_subscribed_sources(server, blobs):
    r = client(server)
    r.hset(bus.SUBSCRIPTIONS, "a", '["blobs"]')
    r.hset(bus.SUBSCRIPTIONS, "b", '["other"]')
    extractor.publish(r, blobs.head(10), "blobs")
    extractor.end(r, "blobs")

    assert observer.run(r, exit_on_end=True, block_ms=100) == 2  # batch + end marker, to "a" only
    assert r.xlen(bus.inbox("a")) == 2
    assert r.xlen(bus.inbox("b")) == 0


def test_remote_counselor_times_out_gracefully(server):
    counselor = detector_service.RemoteCounselor(client(server), "nobody", timeout=0.2)
    found, _, _ = counselor.advise_many(np.array([1.0, 2.0]), window=0)
    assert not found.any()


def test_breakdowns_count_each_flagged_flow_once(server, blobs):
    frame = blobs.assign(label="DDoS", src_ip="10.0.0.66", src_port=1234, dst_ip="10.0.0.80", conn_dst_port=80)
    r = run_pipeline(server, frame, [accurate(frame, "d1"), accurate(frame, "d2")])

    breakdown = monitor.read_breakdown(r)
    flagged = breakdown["ml_flagged_flows"]
    assert flagged > 0
    assert breakdown["ml_labels"] == {"DDoS": flagged}  # not doubled by two detectors
    assert breakdown["sources"][0] == {"ip": "10.0.0.66", "ml": flagged, "snort": 0}
    alert = monitor.read_alerts(r, 1)[0]
    assert alert["src"] == "10.0.0.66:1234" and alert["dst"] == "10.0.0.80:80"
    assert alert["time"] is not None
    assert monitor.read_activity(r) == "ended"
