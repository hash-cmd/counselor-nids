import threading
import time

import fakeredis

from nids.services import bus, journal
from nids.services.snort_bridge import ALERTS as SNORT_ALERTS


def test_journal_records_alerts_written_while_it_runs(tmp_path):
    r = fakeredis.FakeRedis()
    r.xadd(bus.ALERTS, {"detector": "old", "record_id": 1, "time": 1.0})  # before the journal: skipped
    r.hset(bus.LIVE, mapping={"target": "wlan0", "started_at": "100"})
    r.hset(bus.SUBSCRIPTIONS, mapping={"live_dos": "[]", "live_bot": "[]"})
    r.hset(bus.stats("live_dos"), "samples", 40)
    r.hset(bus.stats("live_bot"), "samples", 42)

    done = threading.Event()
    thread = threading.Thread(target=journal.run, args=(r, tmp_path),
                              kwargs={"tick": 0.05, "block_ms": 20, "stop": done.is_set}, daemon=True)
    thread.start()
    time.sleep(0.2)
    r.xadd(bus.ALERTS, {"detector": "live_dos", "record_id": 7, "src": "10.0.0.5:4444", "dst": "10.0.0.1:80"})
    r.xadd(SNORT_ALERTS, {"msg": "scan", "agreement": "confirmed"})
    time.sleep(0.2)
    done.set()
    thread.join(timeout=5)

    entries = journal.read(tmp_path)
    kinds = [e["kind"] for e in entries]
    assert kinds.count("ml") == 1 and kinds.count("snort") == 1
    ml = next(e for e in entries if e["kind"] == "ml")
    assert ml["detector"] == "live_dos" and ml["run"] == "100"
    assert all(e["flows"] == 42 for e in entries if e["kind"] == "tick")


def tick(t, flows, run="1"):
    return {"kind": "tick", "time": t, "run": run, "flows": flows}


def alert(t, record_id, detector="live_dos", run="1"):
    return {"kind": "ml", "time": t, "run": run, "record_id": str(record_id), "detector": detector,
            "src": "10.0.0.5:4444", "dst": "10.0.0.1:80"}


def test_report_counts_flows_across_runs_and_excludes_attack_tests():
    entries = [
        tick(0, 0), tick(60, 1000), tick(120, 2000),
        alert(30, 1), alert(31, 1, detector="live_bot"),  # one flow flagged by two detectors
        tick(200, 0, run="2"), tick(260, 500, run="2"),    # restarted: counters begin again
        alert(230, 1, run="2"),                            # same record id, different run
        tick(320, 4500, run="2"), alert(300, 9, run="2"),  # inside the attack test below
        {"kind": "snort", "time": 40, "msg": "scan", "agreement": "disputed"},
    ]
    out = journal.report(entries, exclude=[(290, 330)])
    assert out["flows_analysed"] == 2500
    assert out["hours_watched"] == round(180 / 3600, 2)
    assert out["ml"]["flagged_flows"] == 2
    assert out["ml"]["per_1000_flows"] == 0.8
    assert out["ml"]["by_detector"] == {"live_dos": 2, "live_bot": 1}
    assert out["excluded_test_alerts"] == {"ml": 1, "snort": 0}
    assert out["snort"]["by_agreement"] == {"disputed": 1}
