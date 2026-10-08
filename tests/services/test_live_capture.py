import pandas as pd

from nids.services.live_capture import carries_payload


def test_carries_payload_keeps_flows_with_data():
    flows = pd.DataFrame({
        "Total Length of Fwd Packets": [0, 120, 0, 44],
        "Total Length of Bwd Packets": [0, 0, 300, 0],
    })
    # row 0: empty (scan/failed connection); 1: fwd data; 2: bwd data; 3: fwd data
    assert carries_payload(flows).tolist() == [False, True, True, True]


def test_carries_payload_handles_missing_and_nonnumeric_columns():
    # a bare SYN flood: no backward column, no forward payload -> dropped
    flows = pd.DataFrame({"Total Length of Fwd Packets": ["0", "0", "80"]})
    assert carries_payload(flows).tolist() == [False, False, True]


# --- live capture survives the interface dropping ---------------------------------

import fakeredis
import pytest

from nids.services import bus, live_capture


class _FakeProcess:
    def __init__(self, *args, **kwargs):
        pass

    def poll(self):
        return 0

    def terminate(self):
        pass


@pytest.fixture
def capture_env(monkeypatch):
    pytest.importorskip("cicflowmeter")
    r = fakeredis.FakeRedis()
    monkeypatch.setattr(live_capture.subprocess, "Popen", _FakeProcess)
    return r


def test_capture_resumes_after_interface_drop(capture_env, monkeypatch):
    r = capture_env
    runs, states = [], []

    def fake_stream(r_, out, process, source, batch_size, drop, next_id, heartbeat=None):
        runs.append(next_id)
        if len(runs) == 3:
            raise KeyboardInterrupt  # stand-in for Ctrl+C on the third run
        return 5, next_id + 5

    # after run 1: the link is down twice, then back; after run 2: back at once
    link = iter([False, False, True, False, True])

    def fake_up(name):
        states.append(r.hget(bus.LIVE, "state").decode())
        return next(link)

    monkeypatch.setattr(live_capture, "_stream", fake_stream)
    monkeypatch.setattr(live_capture, "interface_up", fake_up)

    with pytest.raises(KeyboardInterrupt):
        live_capture.capture(r, "wlan0", "live", retry_wait=0)

    assert runs == [0, 5, 10]                       # restarted twice, record ids continue
    assert "waiting" in states                      # dashboard saw the outage
    assert not r.exists(bus.LIVE)                   # cleared on exit
    ends = [m for _, m in r.xrange(bus.UNKNOWN) if m[b"kind"] == bus.END.encode()]
    assert len(ends) == 1                           # end-of-stream sent once, at the real stop


def test_capture_gives_up_when_it_keeps_failing(capture_env, monkeypatch):
    monkeypatch.setattr(live_capture, "_stream", lambda *a, **k: (0, a[6]))
    monkeypatch.setattr(live_capture, "interface_up", lambda name: True)  # link up, yet it dies
    with pytest.raises(RuntimeError, match="keeps stopping"):
        live_capture.capture(capture_env, "wlan0", "live", retry_wait=0)
    assert not capture_env.exists(bus.LIVE)


def test_recording_is_read_once_and_never_marked_live(capture_env, monkeypatch):
    calls = []
    monkeypatch.setattr(live_capture, "_stream", lambda *a, **k: calls.append(1) or (3, a[6] + 3))
    assert live_capture.capture(capture_env, "demo.pcap", "replay", retry_wait=0) == 3
    assert calls == [1] and not capture_env.exists(bus.LIVE)
