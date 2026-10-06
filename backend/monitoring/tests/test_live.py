from channels.testing import WebsocketCommunicator
from django.contrib.auth import get_user_model
from django.test import TransactionTestCase
from rest_framework_simplejwt.tokens import AccessToken

from config.asgi import application
from monitoring import consumers, replay
from nids.service import bus

from .test_api import FakeRedisMixin


class LiveFeedTests(FakeRedisMixin, TransactionTestCase):
    def setUp(self):
        super().setUp()
        self.user = get_user_model().objects.create_user("analyst", password="s3cret-pass")
        consumers.INTERVAL = 0.05
        self.addCleanup(setattr, consumers, "INTERVAL", 1.0)

    def communicator(self, token):
        query = f"?token={token}" if token else ""
        return WebsocketCommunicator(application, f"/ws/live/{query}",
                                     headers=[(b"origin", b"http://localhost")])

    async def test_accepts_access_cookie(self):
        cookie = f"nids_access={AccessToken.for_user(self.user)}".encode()
        ws = WebsocketCommunicator(application, "/ws/live/",
                                   headers=[(b"origin", b"http://localhost"), (b"cookie", cookie)])
        connected, _ = await ws.connect()
        self.assertTrue(connected)
        await ws.disconnect()

    async def test_rejects_missing_or_bad_token(self):
        for token in (None, "not-a-jwt"):
            connected, code = await self.communicator(token).connect()
            self.assertFalse(connected)

    async def test_streams_stats_and_new_alerts(self):
        self.add_detector("detector1", samples=10, flagged_attack=2)
        self.redis.xadd(bus.ALERTS, {"detector": "detector1", "record_id": 7, "timestamp": 7.0,
                                     "resolution": "cross_check", "counselor": "detector2"})
        ws = self.communicator(str(AccessToken.for_user(self.user)))
        connected, _ = await ws.connect()
        self.assertTrue(connected)

        stats = await ws.receive_json_from(timeout=2)
        self.assertEqual(stats["type"], "stats")
        self.assertEqual(stats["detectors"]["detector1"]["samples"], 10)
        first = await ws.receive_json_from(timeout=2)
        self.assertEqual(first["type"], "alerts")
        self.assertEqual(first["alerts"][0]["counselor"], "detector2")

        # only alerts newer than the last one sent are pushed
        self.redis.xadd(bus.ALERTS, {"detector": "detector1", "record_id": 8, "timestamp": 8.0,
                                     "resolution": "unanimous", "counselor": ""})
        while (message := await ws.receive_json_from(timeout=2))["type"] != "alerts":
            pass
        self.assertEqual([a["record_id"] for a in message["alerts"]], [8])
        await ws.disconnect()

    async def test_streams_snort_summary_and_alerts(self):
        from nids.service import snort

        self.redis.hset(snort.STATS, "alerts", 1)
        self.redis.xadd(snort.ALERTS, {
            "seconds": 100, "msg": "NIDS possible SYN flood", "gid": 1, "sid": 9000010, "priority": 2,
            "class": "attempted-dos", "proto": "TCP", "src": "172.16.0.1:1234", "dst": "10.0.0.80:80",
            "flows": 1, "record_id": 5, "agreement": "confirmed", "ml_verdict": "attack",
            "ml_share": 1.0, "ml_confidence": 0.99, "ml_detector": "detector1"})
        ws = self.communicator(str(AccessToken.for_user(self.user)))
        await ws.connect()
        stats = await ws.receive_json_from(timeout=2)
        self.assertEqual(stats["snort"]["alerts"], 1)
        snort_alerts = await ws.receive_json_from(timeout=2)
        self.assertEqual(snort_alerts["type"], "snort_alerts")
        self.assertEqual(snort_alerts["alerts"][0]["agreement"], "confirmed")
        await ws.disconnect()

    async def test_new_replay_sends_reset(self):
        ws = self.communicator(str(AccessToken.for_user(self.user)))
        await ws.connect()
        await ws.receive_json_from(timeout=2)
        self.redis.set(replay.RUN_KEY, "123")
        types = set()
        for _ in range(5):
            types.add((await ws.receive_json_from(timeout=2))["type"])
        self.assertIn("reset", types)
        await ws.disconnect()
