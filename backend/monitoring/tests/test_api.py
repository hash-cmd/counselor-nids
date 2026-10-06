import json
import tempfile
from pathlib import Path
from unittest import mock

import fakeredis
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from monitoring import redis_client, replay
from nids.service import bus


class FakeRedisMixin:
    """Point every get_redis() at a fresh in-memory Redis."""

    def setUp(self):
        super().setUp()
        self.redis = fakeredis.FakeRedis()
        redis_client.get_redis.cache_clear()
        patcher = mock.patch("monitoring.redis_client.redis.Redis.from_url", return_value=self.redis)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(redis_client.get_redis.cache_clear)

    def add_detector(self, name, **counters):
        self.redis.hset(bus.SUBSCRIPTIONS, name, '["replay"]')
        for key, value in counters.items():
            self.redis.hincrby(bus.stats(name), key, value)


class AuthTests(FakeRedisMixin, TestCase):
    def setUp(self):
        super().setUp()
        get_user_model().objects.create_user("analyst", password="s3cret-pass")
        self.client = APIClient()

    def test_endpoints_require_login(self):
        for url in ["/api/detectors/", "/api/alerts/", "/api/results/", "/api/replay/", "/api/auth/me/"]:
            self.assertEqual(self.client.get(url).status_code, 401, url)

    def test_login_returns_tokens_that_work(self):
        tokens = self.client.post("/api/auth/token/", {"username": "analyst", "password": "s3cret-pass"}).json()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        self.assertEqual(self.client.get("/api/auth/me/").json(), {"username": "analyst"})

        refreshed = self.client.post("/api/auth/token/refresh/", {"refresh": tokens["refresh"]})
        self.assertIn("access", refreshed.json())

    def test_wrong_password_rejected(self):
        response = self.client.post("/api/auth/token/", {"username": "analyst", "password": "nope"})
        self.assertEqual(response.status_code, 401)


class LoggedInTestCase(FakeRedisMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.user = get_user_model().objects.create_user("analyst", password="s3cret-pass")
        self.client = APIClient()
        self.client.force_authenticate(self.user)


class DetectorsAndAlertsTests(LoggedInTestCase):
    def test_detector_stats(self):
        self.add_detector("detector1", samples=200, flagged_attack=80, correct=190,
                          true_attacks=100, detected_attacks=80, **{"resolution:advice": 5})
        body = self.client.get("/api/detectors/").json()

        stats = body["detectors"]["detector1"]
        self.assertEqual(stats["samples"], 200)
        self.assertEqual(stats["advised"], 5)
        self.assertAlmostEqual(stats["accuracy"], 0.95)
        self.assertAlmostEqual(stats["detection_rate"], 0.8)
        self.assertEqual(body["replay"], {"state": "idle"})

    def test_alerts_newest_first_and_after(self):
        ids = [self.redis.xadd(bus.ALERTS, {"detector": "d1", "record_id": i, "timestamp": float(i),
                                            "resolution": "unanimous", "counselor": "", "label": "DDoS"})
               for i in range(5)]
        alerts = self.client.get("/api/alerts/?limit=3").json()["alerts"]
        self.assertEqual([a["record_id"] for a in alerts], [4, 3, 2])
        self.assertIsNone(alerts[0]["counselor"])

        newer = self.client.get(f"/api/alerts/?after={ids[2].decode()}").json()["alerts"]
        self.assertEqual([a["record_id"] for a in newer], [4, 3])


class ResultsTests(LoggedInTestCase):
    def test_reads_comparisons_and_self_learning(self):
        with tempfile.TemporaryDirectory() as root:
            scenario = Path(root) / "results" / "scenario2"
            scenario.mkdir(parents=True)
            (scenario / "detector1_comparison.csv").write_text(
                ",accuracy,detection_rate,false_alarm_rate\n"
                "proposed,0.83,0.62,0.0002\nproposed_cross_check,0.9988,0.9976,0.0002\nsingle:x,0.5,0.5,0.5\n")
            (scenario / "summary.json").write_text(json.dumps({"args": {"seeds": [0, 1, 2]}}))
            learning = Path(root) / "results" / "self_learning"
            learning.mkdir()
            (learning / "chunks.csv").write_text(
                "chunk,detector,retrain,labels,standalone_accuracy,final_accuracy,learned\n"
                "0,detector1,True,BENIGN,0.99,0.99,3\n")

            with override_settings(NIDS_ROOT=Path(root)):
                body = self.client.get("/api/results/").json()

        rows = body["comparisons"]["scenario2"]["detectors"]["detector1"]
        self.assertEqual([r["approach"] for r in rows], ["proposed_cross_check", "proposed"])
        self.assertEqual(body["comparisons"]["scenario2"]["args"], {"seeds": [0, 1, 2]})
        self.assertEqual(body["self_learning"]["cross_check"][0]["learned"], 3)


class ReplayTests(LoggedInTestCase):
    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp())
        (self.root / "data" / "replay").mkdir(parents=True)
        (self.root / "data" / "replay" / "demo.csv").write_text("record_id\n1\n")
        (self.root / "models").mkdir()
        settings_override = override_settings(NIDS_ROOT=self.root)
        settings_override.enable()
        self.addCleanup(settings_override.disable)
        self.addCleanup(setattr, replay.manager, "_run", None)

    def test_lists_replays_and_models(self):
        (self.root / "models" / "detector1.joblib").write_bytes(b"")
        body = self.client.get("/api/replay/").json()
        self.assertEqual(body["replays"], [{"name": "demo.csv", "size_mb": 0.0}])
        self.assertEqual(body["models"], ["detector1"])
        self.assertEqual(body["status"], {"state": "idle"})

    def test_rejects_unknown_replay(self):
        response = self.client.post("/api/replay/start/", {"replay": "../../etc/passwd"}, format="json")
        self.assertEqual(response.status_code, 409)

    def test_rejects_without_models(self):
        response = self.client.post("/api/replay/start/", {"replay": "demo.csv"}, format="json")
        self.assertEqual(response.status_code, 409)
        self.assertIn("no trained models", response.json()["detail"])

    def test_validates_rate(self):
        response = self.client.post("/api/replay/start/", {"replay": "demo.csv", "rate": 0}, format="json")
        self.assertEqual(response.status_code, 400)

    def test_stop_without_replay(self):
        self.assertEqual(self.client.post("/api/replay/stop/").status_code, 409)

    def test_start_launches_services_and_stop_terminates_them(self):
        (self.root / "models" / "detector1.joblib").write_bytes(b"")
        started = []

        class FakeProcess:
            def __init__(self, command, **kwargs):
                self.command, self.returncode = command, None
                started.append(self)

            def poll(self):
                return self.returncode

            def terminate(self):
                self.returncode = -15

            def wait(self, timeout=None):
                return self.returncode

        with mock.patch("monitoring.replay.Popen", FakeProcess):
            response = self.client.post("/api/replay/start/",
                                        {"replay": "demo.csv", "rate": 500, "cross_check": True},
                                        format="json")
            self.assertEqual(response.status_code, 201, response.json())
            self.assertEqual(response.json()["state"], "running")
            self.assertEqual(self.client.post("/api/replay/start/", {"replay": "demo.csv"},
                                              format="json").status_code, 409)

            commands = {" ".join(p.command[3:5]) for p in started}
            self.assertEqual(commands, {"observe --exit-on-end", "detect " + str(self.root / "models" / "detector1.joblib"),
                                        "extract " + str(self.root / "data" / "replay" / "demo.csv")})
            detector = next(p for p in started if p.command[3] == "detect")
            self.assertIn("--cross-check", detector.command)
            self.assertIsNotNone(self.redis.get(replay.RUN_KEY))

            stopped = self.client.post("/api/replay/stop/").json()
            self.assertEqual(stopped["state"], "stopped")
            self.assertTrue(all(p.returncode == -15 for p in started))
