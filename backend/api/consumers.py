"""Live feed for the dashboard over a WebSocket.

Every ``INTERVAL`` seconds the client receives:
    {"type": "stats",  "detectors": {...}, "snort": {...} | null, "breakdown": {...},
     "activity": "idle" | "running" | "ended", "replay": {...}, "time": <unix s>}
    {"type": "alerts", "alerts": [...newest first, at most MAX_ALERTS...]}   (only when new)
    {"type": "snort_alerts", "alerts": [...]}                               (only when new)
When a new replay starts it first receives {"type": "reset"}.
"""

import asyncio
import time

from channels.generic.websocket import AsyncJsonWebsocketConsumer

from nids.services import bus, monitor

from . import replay
from .redis_client import get_redis

INTERVAL = 1.0
MAX_ALERTS = 200


class LiveConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        if not self.scope["user"].is_authenticated:
            await self.close(code=4401)
            return
        await self.accept()
        self.task = asyncio.create_task(self.stream())

    async def disconnect(self, code):
        if task := getattr(self, "task", None):
            task.cancel()

    async def stream(self):
        r = get_redis()
        unread = object()  # the run id may legitimately be None (no replay yet)
        run_id, last_alert, last_snort = unread, None, None
        while True:
            current_run = await asyncio.to_thread(r.get, replay.RUN_KEY)
            if current_run != run_id:
                if run_id is not unread:
                    await self.send_json({"type": "reset"})
                run_id, last_alert, last_snort = current_run, None, None

            stats = await asyncio.to_thread(monitor.read_stats, r)
            snort = await asyncio.to_thread(monitor.read_snort, r)
            breakdown = await asyncio.to_thread(monitor.read_breakdown, r)
            activity = await asyncio.to_thread(monitor.read_activity, r)
            live = await asyncio.to_thread(monitor.read_live, r)
            await self.send_json({"type": "stats", "detectors": stats, "snort": snort,
                                  "breakdown": breakdown, "activity": activity, "live": live,
                                  "replay": replay.manager.status(), "time": time.time()})

            snort_alerts = await asyncio.to_thread(monitor.read_snort_alerts, r, MAX_ALERTS, last_snort)
            if snort_alerts:
                last_snort = snort_alerts[0]["id"]
                await self.send_json({"type": "snort_alerts", "alerts": snort_alerts})

            alerts = await asyncio.to_thread(monitor.read_alerts, r, MAX_ALERTS, last_alert)
            if alerts:
                last_alert = alerts[0]["id"]
                await self.send_json({"type": "alerts", "alerts": alerts})
            elif last_alert and not await asyncio.to_thread(r.exists, bus.ALERTS):
                last_alert = None  # stream was reset outside the dashboard (e.g. `nids reset`)

            await asyncio.sleep(INTERVAL)
