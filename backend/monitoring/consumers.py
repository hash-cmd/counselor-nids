"""Live feed for the dashboard over a WebSocket.

Every ``INTERVAL`` seconds the client receives:
    {"type": "stats",  "detectors": {...}, "replay": {...}, "time": <unix s>}
    {"type": "alerts", "alerts": [...newest first, at most MAX_ALERTS...]}   (only when new)
When a new replay starts it first receives {"type": "reset"}.
"""

import asyncio
import time

from channels.generic.websocket import AsyncJsonWebsocketConsumer

from nids.service import bus, monitor

from . import replay
from .redis_client import get_redis

INTERVAL = 1.0
MAX_ALERTS = 100


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
        run_id, last_alert = unread, None
        while True:
            current_run = await asyncio.to_thread(r.get, replay.RUN_KEY)
            if current_run != run_id:
                if run_id is not unread:
                    await self.send_json({"type": "reset"})
                run_id, last_alert = current_run, None

            stats = await asyncio.to_thread(monitor.read_stats, r)
            await self.send_json({"type": "stats", "detectors": stats,
                                  "replay": replay.manager.status(), "time": time.time()})

            alerts = await asyncio.to_thread(monitor.read_alerts, r, MAX_ALERTS, last_alert)
            if alerts:
                last_alert = alerts[0]["id"]
                await self.send_json({"type": "alerts", "alerts": alerts})
            elif last_alert and not await asyncio.to_thread(r.exists, bus.ALERTS):
                last_alert = None  # stream was reset outside the dashboard (e.g. `nids reset`)

            await asyncio.sleep(INTERVAL)
