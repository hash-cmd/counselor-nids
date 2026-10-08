"""Run scripts/live_detectors/learn_feedback.py from the dashboard, one run at a time."""

import json
import sys
import threading
import time
from pathlib import Path
from subprocess import STDOUT, Popen

from django.conf import settings


class LearningManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._process: Popen | None = None
        self._started: float | None = None
        self._log: Path | None = None

    def report_path(self) -> Path:
        return settings.NIDS_ROOT / "logs" / "feedback-learning.json"

    def start(self) -> dict:
        with self._lock:
            if self._process and self._process.poll() is None:
                raise RuntimeError("the detectors are already learning")
            root = settings.NIDS_ROOT
            self._log = root / "logs" / "feedback-learning.log"
            self._log.parent.mkdir(parents=True, exist_ok=True)
            log = open(self._log, "w")
            self._process = Popen([sys.executable, str(root / "scripts" / "live_detectors" / "learn_feedback.py")],
                                  stdout=log, stderr=STDOUT, cwd=root)
            self._started = time.time()
        return self.status()

    def status(self) -> dict:
        running = bool(self._process and self._process.poll() is None)
        state = "running" if running else ("idle" if self._process is None else
                                           "finished" if self._process.returncode == 0 else "failed")
        out = {"state": state, "started_at": self._started}
        path = self.report_path()
        if path.exists():
            try:
                out["report"] = json.loads(path.read_text())
            except ValueError:
                pass
        if state == "failed" and self._log and self._log.exists():
            out["error"] = "".join(self._log.read_text().splitlines(keepends=True)[-8:])
        return out


manager = LearningManager()
