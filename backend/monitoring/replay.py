"""Start and stop a replay from the dashboard.

A replay runs the same services as the command line, as subprocesses of the API — the
Observer and one detector service per trained model, fed by either
  * a flow CSV (data/replay/*.csv) through the Extractor, or
  * a packet capture (data/pcap/*.pcap) through the live Extractor, with Snort run on
    the same capture and its alerts linked to the flows and the ML verdicts.
One replay at a time.
"""

import os
import shutil
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from subprocess import STDOUT, Popen

from django.conf import settings

from nids.service import bus

from .redis_client import get_redis

RUN_KEY = f"{bus.PREFIX}:run"  # id of the current replay, so live clients can reset


class ReplayError(Exception):
    pass


def replay_dir() -> Path:
    return settings.NIDS_ROOT / "data" / "replay"


def pcap_dir() -> Path:
    return settings.NIDS_ROOT / "data" / "pcap"


def models_dir() -> Path:
    return settings.NIDS_ROOT / "models"


def snort_available() -> bool:
    return shutil.which("snort") is not None


def _files() -> dict[str, tuple[str, Path]]:
    # packet captures first: they run with Snort, which flow records cannot
    files = {p.name: ("pcap", p) for p in sorted([*pcap_dir().glob("*.pcap"), *pcap_dir().glob("*.pcapng")])}
    files |= {p.name: ("flows", p) for p in sorted(replay_dir().glob("*.csv"))}
    return files


def available() -> dict:
    replays = [{"name": name, "kind": kind, "size_mb": round(path.stat().st_size / 1e6, 1)}
               for name, (kind, path) in _files().items()]
    return {"replays": replays, "models": sorted(p.stem for p in models_dir().glob("*.joblib")),
            "snort": snort_available()}


@dataclass
class Run:
    id: str
    replay: str
    kind: str
    snort: bool
    rate: float
    cross_check: bool
    min_accuracy: float
    started_at: float
    log_dir: str
    processes: dict[str, Popen] = field(default_factory=dict)
    stopped: bool = False
    finished_at: float | None = None


class ReplayManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._run: Run | None = None

    def _command(self, *args: str) -> list[str]:
        return [sys.executable, "-m", "nids.cli", *args]

    def start(self, replay: str, rate: float, cross_check: bool, min_accuracy: float,
              snort: bool = True) -> dict:
        with self._lock:
            if self._run and self._state(self._run) == "running":
                raise ReplayError("a replay is already running")
            files = _files()
            if replay not in files:
                raise ReplayError(f"unknown replay {replay!r}")
            kind, path = files[replay]
            snort = snort and kind == "pcap"
            if snort and not snort_available():
                raise ReplayError("Snort is not installed on the API host")
            models = sorted(models_dir().glob("*.joblib"))
            if not models:
                raise ReplayError("no trained models: run `nids train scenario2` first")

            r = get_redis()
            bus.reset(r)
            run = Run(id=str(int(time.time() * 1000)), replay=replay, kind=kind, snort=snort, rate=rate,
                      cross_check=cross_check, min_accuracy=min_accuracy,
                      started_at=time.time(), log_dir=tempfile.mkdtemp(prefix="nids-replay-"))
            r.set(RUN_KEY, run.id)
            if snort:
                r.set(bus.SNORT_ACTIVE, 1, ex=24 * 3600)  # detectors wait for the Snort correlator

            env = {**os.environ, "NIDS_REDIS_URL": settings.NIDS_REDIS_URL}
            commands = {"observer": self._command("observe", "--exit-on-end")}
            for model in models:
                commands[model.stem] = self._command(
                    "detect", str(model), "--sources", "replay", "--min-accuracy", str(min_accuracy),
                    "--exit-on-end", *(["--cross-check"] if cross_check else []))
            if kind == "pcap":
                commands["extractor"] = self._command(
                    "extract", "--live", str(path), "--source", "replay", "--wait-for", str(len(models)))
                if snort:
                    commands["snort"] = self._command(
                        "snort", "--pcap", str(path), "--min-accuracy", str(min_accuracy))
            else:
                commands["extractor"] = self._command(
                    "extract", str(path), "--source", "replay", "--wait-for", str(len(models)),
                    "--rate", str(rate), "--batch-size", "500")
            for name, command in commands.items():
                log = open(Path(run.log_dir) / f"{name}.log", "w")
                run.processes[name] = Popen(command, stdout=log, stderr=STDOUT, env=env)
            self._run = run
            return self._describe(run)

    def stop(self) -> dict:
        with self._lock:
            if not self._run:
                raise ReplayError("no replay to stop")
            self._run.stopped = True
            get_redis().delete(bus.SNORT_ACTIVE)
            for process in self._run.processes.values():
                if process.poll() is None:
                    process.terminate()
            for process in self._run.processes.values():
                try:
                    process.wait(timeout=5)
                except Exception:
                    process.kill()
            return self._describe(self._run)

    def status(self) -> dict:
        with self._lock:
            return self._describe(self._run) if self._run else {"state": "idle"}

    def _state(self, run: Run) -> str:
        codes = [p.poll() for p in run.processes.values()]
        if run.stopped:
            return "stopped"
        if any(code is None for code in codes):
            return "running"
        return "finished" if all(code == 0 for code in codes) else "failed"

    def _describe(self, run: Run) -> dict:
        state = self._state(run)
        if state != "running" and run.finished_at is None:
            run.finished_at = time.time()
        described = {
            "id": run.id, "state": state, "replay": run.replay, "kind": run.kind, "snort": run.snort,
            "rate": run.rate,
            "cross_check": run.cross_check, "min_accuracy": run.min_accuracy,
            "started_at": run.started_at, "finished_at": run.finished_at,
            "processes": {name: ("running" if p.poll() is None else f"exited {p.returncode}")
                          for name, p in run.processes.items()},
        }
        if state == "failed":
            described["errors"] = {
                name: _tail(Path(run.log_dir) / f"{name}.log")
                for name, p in run.processes.items() if p.poll() not in (None, 0)
            }
        return described


def _tail(path: Path, lines: int = 15) -> str:
    try:
        return "".join(path.read_text().splitlines(keepends=True)[-lines:])
    except OSError:
        return ""


manager = ReplayManager()
