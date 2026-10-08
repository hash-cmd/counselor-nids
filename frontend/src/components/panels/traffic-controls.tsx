"use client";

import { useEffect, useState } from "react";

import { api, ApiError } from "@/lib/api";
import { clock } from "@/lib/format";
import { detectorName } from "@/lib/plain";
import type { Activity, ReplayOptions, ReplayStatus } from "@/lib/types";

import { StatusBadge, type Tone } from "@/components/ui/status-badge";

const TONES: Record<ReplayStatus["state"], Tone> = {
  running: "good", finished: "neutral", stopped: "warning", failed: "critical", idle: "neutral",
};

function statusLabel(status: ReplayStatus, activity: Activity): { tone: Tone; label: string } {
  if (status.state === "idle") {
    return activity === "running" ? { tone: "good", label: "Watching your network live" } : { tone: "neutral", label: "Not running" };
  }
  const state = STATE_LABELS[status.state];
  return { tone: TONES[status.state], label: `${state} · ${status.replay} · started ${clock(status.started_at)}` };
}

const STATE_LABELS: Record<Exclude<ReplayStatus["state"], "idle">, string> = {
  running: "Test running", finished: "Test finished", stopped: "Test stopped", failed: "Test failed",
};

export function TrafficControls({ status, activity, liveCapture = false }: {
  status: ReplayStatus;
  activity: Activity;
  /** a network interface is being captured live — tests must not start over it */
  liveCapture?: boolean;
}) {
  const [options, setOptions] = useState<ReplayOptions | null>(null);
  const [replay, setReplay] = useState("");
  const [crossCheck, setCrossCheck] = useState(true);
  const [snort, setSnort] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<ReplayOptions>("/replay/")
      .then((o) => {
        setOptions(o);
        setReplay(o.replays[0]?.name ?? "");
      })
      .catch((e) => setError(e.message));
  }, []);

  const running = status.state === "running";
  const liveRunning = liveCapture || (status.state === "idle" && activity === "running");
  const noModels = options && options.models.length === 0;
  const badge = statusLabel(status, activity);

  async function send(path: string, body?: object) {
    setBusy(true);
    setError(null);
    try {
      await api(path, { method: "POST", body: body ? JSON.stringify(body) : undefined });
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="rounded-xl border border-line bg-surface p-5">
      <header className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-ink">Run a test</h2>
          <p className="text-xs text-ink-2">
            Try the system on recorded traffic with known attacks. To watch your own network instead, run{" "}
            <code className="rounded bg-wash px-1">./start.sh live wlan0</code> in a terminal.
          </p>
        </div>
        <StatusBadge tone={badge.tone} label={badge.label} />
      </header>

      <div className="rounded-lg border border-line p-4">
        <p className="text-sm font-medium text-ink">Recorded network traffic</p>
        <p className="mt-1 text-xs text-ink-2">
          Plays back a recording of real network traffic. The AI and the rule checker (Snort) both watch it, so you can
          compare what each one catches.
        </p>
        {options && options.models.length > 0 && (
          <p className="mt-1 text-xs text-muted">AI detectors: {options.models.map(detectorName).join(", ")}</p>
        )}
        <select
          value={replay}
          onChange={(e) => setReplay(e.target.value)}
          disabled={running || !options?.replays.length}
          className="mt-3 w-full rounded-md border border-line bg-raised px-2 py-1.5 text-sm text-ink"
          aria-label="Recording"
        >
          {!options?.replays.length && <option>No recordings found in data/pcap/</option>}
          {options?.replays.map((r) => (
            <option key={r.name} value={r.name}>
              {r.name} ({r.size_mb} MB)
            </option>
          ))}
        </select>
        {options?.replays.find((r) => r.name === replay)?.description && (
          <p className="mt-2 text-xs text-ink-2">{options.replays.find((r) => r.name === replay)?.description}</p>
        )}
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-3">
        <label
          className="flex items-center gap-2 text-sm text-ink"
          title="Each AI detector only knows some kinds of attack. With this on, when one thinks a connection is safe, it asks the others too, so attacks it never learned about are still caught."
        >
          <input type="checkbox" checked={crossCheck} onChange={(e) => setCrossCheck(e.target.checked)}
                 disabled={running} className="size-4 accent-[var(--accent)]" />
          Detectors double-check each other <span className="text-muted">(recommended)</span>
        </label>
        <label className="flex items-center gap-2 text-sm text-ink" title={options?.snort ? undefined : "Snort is not installed on this computer"}>
          <input type="checkbox" checked={snort && !!options?.snort} onChange={(e) => setSnort(e.target.checked)}
                 disabled={running || !options?.snort} className="size-4 accent-[var(--accent)]" />
          Also run the rule checker (Snort) {options && !options.snort && <span className="text-muted">(not installed)</span>}
        </label>
        <div className="ml-auto">
          {running ? (
            <button type="button" onClick={() => send("/replay/stop/")} disabled={busy}
                    className="rounded-md border border-line px-4 py-1.5 text-sm font-medium text-ink hover:bg-wash disabled:opacity-50">
              Stop test
            </button>
          ) : (
            <button
              type="button"
              onClick={() => send("/replay/start/", { replay, cross_check: crossCheck, snort: snort && !!options?.snort })}
              disabled={busy || !replay || !!noModels || liveRunning}
              title={liveRunning ? "Your network is being watched live — stop that in its terminal first" : undefined}
              className="rounded-md bg-accent px-4 py-1.5 text-sm font-semibold text-[var(--accent-ink)] hover:opacity-90 disabled:opacity-50"
            >
              Start test
            </button>
          )}
        </div>
      </div>

      {(error || noModels) && (
        <p className="mt-3 text-sm text-critical">
          {error ?? "The AI detectors haven't been trained yet. Run ./start.sh setup first."}
        </p>
      )}
      {status.state === "failed" && status.errors && (
        <details className="mt-3 text-xs text-ink-2">
          <summary className="cursor-pointer text-critical">The test failed. Show the technical logs</summary>
          {Object.entries(status.errors).map(([name, log]) => (
            <pre key={name} className="mt-2 overflow-auto rounded bg-wash p-2">
              <strong>{name}</strong>
              {"\n"}
              {log}
            </pre>
          ))}
        </details>
      )}
    </section>
  );
}
