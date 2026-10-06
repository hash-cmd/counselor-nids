"use client";

import { useEffect, useState } from "react";

import { api, ApiError } from "@/lib/api";
import { clock } from "@/lib/format";
import type { ReplayOptions, ReplayStatus } from "@/lib/types";

import { StatusBadge } from "./status-badge";

const TONES = { running: "good", finished: "neutral", stopped: "warning", failed: "critical", idle: "neutral" } as const;

export function ReplayControls({ status }: { status: ReplayStatus }) {
  const [options, setOptions] = useState<ReplayOptions | null>(null);
  const [replay, setReplay] = useState("");
  const [rate, setRate] = useState(1000);
  const [crossCheck, setCrossCheck] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<ReplayOptions>("/replay/")
      .then((o) => {
        setOptions(o);
        setReplay((current) => current || o.replays[0]?.name || "");
      })
      .catch((e) => setError(e.message));
  }, []);

  const running = status.state === "running";

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

  const noModels = options && options.models.length === 0;
  const noReplays = options && options.replays.length === 0;

  return (
    <section className="rounded-xl border border-line bg-surface p-4">
      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-xs text-ink-2">
          Traffic to replay
          <select
            value={replay}
            onChange={(e) => setReplay(e.target.value)}
            disabled={running || !options?.replays.length}
            className="min-w-48 rounded-md border border-line bg-raised px-2 py-1.5 text-sm text-ink"
          >
            {options?.replays.map((r) => (
              <option key={r.name} value={r.name}>
                {r.name} ({r.size_mb} MB)
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs text-ink-2">
          Flows per second
          <input
            type="number"
            min={10}
            max={50000}
            step={100}
            value={rate}
            onChange={(e) => setRate(Number(e.target.value))}
            disabled={running}
            className="w-28 rounded-md border border-line bg-raised px-2 py-1.5 text-sm text-ink"
          />
        </label>
        <label className="flex items-center gap-2 pb-1.5 text-sm text-ink">
          <input
            type="checkbox"
            checked={crossCheck}
            onChange={(e) => setCrossCheck(e.target.checked)}
            disabled={running}
            className="size-4 accent-[var(--accent)]"
          />
          Cross-check normal verdicts
        </label>
        <div className="ml-auto flex items-center gap-3">
          <StatusBadge
            tone={TONES[status.state]}
            label={
              status.state === "idle"
                ? "Idle"
                : `${status.state[0].toUpperCase()}${status.state.slice(1)} · ${status.replay} · ${clock(status.started_at)}`
            }
          />
          {running ? (
            <button
              type="button"
              onClick={() => send("/replay/stop/")}
              disabled={busy}
              className="rounded-md border border-line px-4 py-1.5 text-sm font-medium text-ink hover:bg-wash disabled:opacity-50"
            >
              Stop
            </button>
          ) : (
            <button
              type="button"
              onClick={() => send("/replay/start/", { replay, rate, cross_check: crossCheck })}
              disabled={busy || !replay || !!noModels}
              className="rounded-md bg-accent px-4 py-1.5 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
            >
              Start replay
            </button>
          )}
        </div>
      </div>
      {(error || noModels || noReplays) && (
        <p className="mt-3 text-sm text-critical">
          {error ??
            (noModels
              ? "No trained detectors found. Run `nids train scenario2` on the server first."
              : "No replay files found in data/replay/. Run `nids train scenario2` on the server first.")}
        </p>
      )}
      {status.state === "failed" && status.errors && (
        <details className="mt-3 text-xs text-ink-2">
          <summary className="cursor-pointer text-critical">Replay failed — show service logs</summary>
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
