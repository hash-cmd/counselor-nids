"use client";

import { useEffect, useState } from "react";

import { api, ApiError } from "@/lib/api";
import { clock } from "@/lib/format";
import { detectorName } from "@/lib/plain";
import type { Activity, ReplayOptions, ReplayStatus } from "@/lib/types";

import { StatusBadge, type Tone } from "@/components/ui/status-badge";

type Kind = "pcap" | "flows";

const KINDS: Record<Kind, { title: string; text: string }> = {
  pcap: {
    title: "Recorded network traffic",
    text: "Plays back a recording of real network traffic. The AI and the rule checker (Snort) both watch it, so you can compare what each one catches.",
  },
  flows: {
    title: "Practice data with known answers",
    text: "Connections from a public research dataset (CICIDS2017) where every attack is already marked, so the dashboard can score how often the AI is right. The rule checker can't run on this.",
  },
};

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

export function TrafficControls({ status, activity }: { status: ReplayStatus; activity: Activity }) {
  const [options, setOptions] = useState<ReplayOptions | null>(null);
  const [kind, setKind] = useState<Kind>("pcap");
  const [files, setFiles] = useState<Record<Kind, string>>({ pcap: "", flows: "" });
  const [rate, setRate] = useState(1000);
  const [crossCheck, setCrossCheck] = useState(true);
  const [snort, setSnort] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<ReplayOptions>("/replay/")
      .then((o) => {
        setOptions(o);
        const first = (k: Kind) => o.replays.find((r) => r.kind === k)?.name ?? "";
        setFiles({ pcap: first("pcap"), flows: first("flows") });
        if (!o.replays.some((r) => r.kind === "pcap")) setKind("flows");
      })
      .catch((e) => setError(e.message));
  }, []);

  const running = status.state === "running";
  const liveRunning = status.state === "idle" && activity === "running";
  const replay = files[kind];
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

      <div className="grid gap-3 md:grid-cols-2" role="radiogroup" aria-label="What to test on">
        {(Object.keys(KINDS) as Kind[]).map((k) => {
          const available = options?.replays.filter((r) => r.kind === k) ?? [];
          const active = kind === k;
          return (
            <div
              key={k}
              role="radio"
              aria-checked={active}
              tabIndex={0}
              onClick={() => !running && setKind(k)}
              onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && !running && setKind(k)}
              className={`cursor-pointer rounded-lg border p-4 ${active ? "border-accent bg-wash" : "border-line hover:bg-wash"}`}
            >
              <p className="flex items-center gap-2 text-sm font-medium text-ink">
                <span className={`inline-block size-3 rounded-full border-2 ${active ? "border-accent bg-accent" : "border-line"}`} />
                {KINDS[k].title}
              </p>
              <p className="mt-1 text-xs text-ink-2">{KINDS[k].text}</p>
              {k === "pcap" && options && (
                <p className={`mt-1 text-xs ${options.live_models.length ? "text-muted" : "text-critical"}`}>
                  {options.live_models.length
                    ? `AI detectors: ${options.live_models.map(detectorName).join(", ")}`
                    : "The AI detectors for real traffic aren't set up yet, so the AI will miss most attacks here. Run ./start.sh setup."}
                </p>
              )}
              {active && (
                <select
                  value={files[k]}
                  onChange={(e) => setFiles((f) => ({ ...f, [k]: e.target.value }))}
                  onClick={(e) => e.stopPropagation()}
                  disabled={running || available.length === 0}
                  className="mt-3 w-full rounded-md border border-line bg-raised px-2 py-1.5 text-sm text-ink"
                  aria-label={`${KINDS[k].title} file`}
                >
                  {available.length === 0 && <option>No files found</option>}
                  {available.map((r) => (
                    <option key={r.name} value={r.name}>
                      {r.name} ({r.size_mb} MB)
                    </option>
                  ))}
                </select>
              )}
              {active && available.find((r) => r.name === files[k])?.description && (
                <p className="mt-2 text-xs text-ink-2">{available.find((r) => r.name === files[k])?.description}</p>
              )}
            </div>
          );
        })}
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-3">
        {kind === "flows" && (
          <label className="flex items-center gap-2 text-sm text-ink-2">
            Speed (connections per second)
            <input
              type="number"
              min={10}
              max={50000}
              step={100}
              value={rate}
              onChange={(e) => setRate(Number(e.target.value))}
              disabled={running}
              className="w-24 rounded-md border border-line bg-raised px-2 py-1 text-sm text-ink"
            />
          </label>
        )}
        <label
          className="flex items-center gap-2 text-sm text-ink"
          title="Each AI detector only knows some kinds of attack. With this on, when one thinks a connection is safe, it asks the others too, so attacks it never learned about are still caught."
        >
          <input type="checkbox" checked={crossCheck} onChange={(e) => setCrossCheck(e.target.checked)}
                 disabled={running} className="size-4 accent-[var(--accent)]" />
          Detectors double-check each other <span className="text-muted">(recommended)</span>
        </label>
        {kind === "pcap" && (
          <label className="flex items-center gap-2 text-sm text-ink" title={options?.snort ? undefined : "Snort is not installed on this computer"}>
            <input type="checkbox" checked={snort && !!options?.snort} onChange={(e) => setSnort(e.target.checked)}
                   disabled={running || !options?.snort} className="size-4 accent-[var(--accent)]" />
            Also run the rule checker (Snort) {options && !options.snort && <span className="text-muted">(not installed)</span>}
          </label>
        )}
        <div className="ml-auto">
          {running ? (
            <button type="button" onClick={() => send("/replay/stop/")} disabled={busy}
                    className="rounded-md border border-line px-4 py-1.5 text-sm font-medium text-ink hover:bg-wash disabled:opacity-50">
              Stop test
            </button>
          ) : (
            <button
              type="button"
              onClick={() => send("/replay/start/", { replay, rate, cross_check: crossCheck, snort: kind === "pcap" && snort && !!options?.snort })}
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
