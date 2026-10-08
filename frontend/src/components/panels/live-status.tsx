"use client";

import Link from "next/link";
import { useState } from "react";

import { clock, count } from "@/lib/format";
import type { LiveState } from "@/lib/live-feed";

import { StatusBadge } from "@/components/ui/status-badge";

const START = "./start.sh live wlan0";

function CopyCommand({ command }: { command: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked — the command stays selectable */
    }
  }
  return (
    <div className="flex items-center gap-2">
      <code className="figure rounded-md bg-wash px-2.5 py-1.5 text-sm text-ink">{command}</code>
      <button type="button" onClick={copy}
              className="rounded-md border border-line px-2.5 py-1.5 text-xs text-ink-2 hover:bg-wash hover:text-ink">
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="eyebrow">{label}</p>
      <p className="figure mt-1 text-xl font-semibold text-ink">{value}</p>
    </div>
  );
}

/** What the system is watching right now: the live network, a test recording, or nothing. */
export function LiveStatus({ live }: { live: LiveState }) {
  const checked = Math.max(0, ...Object.values(live.detectors).map((d) => d.samples));
  const flagged = live.breakdown?.ml_flagged_flows ?? 0;
  const replay = live.replay;

  // A test replay is running: the dashboard is showing the recording, not the network.
  if (replay.state === "running") {
    return (
      <section className="rounded-xl border border-line bg-surface p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="eyebrow">Live monitoring</p>
            <h2 className="mt-1 text-base font-semibold text-ink">Paused — a test recording is playing</h2>
            <p className="mt-1 text-sm text-ink-2">
              The numbers below come from <span className="figure">{replay.replay}</span>, not your network.
            </p>
          </div>
          <Link href="/test" className="rounded-md border border-line px-3 py-1.5 text-sm text-ink hover:bg-wash">
            Go to the test →
          </Link>
        </div>
      </section>
    );
  }

  // Live capture on a network interface.
  if (live.live) {
    return (
      <section className="rounded-xl border border-line bg-surface p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="eyebrow">Live monitoring</p>
            <h2 className="mt-1 flex items-center gap-2 text-base font-semibold text-ink">
              Watching <span className="figure text-accent">{live.live.target}</span>
            </h2>
            <p className="mt-1 text-sm text-ink-2">
              Every connection on this network interface is checked by the AI detectors
              {live.snort ? " and the rule checker (Snort)" : ""} as it happens.
            </p>
          </div>
          {live.live.state === "waiting" ? (
            <StatusBadge tone="warning" label="Network down — waiting to reconnect" />
          ) : (
            <StatusBadge tone={live.activity === "running" ? "good" : "warning"}
                         label={live.activity === "running" ? `Running since ${clock(live.live.started_at)}` : "Starting…"} />
          )}
        </div>
        {live.live.state === "waiting" && (
          <p className="mt-3 rounded-md bg-wash p-3 text-sm text-ink-2">
            {live.live.target} lost its connection (for example, Wi-Fi dropped). Monitoring is paused and will
            resume on its own as soon as the network is back — no need to restart anything.
          </p>
        )}
        <div className="mt-4 grid grid-cols-2 gap-4 border-t border-line pt-4 sm:grid-cols-4">
          <Stat label="Connections checked" value={count(checked)} />
          <Stat label="Flagged by the AI" value={count(flagged)} />
          <Stat label="Rule checker alarms" value={live.snort ? count(live.snort.alerts) : "off"} />
          <Stat label="AI detectors" value={String(Object.keys(live.detectors).length)} />
        </div>
        <p className="mt-3 text-xs text-muted">To stop, press Ctrl+C in the terminal where live monitoring was started.</p>
      </section>
    );
  }

  // Nothing is being watched.
  const lastTest = replay.state === "idle" ? null : replay.replay;
  return (
    <section className="rounded-xl border border-line bg-surface p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="eyebrow">Live monitoring</p>
          <h2 className="mt-1 text-base font-semibold text-ink">Not watching your network</h2>
          <p className="mt-1 max-w-2xl text-sm text-ink-2">
            Start live monitoring from a terminal in the project folder. It asks for your password once, because
            capturing network traffic needs administrator rights. Replace <span className="figure">wlan0</span> with
            your interface (<span className="figure">ip link</span> lists them; Wi-Fi is usually wlan0, cable eth0).
          </p>
        </div>
        <StatusBadge tone="neutral" label="Off" />
      </div>
      <div className="mt-4">
        <CopyCommand command={START} />
      </div>
      {lastTest && (
        <p className="mt-3 text-xs text-muted">
          The numbers below are from the last test ({lastTest}). They reset when live monitoring starts.
        </p>
      )}
    </section>
  );
}
