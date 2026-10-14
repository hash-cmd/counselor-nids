"use client";

import { useCallback, useEffect, useState } from "react";

import { Card, DataTable } from "@/components/ui/chart-parts";
import { StatusBadge } from "@/components/ui/status-badge";
import { API_URL, api } from "@/lib/api";
import { clock, count } from "@/lib/format";

type Connection = {
  id: string; record_id: string; src: string | null; dst: string | null;
  source: string | null; time: number | null; flagged: boolean;
  proto: string | null; flags: string | null; name: string | null;
  packets: number | null; bytes: number | null; duration: number | null;
};
type Feed = { feed_on: boolean; total_window: number; connections: Connection[] };

export default function TrafficPage() {
  const [feed, setFeed] = useState<Feed | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(
    () => api<Feed>("/connections/?limit=400").then(setFeed).catch((e) => setError(e.message)),
    [],
  );

  useEffect(() => {
    let live = true;
    const tick = () => live && load();
    tick();
    const t = setInterval(tick, 3000); // the feed is live; refresh a few times a minute
    return () => {
      live = false;
      clearInterval(t);
    };
  }, [load]);

  const toggle = useCallback(async () => {
    setBusy(true);
    try {
      await api<{ feed_on: boolean }>("/connections/", { method: "POST", body: JSON.stringify({ on: !feed?.feed_on }) });
      await load();
    } finally {
      setBusy(false);
    }
  }, [feed?.feed_on, load]);

  const exportCsv = useCallback(async () => {
    const res = await fetch(`${API_URL}/api/connections/?format=csv&limit=2000`, {
      credentials: "include",
      headers: { "X-NIDS-Client": "web" },
    });
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = "connections.csv";
    a.click();
    URL.revokeObjectURL(url);
  }, []);

  if (error) return <p className="text-sm text-critical">Could not load traffic: {error}</p>;
  if (!feed) return <p className="text-sm text-muted">Loading traffic…</p>;

  return (
    <>
      <p className="max-w-3xl text-sm text-ink-2">
        Every connection the system judged, flagged or not — the live traffic passing the detectors. Normal connections
        are not alarms; they are shown so the full traffic is visible and can be exported for a report. It is off by
        default, because a busy network produces thousands of connections a second.
      </p>

      <Card
        title="Live traffic"
        subtitle={
          feed.feed_on
            ? `Recording on · the latest ${count(feed.connections.length)} of the last ${count(feed.total_window)} connections (newest first, refreshing every 3 s).`
            : "Recording is off. Turn it on to see every connection pass through — live monitoring must be running."
        }
        actions={
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={toggle}
              disabled={busy}
              className={`rounded-md px-3 py-1 text-xs ${feed.feed_on ? "bg-[var(--accent)] text-white" : "border border-line text-ink-2 hover:bg-wash"} disabled:opacity-50`}
            >
              {feed.feed_on ? "Recording on — turn off" : "Turn on recording"}
            </button>
            {feed.feed_on && feed.total_window > 0 && (
              <button type="button" onClick={exportCsv} className="rounded-md border border-line px-3 py-1 text-xs text-ink-2 hover:bg-wash">
                Export CSV
              </button>
            )}
          </div>
        }
      >
        {!feed.feed_on ? (
          <p className="py-6 text-center text-sm text-muted">
            Recording is off. Click <span className="font-semibold text-ink-2">Turn on recording</span> above (live
            monitoring must be running for connections to appear). Suspicious connections are always on the Alerts page.
          </p>
        ) : feed.connections.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted">Recording on — waiting for connections…</p>
        ) : (
          <DataTable
            columns={[
              { key: "time", label: "Time" },
              { key: "from", label: "From" },
              { key: "to", label: "To" },
              { key: "proto", label: "Proto" },
              { key: "flags", label: "TCP flags" },
              { key: "packets", label: "Packets", align: "right" },
              { key: "bytes", label: "Bytes", align: "right" },
              { key: "duration", label: "Duration", align: "right" },
              { key: "verdict", label: "Verdict" },
            ]}
            rows={feed.connections.map((c) => ({
              time: c.time ? clock(c.time) : "—",
              from: c.src ?? "—",
              to: c.name ? (
                <span>
                  {c.name}
                  <span className="block text-xs text-muted">{c.dst}</span>
                </span>
              ) : (c.dst ?? "—"),
              proto: c.proto ?? "—",
              flags: c.flags ? <span className="font-mono text-xs">{c.flags}</span> : <span className="text-muted">—</span>,
              packets: c.packets == null ? "—" : count(c.packets),
              bytes: c.bytes == null ? "—" : count(c.bytes),
              duration: c.duration == null ? "—" : `${c.duration.toFixed(1)}s`,
              verdict: c.flagged ? <StatusBadge tone="critical" label="flagged" /> : <span className="text-muted">normal</span>,
            }))}
          />
        )}
      </Card>
    </>
  );
}
