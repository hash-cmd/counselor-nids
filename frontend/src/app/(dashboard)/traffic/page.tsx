"use client";

import { useCallback, useEffect, useState } from "react";

import { Card, DataTable } from "@/components/ui/chart-parts";
import { StatusBadge } from "@/components/ui/status-badge";
import { API_URL, api } from "@/lib/api";
import { clock, count } from "@/lib/format";

type Connection = {
  id: string; record_id: string; src: string | null; dst: string | null;
  source: string | null; time: number | null; flagged: boolean;
};
type Feed = { enabled: boolean; total_window: number; connections: Connection[] };

export default function TrafficPage() {
  const [feed, setFeed] = useState<Feed | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    const load = () =>
      api<Feed>("/connections/?limit=400")
        .then((f) => live && setFeed(f))
        .catch((e) => live && setError(e.message));
    load();
    const t = setInterval(load, 3000); // the feed is live; refresh a few times a minute
    return () => {
      live = false;
      clearInterval(t);
    };
  }, []);

  const exportCsv = useCallback(async () => {
    const res = await fetch(`${API_URL}/api/connections/?format=csv&limit=2000`, {
      credentials: "include",
      headers: { "X-NIDS-Client": "web" },
    });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
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
        are not alarms; they are shown so the full traffic is visible and can be exported for a report.
      </p>

      {!feed.enabled ? (
        <div className="rounded-xl border border-dashed border-line bg-surface p-8 text-center text-sm text-ink-2">
          <p className="font-semibold text-ink">The full-traffic feed is off.</p>
          <p className="mt-1">
            It is optional, because a busy network produces thousands of connections a second. To record every
            connection, restart live monitoring with it on:
          </p>
          <code className="mt-2 inline-block rounded bg-wash px-2 py-1">NIDS_FEED_ALL=1 ./start.sh live wlan0</code>
          <p className="mt-2 text-muted">Suspicious connections are always on the Alerts page regardless of this setting.</p>
        </div>
      ) : (
        <Card
          title="Live traffic"
          subtitle={`The latest ${count(feed.connections.length)} of the last ${count(feed.total_window)} connections (newest first, refreshing every 3 s).`}
          actions={
            <button
              type="button"
              onClick={exportCsv}
              className="rounded-md border border-line px-3 py-1 text-xs text-ink-2 hover:bg-wash"
            >
              Export CSV
            </button>
          }
        >
          <DataTable
            columns={[
              { key: "time", label: "Time" },
              { key: "from", label: "From" },
              { key: "to", label: "To" },
              { key: "verdict", label: "Verdict" },
            ]}
            rows={feed.connections.map((c) => ({
              time: c.time ? clock(c.time) : "—",
              from: c.src ?? "—",
              to: c.dst ?? "—",
              verdict: c.flagged ? (
                <StatusBadge tone="critical" label="flagged" />
              ) : (
                <span className="text-muted">normal</span>
              ),
            }))}
          />
        </Card>
      )}
    </>
  );
}
