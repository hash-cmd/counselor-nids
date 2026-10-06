"use client";

import { AlertsTable } from "@/components/alerts-table";
import { DecisionsChart } from "@/components/decisions-chart";
import { DetectorTiles } from "@/components/detector-tiles";
import { RateChart } from "@/components/rate-chart";
import { ReplayControls } from "@/components/replay-controls";
import { StatusBadge } from "@/components/status-badge";
import { useAuth } from "@/lib/auth";
import { seriesColor } from "@/lib/format";
import { useLiveFeed } from "@/lib/live";

export default function LivePage() {
  const { logout } = useAuth();
  const live = useLiveFeed(logout);
  const detectors = Object.keys(live.detectors).sort();
  const perDetector = detectors.map((d) => ({ key: d, name: d, color: seriesColor(d, detectors) }));
  // Every detector analyses the same stream, so throughput is one stream-level series.
  const streamRate = live.sampleRate.map((p) => ({
    time: p.time,
    stream: Math.max(0, ...detectors.map((d) => p[d] ?? 0)),
  }));

  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-ink">Live detection</h1>
        <StatusBadge
          tone={live.connection === "open" ? "good" : "warning"}
          label={live.connection === "open" ? "Live" : live.connection === "connecting" ? "Connecting…" : "Reconnecting…"}
        />
      </div>
      <ReplayControls status={live.replay} />
      <DetectorTiles detectors={live.detectors} />
      <div className="grid gap-4 lg:grid-cols-3">
        <RateChart
          title="Flows analysed per second"
          subtitle="Last two minutes, whole stream"
          points={streamRate}
          series={[{ key: "stream", name: "Flows analysed", color: "var(--ink-secondary)" }]}
        />
        <div className="lg:col-span-2">
        <RateChart
          title="Attacks flagged per second"
          subtitle="Last two minutes, per detector, same scale"
          points={live.flaggedRate}
          series={perDetector}
        />
        </div>
      </div>
      <DecisionsChart detectors={live.detectors} />
      <AlertsTable alerts={live.alerts} detectors={detectors} />
    </>
  );
}
