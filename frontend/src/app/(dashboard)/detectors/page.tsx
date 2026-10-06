"use client";

import { DecisionsChart } from "@/components/decisions-chart";
import { DetectorTiles } from "@/components/detector-tiles";
import { RateChart } from "@/components/rate-chart";
import { seriesColor } from "@/lib/format";
import { useLive } from "@/lib/live";

export default function DetectorsPage() {
  const live = useLive();
  const detectors = Object.keys(live.detectors).sort();
  const perDetector = detectors.map((d) => ({ key: d, name: d, color: seriesColor(d, detectors) }));
  // Every detector analyses the same stream, so throughput is one stream-level series.
  const streamRate = live.sampleRate.map((p) => ({ time: p.time, stream: Math.max(0, ...detectors.map((d) => p[d] ?? 0)) }));

  return (
    <>
      <div>
        <h1 className="text-xl font-semibold text-ink">Detectors</h1>
        <p className="text-sm text-ink-2">
          Each ML detector, how it decided, and how often it needed its counselors.
        </p>
      </div>
      <DetectorTiles detectors={live.detectors} />
      <div className="grid gap-4 lg:grid-cols-3">
        <RateChart
          title="Flows analysed per second"
          subtitle="Whole stream"
          points={streamRate}
          series={[{ key: "stream", name: "Flows analysed", color: "var(--ink-secondary)" }]}
        />
        <div className="lg:col-span-2">
          <RateChart title="Attacks flagged per second" subtitle="Per detector, same scale" points={live.flaggedRate} series={perDetector} />
        </div>
      </div>
      <DecisionsChart detectors={live.detectors} />
    </>
  );
}
