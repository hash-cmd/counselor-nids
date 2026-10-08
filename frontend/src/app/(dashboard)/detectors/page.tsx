"use client";

import { DecisionsChart } from "@/components/charts/decisions-chart";
import { DetectorTiles } from "@/components/panels/detector-tiles";
import { RateChart } from "@/components/charts/rate-chart";
import { SnortCounselor } from "@/components/panels/snort-counselor";
import { TeachPanel } from "@/components/panels/teach";
import { seriesColor } from "@/lib/format";
import { useLive } from "@/lib/live-feed";
import { detectorName } from "@/lib/plain";

export default function DetectorsPage() {
  const live = useLive();
  const detectors = Object.keys(live.detectors).sort();
  const perDetector = detectors.map((d) => ({ key: d, name: detectorName(d), color: seriesColor(d, detectors) }));
  // Every detector analyses the same stream, so throughput is one stream-level series.
  const streamRate = live.sampleRate.map((p) => ({ time: p.time, stream: Math.max(0, ...detectors.map((d) => p[d] ?? 0)) }));

  return (
    <>
      <p className="max-w-3xl text-sm text-ink-2">
        The AI is a team of specialists. Each detector learned to recognise certain kinds of attack and checks
        every connection. When a detector is unsure, it asks the others for advice, like asking a colleague; and
        when it thinks a connection is safe, it checks with the others in case it is an attack it never learned.
        The rule checker (Snort) is a counselor too: it helps settle a detector&apos;s doubts.
      </p>
      <DetectorTiles detectors={live.detectors} />
      <div className="grid gap-4 lg:grid-cols-3">
        <RateChart
          title="Connections checked per second"
          tag="Fig.2 · Throughput"
          subtitle="How busy the system is"
          points={streamRate}
          series={[{ key: "stream", name: "Connections checked", color: "var(--ink-secondary)" }]}
        />
        <div className="lg:col-span-2">
          <RateChart title="Attacks flagged per second" tag="Fig.3 · Per detector" subtitle="By each detector, on the same scale" points={live.flaggedRate} series={perDetector} />
        </div>
      </div>
      <DecisionsChart detectors={live.detectors} />
      <TeachPanel />
      <SnortCounselor detectors={live.detectors} trust={live.snortTrust} health={live.health} />
    </>
  );
}
