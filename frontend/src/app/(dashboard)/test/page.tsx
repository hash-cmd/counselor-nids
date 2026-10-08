"use client";

import Link from "next/link";
import { useMemo } from "react";

import { DetectionTimeline } from "@/components/charts/detection-timeline";
import { KpiStrip } from "@/components/panels/kpi-strip";
import { TrafficControls } from "@/components/panels/traffic-controls";
import { buildIncidents } from "@/lib/incidents";
import { useLive } from "@/lib/live-feed";

/** Replay recorded traffic with known attacks to check what the system catches.
 *  Kept apart from the Overview, which is for monitoring the live network. */
export default function TestPage() {
  const live = useLive();
  const incidents = useMemo(() => buildIncidents(live.alerts, live.snortAlerts), [live.alerts, live.snortAlerts]);
  const testing = live.replay.state !== "idle";

  return (
    <>
      <p className="max-w-3xl text-sm text-ink-2">
        Play back recorded traffic where the attacks are already known, to check what the system catches and how
        often it is right. This doesn&apos;t touch live monitoring — and it can&apos;t start while live monitoring
        is running, so test results never mix with your real network data.
      </p>

      <TrafficControls status={live.replay} activity={live.activity} liveCapture={live.live != null} />

      {testing && (
        <>
          <KpiStrip live={live} incidents={incidents} />
          <DetectionTimeline points={live.detectionRate} snort={live.snort != null} />
          <p className="text-right text-sm">
            <Link href="/alerts" className="text-accent hover:underline">
              See every connection the test flagged →
            </Link>
          </p>
        </>
      )}
    </>
  );
}
