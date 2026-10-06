"use client";

import Link from "next/link";
import { useMemo } from "react";

import { BreakdownBars } from "@/components/breakdown-bars";
import { DetectionTimeline, SOURCE_COLORS } from "@/components/detection-timeline";
import { IncidentsTable } from "@/components/incidents";
import { KpiStrip } from "@/components/kpi-strip";
import { ReplayControls } from "@/components/replay-controls";
import { OverlapChart } from "@/components/snort-panel";
import { TopSources } from "@/components/top-sources";
import { buildIncidents } from "@/lib/incidents";
import { useLive } from "@/lib/live";

export default function OverviewPage() {
  const live = useLive();
  const incidents = useMemo(() => buildIncidents(live.alerts, live.snortAlerts), [live.alerts, live.snortAlerts]);
  const breakdown = live.breakdown;

  return (
    <>
      <h1 className="text-xl font-semibold text-ink">Overview</h1>
      <ReplayControls status={live.replay} activity={live.activity} />
      <KpiStrip live={live} />

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <DetectionTimeline points={live.detectionRate} snort={live.snort != null} />
        </div>
        {live.snort ? <OverlapChart summary={live.snort} /> : <TopSources sources={breakdown?.sources ?? []} />}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <BreakdownBars
          title="Attack types caught by the ML"
          subtitle="Flagged flows by their true label"
          counts={breakdown?.ml_labels ?? {}}
          color={SOURCE_COLORS.ml}
          empty="True labels exist only for recorded flows (CICIDS2017); captures and live traffic are unlabelled."
        />
        <BreakdownBars
          title="Snort rules triggered"
          subtitle="Snort alerts by rule"
          counts={breakdown?.snort_rules ?? {}}
          color={SOURCE_COLORS.snort}
          empty="Snort runs on packet captures and live traffic. Choose “Packet capture + Snort” above."
        />
      </div>

      {live.snort && <TopSources sources={breakdown?.sources ?? []} />}

      <IncidentsTable
        incidents={incidents.slice(0, 10)}
        subtitle="Latest flagged flows, with what the ML and Snort said"
        footer={
          incidents.length > 0 && (
            <p className="mt-3 text-right text-sm">
              <Link href="/alerts" className="text-accent hover:underline">
                Search all incidents →
              </Link>
            </p>
          )
        }
      />
    </>
  );
}
