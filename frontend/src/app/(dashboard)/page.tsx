"use client";

import Link from "next/link";
import { useMemo } from "react";

import { BreakdownChart } from "@/components/charts/breakdown-chart";
import { DetectionTimeline, SOURCE_COLORS } from "@/components/charts/detection-timeline";
import { IncidentsTable } from "@/components/panels/incidents";
import { KpiStrip } from "@/components/panels/kpi-strip";
import { LiveStatus } from "@/components/panels/live-status";
import { AttackersPanel } from "@/components/panels/attackers";
import { FalseAlarms } from "@/components/panels/false-alarms";
import { OverlapChart } from "@/components/charts/overlap-chart";
import { TopSources } from "@/components/panels/top-sources";
import { buildIncidents } from "@/lib/incidents";
import { useFeedback } from "@/lib/feedback";
import { useLive } from "@/lib/live-feed";
import { detectorName, ruleName } from "@/lib/plain";

export default function OverviewPage() {
  const live = useLive();
  const feedback = useFeedback();
  const incidents = useMemo(() => buildIncidents(live.alerts, live.snortAlerts, feedback.verdicts), [live.alerts, live.snortAlerts, feedback.verdicts]);
  const breakdown = live.breakdown;
  // each flagged connection once, credited to the detector that recognised the attack
  // (a double-checked alarm belongs to the counselor, not to the detector that asked)
  const byDetector = useMemo(() => {
    const seen = new Set<string>();
    const counts: Record<string, number> = {};
    for (const a of live.alerts) {
      const origin = a.resolution === "cross_check" && a.counselor ? a.counselor : a.detector;
      const key = `${a.record_id}|${origin}`;
      if (seen.has(key)) continue;
      seen.add(key);
      counts[origin] = (counts[origin] ?? 0) + 1;
    }
    return counts;
  }, [live.alerts]);

  return (
    <>
      <LiveStatus live={live} />
      <KpiStrip live={live} incidents={incidents} />

      {/* Hero row: the activity timeline paired with the ranked top-risk side panel.
          Both are direct grid children so they stretch to the same height. */}
      <div className="grid items-stretch gap-4 lg:grid-cols-3">
        <DetectionTimeline className="flex flex-col lg:col-span-2" points={live.detectionRate} snort={live.snort != null} />
        <AttackersPanel incidents={incidents} limit={6} title="Top risks" className="flex flex-col" />
      </div>

      {/* Breakdowns side by side. */}
      <div className="grid gap-4 lg:grid-cols-2">
        <BreakdownChart
          title="AI: which detector raised the alarms"
          subtitle="Recent suspicious connections, by the specialist detector that recognised the attack"
          counts={byDetector}
          color={SOURCE_COLORS.ml}
          format={detectorName}
          empty="No AI alarms yet."
        />
        <BreakdownChart
          title="Rule checker (Snort): which rules went off"
          subtitle="Each alarm Snort raised, by the rule that triggered it"
          counts={breakdown?.snort_rules ?? {}}
          color={SOURCE_COLORS.snort}
          format={ruleName}
          empty={live.snort ? "No rule checker alarms yet." : "The rule checker runs on live traffic."}
        />
      </div>

      {/* Who-spotted overlap + top sources (only meaningful with packet traffic). */}
      {live.snort ? (
        <div className="grid gap-4 lg:grid-cols-2">
          <OverlapChart summary={live.snort} />
          <TopSources sources={breakdown?.sources ?? []} />
        </div>
      ) : (
        <TopSources sources={breakdown?.sources ?? []} />
      )}

      <FalseAlarms />

      <IncidentsTable
        incidents={incidents.slice(0, 10)}
        subtitle="The latest connections that looked like an attack. Click one to see what it means."
        footer={
          incidents.length > 0 && (
            <p className="mt-3 text-right text-sm">
              <Link href="/alerts" className="text-accent hover:underline">
                See and search all alerts →
              </Link>
            </p>
          )
        }
      />
    </>
  );
}
