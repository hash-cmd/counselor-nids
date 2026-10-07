"use client";

import Link from "next/link";
import { useMemo } from "react";

import { BreakdownChart } from "@/components/charts/breakdown-chart";
import { DetectionTimeline, SOURCE_COLORS } from "@/components/charts/detection-timeline";
import { IncidentsTable } from "@/components/panels/incidents";
import { KpiStrip } from "@/components/panels/kpi-strip";
import { TrafficControls } from "@/components/panels/traffic-controls";
import { AttackersPanel } from "@/components/panels/attackers";
import { OverlapChart } from "@/components/charts/overlap-chart";
import { TopSources } from "@/components/panels/top-sources";
import { buildIncidents } from "@/lib/incidents";
import { useLive } from "@/lib/live-feed";
import { attackName, ruleName } from "@/lib/plain";

/** What the dashboard is, for someone seeing it for the first time. */
function HowItWorks() {
  return (
    <details className="rounded-xl border border-line bg-surface p-5 text-sm text-ink-2">
      <summary className="cursor-pointer font-semibold text-ink">How this works</summary>
      <div className="mt-3 space-y-2">
        <p>
          Every time two computers talk over the network, that conversation is a <strong>connection</strong>.
          This system checks each connection for signs of an attack, in two independent ways:
        </p>
        <ul className="list-disc space-y-1 pl-5">
          <li>
            <strong className="text-ink">The AI</strong> learned from thousands of real attacks what attack traffic
            looks like (its size, speed and timing), and spots new connections that look the same. It is a team of
            specialist detectors that ask each other for advice when unsure.
          </li>
          <li>
            <strong className="text-ink">The rule checker (Snort)</strong> is a widely used security tool. It looks
            inside the traffic for known attack patterns, like a virus scanner does.
          </li>
        </ul>
        <p>
          When both raise an alarm about the same connection, it is very likely a real attack. When only one
          does, it is worth a look: it could be a false alarm, or something only that method can see.
        </p>
      </div>
    </details>
  );
}

export default function OverviewPage() {
  const live = useLive();
  const incidents = useMemo(() => buildIncidents(live.alerts, live.snortAlerts), [live.alerts, live.snortAlerts]);
  const breakdown = live.breakdown;

  return (
    <>
      <HowItWorks />
      <TrafficControls status={live.replay} activity={live.activity} />
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
          title="Kinds of attack the AI caught"
          tag="Fig.5 · By type"
          subtitle="Flagged connections, by the attack they really were"
          counts={breakdown?.ml_labels ?? {}}
          color={SOURCE_COLORS.ml}
          format={attackName}
          empty="The real attack type is only known for the practice data. Recorded and live traffic come without answers."
        />
        <BreakdownChart
          title="Rule checker (Snort): which rules went off"
          tag="Fig.6 · By rule"
          subtitle="Each alarm Snort raised, by the rule that triggered it"
          counts={breakdown?.snort_rules ?? {}}
          color={SOURCE_COLORS.snort}
          format={ruleName}
          empty="The rule checker runs on recorded or live traffic. Choose “Recorded network traffic” above."
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
