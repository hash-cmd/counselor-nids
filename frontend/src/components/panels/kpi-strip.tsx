import { count, percent } from "@/lib/format";
import type { LiveState } from "@/lib/live-feed";
import type { Incident } from "@/lib/incidents";
import { severityCounts, TIER_META, type Tier } from "@/lib/severity";

function Kpi({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="min-w-0">
      <p className="text-xs text-ink-2">{label}</p>
      <p className="mt-0.5 text-2xl font-semibold text-ink">{value}</p>
      {hint && <p className="text-xs text-muted">{hint}</p>}
    </div>
  );
}

const TIER_ORDER: Tier[] = ["critical", "high", "medium", "low"];

/** One line answering "is anything wrong?", with a severity breakdown, before any number. */
function Verdict({ checked, suspicious, running, incidents }: {
  checked: number; suspicious: number; running: boolean; incidents: Incident[];
}) {
  if (checked === 0) {
    return (
      <p className="text-sm text-ink-2">
        {running ? "Waiting for the first connections…" : "Nothing is being watched right now. Start a test above, or a live capture."}
      </p>
    );
  }
  if (suspicious === 0) {
    return (
      <p className="text-base font-semibold text-good">
        All clear: {count(checked)} connections checked, none looked like an attack.
      </p>
    );
  }
  const counts = severityCounts(incidents);
  const worst = TIER_ORDER.find((t) => counts[t] > 0);
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
      <p className="text-base font-semibold" style={{ color: worst ? TIER_META[worst].color : "var(--critical-text)" }}>
        {count(suspicious)} suspicious connection{suspicious === 1 ? "" : "s"} out of {count(checked)} checked.
      </p>
      <span className="flex flex-wrap gap-1.5">
        {TIER_ORDER.filter((t) => counts[t] > 0).map((t) => (
          <span key={t} className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium"
                style={{ background: `color-mix(in srgb, ${TIER_META[t].color} 16%, transparent)`, color: TIER_META[t].color }}>
            {counts[t]} {TIER_META[t].label}
          </span>
        ))}
      </span>
    </div>
  );
}

/** Headline numbers across all detectors and Snort. */
export function KpiStrip({ live, incidents }: { live: LiveState; incidents: Incident[] }) {
  const detectors = Object.values(live.detectors);
  const flows = Math.max(0, ...detectors.map((d) => d.samples));
  const flagged = live.breakdown?.ml_flagged_flows ?? 0;
  const withTruth = detectors.filter((d) => d.accuracy != null);
  const best = withTruth.length ? withTruth.reduce((a, b) => ((a.accuracy ?? 0) >= (b.accuracy ?? 0) ? a : b)) : null;
  const snort = live.snort;
  const decided = snort ? snort.confirmed + snort.disputed : 0;
  const suspicious = flagged + (snort ? snort.flows.snort_only : 0);

  return (
    <section className="rounded-xl border border-line bg-surface p-5">
      <Verdict checked={flows} suspicious={suspicious} running={live.activity === "running"} incidents={incidents} />
      <div className="mt-4 grid grid-cols-2 gap-x-6 gap-y-4 border-t border-line pt-4 md:grid-cols-3 xl:grid-cols-6">
        <Kpi label="Connections checked" value={count(flows)} hint={`by ${detectors.length} AI detector${detectors.length === 1 ? "" : "s"}`} />
        <Kpi label="Flagged by the AI" value={count(flagged)} hint={flows ? `${percent(flagged / flows, 1)} of connections` : undefined} />
        <Kpi
          label="Rule checker alarms"
          value={snort ? count(snort.alerts) : "—"}
          hint={snort ? `on ${count(snort.flows.both + snort.flows.snort_only)} connections` : "recorded or live traffic only"}
        />
        <Kpi
          label="AI agrees with the rule checker"
          value={decided ? percent(snort!.confirmed / decided, 1) : "—"}
          hint={decided ? `${count(snort!.confirmed)} of ${count(decided)} alarms` : undefined}
        />
        <Kpi
          label="AI verdicts that were right"
          value={best ? percent(best.accuracy) : "—"}
          hint={best ? "best detector" : "known only for practice data"}
        />
        <Kpi
          label="Attacks the AI caught"
          value={best ? percent(best.detection_rate) : "—"}
          hint={best ? "out of all real attacks" : "known only for practice data"}
        />
      </div>
    </section>
  );
}
