import { count, percent } from "@/lib/format";
import type { LiveState } from "@/lib/live-feed";

function Kpi({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="min-w-0">
      <p className="truncate text-xs text-ink-2">{label}</p>
      <p className="mt-0.5 text-2xl font-semibold text-ink">{value}</p>
      {hint && <p className="truncate text-xs text-muted">{hint}</p>}
    </div>
  );
}

/** Headline numbers across all detectors and Snort. */
export function KpiStrip({ live }: { live: LiveState }) {
  const detectors = Object.values(live.detectors);
  const flows = Math.max(0, ...detectors.map((d) => d.samples));
  const flagged = live.breakdown?.ml_flagged_flows ?? 0;
  const withTruth = detectors.filter((d) => d.accuracy != null);
  const best = withTruth.length ? withTruth.reduce((a, b) => ((a.accuracy ?? 0) >= (b.accuracy ?? 0) ? a : b)) : null;
  const snort = live.snort;
  const decided = snort ? snort.confirmed + snort.disputed : 0;

  return (
    <section className="grid grid-cols-2 gap-x-6 gap-y-4 rounded-xl border border-line bg-surface p-5 md:grid-cols-3 xl:grid-cols-6">
      <Kpi label="Flows analysed" value={count(flows)} hint={`${detectors.length} detector${detectors.length === 1 ? "" : "s"}`} />
      <Kpi label="Flagged by the ML" value={count(flagged)} hint={flows ? `${percent(flagged / flows, 1)} of flows` : undefined} />
      <Kpi label="Snort alerts" value={snort ? count(snort.alerts) : "—"} hint={snort ? `${count(snort.flows.both + snort.flows.snort_only)} flows` : "packet captures only"} />
      <Kpi
        label="ML agrees with Snort"
        value={decided ? percent(snort!.confirmed / decided, 1) : "—"}
        hint={decided ? `${count(snort!.confirmed)} of ${count(decided)} alerts` : undefined}
      />
      <Kpi label="Accuracy" value={best ? percent(best.accuracy) : "—"} hint={best ? "best detector, vs. true labels" : "needs labelled traffic"} />
      <Kpi label="Detection rate" value={best ? percent(best.detection_rate) : "—"} hint={best ? "attacks caught" : "needs labelled traffic"} />
    </section>
  );
}
