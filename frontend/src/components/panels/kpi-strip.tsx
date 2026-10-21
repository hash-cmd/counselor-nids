import { count, percent } from "@/lib/format";
import type { LiveState } from "@/lib/live-feed";
import type { Incident } from "@/lib/incidents";
import { severityCounts, TIER_META, type Tier } from "@/lib/severity";

function Kpi({ label, value, unit, hint }: { label: string; value: string; unit?: string; hint?: string }) {
  return (
    <div className="min-w-0 px-4 py-4 sm:border-l sm:border-line sm:first:border-l-0 sm:first:pl-0">
      <p className="eyebrow">{label}</p>
      <p className="figure mt-2 text-[28px] font-semibold leading-none text-ink">
        {value}
        {unit && <span className="ml-0.5 text-base font-medium text-muted">{unit}</span>}
      </p>
      {hint && <p className="mt-2 text-xs leading-snug text-muted">{hint}</p>}
    </div>
  );
}

/** Split "357.6%" into the number and a unit suffix for the big-figure treatment. */
function split(value: string): { value: string; unit?: string } {
  const m = value.match(/^([\d.,—-]+)(.*)$/);
  return m && m[2] ? { value: m[1], unit: m[2] } : { value };
}

const TIER_ORDER: Tier[] = ["critical", "high", "medium", "low"];

/** One line answering "is anything wrong?", with a severity breakdown, before any number. */
function Verdict({ checked, suspicious, running, incidents }: {
  checked: number; suspicious: number; running: boolean; incidents: Incident[];
}) {
  if (checked === 0) {
    return (
      <p className="text-sm text-ink-2">
        {running ? "Waiting for the first connections…" : "Nothing is being watched right now. Start live monitoring to check your network."}
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
      <span className="flex flex-wrap items-center gap-1.5">
        {incidents.length < suspicious && (
          <span className="text-xs text-muted">latest {count(incidents.length)}:</span>
        )}
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
  const snort = live.snort;
  const decided = snort ? snort.confirmed + snort.disputed : 0;
  const suspicious = flagged + (snort ? snort.flows.snort_only : 0);

  const cells = [
    { label: "Connections checked", ...split(count(flows)), hint: `by ${detectors.length} AI detector${detectors.length === 1 ? "" : "s"}` },
    { label: "Flagged by the AI", ...split(count(flagged)), hint: flows ? `${percent(flagged / flows, 1)} of connections` : undefined },
    { label: "Rule checker alarms", ...split(snort ? count(snort.alerts) : "—"),
      hint: snort
        ? `on ${count(snort.flows.both + snort.flows.snort_only)} connections` +
          (snort.unmatched ? ` · ${count(snort.unmatched)} not tied to one (e.g. ICMP, IPv6)` : "")
        : "recorded or live only" },
    { label: "AI agrees with rule checker", ...split(decided ? percent(snort!.confirmed / decided, 1) : "—"),
      hint: decided ? `${count(snort!.confirmed)} of ${count(decided)} alarms` : undefined },
  ];

  return (
    <section className="rounded-2xl border border-line bg-surface p-5 shadow-[var(--shadow)]">
      <Verdict checked={flows} suspicious={suspicious} running={live.activity === "running"} incidents={incidents} />
      <div className="mt-4 grid grid-cols-2 border-t border-line pt-2 xl:grid-cols-4">
        {cells.map((c) => (
          <Kpi key={c.label} label={c.label} value={c.value} unit={c.unit} hint={c.hint} />
        ))}
      </div>
    </section>
  );
}
