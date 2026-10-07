import { count, percent, seriesColor } from "@/lib/format";
import { detectorKnows, detectorName } from "@/lib/plain";
import type { DetectorStats } from "@/lib/types";

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div>
      <p className="eyebrow">{label}</p>
      <p className="figure mt-1 text-2xl font-semibold text-ink">{value}</p>
      {hint && <p className="eyebrow mt-0.5 normal-case tracking-normal">{hint}</p>}
    </div>
  );
}

const TEAMWORK = [
  ["Unsure", "conflicts", "times its own checks disagreed"],
  ["Took advice", "advised", "times another detector settled it"],
  ["Double-checked", "cross_checked", "attacks caught only because another detector spoke up"],
  ["Learned from", "retrained_on", "connections it has since learned from"],
] as const;

export function DetectorTiles({ detectors }: { detectors: Record<string, DetectorStats> }) {
  const names = Object.keys(detectors);
  if (names.length === 0) {
    return (
      <div className="rounded-xl border border-dashed border-line bg-surface p-8 text-center text-sm text-ink-2">
        No detectors are running. Start a test on the Overview page to watch them work.
      </div>
    );
  }
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {names.map((name) => {
        const s = detectors[name];
        const knows = detectorKnows(name);
        return (
          <section key={name} className="rounded-xl border border-line bg-surface p-5">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-ink">
              <span className="inline-block size-2.5 rounded-sm" style={{ background: seriesColor(name, names) }} />
              {detectorName(name)}
            </h2>
            <p className="mb-4 mt-0.5 text-xs text-ink-2">{knows ? `Specialist in ${knows}.` : name}</p>
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <Stat label="Connections checked" value={count(s.samples)} />
              <Stat label="Attacks flagged" value={count(s.flagged)} />
              <Stat label="Verdicts right" value={percent(s.accuracy)} hint={s.accuracy == null ? "practice data only" : undefined} />
              <Stat label="Attacks caught" value={percent(s.detection_rate)} hint={s.detection_rate == null ? "practice data only" : undefined} />
            </div>
            <dl className="mt-4 grid grid-cols-2 gap-x-4 gap-y-2 border-t border-line pt-3 text-xs sm:grid-cols-4">
              {TEAMWORK.map(([label, key, hint]) => (
                <div key={key} title={hint}>
                  <dt className="text-muted">{label}</dt>
                  <dd className="tabular text-ink">{count(s[key])}</dd>
                </div>
              ))}
            </dl>
          </section>
        );
      })}
    </div>
  );
}
