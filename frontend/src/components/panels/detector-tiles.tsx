import { count, percent, seriesColor } from "@/lib/format";
import type { DetectorStats } from "@/lib/types";

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div>
      <p className="text-xs text-ink-2">{label}</p>
      <p className="mt-0.5 text-2xl font-semibold text-ink">{value}</p>
      {hint && <p className="text-xs text-muted">{hint}</p>}
    </div>
  );
}

export function DetectorTiles({ detectors }: { detectors: Record<string, DetectorStats> }) {
  const names = Object.keys(detectors);
  if (names.length === 0) {
    return (
      <div className="rounded-xl border border-dashed border-line bg-surface p-8 text-center text-sm text-ink-2">
        No detectors are running. Start a replay above to watch them work.
      </div>
    );
  }
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {names.map((name) => {
        const s = detectors[name];
        return (
          <section key={name} className="rounded-xl border border-line bg-surface p-5">
            <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold text-ink">
              <span className="inline-block size-2.5 rounded-sm" style={{ background: seriesColor(name, names) }} />
              {name}
            </h2>
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <Stat label="Flows analysed" value={count(s.samples)} />
              <Stat label="Attacks flagged" value={count(s.flagged)} />
              <Stat label="Accuracy" value={percent(s.accuracy)} />
              <Stat label="Detection rate" value={percent(s.detection_rate)} />
            </div>
            <dl className="mt-4 grid grid-cols-2 gap-x-4 gap-y-1 border-t border-line pt-3 text-xs sm:grid-cols-4">
              {[
                ["Conflicts", s.conflicts],
                ["Advised", s.advised],
                ["Cross-checked", s.cross_checked],
                ["Retrained on", s.retrained_on],
              ].map(([label, value]) => (
                <div key={label as string}>
                  <dt className="text-muted">{label}</dt>
                  <dd className="tabular text-ink">{count(value as number)}</dd>
                </div>
              ))}
            </dl>
          </section>
        );
      })}
    </div>
  );
}
