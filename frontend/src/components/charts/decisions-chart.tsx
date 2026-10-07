"use client";

import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { count, percent } from "@/lib/format";
import { detectorName, resolutionLabel, RESOLUTIONS } from "@/lib/plain";
import type { DetectorStats } from "@/lib/types";

import { axisProps, Card, DataTable, Legend, TooltipBox, useViewToggle } from "@/components/ui/chart-parts";

const PARTS = [
  { key: "unanimous", color: "var(--series-1)" },
  { key: "advice", color: "var(--series-2)" },
  { key: "cross_check", color: "var(--series-3)" },
  { key: "fallback", color: "var(--series-4)" },
] as const;
type PartKey = (typeof PARTS)[number]["key"];

function breakdown(s: DetectorStats) {
  const unanimous = s.samples - s.advised - s.cross_checked - s.fallback;
  return { unanimous, advice: s.advised, cross_check: s.cross_checked, fallback: s.fallback };
}

/** How each detector reached its decisions: alone, with counselor advice, by a
 *  cross-check override, or by falling back to its best local classifier. */
export function DecisionsChart({ detectors }: { detectors: Record<string, DetectorStats> }) {
  const { view, toggle } = useViewToggle();
  const rows = Object.entries(detectors).map(([key, s]) => {
    const name = detectorName(key);
    const parts = breakdown(s);
    const shares = Object.fromEntries(
      PARTS.map((p) => [p.key, s.samples ? parts[p.key] / s.samples : 0]),
    ) as Record<PartKey, number>;
    return { name, samples: s.samples, parts, shares, ...shares };
  });

  return (
    <Card
      title="How each detector made up its mind"
      tag="Fig.4 · Decisions"
      subtitle="Most verdicts should be made alone; the rest show the teamwork"
      actions={toggle}
    >
      {rows.length === 0 || rows.every((r) => r.samples === 0) ? (
        <p className="flex h-32 items-center justify-center text-sm text-muted">No decisions yet.</p>
      ) : view === "table" ? (
        <DataTable
          columns={[
            { key: "name", label: "Detector" },
            ...PARTS.map((p) => ({ key: p.key, label: resolutionLabel(p.key), align: "right" as const })),
          ]}
          rows={rows.map((r) => ({
            name: r.name,
            ...Object.fromEntries(PARTS.map((p) => [p.key, `${count(r.parts[p.key])} (${percent(r.shares[p.key], 1)})`])),
          }))}
        />
      ) : (
        <>
          <Legend items={PARTS.map((p) => ({ name: resolutionLabel(p.key), color: p.color, shape: "rect" as const }))} />
          <div style={{ height: rows.length * 44 + 28 }}>
            <ResponsiveContainer>
              <BarChart data={rows} layout="vertical" margin={{ top: 0, right: 8, bottom: 0, left: 0 }} barCategoryGap={10}>
                <XAxis type="number" domain={[0, 1]} tickFormatter={(v) => percent(v, 0)} {...axisProps} />
                <YAxis type="category" dataKey="name" width={112} axisLine={false} {...axisProps} />
                <Tooltip
                  cursor={{ fill: "var(--wash)" }}
                  isAnimationActive={false}
                  content={({ active, payload }) => {
                    const row = payload?.[0]?.payload as (typeof rows)[number] | undefined;
                    return active && row ? (
                      <TooltipBox
                        title={row.name}
                        rows={PARTS.map((p) => ({
                          name: resolutionLabel(p.key),
                          color: p.color,
                          value: `${percent(row.shares[p.key], 1)} · ${count(row.parts[p.key])}`,
                        }))}
                      />
                    ) : null;
                  }}
                />
                {PARTS.map((p) => (
                  <Bar
                    key={p.key}
                    dataKey={p.key}
                    stackId="decisions"
                    fill={p.color}
                    stroke="var(--surface)"
                    strokeWidth={2}
                    isAnimationActive={false}
                  />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
        </>
      )}
      <dl className="mt-4 grid gap-x-6 gap-y-1 border-t border-line pt-3 text-xs sm:grid-cols-2">
        {PARTS.map((p) => (
          <div key={p.key} className="flex gap-1.5">
            <dt className="font-medium text-ink">{resolutionLabel(p.key)}:</dt>
            <dd className="text-ink-2">{RESOLUTIONS[p.key].meaning}</dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}
