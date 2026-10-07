"use client";

import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { percent } from "@/lib/format";
import { detectorName } from "@/lib/plain";
import type { SelfLearningRow } from "@/lib/types";

import { axisProps, Card, DataTable, Legend, TooltipBox, useViewToggle } from "@/components/ui/chart-parts";

const SERIES = [
  { key: "frozen", name: "Never learns", color: "var(--series-1)" },
  { key: "cross_check", name: "Learns, with double-checking (this system)", color: "var(--series-2)" },
  { key: "conflicts_only", name: "Learns only when unsure (research paper)", color: "var(--series-3)" },
] as const;

type Point = { chunk: number; labels: string } & Partial<Record<(typeof SERIES)[number]["key"], number>>;

function points(variants: Record<string, SelfLearningRow[]>, detector: string): Point[] {
  const byChunk = new Map<number, Point>();
  const take = (rows: SelfLearningRow[] | undefined, retrain: boolean, key: (typeof SERIES)[number]["key"]) => {
    for (const r of rows ?? []) {
      if (r.detector !== detector || r.retrain !== retrain) continue;
      const point = byChunk.get(r.chunk) ?? { chunk: r.chunk, labels: r.labels };
      point[key] = r.standalone_accuracy;
      byChunk.set(r.chunk, point);
    }
  };
  take(variants.cross_check ?? variants.conflicts_only, false, "frozen");
  take(variants.cross_check, true, "cross_check");
  take(variants.conflicts_only, true, "conflicts_only");
  return [...byChunk.values()].sort((a, b) => a.chunk - b.chunk);
}

/** Small multiples: one chart per detector, same y-scale. */
export function SelfLearningChart({ variants }: { variants: Record<string, SelfLearningRow[]> }) {
  const { view, toggle } = useViewToggle();
  const detectors = [...new Set(Object.values(variants).flat().map((r) => r.detector))].sort();
  const present = SERIES.filter((s) => s.key === "frozen" || variants[s.key]);

  return (
    <Card
      title="Learning on the job: each detector's own verdicts over time"
      subtitle="How often each detector is right by itself (before asking anyone), as new kinds of attack arrive. Rising lines mean it learned from the others' advice."
      actions={toggle}
    >
      <Legend items={present.map((s) => ({ name: s.name, color: s.color, shape: "line" as const }))} />
      <div className="grid gap-6 md:grid-cols-2">
        {detectors.map((detector) => {
          const data = points(variants, detector);
          return (
            <div key={detector}>
              <h3 className="mb-2 text-xs font-semibold text-ink">{detectorName(detector)}</h3>
              {view === "table" ? (
                <DataTable
                  columns={[
                    { key: "chunk", label: "Batch" },
                    { key: "labels", label: "Traffic" },
                    ...present.map((s) => ({ key: s.key, label: s.name, align: "right" as const })),
                  ]}
                  rows={data.map((p) => ({
                    chunk: p.chunk,
                    labels: p.labels,
                    ...Object.fromEntries(present.map((s) => [s.key, percent(p[s.key] ?? null, 1)])),
                  }))}
                />
              ) : (
                <div className="h-56">
                  <ResponsiveContainer>
                    <LineChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
                      <CartesianGrid vertical={false} stroke="var(--grid)" />
                      <XAxis dataKey="chunk" {...axisProps} />
                      <YAxis width={44} domain={[0, 1]} tickFormatter={(v) => percent(v, 0)} axisLine={false} {...axisProps} />
                      <Tooltip
                        cursor={{ stroke: "var(--axis)", strokeWidth: 1 }}
                        isAnimationActive={false}
                        content={({ active, payload }) => {
                          const p = payload?.[0]?.payload as Point | undefined;
                          return active && p ? (
                            <TooltipBox
                              title={`Batch ${p.chunk} · ${p.labels}`}
                              rows={present.map((s) => ({ name: s.name, color: s.color, value: percent(p[s.key] ?? null, 1) }))}
                            />
                          ) : null;
                        }}
                      />
                      {present.map((s) => (
                        <Line
                          key={s.key}
                          dataKey={s.key}
                          stroke={s.color}
                          strokeWidth={2}
                          dot={{ r: 4, fill: s.color, stroke: "var(--surface)", strokeWidth: 2 }}
                          activeDot={{ r: 5, stroke: "var(--surface)", strokeWidth: 2 }}
                          isAnimationActive={false}
                        />
                      ))}
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </Card>
  );
}
