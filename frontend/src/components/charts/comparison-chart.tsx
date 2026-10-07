"use client";

import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { percent, seriesColor } from "@/lib/format";
import { APPROACHES, detectorName } from "@/lib/plain";
import type { ComparisonRow } from "@/lib/types";

import { axisProps, Card, DataTable, Legend, TooltipBox, useViewToggle } from "@/components/ui/chart-parts";

export type Metric = "accuracy" | "detection_rate" | "false_alarm_rate";
export const METRIC_LABELS: Record<Metric, string> = {
  accuracy: "Verdicts right (higher is better)",
  detection_rate: "Attacks caught (higher is better)",
  false_alarm_rate: "False alarms (lower is better)",
};

/** One scenario: every approach (rows) for every detector (series), on one metric. */
export function ComparisonChart({
  title,
  subtitle,
  detectors,
  metric,
  note,
}: {
  title: string;
  subtitle?: string;
  detectors: Record<string, ComparisonRow[]>;
  metric: Metric;
  note?: React.ReactNode;
}) {
  const { view, toggle } = useViewToggle();
  const names = Object.keys(detectors);
  const approaches = detectors[names[0]]?.map((r) => ({ approach: r.approach, label: r.label })) ?? [];
  const data: Record<string, string | number | null>[] = approaches.map(({ approach, label }) => ({
    label: APPROACHES[approach] ?? label,
    ...Object.fromEntries(
      names.map((n) => [n, detectors[n].find((r) => r.approach === approach)?.[metric] ?? null]),
    ),
  }));
  const series = names.map((n) => ({ key: n, name: detectorName(n), color: seriesColor(n, names) }));

  return (
    <Card title={title} subtitle={subtitle} actions={toggle}>
      {view === "table" ? (
        <DataTable
          columns={[{ key: "label", label: "Method" }, ...names.map((n) => ({ key: n, label: detectorName(n), align: "right" as const }))]}
          rows={data.map((row) => ({
            label: row.label,
            ...Object.fromEntries(names.map((n) => [n, percent(row[n] as number | null)])),
          }))}
        />
      ) : (
        <>
          {series.length > 1 && <Legend items={series.map((s) => ({ ...s, shape: "rect" as const }))} />}
          <div style={{ height: data.length * (names.length * 14 + 14) + 32 }}>
            <ResponsiveContainer>
              <BarChart data={data} layout="vertical" margin={{ top: 0, right: 16, bottom: 0, left: 0 }} barGap={2} barCategoryGap={8}>
                <CartesianGrid horizontal={false} stroke="var(--grid)" />
                <XAxis type="number" domain={[0, 1]} tickFormatter={(v) => percent(v, 0)} {...axisProps} />
                <YAxis type="category" dataKey="label" width={250} axisLine={false} interval={0} {...axisProps} />
                <Tooltip
                  cursor={{ fill: "var(--wash)" }}
                  isAnimationActive={false}
                  content={({ active, label, payload }) =>
                    active && payload?.length ? (
                      <TooltipBox
                        title={String(label)}
                        rows={series.map((s) => ({
                          name: s.name,
                          color: s.color,
                          value: percent(payload.find((p) => p.dataKey === s.key)?.value as number | null),
                        }))}
                      />
                    ) : null
                  }
                />
                {series.map((s) => (
                  <Bar key={s.key} dataKey={s.key} fill={s.color} barSize={12} radius={[0, 4, 4, 0]} isAnimationActive={false} />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
        </>
      )}
      {note && <div className="mt-3 text-xs text-ink-2">{note}</div>}
    </Card>
  );
}
