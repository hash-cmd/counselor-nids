"use client";

import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { count, percent } from "@/lib/format";
import { attackName, detectorName } from "@/lib/plain";
import type { ByLabelTable } from "@/lib/types";

import { axisProps, Card, DataTable, Legend, TooltipBox, useViewToggle } from "@/components/ui/chart-parts";

const isBenign = (label: string) => label.toLowerCase() === "benign";
const rowName = (label: string) => (isBenign(label) ? "Normal traffic (false alarms)" : attackName(label));

/** "live_dos alone" -> "Flood detector alone"; "counselor network" -> the whole team. */
const seriesName = (name: string) =>
  name === "counselor network" ? "All detectors as a team" : name.replace(/^(\w+)( alone)$/, (_, d, rest) => detectorName(d) + rest);

/** Share of each attack type's test flows flagged, per detector set. The benign row is
 *  the false-alarm rate, so lower is better there and higher everywhere else. */
export function LabelChart({
  title,
  subtitle,
  table,
  note,
}: {
  title: string;
  subtitle: string;
  table: ByLabelTable;
  note?: React.ReactNode;
}) {
  const { view, toggle } = useViewToggle();
  // validated categorical slots in fixed order; series order is fixed by the experiment
  const series = table.series.map((key, i) => ({ key, name: seriesName(key), color: `var(--series-${(i % 4) + 1})` }));
  const data = table.rows.map((r) => ({ ...r, label: rowName(r.label) }));
  type Row = (typeof data)[number];

  return (
    <Card title={title} subtitle={subtitle} actions={toggle}>
      {view === "table" ? (
        <DataTable
          columns={[
            { key: "label", label: "Traffic" },
            { key: "flows", label: "Test connections", align: "right" },
            ...series.map((s) => ({ key: s.key, label: s.name, align: "right" as const })),
          ]}
          rows={data.map((d) => ({
            label: d.label,
            flows: count(d.flows),
            ...Object.fromEntries(series.map((s) => [s.key, percent(d.flagged[s.key], 1)])),
          }))}
        />
      ) : (
        <>
          <Legend items={series.map((s) => ({ ...s, shape: "rect" as const }))} />
          <div style={{ height: data.length * (series.length * 13 + 16) + 32 }}>
            <ResponsiveContainer>
              <BarChart data={data} layout="vertical" margin={{ top: 0, right: 16, bottom: 0, left: 0 }} barGap={2} barCategoryGap={8}>
                <CartesianGrid horizontal={false} stroke="var(--grid)" />
                <XAxis type="number" domain={[0, 1]} tickFormatter={(v) => percent(v, 0)} {...axisProps} />
                <YAxis type="category" dataKey="label" width={250} axisLine={false} interval={0} {...axisProps} />
                <Tooltip
                  cursor={{ fill: "var(--wash)" }}
                  isAnimationActive={false}
                  content={({ active, payload }) => {
                    const row = payload?.[0]?.payload as Row | undefined;
                    return active && row ? (
                      <TooltipBox
                        title={`${row.label} · ${count(row.flows)} test connections`}
                        rows={series.map((s) => ({
                          name: s.name,
                          color: s.color,
                          value: percent(row.flagged[s.key], 1),
                        }))}
                      />
                    ) : null;
                  }}
                />
                {series.map((s) => (
                  <Bar key={s.key} name={s.name} dataKey={(d: Row) => d.flagged[s.key]} fill={s.color} barSize={11} radius={[0, 4, 4, 0]} isAnimationActive={false} />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
        </>
      )}
      {Object.keys(table.summary).length > 0 && (
        <dl className="mt-3 grid gap-x-6 gap-y-1 border-t border-line pt-3 text-xs sm:grid-cols-2">
          {Object.entries(table.summary).map(([name, m]) => (
            <div key={name} className="flex flex-wrap gap-x-3">
              <dt className="font-medium text-ink">{seriesName(name)}</dt>
              <dd className="text-ink-2">
                verdicts right {percent(m.accuracy, 2)} · attacks caught {percent(m.detection_rate, 2)} · false alarms{" "}
                {percent(m.false_alarm_rate, 2)}
              </dd>
            </div>
          ))}
        </dl>
      )}
      {note && <div className="mt-3 text-xs text-ink-2">{note}</div>}
    </Card>
  );
}
