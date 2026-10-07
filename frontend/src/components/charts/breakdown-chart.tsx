"use client";

import { Bar, BarChart, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { count, percent } from "@/lib/format";

import { axisProps, Card, DataTable, TooltipBox, useViewToggle } from "@/components/ui/chart-parts";

/** Keep axis labels on one line. */
function shortName(name: string): string {
  return name.length > 36 ? `${name.slice(0, 35)}…` : name;
}

/** Counts per category, largest first. One measure, so one colour for every bar.
 *  ``format`` turns raw category names into readable ones. */
export function BreakdownChart({
  title,
  subtitle,
  tag,
  counts,
  color,
  empty,
  format = (name) => name,
}: {
  title: string;
  subtitle: string;
  tag?: string;
  counts: Record<string, number>;
  color: string;
  empty: string;
  format?: (name: string) => string;
}) {
  const { view, toggle } = useViewToggle();
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const rows = Object.entries(counts).map(([name, value]) => ({ name: format(name), value, share: total ? value / total : 0 }));

  return (
    <Card title={title} tag={tag} subtitle={subtitle} actions={rows.length ? toggle : undefined}>
      {rows.length === 0 ? (
        <p className="flex h-40 items-center justify-center px-6 text-center text-sm text-muted">{empty}</p>
      ) : view === "table" ? (
        <DataTable
          columns={[{ key: "name", label: "Kind" }, { key: "value", label: "How many", align: "right" }, { key: "share", label: "Share", align: "right" }]}
          rows={rows.map((r) => ({ name: r.name, value: count(r.value), share: percent(r.share, 1) }))}
        />
      ) : (
        <div style={{ height: rows.length * 30 + 8 }}>
          <ResponsiveContainer>
            <BarChart data={rows} layout="vertical" margin={{ top: 0, right: 56, bottom: 0, left: 0 }} barCategoryGap={6}>
              <XAxis type="number" hide domain={[0, "dataMax"]} />
              <YAxis type="category" dataKey="name" width={230} axisLine={false} interval={0}
                     tickFormatter={shortName} {...axisProps} />
              <Tooltip
                cursor={{ fill: "var(--wash)" }}
                isAnimationActive={false}
                content={({ active, payload }) => {
                  const row = payload?.[0]?.payload as (typeof rows)[number] | undefined;
                  return active && row ? (
                    <TooltipBox title={row.name} rows={[{ name: "of all", color, value: `${count(row.value)} · ${percent(row.share, 1)}` }]} />
                  ) : null;
                }}
              />
              <Bar dataKey="value" fill={color} barSize={14} radius={[0, 4, 4, 0]} isAnimationActive={false}>
                <LabelList dataKey="value" position="right" formatter={(v) => count(Number(v))} fill="var(--ink-secondary)" fontSize={11} />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </Card>
  );
}
