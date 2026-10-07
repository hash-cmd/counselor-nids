"use client";

import { Bar, BarChart, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { count, percent } from "@/lib/format";
import type { SnortSummary } from "@/lib/types";

import { axisProps, Card, DataTable, TooltipBox, useViewToggle } from "@/components/ui/chart-parts";

/** Flagged flows by who flagged them. One measure, so one neutral colour for every bar. */
export function OverlapChart({ summary }: { summary: SnortSummary }) {
  const { view, toggle } = useViewToggle();
  const total = summary.flows.both + summary.flows.snort_only + summary.flows.ml_only;
  const rows = [
    { name: "Both", flows: summary.flows.both, hint: "The AI and the rule checker agree: very likely a real attack" },
    { name: "Only rule checker", flows: summary.flows.snort_only, hint: "A false alarm, or an attack the AI never learned about" },
    { name: "Only the AI", flows: summary.flows.ml_only, hint: "No rule matched, but the traffic behaves like an attack" },
  ].map((r) => ({ ...r, share: total ? r.flows / total : 0 }));

  return (
    <Card title="Who spotted it" tag="Fig.2 · Overlap" subtitle="Suspicious connections, by which method raised the alarm" actions={toggle}>
      {view === "table" ? (
        <DataTable
          columns={[
            { key: "name", label: "Spotted by" },
            { key: "flows", label: "Connections", align: "right" },
            { key: "share", label: "Share", align: "right" },
            { key: "hint", label: "Meaning" },
          ]}
          rows={rows.map((r) => ({ ...r, flows: count(r.flows), share: percent(r.share, 1) }))}
        />
      ) : (
        <div className="h-40">
          <ResponsiveContainer>
            <BarChart data={rows} layout="vertical" margin={{ top: 0, right: 64, bottom: 0, left: 0 }} barCategoryGap={10}>
              <XAxis type="number" hide domain={[0, "dataMax"]} />
              <YAxis type="category" dataKey="name" width={124} axisLine={false} {...axisProps} />
              <Tooltip
                cursor={{ fill: "var(--wash)" }}
                isAnimationActive={false}
                content={({ active, payload }) => {
                  const row = payload?.[0]?.payload as (typeof rows)[number] | undefined;
                  return active && row ? (
                    <TooltipBox
                      title={row.hint}
                      rows={[{ name: row.name, color: "var(--ink-secondary)", value: `${count(row.flows)} · ${percent(row.share, 1)}` }]}
                    />
                  ) : null;
                }}
              />
              <Bar dataKey="flows" fill="var(--ink-secondary)" barSize={18} radius={[0, 4, 4, 0]} isAnimationActive={false}>
                <LabelList dataKey="flows" position="right" formatter={(v) => count(Number(v))} fill="var(--ink)" fontSize={12} />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </Card>
  );
}
