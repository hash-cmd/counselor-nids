"use client";

import { useMemo, useState } from "react";
import { Bar, BarChart, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { clock, count, percent } from "@/lib/format";
import type { SnortAlert, SnortSummary } from "@/lib/types";

import { axisProps, Card, DataTable, TooltipBox, useViewToggle } from "./chart-parts";
import { StatusBadge } from "./status-badge";

const AGREEMENT = {
  confirmed: { tone: "good", label: "Confirmed by ML" },
  disputed: { tone: "warning", label: "Disputed by ML" },
  no_verdict: { tone: "neutral", label: "No ML verdict" },
  unmatched: { tone: "neutral", label: "No matching flow" },
} as const;

function Stat({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <div>
      <p className="text-xs text-ink-2">{label}</p>
      <p className="mt-0.5 text-2xl font-semibold text-ink">{value}</p>
      <p className="text-xs text-muted">{hint}</p>
    </div>
  );
}

/** Flagged flows by who flagged them. One measure, so one neutral colour for every bar. */
function OverlapChart({ summary }: { summary: SnortSummary }) {
  const { view, toggle } = useViewToggle();
  const total = summary.flows.both + summary.flows.snort_only + summary.flows.ml_only;
  const rows = [
    { name: "Both flagged", flows: summary.flows.both, hint: "Snort and the ML agree" },
    { name: "Snort only", flows: summary.flows.snort_only, hint: "ML did not flag the flow" },
    { name: "ML only", flows: summary.flows.ml_only, hint: "Snort had no alert for the flow" },
  ].map((r) => ({ ...r, share: total ? r.flows / total : 0 }));

  return (
    <Card title="Who flagged each flow" subtitle="Flows flagged by Snort, by the ML, or by both" actions={toggle}>
      {view === "table" ? (
        <DataTable
          columns={[
            { key: "name", label: "Flagged by" },
            { key: "flows", label: "Flows", align: "right" },
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
              <YAxis type="category" dataKey="name" width={112} axisLine={false} {...axisProps} />
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

function SnortAlertsTable({ alerts }: { alerts: SnortAlert[] }) {
  const [filter, setFilter] = useState<"all" | SnortAlert["agreement"]>("all");
  const shown = useMemo(() => (filter === "all" ? alerts : alerts.filter((a) => a.agreement === filter)), [alerts, filter]);

  return (
    <Card
      title="Snort alerts and the ML's verdict"
      subtitle={`Latest ${count(shown.length)} Snort alerts, each linked to its flow`}
      actions={
        <select
          value={filter}
          onChange={(e) => setFilter(e.target.value as typeof filter)}
          className="rounded-md border border-line bg-raised px-2 py-1 text-xs text-ink"
          aria-label="Filter by agreement"
        >
          <option value="all">All alerts</option>
          {Object.entries(AGREEMENT).map(([key, a]) => (
            <option key={key} value={key}>
              {a.label}
            </option>
          ))}
        </select>
      }
    >
      {shown.length === 0 ? (
        <p className="py-10 text-center text-sm text-muted">No Snort alerts yet.</p>
      ) : (
        <div className="max-h-[28rem] overflow-auto rounded-lg border border-line">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-raised text-left text-muted">
              <tr>
                <th className="px-3 py-2 font-medium">Time</th>
                <th className="px-3 py-2 font-medium">Snort rule</th>
                <th className="px-3 py-2 font-medium">Connection</th>
                <th className="px-3 py-2 text-right font-medium">Flows</th>
                <th className="px-3 py-2 font-medium">ML verdict</th>
                <th className="px-3 py-2 font-medium">Agreement</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((a) => (
                <tr key={a.id} className="border-t border-line align-top">
                  <td className="tabular px-3 py-1.5 text-ink-2">{clock(a.seconds)}</td>
                  <td className="px-3 py-1.5 text-ink">
                    {a.msg}
                    <span className="ml-1.5 text-muted">
                      {a.gid}:{a.sid}
                    </span>
                  </td>
                  <td className="tabular px-3 py-1.5 text-ink-2">
                    {a.src} → {a.dst}
                  </td>
                  <td className="tabular px-3 py-1.5 text-right text-ink-2">{count(a.flows)}</td>
                  <td className="px-3 py-1.5 text-ink-2">
                    {a.ml_verdict == null ? (
                      "—"
                    ) : (
                      <>
                        <span className="text-ink">{a.ml_verdict}</span>
                        {a.flows > 1 && a.ml_share != null && ` (${percent(a.ml_share, 0)} of flows)`}
                        {a.ml_detector && <span className="text-muted"> · {a.ml_detector} {percent(a.ml_confidence, 1)}</span>}
                      </>
                    )}
                  </td>
                  <td className="px-3 py-1.5">
                    <StatusBadge tone={AGREEMENT[a.agreement].tone} label={AGREEMENT[a.agreement].label} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

/** Snort and the ML on the same traffic: shown only while Snort results exist. */
export function SnortPanel({ summary, alerts }: { summary: SnortSummary | null; alerts: SnortAlert[] }) {
  if (!summary) return null;
  const decided = summary.confirmed + summary.disputed;
  return (
    <>
      <h2 className="pt-2 text-base font-semibold text-ink">Snort and the ML</h2>
      <section className="grid gap-4 rounded-xl border border-line bg-surface p-5 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Snort alerts" value={count(summary.alerts)} hint={summary.pending ? `${count(summary.pending)} waiting for their flow` : "all linked or resolved"} />
        <Stat label="Confirmed by ML" value={count(summary.confirmed)} hint={decided ? `${percent(summary.confirmed / decided, 1)} of alerts with a verdict` : "—"} />
        <Stat label="Disputed by ML" value={count(summary.disputed)} hint="Snort flagged, ML says normal" />
        <Stat label="Caught by ML only" value={count(summary.flows.ml_only)} hint="flows with no Snort alert" />
      </section>
      <OverlapChart summary={summary} />
      <SnortAlertsTable alerts={alerts} />
    </>
  );
}
