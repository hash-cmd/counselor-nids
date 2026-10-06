"use client";

import { useMemo, useState } from "react";

import { clock, count, percent } from "@/lib/format";
import type { SnortAlert } from "@/lib/types";

import { Card } from "@/components/ui/chart-parts";
import { StatusBadge } from "@/components/ui/status-badge";

const AGREEMENT = {
  confirmed: { tone: "good", label: "Confirmed by ML" },
  disputed: { tone: "warning", label: "Disputed by ML" },
  no_verdict: { tone: "neutral", label: "No ML verdict" },
  unmatched: { tone: "neutral", label: "No matching flow" },
} as const;

export function SnortAlertsTable({ alerts }: { alerts: SnortAlert[] }) {
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
