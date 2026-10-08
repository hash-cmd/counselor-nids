"use client";

import { useMemo, useState } from "react";

import { clock, count, percent } from "@/lib/format";
import { detectorName, ruleName } from "@/lib/plain";
import type { SnortAlert } from "@/lib/types";

import { Card } from "@/components/ui/chart-parts";
import { StatusBadge } from "@/components/ui/status-badge";

const AGREEMENT = {
  confirmed: { tone: "critical", label: "AI agrees: attack" },
  disputed: { tone: "warning", label: "AI thinks it's normal" },
  no_verdict: { tone: "neutral", label: "AI not sure" },
  unmatched: { tone: "neutral", label: "AI didn't see it" },
} as const;

export function SnortAlertsTable({ alerts }: { alerts: SnortAlert[] }) {
  const [filter, setFilter] = useState<"all" | SnortAlert["agreement"]>("all");
  const shown = useMemo(() => (filter === "all" ? alerts : alerts.filter((a) => a.agreement === filter)), [alerts, filter]);

  return (
    <Card
      title="Rule checker (Snort) alarms, and what the AI thinks"
      subtitle={`The latest ${count(shown.length)} alarms. For each one the AI gives its own opinion on the same connection.`}
      actions={
        <select
          value={filter}
          onChange={(e) => setFilter(e.target.value as typeof filter)}
          className="rounded-md border border-line bg-raised px-2 py-1 text-xs text-ink"
          aria-label="Filter by whether the AI agrees"
        >
          <option value="all">All alarms</option>
          {Object.entries(AGREEMENT).map(([key, a]) => (
            <option key={key} value={key}>
              {a.label}
            </option>
          ))}
        </select>
      }
    >
      {shown.length === 0 ? (
        <p className="py-10 text-center text-sm text-muted">
          No alarms from the rule checker yet.
        </p>
      ) : (
        <div className="max-h-[28rem] overflow-auto rounded-lg border border-line">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-raised text-left text-muted">
              <tr>
                <th className="px-3 py-2 font-medium">Time</th>
                <th className="px-3 py-2 font-medium">Rule that went off</th>
                <th className="px-3 py-2 font-medium">From → to</th>
                <th className="px-3 py-2 text-right font-medium">Connections</th>
                <th className="px-3 py-2 font-medium">AI&apos;s opinion</th>
                <th className="px-3 py-2 font-medium">Do they agree?</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((a) => (
                <tr key={a.id} className="border-t border-line align-top">
                  <td className="tabular px-3 py-1.5 text-ink-2">{clock(a.seconds)}</td>
                  <td className="px-3 py-1.5 text-ink">
                    {ruleName(a.msg)}
                    <span className="ml-1.5 text-muted" title="Snort rule id">
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
                        {a.flows > 1 && a.ml_share != null && ` (${percent(a.ml_share, 0)} of connections)`}
                        {a.ml_detector && (
                          <span className="text-muted" title="Which detector answered, and how often it is right">
                            {" "}· {detectorName(a.ml_detector)}, {percent(a.ml_confidence, 0)} reliable
                          </span>
                        )}
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
