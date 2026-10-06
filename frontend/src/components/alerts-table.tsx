"use client";

import { useMemo, useState } from "react";

import { count, RESOLUTION_LABELS } from "@/lib/format";
import type { Alert } from "@/lib/types";

import { Card } from "./chart-parts";

export function AlertsTable({ alerts, detectors }: { alerts: Alert[]; detectors: string[] }) {
  const [detector, setDetector] = useState("all");
  const shown = useMemo(
    () => (detector === "all" ? alerts : alerts.filter((a) => a.detector === detector)),
    [alerts, detector],
  );

  return (
    <Card
      title="Attack alerts"
      subtitle={`Latest ${count(shown.length)} flows flagged as attacks`}
      actions={
        <select
          value={detector}
          onChange={(e) => setDetector(e.target.value)}
          className="rounded-md border border-line bg-raised px-2 py-1 text-xs text-ink"
          aria-label="Filter by detector"
        >
          <option value="all">All detectors</option>
          {detectors.map((d) => (
            <option key={d} value={d}>
              {d}
            </option>
          ))}
        </select>
      }
    >
      {shown.length === 0 ? (
        <p className="py-10 text-center text-sm text-muted">No alerts yet.</p>
      ) : (
        <div className="max-h-[28rem] overflow-auto rounded-lg border border-line">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-raised text-left text-muted">
              <tr>
                <th className="px-3 py-2 font-medium">Flow</th>
                <th className="px-3 py-2 font-medium">Detector</th>
                <th className="px-3 py-2 font-medium">Decided by</th>
                <th className="px-3 py-2 font-medium">Counselor</th>
                <th className="px-3 py-2 font-medium">True label</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((a) => (
                <tr key={`${a.detector}-${a.id}`} className="border-t border-line">
                  <td className="tabular px-3 py-1.5 text-ink-2">#{a.record_id}</td>
                  <td className="px-3 py-1.5 text-ink">{a.detector}</td>
                  <td className="px-3 py-1.5 text-ink-2">{RESOLUTION_LABELS[a.resolution] ?? a.resolution}</td>
                  <td className="px-3 py-1.5 text-ink-2">{a.counselor ?? "—"}</td>
                  <td className="px-3 py-1.5">
                    {a.label == null ? (
                      <span className="text-muted">unknown</span>
                    ) : a.label === "BENIGN" ? (
                      <span className="text-critical">BENIGN · false alarm</span>
                    ) : (
                      <span className="text-ink">{a.label}</span>
                    )}
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
