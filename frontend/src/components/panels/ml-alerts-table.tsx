"use client";

import { useMemo, useState } from "react";

import { count } from "@/lib/format";
import { attackName, detectorName, resolutionLabel, RESOLUTIONS } from "@/lib/plain";
import type { Alert } from "@/lib/types";

import { Card } from "@/components/ui/chart-parts";

export function MlAlertsTable({ alerts, detectors }: { alerts: Alert[]; detectors: string[] }) {
  const [detector, setDetector] = useState("all");
  const shown = useMemo(
    () => (detector === "all" ? alerts : alerts.filter((a) => a.detector === detector)),
    [alerts, detector],
  );

  return (
    <Card
      title="What each AI detector flagged"
      subtitle={`The latest ${count(shown.length)} connections the AI called an attack, and how it decided`}
      actions={
        <select
          value={detector}
          onChange={(e) => setDetector(e.target.value)}
          className="rounded-md border border-line bg-raised px-2 py-1 text-xs text-ink"
          aria-label="Filter by detector"
        >
          <option value="all">All AI detectors</option>
          {detectors.map((d) => (
            <option key={d} value={d}>
              {detectorName(d)}
            </option>
          ))}
        </select>
      }
    >
      {shown.length === 0 ? (
        <p className="py-10 text-center text-sm text-muted">The AI hasn&apos;t flagged anything yet.</p>
      ) : (
        <div className="max-h-[28rem] overflow-auto rounded-lg border border-line">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-raised text-left text-muted">
              <tr>
                <th className="px-3 py-2 font-medium">Connection</th>
                <th className="px-3 py-2 font-medium">Detector</th>
                <th className="px-3 py-2 font-medium">How it decided</th>
                <th className="px-3 py-2 font-medium">Advice came from</th>
                <th className="px-3 py-2 font-medium">What it really was</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((a) => (
                <tr key={`${a.detector}-${a.id}`} className="border-t border-line">
                  <td className="tabular px-3 py-1.5 text-ink-2">#{a.record_id}</td>
                  <td className="px-3 py-1.5 text-ink">{detectorName(a.detector)}</td>
                  <td className="px-3 py-1.5 text-ink-2" title={RESOLUTIONS[a.resolution]?.meaning}>{resolutionLabel(a.resolution)}</td>
                  <td className="px-3 py-1.5 text-ink-2">{a.counselor ? detectorName(a.counselor) : "—"}</td>
                  <td className="px-3 py-1.5">
                    {a.label == null ? (
                      <span className="text-muted">not known</span>
                    ) : a.label.toLowerCase() === "benign" ? (
                      <span className="text-critical">Normal traffic: a false alarm</span>
                    ) : (
                      <span className="text-ink">{attackName(a.label)}</span>
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
