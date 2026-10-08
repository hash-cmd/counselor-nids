"use client";

import { count, percent } from "@/lib/format";
import { useFeedback } from "@/lib/feedback";
import { detectorName } from "@/lib/plain";

import { Card, DataTable } from "@/components/ui/chart-parts";
import { StatusBadge } from "@/components/ui/status-badge";

const when = (t: number) => new Date(t * 1000).toLocaleString("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });

/** Teach the AI from your verdicts: retrain behind the safety gate, and what came of it. */
export function TeachPanel() {
  const { summary, learning, learn, error } = useFeedback();
  const running = learning.state === "running";
  const report = learning.report;
  const rows = report ? Object.entries(report.detectors) : [];

  return (
    <Card
      title="Teach the AI from your verdicts"
      subtitle="Mark alarms as “Not an attack” or “Real attack” (open one on the Alerts page). The detectors then retrain on your verdicts. A retrained detector is only installed if it gets your marked connections more right and forgets nothing it knew. Running detectors switch to it within a minute, without a restart."
      actions={
        <button type="button" onClick={learn} disabled={running || summary.learnable === 0}
                title={summary.learnable === 0 ? "Mark some alarms first" : undefined}
                className="rounded-md bg-accent px-4 py-1.5 text-sm font-semibold text-[var(--accent-ink)] hover:opacity-90 disabled:opacity-50">
          {running ? "Learning…" : "Teach the AI"}
        </button>
      }
    >
      <div className="mb-4 flex flex-wrap gap-x-8 gap-y-2 text-sm text-ink-2">
        <span><span className="figure font-semibold text-ink">{count(summary.normal)}</span> marked not an attack</span>
        <span><span className="figure font-semibold text-ink">{count(summary.attack)}</span> marked real attacks</span>
        <span><span className="figure font-semibold text-ink">{count(summary.learnable)}</span> the AI can learn from</span>
      </div>
      {error && <p className="mb-3 text-sm text-critical">{error}</p>}
      {running && <p className="text-sm text-ink-2">Retraining the detectors (a few minutes)…</p>}
      {learning.state === "failed" && (
        <details className="text-xs text-ink-2">
          <summary className="cursor-pointer text-critical">Learning failed. Show the log</summary>
          <pre className="mt-2 overflow-auto rounded bg-wash p-2">{learning.error}</pre>
        </details>
      )}
      {!running && report && (report.message ? (
        <p className="text-sm text-muted">{report.message}</p>
      ) : (
        <>
          <p className="mb-2 text-xs text-muted">
            Last run{report.finished ? ` ${when(report.finished)}` : ""}, on {count(report.verdicts)} verdicts.{" "}
            {report.installed.length
              ? `Installed: ${report.installed.map(detectorName).join(", ")}.`
              : "No detector improved enough to be installed."}
          </p>
          <DataTable
            scroll={false}
            columns={[
              { key: "detector", label: "Detector" },
              { key: "marked", label: "Still flags “not an attack”", align: "right" },
              { key: "lab", label: "Lab attacks caught", align: "right" },
              { key: "fa", label: "Lab false alarms", align: "right" },
              { key: "result", label: "Result" },
            ]}
            rows={rows.map(([name, d]) => ({
              detector: detectorName(name),
              marked: `${count(d.marked_flagged_before)} → ${count(d.marked_flagged_after)}`,
              lab: `${percent(d.lab_detection[0], 2)} → ${percent(d.lab_detection[1], 2)}`,
              fa: `${percent(d.lab_false_alarms[0], 2)} → ${percent(d.lab_false_alarms[1], 2)}`,
              result: (
                <span className="flex flex-wrap items-center gap-2">
                  <StatusBadge tone={d.accepted ? "good" : "neutral"} label={d.accepted ? "Installed" : "Kept the old one"} />
                  {!d.accepted && <span className="text-muted">{d.problems.join("; ")}</span>}
                </span>
              ),
            }))}
          />
        </>
      ))}
    </Card>
  );
}
