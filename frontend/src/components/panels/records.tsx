"use client";

import { useCallback, useEffect, useState } from "react";

import { Card, DataTable } from "@/components/ui/chart-parts";
import { StatusBadge } from "@/components/ui/status-badge";
import { API_URL, api } from "@/lib/api";
import { clock, count } from "@/lib/format";

type RecordFile = { name: string; kind: string; bytes: number; rows: number; modified: number };
type RecordsPage = { records: RecordFile[]; recording: boolean };

const KIND_LABEL: Record<string, string> = {
  connections: "Connections", alerts: "AI alerts", snort: "Snort alerts",
};

function size(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

/** The durable CSV files written by the recorder service, with a download button each.
 *  Nothing beyond the live rolling window is lost; these are the record for a report. */
export function RecordsCard() {
  const [data, setData] = useState<RecordsPage | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => api<RecordsPage>("/records/").then(setData).catch((e) => setError(e.message)), []);
  useEffect(() => {
    let live = true;
    const tick = () => live && load();
    tick();
    const t = setInterval(tick, 10000); // files grow slowly; a gentle refresh is enough
    return () => {
      live = false;
      clearInterval(t);
    };
  }, [load]);

  // cookie-authenticated fetch -> blob, so the download carries the session like any other request
  const download = useCallback(async (name: string) => {
    const res = await fetch(`${API_URL}/api/records/?name=${encodeURIComponent(name)}`, {
      credentials: "include",
      headers: { "X-NIDS-Client": "web" },
    });
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  }, []);

  return (
    <Card
      title="Recorded files (CSV)"
      subtitle={
        data?.recording
          ? "Recording is on — every connection and alert is being saved to dated CSV files you can download here."
          : "Durable CSV record of every connection and alert. Start monitoring with NIDS_RECORD=1 to keep recording."
      }
      actions={data ? <StatusBadge tone={data.recording ? "good" : "neutral"} label={data.recording ? "Recording" : "Not recording"} /> : undefined}
    >
      {error ? (
        <p className="text-sm text-critical">Could not load records: {error}</p>
      ) : !data ? (
        <p className="text-sm text-muted">Loading…</p>
      ) : data.records.length === 0 ? (
        <p className="py-6 text-center text-sm text-muted">
          No records yet. They appear once monitoring runs with recording on
          (<span className="font-mono">NIDS_RECORD=1</span>), and the connections file needs the live‑traffic feed on.
        </p>
      ) : (
        <DataTable
          columns={[
            { key: "file", label: "File" },
            { key: "rows", label: "Rows", align: "right" },
            { key: "size", label: "Size", align: "right" },
            { key: "updated", label: "Updated" },
            { key: "dl", label: "" },
          ]}
          rows={data.records.map((r) => ({
            file: (
              <span>
                {KIND_LABEL[r.kind] ?? r.kind}
                <span className="block font-mono text-xs text-muted">{r.name}</span>
              </span>
            ),
            rows: count(r.rows),
            size: size(r.bytes),
            updated: clock(r.modified),
            dl: (
              <button
                type="button"
                onClick={() => download(r.name)}
                className="rounded-md border border-line px-3 py-1 text-xs text-ink-2 hover:bg-wash"
              >
                Download
              </button>
            ),
          }))}
        />
      )}
    </Card>
  );
}
