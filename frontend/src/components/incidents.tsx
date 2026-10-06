"use client";

import { useState } from "react";

import { clock, count, RESOLUTION_LABELS } from "@/lib/format";
import { type Incident, type IncidentSource, SOURCE_LABELS } from "@/lib/incidents";

import { Card } from "./chart-parts";
import { SOURCE_COLORS } from "./detection-timeline";
import { StatusBadge } from "./status-badge";

export function SourceTag({ source }: { source: Incident["source"] }) {
  const keys = source === "both" ? (["ml", "snort"] as const) : ([source] as const);
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border border-line px-2 py-0.5 text-xs text-ink">
      <span className="flex gap-0.5">
        {keys.map((k) => (
          <span key={k} className="inline-block size-2 rounded-full" style={{ background: SOURCE_COLORS[k] }} />
        ))}
      </span>
      {SOURCE_LABELS[source]}
    </span>
  );
}

function what(incident: Incident): string {
  return incident.snort?.rules.join(" · ") ?? incident.label ?? "Flagged as attack";
}

function truth(incident: Incident) {
  if (incident.label == null) return null;
  return incident.label === "BENIGN" ? <span className="text-critical">BENIGN · false alarm</span> : incident.label;
}

export function IncidentDetail({ incident, onClose }: { incident: Incident; onClose: () => void }) {
  const rows: [string, React.ReactNode][] = [
    ["Flagged by", <SourceTag key="s" source={incident.source} />],
    ["Time", incident.time ? clock(incident.time) : "—"],
    ["Flow", incident.record_id != null ? `#${incident.record_id}` : "—"],
    ["Source", incident.src ?? "—"],
    ["Destination", incident.dst ?? "—"],
    ["True label", truth(incident) ?? "unknown (live or captured traffic)"],
  ];
  if (incident.ml) {
    rows.push(["ML detectors", incident.ml.detectors.join(", ")]);
    rows.push(["Decided by", incident.ml.resolutions.map((r) => RESOLUTION_LABELS[r] ?? r).join(", ")]);
    if (incident.ml.counselors.length) rows.push(["Counselor", incident.ml.counselors.join(", ")]);
  }
  if (incident.snort) {
    rows.push(["Snort rules", incident.snort.rules.join(" · ")]);
    rows.push(["Rule ids", incident.snort.ids.slice(0, 6).join(", ") + (incident.snort.ids.length > 6 ? " …" : "")]);
    if (incident.snort.flows > 1) rows.push(["Flows covered", `${count(incident.snort.flows)} (host-level alert, e.g. a port scan)`]);
    rows.push(["ML on this flow", incident.snort.ml_verdict ?? "no confident verdict"]);
  }
  return (
    <aside className="rounded-xl border border-line bg-surface p-5" aria-label="Incident details">
      <header className="mb-3 flex items-start justify-between gap-3">
        <h2 className="text-sm font-semibold text-ink">{what(incident)}</h2>
        <button type="button" onClick={onClose} className="rounded-md px-2 py-1 text-xs text-ink-2 hover:bg-wash">
          Close
        </button>
      </header>
      <dl className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-2 text-xs">
        {rows.map(([label, value]) => (
          <div key={label} className="contents">
            <dt className="text-muted">{label}</dt>
            <dd className="text-ink">{value}</dd>
          </div>
        ))}
      </dl>
      {incident.source === "snort" && incident.snort?.ml_verdict === "normal" && (
        <p className="mt-4 rounded-md bg-wash p-3 text-xs text-ink-2">
          The ML analysed this flow and called it normal. Either Snort raised a false alarm, or this is an attack
          type the ML was never trained on — payload attacks such as SQL injection look like ordinary flows.
        </p>
      )}
    </aside>
  );
}

export const FILTERS = ["all", "both", "ml", "snort"] as const;
export type Filter = (typeof FILTERS)[number];

/** Filter buttons with counts, and a search box — the Alerts page passes these as actions. */
export function IncidentFilters({
  source, onSource, query, onQuery, counts,
}: {
  source: Filter;
  onSource: (f: Filter) => void;
  query: string;
  onQuery: (q: string) => void;
  counts: Record<Filter, number> | null;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <div className="flex rounded-md border border-line p-0.5 text-xs" role="group" aria-label="Flagged by">
        {FILTERS.map((f) => (
          <button
            key={f}
            type="button"
            onClick={() => onSource(f)}
            aria-pressed={source === f}
            className={`rounded px-2 py-1 ${source === f ? "bg-wash font-semibold text-ink" : "text-ink-2 hover:bg-wash"}`}
          >
            {f === "all" ? "All" : SOURCE_LABELS[f as IncidentSource]}{" "}
            <span className="tabular text-muted">{counts ? count(counts[f]) : "…"}</span>
          </button>
        ))}
      </div>
      <input
        type="search"
        value={query}
        onChange={(e) => onQuery(e.target.value)}
        placeholder="Search IP, rule, label, flow…"
        className="w-56 rounded-md border border-line bg-raised px-2 py-1 text-xs text-ink"
        aria-label="Search incidents"
      />
    </div>
  );
}

export function IncidentsTable({
  incidents,
  actions,
  footer,
  empty = "No incidents yet — start a replay or a live capture.",
  subtitle = "Each flagged flow once, with what the ML and Snort said about it",
}: {
  incidents: Incident[];
  actions?: React.ReactNode;
  footer?: React.ReactNode;
  empty?: string;
  subtitle?: string;
}) {
  const [selected, setSelected] = useState<string | null>(null);
  const detail = incidents.find((i) => i.key === selected);

  return (
    <div className={detail ? "grid gap-4 xl:grid-cols-[1fr_24rem]" : ""}>
      <Card title="Incidents" subtitle={subtitle} actions={actions}>
        {incidents.length === 0 ? (
          <p className="py-10 text-center text-sm text-muted">{empty}</p>
        ) : (
          <div className="max-h-[34rem] overflow-auto rounded-lg border border-line">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-raised text-left text-muted">
                <tr>
                  <th className="px-3 py-2 font-medium">Time</th>
                  <th className="px-3 py-2 font-medium">Flagged by</th>
                  <th className="px-3 py-2 font-medium">What</th>
                  <th className="px-3 py-2 font-medium">Source → destination</th>
                  <th className="px-3 py-2 font-medium">ML</th>
                  <th className="px-3 py-2 font-medium">True label</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((i) => (
                  <tr
                    key={i.key}
                    onClick={() => setSelected(i.key === selected ? null : i.key)}
                    onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && setSelected(i.key)}
                    tabIndex={0}
                    aria-selected={i.key === selected}
                    className={`cursor-pointer border-t border-line hover:bg-wash ${i.key === selected ? "bg-wash" : ""}`}
                  >
                    <td className="tabular px-3 py-1.5 text-ink-2">{i.time ? clock(i.time) : "—"}</td>
                    <td className="px-3 py-1.5"><SourceTag source={i.source} /></td>
                    <td className="max-w-72 truncate px-3 py-1.5 text-ink" title={what(i)}>{what(i)}</td>
                    <td className="tabular px-3 py-1.5 text-ink-2">
                      {i.src || i.dst ? `${i.src ?? "?"} → ${i.dst ?? "?"}` : "—"}
                    </td>
                    <td className="px-3 py-1.5 text-ink-2">
                      {i.ml ? i.ml.detectors.join(", ") : i.snort?.ml_verdict === "normal" ? (
                        <StatusBadge tone="warning" label="says normal" />
                      ) : "—"}
                    </td>
                    <td className="px-3 py-1.5 text-ink-2">{truth(i) ?? <span className="text-muted">unknown</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {footer}
      </Card>
      {detail && <IncidentDetail incident={detail} onClose={() => setSelected(null)} />}
    </div>
  );
}
