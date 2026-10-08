"use client";

import { useState } from "react";

import { clock, count } from "@/lib/format";
import { type Incident, type IncidentSource, SOURCE_LABELS } from "@/lib/incidents";
import { ATTACK_INFO, attackCategory, attackName, detectorName, resolutionLabel, RESOLUTIONS, ruleName } from "@/lib/plain";

import { severityScore, tierOf } from "@/lib/severity";

import { Card } from "@/components/ui/chart-parts";
import { SOURCE_COLORS } from "@/components/charts/detection-timeline";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { StatusBadge } from "@/components/ui/status-badge";

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
  if (incident.snort) return incident.snort.rules.map(ruleName).join(" · ");
  return incident.label ? attackName(incident.label) : "Behaves like an attack";
}

/** The best clue to what kind of activity this is: Snort's rule, else the known label. */
function clueText(incident: Incident): string {
  if (incident.snort?.rules.length) return incident.snort.rules.join(" ");
  if (incident.label) return incident.label;
  return "unknown";
}

/** A real, plain-English headline for the alert: the kind of attack it looks like. */
function headline(incident: Incident): string {
  if (incident.label && incident.label.toLowerCase() === "benign") return "Normal traffic — this is a false alarm";
  return ATTACK_INFO[attackCategory(clueText(incident))].title;
}

/** Split an "ip:port" endpoint into its address and port. */
function endpoint(value: string | null): { ip: string; port: string | null } | null {
  if (!value) return null;
  const i = value.lastIndexOf(":");
  return i > 0 ? { ip: value.slice(0, i), port: value.slice(i + 1) } : { ip: value, port: null };
}

/** The concrete, observed facts behind this alert — "what was actually done", at the
 *  level the system records (connections and timing; never packet contents). */
function evidence(incident: Incident): string[] {
  const facts: string[] = [];
  const from = endpoint(incident.src);
  const to = endpoint(incident.dst);
  const category = attackCategory(clueText(incident));

  if (from && to) {
    const dst = to.port ? `${to.ip} on port ${to.port}` : to.ip;
    if (category === "scan") {
      facts.push(`${from.ip} repeatedly connected to ${to.ip}, trying many different ports — not one service, but a sweep across the machine.`);
    } else if (category === "dos") {
      facts.push(`A heavy stream of traffic went from ${from.ip} to ${dst} — far more, and faster, than a normal exchange.`);
    } else if (category === "bruteforce") {
      facts.push(`${from.ip} made repeated connection attempts to ${dst} — the pattern of trying one login after another.`);
    } else {
      facts.push(`A connection went from ${from.ip} to ${dst}.`);
    }
  } else if (incident.src || incident.dst) {
    facts.push(`Connection: ${incident.src ?? "unknown"} → ${incident.dst ?? "unknown"}.`);
  }

  if (incident.snort && incident.snort.flows > 1) {
    facts.push(`This single alarm groups ${count(incident.snort.flows)} separate connections between the two computers — a repeated pattern, not a one-off request.`);
  }

  if (incident.snort) {
    facts.push(`The rule checker matched it against its library of known attacks: ${incident.snort.rules.map(ruleName).join("; ")}.`);
  }
  if (incident.ml) {
    facts.push(`The AI didn't read the contents — it judged how the connection behaved (its size, timing and speed) and found it matched attacks it has learned.`);
  }

  if (incident.time) facts.push(`Seen at ${clock(incident.time)}.`);
  return facts;
}

/** How much to trust this particular alert, given who flagged it. */
function trust(incident: Incident): string {
  if (incident.source === "both") {
    return "Two independent methods — the AI and the rule checker — both flagged this, so it is very likely a real attack. Worth acting on.";
  }
  if (incident.source === "ml") {
    return "Flagged by the AI only: the traffic behaves like attacks it has learned, but no rule matched (or the rule checker wasn't running). The AI is occasionally wrong on unusual-but-harmless traffic, so treat it as a lead to check.";
  }
  if (incident.snort?.ml_verdict === "normal") {
    return "Flagged by the rule checker only — the AI looked at the same connection and thought it was normal. That happens either because the rule checker raised a false alarm, or because it's a kind of attack the AI was never taught (content-based attacks like database break-ins look ordinary to the AI). Judge it by the rule and the source address.";
  }
  return "Flagged by the rule checker: the traffic matched a known attack pattern. The AI had no strong opinion either way.";
}

export function IncidentDetail({ incident, onClose }: { incident: Incident; onClose: () => void }) {
  const sev = severityScore(incident);
  const rows: [string, React.ReactNode][] = [
    ["Risk level", <SeverityBadge key="r" tier={tierOf(sev)} score={sev} />],
    ["Spotted by", <SourceTag key="s" source={incident.source} />],
    ["Time", incident.time ? clock(incident.time) : "—"],
    ["From", incident.src ?? "—"],
    ["To", incident.dst ?? "—"],
  ];
  if (incident.ml) {
    rows.push(["AI detectors", incident.ml.detectors.map(detectorName).join(", ")]);
    rows.push([
      "How they decided",
      incident.ml.resolutions.map((r) => `${resolutionLabel(r)}: ${RESOLUTIONS[r]?.meaning ?? ""}`).join("; "),
    ]);
    if (incident.ml.counselors.length) rows.push(["Advice came from", incident.ml.counselors.map(detectorName).join(", ")]);
  }
  if (incident.snort) {
    rows.push(["Rules that went off", incident.snort.rules.map(ruleName).join(" · ")]);
    if (incident.snort.flows > 1) {
      rows.push(["Connections covered", `${count(incident.snort.flows)} (one alarm about many connections, e.g. a port scan)`]);
    }
    rows.push(["AI's opinion", incident.snort.ml_verdict ?? "no clear opinion"]);
  }
  rows.push(["Technical ids", [
    incident.record_id != null ? `connection #${incident.record_id}` : null,
    incident.snort ? `Snort rules ${incident.snort.ids.slice(0, 6).join(", ")}${incident.snort.ids.length > 6 ? " …" : ""}` : null,
  ].filter(Boolean).join(" · ") || "—"]);

  return (
    <aside className="rounded-xl border border-line bg-surface p-5" aria-label="Alert details">
      <header className="mb-3 flex items-start justify-between gap-3">
        <h2 className="text-sm font-semibold text-ink">{headline(incident)}</h2>
        <button type="button" onClick={onClose} className="rounded-md px-2 py-1 text-xs text-ink-2 hover:bg-wash">
          Close
        </button>
      </header>
      <div className="mb-4 space-y-3 rounded-md bg-wash p-3 text-xs text-ink-2">
        <p>
          <span className="font-semibold text-ink">What this is: </span>
          {ATTACK_INFO[attackCategory(clueText(incident))].what}
        </p>
        <div>
          <p className="font-semibold text-ink">What was actually seen:</p>
          <ul className="mt-1 list-disc space-y-0.5 pl-4">
            {evidence(incident).map((fact, i) => (
              <li key={i}>{fact}</li>
            ))}
          </ul>
          <p className="mt-1 text-muted">
            The system records who connected to whom and how, not the packet contents — so it can show the behaviour,
            not what was typed or taken.
          </p>
        </div>
        <p>
          <span className="font-semibold text-ink">How sure we are: </span>
          {trust(incident)}
        </p>
      </div>
      <dl className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-2 text-xs">
        {rows.map(([label, value]) => (
          <div key={label} className="contents">
            <dt className="text-muted">{label}</dt>
            <dd className="break-words text-ink">{value}</dd>
          </div>
        ))}
      </dl>
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
      <div className="flex rounded-md border border-line p-0.5 text-xs" role="group" aria-label="Spotted by">
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
        placeholder="Search by IP address, rule or attack…"
        className="w-60 rounded-md border border-line bg-raised px-2 py-1 text-xs text-ink"
        aria-label="Search alerts"
      />
    </div>
  );
}

export function IncidentsTable({
  incidents,
  actions,
  footer,
  empty = "No alerts yet. Start live monitoring, or run a test on the Test page.",
  subtitle = "Each suspicious connection once, with what the AI and the rule checker said about it",
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
      <Card title="Alerts" subtitle={subtitle} actions={actions}>
        {incidents.length === 0 ? (
          <p className="py-10 text-center text-sm text-muted">{empty}</p>
        ) : (
          <div className="max-h-[34rem] overflow-auto rounded-lg border border-line">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-raised text-left text-muted">
                <tr>
                  <th className="px-3 py-2 font-medium">Risk</th>
                  <th className="px-3 py-2 font-medium">Time</th>
                  <th className="px-3 py-2 font-medium">Spotted by</th>
                  <th className="px-3 py-2 font-medium">What it looks like</th>
                  <th className="px-3 py-2 font-medium">From → to</th>
                  <th className="px-3 py-2 font-medium">AI&apos;s opinion</th>
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
                    <td className="px-3 py-1.5">{(() => { const s = severityScore(i); return <SeverityBadge tier={tierOf(s)} score={s} />; })()}</td>
                    <td className="tabular px-3 py-1.5 text-ink-2">{i.time ? clock(i.time) : "—"}</td>
                    <td className="px-3 py-1.5"><SourceTag source={i.source} /></td>
                    <td className="max-w-72 truncate px-3 py-1.5 text-ink" title={what(i)}>{what(i)}</td>
                    <td className="tabular px-3 py-1.5 text-ink-2">
                      {i.src || i.dst ? `${i.src ?? "?"} → ${i.dst ?? "?"}` : "—"}
                    </td>
                    <td className="px-3 py-1.5 text-ink-2">
                      {i.ml ? (
                        <StatusBadge tone="critical" label="Attack" />
                      ) : i.snort?.ml_verdict === "normal" ? (
                        <StatusBadge tone="warning" label="Thinks it's normal" />
                      ) : "—"}
                    </td>
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
