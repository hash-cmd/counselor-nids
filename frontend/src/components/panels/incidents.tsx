"use client";

import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import { clock, count } from "@/lib/format";
import { useFeedback, type Verdict } from "@/lib/feedback";
import { type Incident, type IncidentSource, isPossibleUnseen, SOURCE_LABELS } from "@/lib/incidents";
import { ATTACK_INFO, attackCategory, attackName, bySpecificity, detectorClue, detectorName, resolutionLabel, RESOLUTIONS, ruleName } from "@/lib/plain";

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

/** Plain words for a connection the AI judged normal but unlike anything it has learned —
 *  the "possible unseen attack" signal, written for a non-expert. */
const UNSEEN_WHAT =
  "The AI watched how this connection behaved — its size, timing and speed — and did not recognise it as any attack it was taught. But it also looks nothing like the normal traffic it knows. That combination is exactly what a brand-new or unknown attack would look like, so it is surfaced here to be checked rather than quietly let through.";

function what(incident: Incident): string {
  if (incident.snort) return incident.snort.rules.map(ruleName).join(" · ");
  if (isPossibleUnseen(incident)) return "Possible new or unknown attack";
  if (incident.label) return attackName(incident.label);
  const origins = bySpecificity(incident.ml?.origins ?? []);
  if (!origins.length) return "Behaves like an attack";
  return `${ATTACK_INFO[attackCategory(detectorClue(origins[0]))].title} — ${origins.map(detectorName).join(", ")}`;
}

/** The best clue to what kind of activity this is: Snort's rule, else the known label,
 *  else the specialty of the detector that raised it. */
function clueText(incident: Incident): string {
  if (incident.snort?.rules.length) return incident.snort.rules.join(" ");
  if (incident.label) return incident.label;
  if (incident.ml?.origins?.length) return detectorClue(bySpecificity(incident.ml.origins)[0]);
  return "unknown";
}

/** A real, plain-English headline for the alert: the kind of attack it looks like. */
function headline(incident: Incident): string {
  if (incident.label && incident.label.toLowerCase() === "benign") return "Normal traffic — this is a false alarm";
  if (isPossibleUnseen(incident) && !incident.snort) return "Possible new or unknown attack";
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
    facts.push(isPossibleUnseen(incident)
      ? `The AI didn't read the contents — it judged how the connection behaved (its size, timing and speed). It didn't match any attack the AI was taught, but it sat far outside all the normal traffic it knows, which is why it's flagged as possibly new or unknown.`
      : `The AI didn't read the contents — it judged how the connection behaved (its size, timing and speed) and found it matched attacks it has learned.`);
  }

  if (incident.time) facts.push(`Seen at ${clock(incident.time)}.`);
  return facts;
}

/** How much to trust this particular alert, given who flagged it. */
function trust(incident: Incident): string {
  if (isPossibleUnseen(incident) && incident.source === "ml") {
    return "This is not a confirmed attack. The AI didn't recognise it as anything it was taught, but it also sits far outside all the normal traffic it has learned — the signature of something new or unknown. Treat it as a lead worth checking: look at who the connection is with and whether that traffic belongs on your network. If it's harmless, mark it \"Not an attack\" and the AI will learn to expect it.";
  }
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

const VERDICT_BADGE = {
  normal: { tone: "neutral", label: "Not an attack" },
  attack: { tone: "critical", label: "Real attack" },
} as const;

/** "Not an attack" / "Real attack": the analyst's verdict, which the detectors learn from. */
function VerdictButtons({ incident }: { incident: Incident }) {
  const { mark, error } = useFeedback();
  const [busy, setBusy] = useState(false);
  if (incident.record_id == null) {
    return <p className="text-xs text-muted">This alarm isn&apos;t tied to one connection, so it can&apos;t be marked.</p>;
  }
  const choose = async (verdict: "normal" | "attack") => {
    // both methods agreed it is an attack: a wrong "not an attack" would teach the AI to
    // ignore a real one, so ask before taking it
    if (verdict === "normal" && incident.source === "both" &&
        !window.confirm("Both the AI and the rule checker flagged this connection. Mark it as not an attack anyway? The AI will learn to ignore connections like it.")) {
      return;
    }
    setBusy(true);
    await mark(incident.record_id!, verdict);
    setBusy(false);
  };
  return (
    <div className="space-y-2">
      <p className="text-xs text-ink-2">
        Was it really an attack? Your answer takes it out of (or confirms it in) the counts, and the AI detectors learn
        from it when you choose <span className="font-semibold">Teach the AI</span> on the AI detectors page.
      </p>
      <div className="flex flex-wrap items-center gap-2">
        {(["normal", "attack"] as const).map((v) => (
          <button key={v} type="button" disabled={busy} onClick={() => choose(v)} aria-pressed={incident.feedback === v}
                  className={`rounded-md border px-3 py-1.5 text-xs font-medium disabled:opacity-50 ${
                    incident.feedback === v ? "border-accent bg-wash text-ink" : "border-line text-ink-2 hover:bg-wash hover:text-ink"}`}>
            {v === "normal" ? "Not an attack" : "Real attack"}
          </button>
        ))}
        {incident.feedback && <StatusBadge tone={VERDICT_BADGE[incident.feedback].tone} label={`You said: ${VERDICT_BADGE[incident.feedback].label}`} />}
      </div>
      {error && <p className="text-xs text-critical">{error}</p>}
    </div>
  );
}

type ExplainFeature = { feature: string; contribution: number; toward: "attack" | "normal" };
type ExplainResponse = { available: boolean; detector?: string; features?: ExplainFeature[]; reason?: string };

/** Model-internal explanation: the connection features that drove the AI's verdict (SHAP),
 *  fetched on demand from /explain/. Shown only for AI alerts whose flow is still stored. */
function WhyFlagged({ incident }: { incident: Incident }) {
  const origin = incident.ml?.origins.length ? bySpecificity(incident.ml.origins)[0] : null;
  const [res, setRes] = useState<ExplainResponse | null>(null);
  const [err, setErr] = useState(false);
  useEffect(() => {
    if (incident.record_id == null || !origin) return;
    let live = true;
    api<ExplainResponse>(`/explain/?record_id=${incident.record_id}&detector=${encodeURIComponent(origin)}`)
      .then((r) => live && setRes(r))
      .catch(() => live && setErr(true));
    return () => {
      live = false;
    };
  }, [incident.record_id, origin]);

  if (incident.ml == null || origin == null) return null; // AI alerts only
  if (isPossibleUnseen(incident)) return null; // the AI judged it normal — there's no "why flagged as attack"
  const feats = res?.features ?? [];
  const max = Math.max(1e-9, ...feats.map((f) => Math.abs(f.contribution)));
  return (
    <div className="mb-4 rounded-md bg-wash p-3 text-xs">
      <p className="font-semibold text-ink">Why the AI flagged this — top features</p>
      <p className="mt-0.5 text-muted">
        How much each measurement pushed the {detectorName(origin)}&apos;s verdict toward attack (orange) or normal (grey).
      </p>
      {err ? (
        <p className="mt-2 text-muted">Explanation unavailable.</p>
      ) : res == null ? (
        <p className="mt-2 text-muted">Working out the reason…</p>
      ) : !res.available ? (
        <p className="mt-2 text-muted">{res.reason ?? "No explanation available."}</p>
      ) : feats.length === 0 ? (
        <p className="mt-2 text-muted">No per-feature explanation for this connection.</p>
      ) : (
        <ul className="mt-2 space-y-1">
          {feats.map((f) => (
            <li key={f.feature} className="grid grid-cols-[9rem_1fr] items-center gap-2">
              <span className="truncate text-ink-2" title={f.feature}>
                {f.feature}
              </span>
              <span className="flex items-center gap-1.5">
                <span
                  className="h-2 rounded"
                  style={{
                    width: `${Math.round((Math.abs(f.contribution) / max) * 100)}%`,
                    background: f.toward === "attack" ? "var(--accent)" : "var(--ink-muted)",
                  }}
                />
                <span className="text-muted">{f.toward}</span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Plain-language "is this a known attack, or something never seen before?" — the novelty signal. */
function Familiarity({ novelty }: { novelty: Incident["novelty"] }) {
  if (!novelty) return null;
  const unfamiliar = novelty.novel;
  const color = unfamiliar ? "var(--status-warning)" : "var(--status-good)";
  return (
    <div
      className="mb-4 flex items-start gap-2.5 rounded-lg border p-3 text-xs"
      style={{
        borderColor: `color-mix(in oklab, ${color} 45%, transparent)`,
        background: `color-mix(in oklab, ${color} 9%, transparent)`,
      }}
    >
      <span aria-hidden className="text-base leading-none" style={{ color }}>
        {unfamiliar ? "⚠" : "✓"}
      </span>
      <div>
        <p className="font-semibold text-ink">{unfamiliar ? "Never seen before" : "A known pattern"}</p>
        <p className="mt-0.5 text-ink-2">
          {unfamiliar
            ? "This doesn’t look like any attack the system has learned before. It could be a brand-new or unknown type of attack, so it is worth a closer look."
            : "This matches the kind of traffic the system already learned, so it recognises what it is."}
        </p>
      </div>
    </div>
  );
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
    <aside className="rounded-2xl border border-line bg-surface shadow-[var(--shadow)] p-5" aria-label="Alert details">
      <header className="mb-3 flex items-start justify-between gap-3">
        <h2 className="text-sm font-semibold text-ink">{headline(incident)}</h2>
        <button type="button" onClick={onClose} className="rounded-md px-2 py-1 text-xs text-ink-2 hover:bg-wash">
          Close
        </button>
      </header>
      <div className="mb-4">
        <VerdictButtons incident={incident} />
      </div>
      <Familiarity novelty={incident.novelty} />
      <div className="mb-4 space-y-3 rounded-md bg-wash p-3 text-xs text-ink-2">
        <p>
          <span className="font-semibold text-ink">What this is: </span>
          {isPossibleUnseen(incident) && !incident.snort ? UNSEEN_WHAT : ATTACK_INFO[attackCategory(clueText(incident))].what}
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
      <WhyFlagged key={incident.record_id ?? "none"} incident={incident} />
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
  empty = "No alerts yet. Start live monitoring to watch your network.",
  subtitle = "Each suspicious connection once, with what the AI and the rule checker said about it",
}: {
  incidents: Incident[];
  actions?: React.ReactNode;
  footer?: React.ReactNode;
  empty?: string;
  subtitle?: string;
}) {
  const [selected, setSelected] = useState<string | null>(null);
  const { verdicts } = useFeedback();
  // the newest verdicts (this page's own clicks included) over what the server sent
  const rows = incidents.map((i): Incident => {
    const mine: Verdict | undefined = i.record_id != null ? verdicts[i.record_id] : undefined;
    return { ...i, feedback: mine ?? i.feedback ?? null };
  });
  const detail = rows.find((i) => i.key === selected);

  return (
    <div className={detail ? "grid gap-4 xl:grid-cols-[1fr_24rem]" : ""}>
      <Card title="Alerts" subtitle={subtitle} actions={actions} className="min-w-0">
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
                  <th className="px-3 py-2 font-medium">Your verdict</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((i) => (
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
                    <td className="max-w-72 px-3 py-1.5 text-ink">
                      <span className="flex items-center gap-1.5">
                        <span className="truncate" title={what(i)}>{what(i)}</span>
                        {(i.novelty?.novel || isPossibleUnseen(i)) && (
                          <span
                            title="This doesn’t match anything the system has seen before — possibly a new or unknown attack."
                            className="shrink-0 rounded-full px-1.5 py-0.5 text-[10px] font-medium"
                            style={{ color: "var(--status-warning)", background: "color-mix(in oklab, var(--status-warning) 14%, transparent)" }}
                          >
                            never seen before
                          </span>
                        )}
                      </span>
                    </td>
                    <td className="tabular px-3 py-1.5 text-ink-2">
                      {i.src || i.dst ? `${i.src ?? "?"} → ${i.dst ?? "?"}` : "—"}
                    </td>
                    <td className="px-3 py-1.5 text-ink-2">
                      {isPossibleUnseen(i) ? (
                        <StatusBadge tone="warning" label="Possibly unknown" />
                      ) : i.ml ? (
                        <StatusBadge tone="critical" label="Attack" />
                      ) : i.snort?.ml_verdict === "normal" ? (
                        <StatusBadge tone="warning" label="Thinks it's normal" />
                      ) : "—"}
                    </td>
                    <td className="px-3 py-1.5 text-ink-2">
                      {i.feedback ? <StatusBadge tone={VERDICT_BADGE[i.feedback].tone} label={VERDICT_BADGE[i.feedback].label} /> : "—"}
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
