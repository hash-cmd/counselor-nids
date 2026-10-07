"use client";

import { useState } from "react";

import { clock, count } from "@/lib/format";
import type { Incident } from "@/lib/incidents";
import { ATTACK_INFO } from "@/lib/plain";
import { useReputation } from "@/lib/reputation";
import { type Attacker, attackStory, BADGE_LABEL, categoryOf, groupByAttacker, severityScore, tierOf } from "@/lib/severity";

import { BlockDialog } from "@/components/panels/block-dialog";
import { Card } from "@/components/ui/chart-parts";
import { SeverityBadge } from "@/components/ui/severity-badge";

function timeRange(a: Attacker): string {
  if (!a.firstSeen) return "—";
  if (!a.lastSeen || a.lastSeen === a.firstSeen) return clock(a.firstSeen);
  return `${clock(a.firstSeen)} – ${clock(a.lastSeen)}`;
}

function AttackerCard({ attacker, reputation }: { attacker: Attacker; reputation?: { listed: boolean; source: string | null } }) {
  const [open, setOpen] = useState(false);
  const [blocking, setBlocking] = useState(false);
  const worstIncident = attacker.incidents.reduce((a, b) => (severityScore(a) >= severityScore(b) ? a : b));
  const worst = ATTACK_INFO[categoryOf(worstIncident)];

  return (
    <div className="rounded-lg border border-line">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-wash"
      >
        <SeverityBadge tier={attacker.threatTier} score={attacker.threatScore} />
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="tabular font-semibold text-ink">{attacker.ip}</span>
            {reputation?.listed && (
              <span className="rounded border border-[var(--status-critical)] px-1.5 py-0 text-[10px] font-semibold uppercase tracking-wide text-critical"
                    title={`On the ${reputation.source} blocklist of known-bad IPs`}>
                Known bad
              </span>
            )}
            {attacker.badges.map((b) => (
              <span key={b} className="rounded border border-line px-1.5 py-0 text-[10px] font-medium uppercase tracking-wide text-ink-2">
                {BADGE_LABEL[b]}
              </span>
            ))}
            <span className="text-xs text-muted">{timeRange(attacker)}</span>
          </span>
          <span className="mt-0.5 block truncate text-xs text-ink-2">{attackStory(attacker)}</span>
        </span>
        <span className="shrink-0 text-right text-xs text-muted">
          {count(attacker.incidents.length)} alert{attacker.incidents.length === 1 ? "" : "s"}
          <br />
          {attacker.targets.length} target{attacker.targets.length === 1 ? "" : "s"}
        </span>
        <span className="shrink-0 text-muted">{open ? "▾" : "▸"}</span>
      </button>

      {open && (
        <div className="border-t border-line px-4 py-3 text-xs">
          <div className="mb-2 flex items-start justify-between gap-3">
            <p className="text-ink-2">
              <span className="font-semibold text-ink">What {attacker.ip} did:</span> {worst.what}
            </p>
            <button
              type="button"
              onClick={() => setBlocking(true)}
              className="shrink-0 rounded-md border border-line px-2.5 py-1 text-xs font-medium text-ink-2 hover:bg-wash hover:text-ink print:hidden"
            >
              Block this IP
            </button>
          </div>
          {blocking && <BlockDialog ip={attacker.ip} onClose={() => setBlocking(false)} />}
          <ol className="space-y-1">
            {attacker.incidents.map((i: Incident) => (
              <li key={i.key} className="flex items-baseline gap-2">
                <span className="tabular w-16 shrink-0 text-muted">{i.time ? clock(i.time) : "—"}</span>
                <SeverityBadge tier={tierOf(severityScore(i))} />
                <span className="text-ink-2">
                  {ATTACK_INFO[categoryOf(i)].title.replace(/\s*\(.*\)$/, "")}
                  {i.dst && <span className="text-muted"> → {i.dst}</span>}
                </span>
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}

export function AttackersPanel({ incidents, limit, title = "Attackers", footer, className }: {
  incidents: Incident[];
  limit?: number;
  title?: string;
  footer?: React.ReactNode;
  className?: string;
}) {
  const all = groupByAttacker(incidents);
  const attackers = limit ? all.slice(0, limit) : all;
  const reputation = useReputation(attackers.map((a) => a.ip));
  return (
    <Card
      className={className}
      title={title}
      tag="Movers"
      subtitle="Each suspicious source, ranked by severity, with the story of what it did. Click one to expand."
    >
      {attackers.length === 0 ? (
        <p className="flex flex-1 items-center justify-center py-10 text-center text-sm text-muted">
          No attackers to show. They appear once suspicious traffic has a source address (recorded or live traffic).
        </p>
      ) : (
        <div className="min-h-0 flex-1 space-y-2 overflow-auto">
          {attackers.map((a) => (
            <AttackerCard key={a.ip} attacker={a} reputation={reputation[a.ip]} />
          ))}
          {limit && all.length > limit && (
            <p className="pt-1 text-right text-xs text-muted">+{all.length - limit} more on the Alerts page</p>
          )}
        </div>
      )}
      {footer}
    </Card>
  );
}
