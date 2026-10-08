"use client";

import { useCallback, useEffect, useState } from "react";

import { api, ApiError } from "@/lib/api";
import { count } from "@/lib/format";
import { detectorName } from "@/lib/plain";
import type { AttackTest, Journal } from "@/lib/types";

import { Card } from "@/components/ui/chart-parts";
import { StatusBadge, type Tone } from "@/components/ui/status-badge";

const DAYS = [1, 7, 30] as const;

/** How often an alarm comes, in words: "about 1 every 6 hours". */
function every(perHour: number | null): string {
  if (!perHour) return "none so far";
  if (perHour >= 1) return `about ${perHour.toFixed(perHour >= 10 ? 0 : 1)} per hour`;
  const hours = 1 / perHour;
  return hours < 48 ? `about 1 every ${Math.round(hours)} hours` : `about 1 every ${Math.round(hours / 24)} days`;
}

/** The headline judgement: healthy is a handful of false alarms a day or fewer. */
function verdict(perHour: number | null, hours: number): { tone: Tone; label: string } {
  if (hours < 1) return { tone: "neutral", label: "Too early to judge" };
  if (!perHour || perHour <= 0.25) return { tone: "good", label: "Quiet: a handful a day or fewer" };
  if (perHour <= 2) return { tone: "warning", label: "Noticeable: worth tuning" };
  return { tone: "critical", label: "Noisy: alerts can't be trusted yet" };
}

const when = (t: number) =>
  new Date(t * 1000).toLocaleString("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="min-w-0">
      <p className="eyebrow">{label}</p>
      <p className="figure mt-1 text-2xl font-semibold text-ink">{value}</p>
      {hint && <p className="mt-0.5 text-xs text-muted">{hint}</p>}
    </div>
  );
}

/** Attack tests: alerts while one runs are the test working, not false alarms. */
function Tests({ tests, onChange }: { tests: AttackTest[]; onChange: (tests: AttackTest[]) => void }) {
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const running = tests.find((t) => t.end == null);

  async function send(body: Record<string, unknown>) {
    setError(null);
    try {
      onChange((await api<{ tests: AttackTest[] }>("/journal/tests/", { method: "POST", body: JSON.stringify(body) })).tests);
      setNote("");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the server");
    }
  }

  return (
    <div className="border-t border-line pt-4">
      <p className="text-sm font-semibold text-ink">Your attack tests</p>
      <p className="mt-0.5 text-xs text-ink-2">
        Attacking your own machine on purpose? Mark it, so the alarms it causes aren&apos;t counted as false ones.
      </p>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        {running ? (
          <>
            <StatusBadge tone="warning" label={`Test running since ${when(running.start)}${running.note ? ` · ${running.note}` : ""}`} />
            <button type="button" onClick={() => send({ action: "stop" })}
                    className="rounded-md border border-line px-4 py-1.5 text-sm font-medium text-ink hover:bg-wash">
              Test finished
            </button>
          </>
        ) : (
          <>
            <input value={note} onChange={(e) => setNote(e.target.value)} maxLength={200}
                   placeholder="What you're running, e.g. nmap scan"
                   className="w-64 max-w-full rounded-md border border-line bg-raised px-2 py-1.5 text-sm text-ink" />
            <button type="button" onClick={() => send({ action: "start", note })}
                    className="rounded-md bg-accent px-4 py-1.5 text-sm font-semibold text-[var(--accent-ink)] hover:opacity-90">
              I&apos;m starting an attack test
            </button>
          </>
        )}
      </div>
      {error && <p className="mt-2 text-xs text-[var(--critical-text)]">{error}</p>}
      {tests.length > 0 && (
        <ul className="mt-3 space-y-1 text-xs text-ink-2">
          {tests.map((t, i) => (
            <li key={`${t.start}-${i}`} className="flex flex-wrap items-center gap-2">
              <span className="tabular">{when(t.start)} – {t.end ? when(t.end) : "now"}</span>
              {t.note && <span className="text-muted">{t.note}</span>}
              <button type="button" onClick={() => send({ action: "delete", index: i })}
                      className="text-accent hover:underline" aria-label={`Remove the test from ${when(t.start)}`}>
                remove
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** False alarms on your own network, from the live alert journal (logs/journal/). */
export function FalseAlarms() {
  const [days, setDays] = useState<(typeof DAYS)[number]>(7);
  const [journal, setJournal] = useState<Journal | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api<Journal>(`/journal/?days=${days}`)
      .then((j) => { setJournal(j); setError(null); })
      .catch((e) => setError(e instanceof ApiError ? e.message : "Could not reach the server"));
  }, [days]);

  useEffect(() => {
    load();
    const timer = setInterval(load, 60_000);
    return () => clearInterval(timer);
  }, [load]);

  const r = journal?.report;
  const v = r ? verdict(r.ml.per_hour, r.hours_watched) : null;
  const top = r ? Object.entries(r.ml.top_connections) : [];
  const maxDay = Math.max(1, ...(r?.daily ?? []).map((d) => d.ml_flagged));

  return (
    <Card
      title="False alarms on your network"
      subtitle="While you aren't attacking anything, every AI alarm on live traffic is a false one. Kept across restarts, so leave live monitoring running for a few days."
      actions={
        <div className="flex gap-1" role="group" aria-label="Period">
          {DAYS.map((d) => (
            <button key={d} type="button" onClick={() => setDays(d)} aria-pressed={days === d}
                    className={`rounded-md border px-2.5 py-1 text-xs ${days === d ? "border-accent text-ink" : "border-line text-muted hover:text-ink"}`}>
              {d === 1 ? "Today" : `${d} days`}
            </button>
          ))}
        </div>
      }
    >
      {error && <p className="text-sm text-[var(--critical-text)]">{error}</p>}
      {r && r.hours_watched === 0 ? (
        <p className="py-6 text-center text-sm text-muted">
          Nothing recorded yet. Start live monitoring (<code>./start.sh live wlan0</code>) and use your network normally.
        </p>
      ) : r && v ? (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-3">
            <StatusBadge tone={v.tone} label={v.label} />
            <p className="text-sm text-ink-2">
              The AI flagged {count(r.ml.flagged_flows)} of {count(r.flows_analysed)} connections in{" "}
              {r.hours_watched.toFixed(1)} hours watched: {every(r.ml.per_hour)}.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <Stat label="Hours watched" value={r.hours_watched.toFixed(1)} />
            <Stat label="Connections checked" value={count(r.flows_analysed)} />
            <Stat label="AI false alarms" value={r.ml.per_1000_flows == null ? "—" : r.ml.per_1000_flows.toFixed(2)}
                  hint="per 1,000 connections" />
            <Stat label="Rule checker alarms" value={count(r.snort.alerts)}
                  hint={r.snort.by_agreement.confirmed ? `${count(r.snort.by_agreement.confirmed)} the AI agreed with` : undefined} />
          </div>

          <div className="grid gap-5 lg:grid-cols-2">
            <div>
              <p className="eyebrow mb-2">AI alarms per day</p>
              {r.daily.length === 0 ? <p className="text-xs text-muted">No days yet.</p> : (
                <table className="w-full text-xs">
                  <tbody>
                    {r.daily.map((d) => (
                      <tr key={d.day} className="border-t border-line">
                        <td className="tabular py-1.5 pr-3 text-ink">{d.day}</td>
                        <td className="py-1.5 pr-3">
                          <div className="flex items-center gap-2">
                            <span className="inline-block h-2 rounded-sm bg-[var(--series-1)]"
                                  style={{ width: `${(d.ml_flagged / maxDay) * 80}px` }} />
                            <span className="tabular text-ink-2">{count(d.ml_flagged)}</span>
                          </div>
                        </td>
                        <td className="tabular py-1.5 text-right text-muted">
                          {count(d.flows)} checked · {d.hours.toFixed(1)} h
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
            <div>
              <p className="eyebrow mb-2">Connections flagged most often</p>
              {top.length === 0 ? <p className="text-xs text-muted">None: no false alarms so far.</p> : (
                <table className="w-full text-xs">
                  <tbody>
                    {top.map(([pair, n]) => (
                      <tr key={pair} className="border-t border-line">
                        <td className="tabular break-all py-1.5 pr-3 text-ink">{pair}</td>
                        <td className="tabular py-1.5 text-right text-ink-2">{count(n)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              {Object.keys(r.ml.by_detector).length > 0 && (
                <p className="mt-2 text-xs text-muted">
                  Raised by: {Object.entries(r.ml.by_detector).map(([d, n]) => `${detectorName(d)} ${count(n)}`).join(" · ")}
                </p>
              )}
            </div>
          </div>

          {(r.excluded_test_alerts.ml > 0 || r.excluded_test_alerts.snort > 0) && (
            <p className="text-xs text-muted">
              Not counted: {count(r.excluded_test_alerts.ml)} AI and {count(r.excluded_test_alerts.snort)} rule checker
              alarms during your attack tests.
            </p>
          )}
        </div>
      ) : (
        !error && <p className="py-6 text-center text-sm text-muted">Loading…</p>
      )}
      {journal && (
        <div className="mt-5">
          <Tests tests={journal.tests} onChange={(tests) => { setJournal({ ...journal, tests }); load(); }} />
        </div>
      )}
    </Card>
  );
}
