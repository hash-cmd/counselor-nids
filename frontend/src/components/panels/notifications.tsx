"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import { clock } from "@/lib/format";
import { buildIncidents } from "@/lib/incidents";
import { ATTACK_INFO } from "@/lib/plain";
import { useLive } from "@/lib/live-feed";
import { categoryOf, ipOf, severityScore, type Tier, tierOf, TIER_META } from "@/lib/severity";

import { SeverityBadge } from "@/components/ui/severity-badge";

type Settings = { desktop: boolean; sound: boolean; minTier: "critical" | "high" };
const DEFAULTS: Settings = { desktop: false, sound: true, minTier: "high" };
const KEY = "nids.notify";

function load(): Settings {
  try {
    return { ...DEFAULTS, ...JSON.parse(localStorage.getItem(KEY) ?? "{}") };
  } catch {
    return DEFAULTS;
  }
}

const RANK: Record<Tier, number> = { critical: 3, high: 2, medium: 1, low: 0 };

/** A short beep via Web Audio — no asset, fails silently if blocked. */
function beep() {
  try {
    const Ctx = window.AudioContext ?? (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
    const ctx = new Ctx();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.frequency.value = 880;
    gain.gain.value = 0.04;
    osc.start();
    osc.stop(ctx.currentTime + 0.15);
    osc.onended = () => ctx.close();
  } catch {
    /* audio blocked (no gesture yet, or unsupported) */
  }
}

function IconBell({ active }: { active: boolean }) {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill={active ? "currentColor" : "none"} stroke="currentColor"
         strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9" />
      <path d="M10.3 21a1.94 1.94 0 0 0 3.4 0" />
    </svg>
  );
}

export function NotificationBell() {
  const live = useLive();
  const [settings, setSettings] = useState<Settings>(() => (typeof window === "undefined" ? DEFAULTS : load()));
  const [open, setOpen] = useState(false);
  const notified = useRef<Set<string> | null>(null); // null until primed
  const runRef = useRef<string>("");

  const incidents = useMemo(
    () => buildIncidents(live.alerts, live.snortAlerts),
    [live.alerts, live.snortAlerts],
  );
  const alerts = useMemo(
    () => incidents
      .map((i) => ({ incident: i, score: severityScore(i), tier: tierOf(severityScore(i)) }))
      .filter((a) => a.score > 0 && RANK[a.tier] >= RANK[settings.minTier]),
    [incidents, settings.minTier],
  );

  // Fire desktop/sound alerts for newly-seen high-severity incidents (side effects only).
  const runId = live.replay.state === "idle" ? "live" : live.replay.id;
  useEffect(() => {
    if (notified.current === null || runRef.current !== runId) {
      notified.current = new Set(alerts.map((a) => a.incident.key)); // prime: don't alert on the backlog
      runRef.current = runId;
      return;
    }
    const fresh = alerts.filter((a) => !notified.current!.has(a.incident.key));
    fresh.forEach((a) => notified.current!.add(a.incident.key));
    if (fresh.length === 0) return;
    if (settings.sound) beep();
    if (settings.desktop && typeof Notification !== "undefined" && Notification.permission === "granted") {
      for (const a of fresh.slice(0, 3)) {
        const title = `${TIER_META[a.tier].label} alert — ${ATTACK_INFO[categoryOf(a.incident)].title.replace(/\s*\(.*\)$/, "")}`;
        const from = ipOf(a.incident.src);
        try {
          new Notification(title, { body: from ? `From ${from}` : "See the dashboard", tag: a.incident.key });
        } catch {
          /* notifications unavailable */
        }
      }
    }
  }, [alerts, runId, settings.sound, settings.desktop]);

  function update(patch: Partial<Settings>) {
    const next = { ...settings, ...patch };
    setSettings(next);
    try {
      localStorage.setItem(KEY, JSON.stringify(next));
    } catch {
      /* storage blocked */
    }
  }

  async function toggleDesktop(on: boolean) {
    if (on && typeof Notification !== "undefined" && Notification.permission !== "granted") {
      const res = await Notification.requestPermission();
      if (res !== "granted") return; // user declined; leave it off
    }
    update({ desktop: on });
  }

  const count = alerts.length;

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        title="Alerts & notifications"
        aria-label="Alerts and notifications"
        className="relative rounded-md p-1.5 text-ink-2 hover:bg-wash hover:text-ink"
      >
        <IconBell active={count > 0} />
        {count > 0 && (
          <span
            className="absolute -right-0.5 -top-0.5 grid min-w-4 place-items-center rounded-full px-1 text-[10px] font-bold text-white"
            style={{ background: TIER_META[alerts[0].tier].color }}
          >
            {count > 9 ? "9+" : count}
          </span>
        )}
      </button>

      {open && (
        <>
          <div className="fixed inset-0 z-20" onClick={() => setOpen(false)} aria-hidden />
          <div className="absolute right-0 z-30 mt-2 w-80 rounded-xl border border-line bg-surface p-3 shadow-lg">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-sm font-semibold text-ink">High-severity alerts</span>
              <span className="text-xs text-muted">{count} active</span>
            </div>

            <div className="mb-3 space-y-1.5 rounded-lg bg-wash p-2 text-xs">
              <label className="flex items-center justify-between">
                <span className="text-ink-2">Desktop notifications</span>
                <input type="checkbox" checked={settings.desktop} onChange={(e) => toggleDesktop(e.target.checked)}
                       className="size-4 accent-[var(--accent)]" />
              </label>
              <label className="flex items-center justify-between">
                <span className="text-ink-2">Sound</span>
                <input type="checkbox" checked={settings.sound} onChange={(e) => update({ sound: e.target.checked })}
                       className="size-4 accent-[var(--accent)]" />
              </label>
              <label className="flex items-center justify-between">
                <span className="text-ink-2">Notify on</span>
                <select value={settings.minTier} onChange={(e) => update({ minTier: e.target.value as Settings["minTier"] })}
                        className="rounded border border-line bg-raised px-1.5 py-0.5 text-ink">
                  <option value="high">High and above</option>
                  <option value="critical">Critical only</option>
                </select>
              </label>
            </div>

            <div className="max-h-64 space-y-1 overflow-auto">
              {count === 0 ? (
                <p className="py-6 text-center text-xs text-muted">Nothing high-severity right now.</p>
              ) : (
                alerts.slice(0, 20).map((a) => (
                  <div key={a.incident.key} className="flex items-center gap-2 rounded-md px-1.5 py-1 text-xs">
                    <SeverityBadge tier={a.tier} />
                    <span className="min-w-0 flex-1 truncate text-ink-2">
                      {ATTACK_INFO[categoryOf(a.incident)].title.replace(/\s*\(.*\)$/, "")}
                      {a.incident.src && <span className="text-muted"> · {ipOf(a.incident.src)}</span>}
                    </span>
                    <span className="tabular shrink-0 text-muted">{a.incident.time ? clock(a.incident.time) : ""}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
