"use client";

import { useEffect, useState } from "react";

import { api } from "./api";
import type { Alert, SnortAlert } from "./types";

export type IncidentSource = "both" | "ml" | "snort";

/** One flagged flow, with everything the ML and Snort said about it (same shape as
 *  GET /api/incidents/). */
export type Incident = {
  key: string;
  record_id: number | null;
  time: number | null;
  src: string | null;
  dst: string | null;
  label: string | null;
  source: IncidentSource;
  /** the analyst's verdict on this connection, if any */
  feedback?: "normal" | "attack" | null;
  /** origins: the detectors that raised the alarm themselves (a cross-checked alarm
   *  belongs to the counselor that recognised the attack, not to the detector that asked) */
  ml: { detectors: string[]; resolutions: string[]; counselors: string[]; origins: string[] } | null;
  snort: {
    rules: string[];
    ids: string[];
    flows: number;
    agreement: SnortAlert["agreement"];
    ml_verdict: string | null;
  } | null;
};

export const SOURCE_LABELS: Record<IncidentSource, string> = {
  both: "AI + rule checker",
  ml: "AI only",
  snort: "Rule checker only",
};

/** Group the live feed's latest alerts by flow — for the overview's "latest" list.
 *  The Alerts page asks the server instead, which searches the full history. */
export function buildIncidents(alerts: Alert[], snortAlerts: SnortAlert[],
                               verdicts: Record<number, "normal" | "attack"> = {}): Incident[] {
  const byFlow = new Map<string, Incident>();
  const get = (key: string, recordId: number | null) => {
    let incident = byFlow.get(key);
    if (!incident) {
      incident = { key, record_id: recordId, time: null, src: null, dst: null, label: null, source: "ml", ml: null, snort: null };
      byFlow.set(key, incident);
    }
    return incident;
  };

  for (const a of alerts) {
    const incident = get(`flow-${a.record_id}`, a.record_id);
    incident.ml ??= { detectors: [], resolutions: [], counselors: [], origins: [] };
    const origin = a.resolution === "cross_check" && a.counselor ? a.counselor : a.detector;
    if (!incident.ml.origins.includes(origin)) incident.ml.origins.push(origin);
    if (!incident.ml.detectors.includes(a.detector)) incident.ml.detectors.push(a.detector);
    if (!incident.ml.resolutions.includes(a.resolution)) incident.ml.resolutions.push(a.resolution);
    if (a.counselor && !incident.ml.counselors.includes(a.counselor)) incident.ml.counselors.push(a.counselor);
    incident.time = Math.max(incident.time ?? 0, a.time ?? 0) || null;
    incident.src ??= a.src;
    incident.dst ??= a.dst;
    incident.label ??= a.label ?? null;
  }

  for (const s of snortAlerts) {
    const key = s.record_id >= 0 ? `flow-${s.record_id}` : `snort-${s.id}`;
    const incident = get(key, s.record_id >= 0 ? s.record_id : null);
    incident.snort ??= { rules: [], ids: [], flows: s.flows, agreement: s.agreement, ml_verdict: s.ml_verdict };
    if (!incident.snort.rules.includes(s.msg)) incident.snort.rules.push(s.msg);
    incident.snort.ids.push(`${s.gid}:${s.sid}`);
    incident.snort.flows = Math.max(incident.snort.flows, s.flows);
    if (s.agreement === "confirmed") incident.snort.agreement = "confirmed";
    incident.time = Math.max(incident.time ?? 0, s.time ?? 0) || null;
    incident.src ??= s.src || null;
    incident.dst ??= s.dst || null;
  }

  for (const incident of byFlow.values()) {
    incident.source = incident.ml && incident.snort ? "both" : incident.snort ? "snort" : "ml";
    incident.feedback = incident.record_id != null ? verdicts[incident.record_id] ?? null : null;
  }
  return [...byFlow.values()].sort((a, b) => (b.time ?? 0) - (a.time ?? 0) || (b.record_id ?? 0) - (a.record_id ?? 0));
}

export type IncidentPage = {
  counts: Record<"all" | IncidentSource, number>;
  total: number;
  incidents: Incident[];
};

/** Server-side incidents over the full alert history; refreshes while detection runs.
 *  ``refreshKey`` changes (e.g. a new replay) trigger a refetch. */
export function useIncidents(source: "all" | IncidentSource, query: string, limit: number, live: boolean, refreshKey: string) {
  const [data, setData] = useState<IncidentPage | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const params = new URLSearchParams({ source, q: query, limit: String(limit) });

    async function load() {
      try {
        const page = await api<IncidentPage>(`/incidents/?${params}`);
        if (!cancelled) {
          setData(page);
          setError(null);
        }
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : "Could not load incidents");
      }
      if (!cancelled && live) timer = setTimeout(load, 3000);
    }

    // debounce typing in the search box
    const start = setTimeout(load, query ? 250 : 0);
    return () => {
      cancelled = true;
      clearTimeout(start);
      clearTimeout(timer);
    };
  }, [source, query, limit, live, refreshKey]);

  return { data, error };
}
