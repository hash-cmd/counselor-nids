"use client";

import { createContext, useContext, useEffect, useEffectEvent, useState } from "react";

import { api, ApiError, WS_URL } from "./api";
import type { Activity, Alert, LiveCapture, Breakdown, DetectorStats, ReplayStatus, SnortAlert, SnortSummary } from "./types";

const MAX_ALERTS = 500;
const MAX_POINTS = 180; // ~3 minutes at one stats message per second

export type RatePoint = { time: number } & Record<string, number>;

export type LiveState = {
  connection: "connecting" | "open" | "reconnecting";
  detectors: Record<string, DetectorStats>;
  replay: ReplayStatus;
  /** running while detector services process a stream — a replay or `./start.sh live` */
  activity: Activity;
  /** set while a network interface is being captured live (not for recordings) */
  live: LiveCapture | null;
  alerts: Alert[];
  /** Snort running next to the ML: summary (null when Snort is not running) and alerts. */
  snort: SnortSummary | null;
  snortAlerts: SnortAlert[];
  breakdown: Breakdown | null;
  /** Detections per second: flows the ML flagged (any detector) and Snort alerts. */
  detectionRate: RatePoint[];
  /** Attacks flagged per second, per detector. */
  flaggedRate: RatePoint[];
  /** Flows analysed per second, per detector. */
  sampleRate: RatePoint[];
};

const initial: LiveState = {
  connection: "connecting",
  detectors: {},
  replay: { state: "idle" },
  activity: "idle",
  live: null,
  alerts: [],
  snort: null,
  snortAlerts: [],
  breakdown: null,
  detectionRate: [],
  flaggedRate: [],
  sampleRate: [],
};

/** A rejected WebSocket handshake reaches the browser only as a generic close, so
 *  check the session first: this renews an expired access cookie, and the handshake
 *  then carries a valid one. */
async function sessionValid(): Promise<boolean> {
  try {
    await api("/auth/me/");
    return true;
  } catch (e) {
    return !(e instanceof ApiError && e.status === 401); // network trouble: retry the socket
  }
}

type Snapshot = { time: number; values: Record<string, number> };

/** Per-second rate of each counter between two snapshots. */
function rate(previous: Snapshot | null, current: Snapshot): RatePoint | null {
  if (!previous || current.time <= previous.time) return null;
  const point: RatePoint = { time: current.time };
  for (const [name, value] of Object.entries(current.values)) {
    point[name] = Math.max(0, (value - (previous.values[name] ?? 0)) / (current.time - previous.time));
  }
  return point;
}

const append = (points: RatePoint[], point: RatePoint | null) =>
  point ? [...points, point].slice(-MAX_POINTS) : points;

function merge<T extends { id: string }>(current: T[], incoming: T[]): T[] {
  const known = new Set(current.map((a) => a.id));
  return [...incoming.filter((a) => !known.has(a.id)), ...current].slice(0, MAX_ALERTS);
}

function useLiveFeed(onSessionEnd: () => void): LiveState {
  const [state, setState] = useState<LiveState>(initial);
  const sessionEnded = useEffectEvent(onSessionEnd);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let attempts = 0;
    let closed = false;
    let previous: { flagged: Snapshot; samples: Snapshot; detections: Snapshot } | null = null;

    async function connect() {
      const valid = await sessionValid();
      if (closed) return;
      if (!valid) {
        sessionEnded();
        return;
      }
      socket = new WebSocket(`${WS_URL}/ws/live/`); // the access cookie authenticates it

      socket.onopen = () => {
        attempts = 0;
        setState((s) => ({ ...s, connection: "open" }));
      };

      socket.onmessage = (event) => {
        const message = JSON.parse(event.data);
        if (message.type === "reset") {
          previous = null;
          setState((s) => ({
            ...s, alerts: [], snort: null, snortAlerts: [], breakdown: null,
            detectionRate: [], flaggedRate: [], sampleRate: [],
          }));
        } else if (message.type === "stats") {
          const detectors: Record<string, DetectorStats> = message.detectors;
          const current = {
            flagged: { time: message.time, values: Object.fromEntries(Object.entries(detectors).map(([n, d]) => [n, d.flagged])) },
            samples: { time: message.time, values: Object.fromEntries(Object.entries(detectors).map(([n, d]) => [n, d.samples])) },
            detections: {
              time: message.time,
              values: { ml: message.breakdown?.ml_flagged_flows ?? 0, snort: message.snort?.alerts ?? 0 },
            },
          };
          const points = {
            flagged: rate(previous?.flagged ?? null, current.flagged),
            samples: rate(previous?.samples ?? null, current.samples),
            detections: rate(previous?.detections ?? null, current.detections),
          };
          previous = current;
          setState((s) => ({
            ...s,
            detectors,
            snort: message.snort ?? null,
            breakdown: message.breakdown ?? null,
            activity: message.activity ?? "idle",
            live: message.live ?? null,
            replay: message.replay,
            flaggedRate: append(s.flaggedRate, points.flagged),
            sampleRate: append(s.sampleRate, points.samples),
            detectionRate: append(s.detectionRate, points.detections),
          }));
        } else if (message.type === "snort_alerts") {
          setState((s) => ({ ...s, snortAlerts: merge(s.snortAlerts, message.alerts as SnortAlert[]) }));
        } else if (message.type === "alerts") {
          setState((s) => ({ ...s, alerts: merge(s.alerts, message.alerts as Alert[]) }));
        }
      };

      socket.onclose = () => {
        if (closed) return;
        setState((s) => ({ ...s, connection: "reconnecting" }));
        attempts += 1;
        retry = setTimeout(connect, Math.min(1000 * 2 ** (attempts - 1), 10_000));
      };
    }

    connect();
    return () => {
      closed = true;
      clearTimeout(retry);
      socket?.close();
    };
  }, []);

  return state;
}

const LiveContext = createContext<LiveState | null>(null);

/** One WebSocket for every dashboard page, so switching pages keeps the live data. */
export function LiveProvider({ onSessionEnd, children }: { onSessionEnd: () => void; children: React.ReactNode }) {
  const live = useLiveFeed(onSessionEnd);
  return <LiveContext.Provider value={live}>{children}</LiveContext.Provider>;
}

export function useLive(): LiveState {
  const live = useContext(LiveContext);
  if (!live) throw new Error("useLive must be used inside LiveProvider");
  return live;
}
