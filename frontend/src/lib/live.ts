"use client";

import { useEffect, useEffectEvent, useState } from "react";

import { refreshAccess, tokens, WS_URL } from "./api";
import type { Alert, DetectorStats, ReplayStatus } from "./types";

const MAX_ALERTS = 200;
const MAX_POINTS = 120; // ~2 minutes at one stats message per second

export type RatePoint = { time: number } & Record<string, number>;

export type LiveState = {
  connection: "connecting" | "open" | "reconnecting";
  detectors: Record<string, DetectorStats>;
  replay: ReplayStatus;
  alerts: Alert[];
  /** Attacks flagged per second, per detector, one point per stats message. */
  flaggedRate: RatePoint[];
  /** Flows analysed per second, per detector. */
  sampleRate: RatePoint[];
};

const initial: LiveState = {
  connection: "connecting",
  detectors: {},
  replay: { state: "idle" },
  alerts: [],
  flaggedRate: [],
  sampleRate: [],
};

function secondsUntilExpiry(token: string | null): number {
  if (!token) return -1;
  try {
    const payload = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return payload.exp - Date.now() / 1000;
  } catch {
    return -1;
  }
}

/** A rejected WebSocket handshake reaches the browser only as a generic close, so
 *  refresh the access token *before* connecting when it is about to expire. */
async function freshToken(): Promise<string | null> {
  if (secondsUntilExpiry(tokens.access()) < 30 && !(await refreshAccess())) return null;
  return tokens.access();
}

function rate(
  previous: { time: number; detectors: Record<string, DetectorStats> } | null,
  time: number,
  detectors: Record<string, DetectorStats>,
  key: "flagged" | "samples",
): RatePoint | null {
  if (!previous || time <= previous.time) return null;
  const point: RatePoint = { time };
  for (const [name, stats] of Object.entries(detectors)) {
    const before = previous.detectors[name]?.[key] ?? 0;
    point[name] = Math.max(0, (stats[key] - before) / (time - previous.time));
  }
  return point;
}

export function useLiveFeed(onSessionEnd: () => void): LiveState {
  const [state, setState] = useState<LiveState>(initial);
  const sessionEnded = useEffectEvent(onSessionEnd);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let attempts = 0;
    let closed = false;
    let previous: { time: number; detectors: Record<string, DetectorStats> } | null = null;

    async function connect() {
      const token = await freshToken();
      if (closed) return;
      if (!token) {
        sessionEnded();
        return;
      }
      socket = new WebSocket(`${WS_URL}/ws/live/?token=${encodeURIComponent(token)}`);

      socket.onopen = () => {
        attempts = 0;
        setState((s) => ({ ...s, connection: "open" }));
      };

      socket.onmessage = (event) => {
        const message = JSON.parse(event.data);
        if (message.type === "reset") {
          previous = null;
          setState((s) => ({ ...s, alerts: [], flaggedRate: [], sampleRate: [] }));
        } else if (message.type === "stats") {
          const flagged = rate(previous, message.time, message.detectors, "flagged");
          const samples = rate(previous, message.time, message.detectors, "samples");
          previous = { time: message.time, detectors: message.detectors };
          setState((s) => ({
            ...s,
            detectors: message.detectors,
            replay: message.replay,
            flaggedRate: flagged ? [...s.flaggedRate, flagged].slice(-MAX_POINTS) : s.flaggedRate,
            sampleRate: samples ? [...s.sampleRate, samples].slice(-MAX_POINTS) : s.sampleRate,
          }));
        } else if (message.type === "alerts") {
          setState((s) => {
            const known = new Set(s.alerts.map((a) => a.id));
            const fresh = (message.alerts as Alert[]).filter((a) => !known.has(a.id));
            return { ...s, alerts: [...fresh, ...s.alerts].slice(0, MAX_ALERTS) };
          });
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
