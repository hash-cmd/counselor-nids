"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";

import { api, ApiError } from "./api";

export type Verdict = "normal" | "attack";

export type LearningReport = {
  verdicts: number;
  installed: string[];
  message?: string;
  finished?: number;
  detectors: Record<string, {
    marked_flagged_before: number; marked_flagged_after: number;
    real_attacks_caught_before: number; real_attacks_caught_after: number;
    lab_detection: [number, number]; lab_false_alarms: [number, number];
    accepted: boolean; problems: string[];
  }>;
};

export type LearningStatus = {
  state: "idle" | "running" | "finished" | "failed";
  started_at: number | null;
  report?: LearningReport;
  error?: string;
};

export type FeedbackState = {
  /** this run's verdicts: record id -> verdict */
  verdicts: Record<number, Verdict>;
  summary: { total: number; normal: number; attack: number; learnable: number };
  learning: LearningStatus;
};

type FeedbackContextValue = FeedbackState & {
  mark: (recordId: number, verdict: Verdict) => Promise<void>;
  learn: () => Promise<void>;
  error: string | null;
};

const empty: FeedbackState = {
  verdicts: {}, summary: { total: 0, normal: 0, attack: 0, learnable: 0 }, learning: { state: "idle", started_at: null },
};

const FeedbackContext = createContext<FeedbackContextValue | null>(null);

/** The analyst's verdicts on alarms ("Not an attack" / "Real attack") and the detectors'
 *  learning from them, shared by every page. */
export function FeedbackProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<FeedbackState>(empty);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(
    () => api<FeedbackState>("/feedback/").then(setState).catch(() => undefined), // the next poll retries
    [],
  );

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, state.learning.state === "running" ? 3000 : 10000);
    return () => clearInterval(timer);
  }, [refresh, state.learning.state]);

  const mark = useCallback(async (recordId: number, verdict: Verdict) => {
    setError(null);
    setState((s) => ({ ...s, verdicts: { ...s.verdicts, [recordId]: verdict } })); // optimistic
    try {
      await api("/feedback/", { method: "POST", body: JSON.stringify({ record_id: recordId, verdict }) });
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not save your verdict");
    }
    await refresh();
  }, [refresh]);

  const learn = useCallback(async () => {
    setError(null);
    try {
      await api("/feedback/learn/", { method: "POST" });
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not start learning");
    }
    await refresh();
  }, [refresh]);

  return <FeedbackContext.Provider value={{ ...state, mark, learn, error }}>{children}</FeedbackContext.Provider>;
}

export function useFeedback(): FeedbackContextValue {
  const value = useContext(FeedbackContext);
  if (!value) throw new Error("useFeedback must be used inside FeedbackProvider");
  return value;
}
