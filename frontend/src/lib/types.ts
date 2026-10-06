export type DetectorStats = {
  samples: number;
  flagged: number;
  conflicts: number;
  advised: number;
  cross_checked: number;
  fallback: number;
  retrained_on: number;
  accuracy: number | null;
  detection_rate: number | null;
};

export type ReplayStatus =
  | { state: "idle" }
  | {
      id: string;
      state: "running" | "finished" | "failed" | "stopped";
      replay: string;
      kind: "flows" | "pcap";
      snort: boolean;
      rate: number;
      cross_check: boolean;
      min_accuracy: number;
      started_at: number;
      finished_at: number | null;
      processes: Record<string, string>;
      errors?: Record<string, string>;
    };

export type Alert = {
  id: string;
  detector: string;
  record_id: number;
  timestamp: number;
  /** wall-clock time the detector decided (Unix seconds) */
  time: number | null;
  resolution: "unanimous" | "advice" | "cross_check" | "fallback";
  counselor: string | null;
  label?: string;
  /** "ip:port" — packet captures and live traffic only */
  src: string | null;
  /** "ip:port", or "port N" for replayed flow records */
  dst: string | null;
};

export type Breakdown = {
  ml_labels: Record<string, number>;
  snort_rules: Record<string, number>;
  sources: { ip: string; ml: number; snort: number }[];
  ml_flagged_flows: number;
};

export type Activity = "idle" | "running" | "ended";

export type ReplayOptions = {
  replays: { name: string; kind: "flows" | "pcap"; size_mb: number }[];
  models: string[];
  snort: boolean;
  status: ReplayStatus;
};

export type SnortSummary = {
  alerts: number;
  confirmed: number;
  disputed: number;
  no_verdict: number;
  unmatched: number;
  pending: number;
  flows: { both: number; snort_only: number; ml_only: number };
};

export type SnortAlert = {
  id: string;
  seconds: number;
  msg: string;
  gid: number;
  sid: number;
  priority: number;
  class: string;
  proto: string;
  src: string;
  dst: string;
  flows: number;
  record_id: number;
  agreement: "confirmed" | "disputed" | "no_verdict" | "unmatched";
  ml_verdict: "attack" | "normal" | null;
  ml_share: number | null;
  ml_confidence: number | null;
  ml_detector: string | null;
  time: number | null;
};

export type ComparisonRow = {
  approach: string;
  label: string;
  accuracy: number | null;
  detection_rate: number | null;
  false_alarm_rate: number | null;
};

export type SelfLearningRow = {
  chunk: number;
  detector: string;
  retrain: boolean;
  labels: string;
  standalone_accuracy: number;
  final_accuracy: number;
  learned: number;
};

export type Results = {
  comparisons: Record<string, { detectors: Record<string, ComparisonRow[]>; args: Record<string, unknown> | null }>;
  self_learning: Record<string, SelfLearningRow[]>;
};
