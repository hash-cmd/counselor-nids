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
  resolution: "unanimous" | "advice" | "cross_check" | "fallback";
  counselor: string | null;
  label?: string;
};

export type ReplayOptions = {
  replays: { name: string; size_mb: number }[];
  models: string[];
  status: ReplayStatus;
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
