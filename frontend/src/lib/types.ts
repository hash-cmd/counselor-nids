export type DetectorStats = {
  samples: number;
  flagged: number;
  conflicts: number;
  advised: number;
  cross_checked: number;
  fallback: number;
  retrained_on: number;
};

export type ReplayStatus =
  | { state: "idle" }
  | {
      id: string;
      state: "running" | "finished" | "failed" | "stopped";
      replay: string;
      kind: "pcap";
      snort: boolean;
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
  /** "ip:port" */
  dst: string | null;
};

export type Breakdown = {
  snort_rules: Record<string, number>;
  sources: { ip: string; ml: number; snort: number }[];
  ml_flagged_flows: number;
};

export type Activity = "idle" | "running" | "ended";

/** The network interface being captured, while `./start.sh live <iface>` runs. */
export type LiveCapture = { target: string; started_at: number; /** "waiting": the interface is down, capture resumes when it is back */ state: "capturing" | "waiting" };

export type ReplayOptions = {
  replays: { name: string; kind: "pcap"; size_mb: number; description: string | null }[];
  /** the live detectors that will judge the recording */
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

export type Metrics = { accuracy: number; detection_rate: number; false_alarm_rate: number };

export type ByLabelTable = {
  series: string[];
  rows: { label: string; flows: number; flagged: Record<string, number | null> }[];
  summary: Record<string, Metrics>;
};

export type Results = {
  by_label: Partial<Record<"live", ByLabelTable>>;
};

export type AttackTest = { start: number; end: number | null; note: string };

export type JournalReport = {
  hours_watched: number;
  flows_analysed: number;
  ml: {
    flagged_flows: number;
    per_1000_flows: number | null;
    per_hour: number | null;
    by_detector: Record<string, number>;
    top_connections: Record<string, number>;
  };
  snort: { alerts: number; by_agreement: Record<string, number>; top_rules: Record<string, number> };
  excluded_test_alerts: { ml: number; snort: number };
  daily: { day: string; flows: number; hours: number; ml_flagged: number; snort: number }[];
};

export type Journal = { days: number; report: JournalReport; tests: AttackTest[] };

/** One service's heartbeat: ok unless it has gone quiet (or, for Snort, its process exited). */
export type ServiceHealth = { service: string; ok: boolean; age: number } & Record<string, unknown>;
