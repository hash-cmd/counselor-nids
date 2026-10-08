export type DetectorStats = {
  samples: number;
  flagged: number;
  conflicts: number;
  advised: number;
  cross_checked: number;
  fallback: number;
  retrained_on: number;
  /** conflicts settled by Snort's advice (Snort as a counselor) */
  snort_advised: number;
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

export type Interval = { low: number | null; high: number | null };

export type ByLabelTable = {
  series: string[];
  rows: { label: string; flows: number; flagged: Record<string, number | null>; interval?: Interval | null }[];
  summary: Record<string, Metrics>;
};

export type SystemTestRow = { traffic: string; flows: number; ai: number; snort: number; either: number };

export type CrossHost = {
  host: string; bot_flows: number; benign_flows: number;
  detection_rate: number; false_alarm_rate: number; detection_interval: Interval; false_alarm_interval: Interval;
};

export type AdaptScore = {
  detection_rate: number; detection_rate_low: number; detection_rate_high: number;
  false_alarm_rate: number; false_alarm_rate_low: number; false_alarm_rate_high: number;
  balanced: number | null; labels: Record<string, number | null>;
};

export type SnortTrustRow = { rule: string; msg: string; agree: number; disagree: number; trust: number };

export type Adaptation = {
  name: string; source: string; target: string; development: boolean; chunks: number;
  curve: { config: string; step: number; detection_rate: number; false_alarm_rate: number; balanced: number | null }[];
  final: Record<string, AdaptScore>;
  baselines: Record<string, AdaptScore>;
  mcnemar: { system_a: string; system_b: string; b: number; c: number; test: string; statistic: number; p_value: number }[];
  agreement: { config: string; attack_labels: number; normal_labels: number; attack_precision: number | null;
               normal_precision: number | null; attack_interval: Interval; normal_interval: Interval }[];
  rule_trust: SnortTrustRow[];
};

export type Results = {
  by_label: Partial<Record<"live", ByLabelTable>>;
  system_tests: Partial<Record<"project_rules" | "project_rules_snort_counselor" | "community_rules" | "community_rules_snort_counselor", SystemTestRow[]>>;
  cross_host: CrossHost | null;
  adaptation: Adaptation[];
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
  /** your verdicts: alarms you marked real attacks are not counted as false alarms */
  marked?: { real_attacks: number; confirmed_false_alarms: number };
  daily: { day: string; flows: number; hours: number; ml_flagged: number; snort: number }[];
};

export type Journal = { days: number; report: JournalReport; tests: AttackTest[] };

/** One service's heartbeat: ok unless it has gone quiet (or, for Snort, its process exited). */
export type ServiceHealth = { service: string; ok: boolean; age: number } & Record<string, unknown>;
