/** Severity scoring and attacker correlation — turns a flat alert list into ranked,
 *  prioritised incidents and "attack stories" grouped by who is doing it. */

import { attackCategory, type Category, ATTACK_INFO } from "./plain";
import type { Incident } from "./incidents";

export type Tier = "critical" | "high" | "medium" | "low";

/** How dangerous each kind of activity is on its own (0–100 base). */
const CATEGORY_WEIGHT: Record<Category, number> = {
  exploit: 85, botnet: 85, "web-sql": 78, "web-files": 70, insider: 68,
  dos: 62, bruteforce: 58, "web-xss": 48, web: 46, smb: 40, rdp: 38, scan: 32, unknown: 42,
};

function clueText(incident: Incident): string {
  if (incident.snort?.rules.length) return incident.snort.rules.join(" ");
  return incident.label ?? "unknown";
}

export function categoryOf(incident: Incident): Category {
  return attackCategory(clueText(incident));
}

/** 0–100 severity for one incident: how dangerous, how corroborated, how broad. */
export function severityScore(incident: Incident): number {
  if (incident.label && incident.label.toLowerCase() === "benign") return 0; // known false alarm
  let score = CATEGORY_WEIGHT[categoryOf(incident)];

  // Corroboration: two independent methods agreeing is the strongest signal.
  if (incident.source === "both") score += 18;
  // The rule checker fired but the AI judged it normal — more likely a false alarm.
  else if (incident.source === "snort" && incident.snort?.ml_verdict === "normal") score -= 14;

  // Breadth: a host-level alert covering many connections (a scan/flood/sweep).
  const flows = incident.snort?.flows ?? 1;
  if (flows > 1) score += Math.min(14, Math.round(Math.log10(flows) * 9));

  return Math.max(1, Math.min(100, score));
}

export function tierOf(score: number): Tier {
  return score >= 75 ? "critical" : score >= 55 ? "high" : score >= 35 ? "medium" : "low";
}

export const TIER_META: Record<Tier, { label: string; color: string; order: number }> = {
  critical: { label: "Critical", color: "var(--status-critical)", order: 3 },
  high: { label: "High", color: "var(--status-warning)", order: 2 },
  medium: { label: "Medium", color: "var(--series-3)", order: 1 },
  low: { label: "Low", color: "var(--ink-muted)", order: 0 },
};

/** IP without the port, from an "ip:port" endpoint. */
export function ipOf(endpoint: string | null): string | null {
  if (!endpoint) return null;
  const i = endpoint.lastIndexOf(":");
  return i > 0 ? endpoint.slice(0, i) : endpoint;
}

export type Attacker = {
  ip: string;
  incidents: Incident[];
  score: number;          // the worst single thing they did
  tier: Tier;
  categories: Category[]; // distinct activity, in the order it first appeared (the "story")
  targets: string[];      // distinct destination IPs they hit
  firstSeen: number | null;
  lastSeen: number | null;
};

/** Group incidents by the source IP behind them into ranked attacker profiles.
 *  Benign (false-alarm) incidents are left out. */
export function groupByAttacker(incidents: Incident[]): Attacker[] {
  const byIp = new Map<string, Incident[]>();
  for (const incident of incidents) {
    if (severityScore(incident) === 0) continue;
    const ip = ipOf(incident.src);
    if (!ip) continue;
    (byIp.get(ip) ?? byIp.set(ip, []).get(ip)!).push(incident);
  }

  const attackers: Attacker[] = [];
  for (const [ip, list] of byIp) {
    const ordered = [...list].sort((a, b) => (a.time ?? 0) - (b.time ?? 0));
    const categories: Category[] = [];
    const targets = new Set<string>();
    for (const i of ordered) {
      const c = categoryOf(i);
      if (!categories.includes(c)) categories.push(c);
      const dst = ipOf(i.dst);
      if (dst) targets.add(dst);
    }
    const score = Math.max(...list.map(severityScore));
    const times = ordered.map((i) => i.time).filter((t): t is number => t != null);
    attackers.push({
      ip, incidents: ordered, score, tier: tierOf(score), categories,
      targets: [...targets],
      firstSeen: times[0] ?? null,
      lastSeen: times[times.length - 1] ?? null,
    });
  }

  return attackers.sort((a, b) => b.score - a.score || b.incidents.length - a.incidents.length);
}

/** How many incidents fall in each severity tier (benign/false-alarm excluded). */
export function severityCounts(incidents: Incident[]): Record<Tier, number> {
  const counts: Record<Tier, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const i of incidents) {
    const s = severityScore(i);
    if (s > 0) counts[tierOf(s)]++;
  }
  return counts;
}

/** The attack as a short sentence: the sequence of distinct activities, in order. */
export function attackStory(attacker: Attacker): string {
  const steps = attacker.categories.map((c) => ATTACK_INFO[c].title.replace(/\s*\(.*\)$/, ""));
  if (steps.length === 1) return steps[0];
  return steps.join(" → ");
}
