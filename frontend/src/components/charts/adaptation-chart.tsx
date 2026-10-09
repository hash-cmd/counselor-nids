"use client";

import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { count, percent } from "@/lib/format";
import { attackName, configName } from "@/lib/plain";
import type { AdaptScore, Adaptation, Interval } from "@/lib/types";

import { axisProps, Card, DataTable, Legend, TooltipBox, useViewToggle } from "@/components/ui/chart-parts";
import { StatusBadge } from "@/components/ui/status-badge";

/** The four configurations drawn over time, each with its own fixed colour slot (colour
 *  follows the configuration, never its rank). Ablations are in the table only. */
const DRAWN = [
  { key: "ai", color: "var(--series-1)" },
  { key: "+snort", color: "var(--series-2)" },
  { key: "+learn", color: "var(--series-3)" },
  { key: "full", color: "var(--series-4)" },
];

const withInterval = (value: number, low: number | null | undefined, high: number | null | undefined, digits = 2) =>
  low == null || high == null ? percent(value, digits) : `${percent(value, digits)} (${percent(low, digits)}–${percent(high, digits)})`;

const interval = (value: number | null, i: Interval) => (value == null ? "—" : withInterval(value, i.low, i.high, 1));

function pValue(p: number): string {
  if (p === 0 || p < 1e-15) return "p < 10⁻¹⁵";
  return p < 0.001 ? `p = ${p.toExponential(1)}` : `p = ${p.toFixed(3)}`;
}

/** Balanced score (mean of every attack type's detection and 1 − false alarms) after each
 *  chunk of the new network's traffic. */
function Curve({ exp }: { exp: Adaptation }) {
  const { view, toggle } = useViewToggle();
  const drawn = DRAWN.filter((d) => exp.curve.some((p) => p.config === d.key));
  const steps = [...new Set(exp.curve.map((p) => p.step))].sort((a, b) => a - b);
  const data = steps.map((step) => ({
    step,
    ...Object.fromEntries(drawn.map((d) => [d.key, exp.curve.find((p) => p.config === d.key && p.step === step)?.balanced ?? null])),
  }));
  const values = data.flatMap((row) => drawn.map((d) => (row as Record<string, number | null>)[d.key])).filter((v): v is number => v != null);
  const low = Math.max(0, Math.floor((Math.min(...values) - 0.01) * 50) / 50);

  return (
    <Card
      title="Balanced score while adapting"
      tag="Fig · Adaptation"
      subtitle={`After each of the ${exp.chunks} chunks of ${exp.target} traffic the detectors watched. Balanced score = average of every attack type's detection rate and (1 − false-alarm rate); higher is better.`}
      actions={toggle}
    >
      {view === "table" ? (
        <DataTable
          columns={[{ key: "step", label: "After chunk" }, ...drawn.map((d) => ({ key: d.key, label: configName(d.key), align: "right" as const }))]}
          rows={data.map((row) => ({
            step: row.step === 0 ? "start" : row.step,
            ...Object.fromEntries(drawn.map((d) => [d.key, percent((row as Record<string, number | null>)[d.key], 2)])),
          }))}
        />
      ) : (
        <>
          <Legend items={drawn.map((d) => {
            // a line drawn exactly under another one is otherwise invisible: say so
            const same = drawn.find((o) => o.key !== d.key && DRAWN.indexOf(o) > DRAWN.indexOf(d) &&
              data.every((row) => (row as Record<string, number | null>)[o.key] === (row as Record<string, number | null>)[d.key]));
            return { name: configName(d.key) + (same ? ` (same as “${configName(same.key)}”)` : ""), color: d.color, shape: "line" as const };
          })} />
          <div className="h-64">
            <ResponsiveContainer>
              <LineChart data={data} margin={{ top: 8, right: 16, bottom: 0, left: 0 }}>
                <CartesianGrid vertical={false} stroke="var(--grid)" />
                <XAxis dataKey="step" tickFormatter={(s) => (s === 0 ? "start" : `chunk ${s}`)} {...axisProps} />
                <YAxis width={52} domain={[low, 1]} tickFormatter={(v) => percent(v, 0)} axisLine={false} {...axisProps} />
                <Tooltip
                  cursor={{ stroke: "var(--axis)", strokeWidth: 1 }}
                  isAnimationActive={false}
                  content={({ active, label, payload }) =>
                    active && payload?.length ? (
                      <TooltipBox
                        title={Number(label) === 0 ? "Before adapting" : `After chunk ${label}`}
                        rows={drawn.map((d) => ({
                          name: configName(d.key), color: d.color,
                          value: percent(payload.find((p) => p.dataKey === d.key)?.value as number | undefined, 2),
                        }))}
                      />
                    ) : null
                  }
                />
                {drawn.map((d) => (
                  <Line key={d.key} dataKey={d.key} stroke={d.color} strokeWidth={2} isAnimationActive={false}
                        dot={{ r: 4, strokeWidth: 2, stroke: "var(--surface)", fill: d.color }}
                        activeDot={{ r: 5, stroke: "var(--surface)", strokeWidth: 2 }} />
                ))}
              </LineChart>
            </ResponsiveContainer>
          </div>
        </>
      )}
    </Card>
  );
}

function Comparison({ exp }: { exp: Adaptation }) {
  const rows: [string, AdaptScore][] = [...Object.entries(exp.baselines), ...Object.entries(exp.final)];
  const vsDeployed = (key: string) => exp.mcnemar.find((m) => m.system_a === key && m.system_b === "ai");

  return (
    <Card
      title="Every configuration at the end"
      subtitle="95% confidence intervals in brackets. McNemar's test compares each configuration with the deployed system on the same test connections: b = connections only it got right, c = only the deployed system got right; p < 0.05 means the difference is very unlikely to be chance."
    >
      <DataTable
        scroll={false}
        columns={[
          { key: "config", label: "Configuration" },
          { key: "detection", label: "Attacks caught", align: "right" },
          { key: "false_alarms", label: "False alarms", align: "right" },
          { key: "balanced", label: "Balanced", align: "right" },
          { key: "mcnemar", label: "vs deployed (McNemar)" },
        ]}
        rows={rows.map(([key, s]) => {
          const m = vsDeployed(key);
          return {
            config: configName(key),
            detection: withInterval(s.detection_rate, s.detection_rate_low, s.detection_rate_high),
            false_alarms: withInterval(s.false_alarm_rate, s.false_alarm_rate_low, s.false_alarm_rate_high),
            balanced: percent(s.balanced, 1),
            mcnemar: m ? (
              <span className="flex items-center gap-2 whitespace-nowrap">
                {count(m.b)} vs {count(m.c)} · {pValue(m.p_value)}
                {m.p_value < 0.05 && <StatusBadge tone={m.b > m.c ? "good" : "critical"} label={m.b > m.c ? "more right" : "more wrong"} />}
              </span>
            ) : key === "ai" ? "—" : "",
          };
        })}
      />
    </Card>
  );
}

/** Per attack type, for the baselines and the four main configurations. */
function PerAttack({ exp }: { exp: Adaptation }) {
  const shown = ["snort alone", "ai or snort", ...DRAWN.map((d) => d.key)];
  const scores: Record<string, AdaptScore> = { ...exp.baselines, ...exp.final };
  const configs = shown.filter((k) => scores[k]);
  const labels = Object.keys(scores[configs[0]]?.labels ?? {});
  return (
    <Card title="Per kind of traffic" subtitle="Share flagged as an attack at the end; the normal-traffic row is the false-alarm rate">
      <DataTable
        scroll={false}
        columns={[{ key: "label", label: "Traffic" }, ...configs.map((k) => ({ key: k, label: configName(k), align: "right" as const }))]}
        rows={labels.map((l) => ({
          label: l === "Benign" ? "Normal traffic (false alarms)" : attackName(l),
          ...Object.fromEntries(configs.map((k) => [k, percent(scores[k].labels[l], 1)])),
        }))}
      />
    </Card>
  );
}

function Agreement({ exp }: { exp: Adaptation }) {
  const rows = exp.agreement.filter((a) => a.config === "full" || a.config === "+learn").slice(0, 1);
  const rules = exp.rule_trust;
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="How accurate the agreement labels were"
            subtitle="Connections labelled from Snort–AI agreement, checked against the dataset's real answers (which the system never sees)">
        {rows.length === 0 ? <p className="text-sm text-muted">No labels recorded.</p> : (
          <DataTable
            columns={[{ key: "kind", label: "Label" }, { key: "n", label: "Labels made", align: "right" }, { key: "right", label: "Right (95% interval)", align: "right" }]}
            rows={[
              { kind: "Attack (Snort + AI agree)", n: count(rows[0].attack_labels), right: interval(rows[0].attack_precision, rows[0].attack_interval) },
              { kind: "Normal (Snort silent, all detectors sure)", n: count(rows[0].normal_labels), right: interval(rows[0].normal_precision, rows[0].normal_interval) },
            ]}
          />
        )}
      </Card>
      <Card title="How much each Snort rule ended up trusted"
            subtitle="Adaptive rule trust: raised when the AI independently agrees, lowered when the AI is sure the traffic is normal and has flagged nothing from that source. Advice counts at 90% or more.">
        {rules.length === 0 ? <p className="text-sm text-muted">No rule trust recorded.</p> : <TrustTable rows={rules} />}
      </Card>
    </div>
  );
}

export function TrustTable({ rows }: { rows: { rule: string; msg: string; agree: number; disagree: number; trust: number }[] }) {
  return (
    <DataTable
      scroll={false}
      columns={[
        { key: "rule", label: "Snort rule" },
        { key: "agree", label: "AI agreed", align: "right" },
        { key: "disagree", label: "AI disagreed", align: "right" },
        { key: "trust", label: "Trust" },
      ]}
      rows={rows.map((r) => ({
        rule: <span title={r.rule}>{r.msg || r.rule}</span>,
        agree: count(r.agree),
        disagree: count(r.disagree),
        trust: (
          <span className="flex items-center gap-2 whitespace-nowrap">
            <span className="tabular">{percent(r.trust, 1)}</span>
            <StatusBadge tone={r.trust >= 0.9 ? "good" : "warning"} label={r.trust >= 0.9 ? "advice counts" : "ignored"} />
          </span>
        ),
      }))}
    />
  );
}

/** One thesis experiment: detectors trained on one lab, adapting to another. */
export function AdaptationSection({ exp }: { exp: Adaptation }) {
  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-base font-semibold text-ink">
          Adapting to a new network: trained on {exp.source}, watching {exp.target}
        </h2>
        {exp.development && <StatusBadge tone="warning" label="Development run: one lab, checks the method" />}
      </div>
      {exp.development && (
        <p className="max-w-3xl text-sm text-ink-2">
          This run adapts to the held-out part of the same lab the detectors trained on, to check the method works. The
          thesis result trains on one lab and adapts to the other.
        </p>
      )}
      <Curve exp={exp} />
      <Comparison exp={exp} />
      <PerAttack exp={exp} />
      <Agreement exp={exp} />
    </section>
  );
}
