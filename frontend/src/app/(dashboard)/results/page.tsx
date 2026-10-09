"use client";

import { useEffect, useState } from "react";

import { AdaptationSection } from "@/components/charts/adaptation-chart";
import { Card, DataTable } from "@/components/ui/chart-parts";
import { LabelChart } from "@/components/charts/label-chart";
import { api } from "@/lib/api";
import { count, percent } from "@/lib/format";
import { attackName } from "@/lib/plain";
import type { ByLabelTable, CrossHost, Results, SystemTestRow } from "@/lib/types";

const range = (v: number, low: number | null, high: number | null, d = 2) =>
  low == null || high == null ? percent(v, d) : `${percent(v, d)} (${percent(low, d)}–${percent(high, d)})`;

/** The whole system's share flagged per attack type, with its 95% interval. */
function Intervals({ table }: { table: ByLabelTable }) {
  return (
    <Card title="With 95% confidence intervals" subtitle="The whole team's result per kind of traffic; the range is where the true rate lies with 95% confidence">
      <DataTable
        scroll={false}
        columns={[{ key: "label", label: "Traffic" }, { key: "flows", label: "Test connections", align: "right" },
                  { key: "rate", label: "Flagged (95% interval)", align: "right" }]}
        rows={table.rows.map((r) => ({
          label: r.label.toLowerCase() === "benign" ? "Normal traffic (false alarms)" : attackName(r.label),
          flows: count(r.flows),
          rate: range(r.flagged["counselor network"] ?? 0, r.interval?.low ?? null, r.interval?.high ?? null),
        }))}
      />
    </Card>
  );
}

function SystemTest({ tests }: { tests: Results["system_tests"] }) {
  const [community, setCommunity] = useState(false);
  const base = tests[community ? "community_rules" : "project_rules"];
  const counselor = tests[community ? "community_rules_snort_counselor" : "project_rules_snort_counselor"];
  if (!base) return null;
  const byTraffic = Object.fromEntries((counselor ?? []).map((r) => [r.traffic, r]));
  const name = (t: string) => (t === "Normal" ? "Normal traffic (false alarms)" : t);
  return (
    <Card
      title="The whole system on a recording it never saw"
      subtitle="Real attacks from the final minutes of each recorded attack, through the flow meter, the AI, Snort and alert linking"
      actions={
        <label className="flex items-center gap-2 text-xs text-ink-2">
          <input type="checkbox" checked={community} onChange={(e) => setCommunity(e.target.checked)} className="size-4 accent-[var(--accent)]" />
          Snort community rules on
        </label>
      }
    >
      <DataTable
        scroll={false}
        columns={[
          { key: "traffic", label: "Traffic" }, { key: "flows", label: "Connections", align: "right" },
          { key: "ai", label: "AI", align: "right" }, { key: "counsel", label: "AI with Snort as counselor", align: "right" },
          { key: "snort", label: "Rule checker (Snort)", align: "right" }, { key: "either", label: "Either", align: "right" },
        ]}
        rows={base.map((r: SystemTestRow) => ({
          traffic: name(r.traffic), flows: count(r.flows), ai: percent(r.ai, 1),
          counsel: byTraffic[r.traffic] ? percent(byTraffic[r.traffic].ai, 1) : "—",
          snort: percent(r.snort, 1), either: percent(r.either, 1),
        }))}
      />
    </Card>
  );
}

function UnseenMachine({ c }: { c: CrossHost }) {
  return (
    <Card title="A botnet-infected machine it never saw"
          subtitle={`Every connection of ${c.host}, an infected computer whose traffic was never used for training`}>
      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <p className="eyebrow">Botnet connections caught</p>
          <p className="figure mt-1 text-2xl font-semibold text-ink">{percent(c.detection_rate, 2)}</p>
          <p className="mt-0.5 text-xs text-muted">
            of {count(c.bot_flows)} · 95%: {percent(c.detection_interval.low, 2)}–{percent(c.detection_interval.high, 2)}
          </p>
        </div>
        <div>
          <p className="eyebrow">False alarms</p>
          <p className="figure mt-1 text-2xl font-semibold text-ink">{percent(c.false_alarm_rate, 2)}</p>
          <p className="mt-0.5 text-xs text-muted">
            of {count(c.benign_flows)} normal · 95%: {percent(c.false_alarm_interval.low, 2)}–{percent(c.false_alarm_interval.high, 2)}
          </p>
        </div>
      </div>
    </Card>
  );
}

export default function ResultsPage() {
  const [results, setResults] = useState<Results | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // an older API may not send every section yet: show what there is
    api<Results>("/results/")
      .then((r) => setResults({ ...r, by_label: r.by_label ?? {}, system_tests: r.system_tests ?? {},
                                cross_host: r.cross_host ?? null, adaptation: r.adaptation ?? [] }))
      .catch((e) => setError(e.message));
  }, []);

  if (error) return <p className="text-sm text-critical">Could not load results: {error}</p>;
  if (!results) return <p className="text-sm text-muted">Loading results…</p>;
  const thesis = [...results.adaptation].sort((a, b) => Number(a.development) - Number(b.development));

  return (
    <>
      <p className="max-w-3xl text-sm text-ink-2">
        How well the system did on recorded real attacks, where the right answer for every connection is known. Each
        detector learned from the first part of every recorded attack and was tested on the later part, which it had
        never seen.
      </p>

      {results.by_label.live ? (
        <div className="grid gap-4 xl:grid-cols-3">
          <div className="xl:col-span-2">
            <LabelChart
              tag="Fig · Test"
              title="Recorded real attacks they had never seen"
              subtitle="Share of each kind of traffic flagged as an attack. High is good, except for normal traffic (false alarms). Alone, each detector only catches its own specialty, so its overall score is low; the team is what runs."
              table={results.by_label.live}
            />
          </div>
          <Intervals table={results.by_label.live} />
        </div>
      ) : (
        <p className="rounded-xl border border-dashed border-line bg-surface p-8 text-center text-sm text-ink-2">
          No test results yet. Run <code>python scripts/live_detectors/train.py</code> on the server.
        </p>
      )}

      <SystemTest tests={results.system_tests} />
      {results.cross_host && <UnseenMachine c={results.cross_host} />}

      <h2 className="pt-4 text-lg font-semibold text-ink">Thesis: Snort teaches the AI on a new network</h2>
      <p className="-mt-2 max-w-3xl text-sm text-ink-2">
        AI detectors lose much of their accuracy on a network they weren&apos;t trained on, and nobody labels a new
        network&apos;s traffic. Here Snort, whose rules work the same everywhere, becomes a counselor: it settles the
        AI&apos;s doubts, its agreement with the AI becomes labels the detectors learn from, and each rule&apos;s trust
        adapts to how often the AI agrees with it.
      </p>
      {thesis.length === 0 ? (
        <p className="rounded-xl border border-dashed border-line bg-surface p-8 text-center text-sm text-ink-2">
          No experiment yet. Run <code>python scripts/live_detectors/adapt.py --source 2018 --target 2017</code>.
        </p>
      ) : thesis.map((exp) => <AdaptationSection key={exp.name} exp={exp} />)}

      <Card title="Things to keep in mind" subtitle="What these results do and don't show">
        <ul className="list-disc space-y-1.5 pl-5 text-sm text-ink-2">
          <li>
            The recordings come from test labs, with one attacker per kind of attack. Your network is different: watch
            the false-alarm panel on the Overview for a few days before trusting the alerts.
          </li>
          <li>
            Website attacks are mainly the rule checker&apos;s job: the AI learned from too few examples to be relied on,
            and with so few test connections their rates swing widely (see the intervals).
          </li>
          <li>
            Adaptive trust is applied to Snort&apos;s rules only. Re-estimating the AI&apos;s own trust from agreement
            labels made results worse (the ablations): those labels are the easy cases every method gets right.
          </li>
        </ul>
      </Card>
    </>
  );
}
