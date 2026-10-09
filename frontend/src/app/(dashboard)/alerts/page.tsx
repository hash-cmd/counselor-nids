"use client";

import { useState } from "react";

import { AttackersPanel } from "@/components/panels/attackers";
import { MlAlertsTable } from "@/components/panels/ml-alerts-table";
import { type Filter, IncidentFilters, IncidentsTable } from "@/components/panels/incidents";
import { SnortAlertsTable } from "@/components/panels/snort-alerts-table";
import { count } from "@/lib/format";
import { useIncidents } from "@/lib/incidents";
import { useLive } from "@/lib/live-feed";

const TABS = [
  { key: "incidents", label: "All alerts" },
  { key: "attackers", label: "Attackers" },
  { key: "ml", label: "AI details" },
  { key: "snort", label: "Rule checker details" },
] as const;

const PAGE = 100;
const ATTACKER_WINDOW = 500;

export default function AlertsPage() {
  const live = useLive();
  const [tab, setTab] = useState<(typeof TABS)[number]["key"]>("incidents");
  const [source, setSource] = useState<Filter>("all");
  const [query, setQuery] = useState("");
  const [limit, setLimit] = useState(PAGE);
  const runId = live.replay.state === "idle" ? "live" : live.replay.id;
  const { data, error } = useIncidents(source, query, limit, live.activity === "running", runId);
  // attackers are grouped from the latest alarms (the API returns at most 500 at a time)
  const latest = useIncidents("all", "", ATTACKER_WINDOW, live.activity === "running", runId);
  const detectors = Object.keys(live.detectors).sort();

  const changeSource = (f: Filter) => {
    setSource(f);
    setLimit(PAGE);
  };
  const changeQuery = (q: string) => {
    setQuery(q);
    setLimit(PAGE);
  };

  return (
    <>
      <div className="flex flex-wrap items-end justify-between gap-3">
        <p className="max-w-2xl text-sm text-ink-2">
          Every connection that looked like an attack, to the AI, the rule checker, or both. Click one to see
          what it means.
        </p>
        <div className="flex items-center gap-2 print:hidden">
          <div className="flex rounded-md border border-line p-0.5 text-sm" role="tablist">
            {TABS.map((t) => (
              <button
                key={t.key}
                type="button"
                role="tab"
                aria-selected={tab === t.key}
                onClick={() => setTab(t.key)}
                className={`rounded px-3 py-1 ${tab === t.key ? "bg-wash font-semibold text-ink" : "text-ink-2 hover:bg-wash"}`}
              >
                {t.label}
              </button>
            ))}
          </div>
          <button
            type="button"
            onClick={() => window.print()}
            title="Print or save the current view as a PDF report"
            className="rounded-md border border-line px-3 py-1 text-sm text-ink-2 hover:bg-wash hover:text-ink"
          >
            Print / PDF
          </button>
        </div>
      </div>

      <div className="hidden print:block">
        <h1 className="text-lg font-semibold text-ink">NIDS incident report</h1>
        <p className="text-xs text-muted">Generated {new Date().toLocaleString()}</p>
      </div>

      {tab === "incidents" && (
        <IncidentsTable
          incidents={data?.incidents ?? []}
          subtitle={
            data
              ? `${count(data.total)} suspicious connection${data.total === 1 ? "" : "s"}${source !== "all" || query ? " match" : ""}`
              : "Loading…"
          }
          empty={error ?? (data?.counts.all ? "No alerts match your search." : "No alerts yet. Start live monitoring, or run a test on the Test page.")}
          actions={<IncidentFilters source={source} onSource={changeSource} query={query} onQuery={changeQuery} counts={data?.counts ?? null} />}
          footer={
            data && data.incidents.length < data.total && (
              <div className="mt-3 flex items-center justify-between text-sm text-ink-2">
                <span>
                  Showing {count(data.incidents.length)} of {count(data.total)}
                </span>
                <button type="button" onClick={() => setLimit((l) => l + PAGE)}
                        className="rounded-md border border-line px-3 py-1 text-ink hover:bg-wash">
                  Load {PAGE} more
                </button>
              </div>
            )
          }
        />
      )}
      {tab === "attackers" && (
        <AttackersPanel
          incidents={latest.data?.incidents ?? []}
          basis={latest.data && latest.data.incidents.length < latest.data.total
            ? `From the latest ${count(latest.data.incidents.length)} of ${count(latest.data.total)} suspicious connections.`
            : undefined}
        />
      )}
      {tab === "ml" && <MlAlertsTable alerts={live.alerts} detectors={detectors} />}
      {tab === "snort" && <SnortAlertsTable alerts={live.snortAlerts} />}
    </>
  );
}
