"use client";

import { useState } from "react";

import { AlertsTable } from "@/components/alerts-table";
import { type Filter, IncidentFilters, IncidentsTable } from "@/components/incidents";
import { SnortAlertsTable } from "@/components/snort-panel";
import { count } from "@/lib/format";
import { useIncidents } from "@/lib/incidents";
import { useLive } from "@/lib/live";

const TABS = [
  { key: "incidents", label: "Incidents" },
  { key: "ml", label: "ML alerts" },
  { key: "snort", label: "Snort alerts" },
] as const;

const PAGE = 100;

export default function AlertsPage() {
  const live = useLive();
  const [tab, setTab] = useState<(typeof TABS)[number]["key"]>("incidents");
  const [source, setSource] = useState<Filter>("all");
  const [query, setQuery] = useState("");
  const [limit, setLimit] = useState(PAGE);
  const runId = live.replay.state === "idle" ? "live" : live.replay.id;
  const { data, error } = useIncidents(source, query, limit, live.activity === "running", runId);
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
        <div>
          <h1 className="text-xl font-semibold text-ink">Alerts</h1>
          <p className="text-sm text-ink-2">
            Every flow the ML or Snort flagged, linked by flow. Click an incident for details.
          </p>
        </div>
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
      </div>

      {tab === "incidents" && (
        <IncidentsTable
          incidents={data?.incidents ?? []}
          subtitle={
            data
              ? `${count(data.total)} incident${data.total === 1 ? "" : "s"}${source !== "all" || query ? " match" : ""} · each flagged flow once`
              : "Loading…"
          }
          empty={error ?? (data?.counts.all ? "No incidents match." : "No incidents yet — start a replay or a live capture.")}
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
      {tab === "ml" && <AlertsTable alerts={live.alerts} detectors={detectors} />}
      {tab === "snort" && <SnortAlertsTable alerts={live.snortAlerts} />}
    </>
  );
}
