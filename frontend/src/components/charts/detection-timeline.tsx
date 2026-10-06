"use client";

import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { clock, perSecond } from "@/lib/format";
import type { RatePoint } from "@/lib/live-feed";

import { axisProps, Card, DataTable, Legend, TooltipBox, useViewToggle } from "@/components/ui/chart-parts";

// The ML (all detectors together) and Snort keep these colours on every page.
export const SOURCE_COLORS = { ml: "var(--ink-secondary)", snort: "var(--series-3)" } as const;

const SERIES = [
  { key: "ml", name: "Flows flagged by the ML", color: SOURCE_COLORS.ml },
  { key: "snort", name: "Snort alerts", color: SOURCE_COLORS.snort },
] as const;

/** Detections per second from both systems, on one axis (same unit). */
export function DetectionTimeline({ points, snort }: { points: RatePoint[]; snort: boolean }) {
  const { view, toggle } = useViewToggle();
  const series = SERIES.filter((s) => s.key === "ml" || snort);

  return (
    <Card title="Detections over time" subtitle="Per second, last three minutes" actions={toggle}>
      {points.length < 2 ? (
        <p className="flex h-56 items-center justify-center text-sm text-muted">Waiting for traffic…</p>
      ) : view === "table" ? (
        <DataTable
          columns={[{ key: "time", label: "Time" }, ...series.map((s) => ({ key: s.key, label: s.name, align: "right" as const }))]}
          rows={[...points].reverse().map((p) => ({
            time: clock(p.time),
            ...Object.fromEntries(series.map((s) => [s.key, perSecond(p[s.key] ?? 0)])),
          }))}
        />
      ) : (
        <>
          {series.length > 1 && <Legend items={series.map((s) => ({ name: s.name, color: s.color, shape: "line" as const }))} />}
          <div className="h-56">
            <ResponsiveContainer>
              <LineChart data={points} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
                <CartesianGrid vertical={false} stroke="var(--grid)" />
                <XAxis dataKey="time" tickFormatter={clock} minTickGap={64} {...axisProps} />
                <YAxis width={56} tickFormatter={(v) => perSecond(v)} axisLine={false} {...axisProps} />
                <Tooltip
                  cursor={{ stroke: "var(--axis)", strokeWidth: 1 }}
                  isAnimationActive={false}
                  content={({ active, label, payload }) =>
                    active && payload?.length ? (
                      <TooltipBox
                        title={clock(Number(label))}
                        rows={series.map((s) => ({
                          name: s.name,
                          color: s.color,
                          value: perSecond(Number(payload.find((p) => p.dataKey === s.key)?.value ?? 0)),
                        }))}
                      />
                    ) : null
                  }
                />
                {series.map((s) => (
                  <Line key={s.key} dataKey={s.key} stroke={s.color} strokeWidth={2} dot={false}
                        activeDot={{ r: 4, stroke: "var(--surface)", strokeWidth: 2 }} isAnimationActive={false} />
                ))}
              </LineChart>
            </ResponsiveContainer>
          </div>
        </>
      )}
    </Card>
  );
}
