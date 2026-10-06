"use client";

import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { clock, perSecond } from "@/lib/format";
import type { RatePoint } from "@/lib/live";

import { axisProps, Card, DataTable, TooltipBox, useViewToggle } from "./chart-parts";

/** Round up to 1, 2 or 5 times a power of ten, so axis ticks land on round numbers. */
function niceStep(value: number): number {
  const power = 10 ** Math.floor(Math.log10(value));
  const m = value / power;
  return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * power;
}

export type RateSeries = { key: string; name: string; color: string };

function MiniChart({ points, series, max }: { points: RatePoint[]; series: RateSeries; max: number }) {
  return (
    <div className="h-48">
      <ResponsiveContainer>
        <LineChart data={points} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
          <CartesianGrid vertical={false} stroke="var(--grid)" />
          <XAxis dataKey="time" tickFormatter={clock} minTickGap={56} {...axisProps} />
          <YAxis width={56} domain={[0, max]} ticks={[0, max / 4, max / 2, (3 * max) / 4, max]} tickFormatter={(v) => perSecond(v)} axisLine={false} {...axisProps} />
          <Tooltip
            cursor={{ stroke: "var(--axis)", strokeWidth: 1 }}
            isAnimationActive={false}
            content={({ active, label, payload }) =>
              active && payload?.length ? (
                <TooltipBox
                  title={clock(Number(label))}
                  rows={[{ name: series.name, color: series.color, value: perSecond(Number(payload[0].value ?? 0)) }]}
                />
              ) : null
            }
          />
          <Line
            dataKey={series.key}
            stroke={series.color}
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 4, stroke: "var(--surface)", strokeWidth: 2 }}
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

/** Rates over the last two minutes. Several series are drawn as small multiples on a
 *  shared scale: detectors that agree would otherwise hide each other's lines. */
export function RateChart({
  title,
  subtitle,
  points,
  series,
}: {
  title: string;
  subtitle: string;
  points: RatePoint[];
  series: RateSeries[];
}) {
  const { view, toggle } = useViewToggle();
  const max = Math.max(1, ...points.flatMap((p) => series.map((s) => p[s.key] ?? 0)));
  const niceMax = niceStep(max / 4) * 4;

  return (
    <Card title={title} subtitle={subtitle} actions={toggle}>
      {points.length < 2 ? (
        <p className="flex h-48 items-center justify-center text-sm text-muted">Waiting for traffic…</p>
      ) : view === "table" ? (
        <DataTable
          columns={[{ key: "time", label: "Time" }, ...series.map((s) => ({ key: s.key, label: s.name, align: "right" as const }))]}
          rows={[...points].reverse().map((p) => ({
            time: clock(p.time),
            ...Object.fromEntries(series.map((s) => [s.key, perSecond(p[s.key] ?? 0)])),
          }))}
        />
      ) : series.length === 1 ? (
        <MiniChart points={points} series={series[0]} max={niceMax} />
      ) : (
        <div className="grid gap-4 sm:grid-cols-2">
          {series.map((s) => (
            <div key={s.key}>
              <h3 className="mb-1 flex items-center gap-1.5 text-xs text-ink-2">
                <span className="inline-block h-0.5 w-3 rounded" style={{ background: s.color }} />
                {s.name}
              </h3>
              <MiniChart points={points} series={s} max={niceMax} />
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
