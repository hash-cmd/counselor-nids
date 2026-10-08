"use client";

import { useState } from "react";

export function Card({
  title,
  subtitle,
  tag,
  actions,
  children,
  className,
}: {
  title: string;
  subtitle?: string;
  tag?: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-xl border border-line bg-surface p-5 ${className ?? ""}`}>
      <header className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="flex items-center gap-2 text-sm font-semibold tracking-tight text-ink">
            {title}
            {tag && <span className="eyebrow">{tag}</span>}
          </h2>
          {subtitle && <p className="mt-1 text-xs text-ink-2">{subtitle}</p>}
        </div>
        {actions}
      </header>
      {children}
    </section>
  );
}

/** Chart / table toggle: every chart has a table twin. */
export function useViewToggle() {
  const [view, setView] = useState<"chart" | "table">("chart");
  const toggle = (
    <div className="flex rounded-md border border-line p-0.5 text-xs" role="group" aria-label="View">
      {(["chart", "table"] as const).map((v) => (
        <button
          key={v}
          type="button"
          onClick={() => setView(v)}
          aria-pressed={view === v}
          className={`rounded px-2 py-1 capitalize ${view === v ? "bg-wash font-semibold text-ink" : "text-ink-2 hover:bg-wash"}`}
        >
          {v}
        </button>
      ))}
    </div>
  );
  return { view, toggle };
}

export type LegendItem = { name: string; color: string; shape: "line" | "rect" };

export function Legend({ items }: { items: LegendItem[] }) {
  return (
    <ul className="mb-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-ink-2">
      {items.map((item) => (
        <li key={item.name} className="flex items-center gap-1.5">
          {item.shape === "line" ? (
            <span className="inline-block h-0.5 w-3.5 rounded" style={{ background: item.color }} />
          ) : (
            <span className="inline-block size-2.5 rounded-sm" style={{ background: item.color }} />
          )}
          {item.name}
        </li>
      ))}
    </ul>
  );
}

type TooltipRow = { name: string; value: string; color: string };

/** Values lead, names follow; rows keyed with a short line of the series colour. */
export function TooltipBox({ title, rows }: { title: string; rows: TooltipRow[] }) {
  return (
    <div className="min-w-40 rounded-lg border border-line bg-raised px-3 py-2 text-xs shadow-sm">
      <p className="mb-1 text-muted">{title}</p>
      {rows.map((row) => (
        <p key={row.name} className="flex items-center gap-2 py-0.5">
          <span className="inline-block h-0.5 w-3 rounded" style={{ background: row.color }} />
          <span className="tabular font-semibold text-ink">{row.value}</span>
          <span className="text-ink-2">{row.name}</span>
        </p>
      ))}
    </div>
  );
}

export function DataTable({
  columns,
  rows,
  scroll = true,
}: {
  columns: { key: string; label: string; align?: "left" | "right" }[];
  rows: Record<string, React.ReactNode>[];
  /** cap the height and scroll (long, live tables); false shows every row */
  scroll?: boolean;
}) {
  return (
    <div className={`${scroll ? "max-h-80" : ""} overflow-auto rounded-lg border border-line`}>
      <table className="w-full text-xs">
        <thead className="sticky top-0 bg-raised text-muted">
          <tr>
            {columns.map((c) => (
              <th key={c.key} className={`px-3 py-2 font-medium ${c.align === "right" ? "text-right" : "text-left"}`}>
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="tabular">
          {rows.map((row, i) => (
            <tr key={i} className="border-t border-line">
              {columns.map((c) => (
                <td key={c.key} className={`px-3 py-1.5 ${c.align === "right" ? "text-right" : "text-left"}`}>
                  {row[c.key]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export const axisProps = {
  stroke: "var(--axis)",
  tick: { fill: "var(--ink-muted)", fontSize: 11 },
  tickLine: false,
} as const;
