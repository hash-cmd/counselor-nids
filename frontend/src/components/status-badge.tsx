/** Status always pairs colour with an icon and a label, never colour alone. */
const STYLES = {
  good: { color: "var(--status-good)", icon: "●" },
  warning: { color: "var(--status-warning)", icon: "◐" },
  critical: { color: "var(--status-critical)", icon: "▲" },
  neutral: { color: "var(--ink-muted)", icon: "○" },
} as const;

export function StatusBadge({ tone, label }: { tone: keyof typeof STYLES; label: string }) {
  const style = STYLES[tone];
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-line px-2.5 py-0.5 text-xs text-ink">
      <span aria-hidden style={{ color: style.color }}>
        {style.icon}
      </span>
      {label}
    </span>
  );
}
