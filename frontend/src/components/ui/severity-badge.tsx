import { type Tier, TIER_META } from "@/lib/severity";

/** A coloured severity chip. Pairs colour with the word, never colour alone. */
export function SeverityBadge({ tier, score }: { tier: Tier; score?: number }) {
  const meta = TIER_META[tier];
  return (
    <span
      className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium"
      style={{ background: `color-mix(in srgb, ${meta.color} 16%, transparent)`, color: meta.color }}
    >
      <span className="inline-block size-1.5 rounded-full" style={{ background: meta.color }} />
      {meta.label}
      {score != null && <span className="opacity-70">· {score}</span>}
    </span>
  );
}
