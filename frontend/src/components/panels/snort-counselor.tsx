import { count } from "@/lib/format";
import type { DetectorStats, SnortTrustRow } from "@/lib/types";

import { TrustTable } from "@/components/charts/adaptation-chart";
import { Card } from "@/components/ui/chart-parts";
import { StatusBadge } from "@/components/ui/status-badge";

/** Snort as a counselor, live: how often it settled a detector's doubt, and how much the AI
 *  has come to trust each of its rules. */
export function SnortCounselor({ detectors, trust }: { detectors: Record<string, DetectorStats>; trust: SnortTrustRow[] }) {
  const settled = Object.values(detectors).reduce((n, d) => n + (d.snort_advised ?? 0), 0);
  const conflicts = Object.values(detectors).reduce((n, d) => n + d.conflicts, 0);
  const active = trust.length > 0 || settled > 0;
  return (
    <Card
      title="The rule checker as a counselor"
      subtitle="When a detector is unsure, the rule checker's verdict on that connection counts as advice. Each rule's trust grows when the AI independently agrees with it and shrinks when the AI is sure the traffic is normal; advice counts at 90% trust or more. Trust is kept between runs."
      actions={<StatusBadge tone={active ? "good" : "neutral"} label={active ? "Active" : "Not active (needs the rule checker)"} />}
    >
      <p className="mb-3 text-sm text-ink-2">
        Settled <span className="figure font-semibold text-ink">{count(settled)}</span> of the detectors&apos;{" "}
        {count(conflicts)} doubts so far.
      </p>
      {trust.length === 0 ? (
        <p className="text-sm text-muted">No rule has been judged yet.</p>
      ) : (
        <TrustTable rows={trust} />
      )}
    </Card>
  );
}
