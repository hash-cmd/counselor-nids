import { isLocalIp } from "@/lib/blocking";
import { count } from "@/lib/format";
import type { Breakdown } from "@/lib/types";

import { Card } from "@/components/ui/chart-parts";
import { SOURCE_COLORS } from "@/components/charts/detection-timeline";

/** Addresses that sent the first packet of the most flagged flows. For connections already
 *  open when capture started, that can be the victim answering, so this is a lead, not proof. */
export function TopSources({ sources }: { sources: Breakdown["sources"] }) {
  const max = Math.max(1, ...sources.map((s) => Math.max(s.ml, s.snort)));
  return (
    <Card
      title="Where the suspicious traffic came from"
      subtitle="The computers (by IP address) that started the most flagged connections. Usually the attacker, but treat it as a lead, not proof."
    >
      {sources.length === 0 ? (
        <p className="flex h-40 items-center justify-center px-6 text-center text-sm text-muted">
          No suspicious traffic yet.
        </p>
      ) : (
        <table className="w-full text-xs">
          <thead className="text-left text-muted">
            <tr>
              <th className="pb-2 font-medium">Computer (IP address)</th>
              <th className="pb-2 font-medium">Flagged by the AI</th>
              <th className="pb-2 font-medium">Rule checker alarms</th>
            </tr>
          </thead>
          <tbody>
            {sources.map((s) => (
              <tr key={s.ip} className="border-t border-line">
                <td className="tabular py-1.5 pr-3 text-ink">
                  {s.ip}
                  {isLocalIp(s.ip) && <span className="ml-1.5 text-muted" title="An address on your own network, often this computer">(your network)</span>}
                </td>
                {(["ml", "snort"] as const).map((key) => (
                  <td key={key} className="py-1.5 pr-3">
                    <div className="flex items-center gap-2">
                      <span className="inline-block h-2 rounded-sm" style={{ width: `${(s[key] / max) * 64}px`, background: SOURCE_COLORS[key] }} />
                      <span className="tabular text-ink-2">{count(s[key])}</span>
                    </div>
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}
