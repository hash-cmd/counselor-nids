"use client";

import { useState } from "react";

import { blockPlan } from "@/lib/blocking";

function CopyRow({ label, command }: { label: string; command: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked — the text is selectable below */
    }
  }
  return (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <span className="text-xs font-medium text-ink-2">{label}</span>
        <button type="button" onClick={copy} className="rounded border border-line px-2 py-0.5 text-xs text-ink-2 hover:bg-wash hover:text-ink">
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="overflow-auto rounded-md bg-wash p-2 text-xs text-ink">{command}</pre>
    </div>
  );
}

/** Shows ready-to-paste firewall commands to block an IP. Nothing runs here — the
 *  person runs the command themselves, so the dashboard never needs root. */
export function BlockDialog({ ip, onClose }: { ip: string; onClose: () => void }) {
  const [engine, setEngine] = useState<"iptables" | "nftables">("iptables");
  const plan = blockPlan(ip);
  const cmds = plan[engine];

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/40" onClick={onClose} aria-hidden />
      <div className="relative w-full max-w-lg rounded-xl border border-line bg-surface p-5 shadow-xl" role="dialog" aria-label={`Block ${ip}`}>
        <div className="mb-3 flex items-start justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-ink">Block {ip}</h2>
            <p className="text-xs text-ink-2">Run this on the machine watching the traffic. The dashboard won&apos;t run it for you.</p>
          </div>
          <button type="button" onClick={onClose} className="rounded-md px-2 py-1 text-xs text-ink-2 hover:bg-wash">Close</button>
        </div>

        {plan.local && (
          <p className="mb-3 rounded-md border border-[var(--status-critical)] bg-[color-mix(in_srgb,var(--status-critical)_12%,transparent)] p-2.5 text-xs text-critical">
            ⚠ {ip} is a <strong>local / private address</strong> — it may be your own device, router or a machine on
            your network. Blocking it could cut off your own connectivity. Make sure this is really an outside
            attacker before you run anything.
          </p>
        )}

        <div className="mb-3 flex gap-1 rounded-md border border-line p-0.5 text-xs w-fit" role="group" aria-label="Firewall tool">
          {(["iptables", "nftables"] as const).map((e) => (
            <button key={e} type="button" onClick={() => setEngine(e)} aria-pressed={engine === e}
                    className={`rounded px-3 py-1 ${engine === e ? "bg-wash font-semibold text-ink" : "text-ink-2 hover:bg-wash"}`}>
              {e}
            </button>
          ))}
        </div>

        <div className="space-y-3">
          <CopyRow label="Block (drop all traffic from this IP)" command={cmds.block} />
          <CopyRow label="Undo (remove the block)" command={cmds.unblock} />
        </div>

        <p className="mt-3 text-xs text-muted">
          Tip: to make a block temporary, pair it with a scheduled undo, e.g.
          <code className="mx-1 rounded bg-wash px-1">echo &quot;{cmds.unblock}&quot; | at now + 1 hour</code>.
        </p>
      </div>
    </div>
  );
}
