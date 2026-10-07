"use client";

import { useEffect, useState } from "react";

import { api } from "./api";

export type Reputation = Record<string, { listed: boolean; source: string | null }>;

/** Look up offline reputation (local blocklists) for a set of IPs. Returns {} until
 *  loaded, and quietly stays empty if no blocklists are installed. */
export function useReputation(ips: string[]): Reputation {
  const [rep, setRep] = useState<Reputation>({});
  const key = [...new Set(ips)].sort().join(",");

  useEffect(() => {
    if (!key) return;
    let cancelled = false;
    api<{ reputation: Reputation }>(`/reputation/?ips=${encodeURIComponent(key)}`)
      .then((r) => !cancelled && setRep(r.reputation))
      .catch(() => {
        /* endpoint or blocklists unavailable — reputation just stays empty */
      });
    return () => {
      cancelled = true;
    };
  }, [key]);

  return rep;
}
