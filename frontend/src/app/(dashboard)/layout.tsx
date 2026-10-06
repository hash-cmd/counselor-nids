"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { StatusBadge } from "@/components/status-badge";
import { useAuth, useRequireAuth } from "@/lib/auth";
import { LiveProvider, useLive } from "@/lib/live";

const NAV = [
  { href: "/", label: "Overview" },
  { href: "/alerts", label: "Alerts" },
  { href: "/detectors", label: "Detectors" },
  { href: "/results", label: "Results" },
];

function ConnectionBadge() {
  const { connection, activity } = useLive();
  if (connection !== "open") {
    return <StatusBadge tone="warning" label={connection === "connecting" ? "Connecting…" : "Reconnecting…"} />;
  }
  return <StatusBadge tone={activity === "running" ? "good" : "neutral"} label={activity === "running" ? "Detecting" : "Connected"} />;
}

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const session = useRequireAuth();
  const { logout } = useAuth();
  const pathname = usePathname();

  if (session.state !== "signed-in") {
    return <p className="p-8 text-sm text-muted">Loading…</p>;
  }

  return (
    <LiveProvider onSessionEnd={logout}>
      <div className="min-h-screen">
        <header className="sticky top-0 z-10 border-b border-line bg-surface/95 backdrop-blur">
          <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
            <span className="font-semibold text-ink">Counselor NIDS</span>
            <nav className="flex gap-1 text-sm">
              {NAV.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  aria-current={pathname === item.href ? "page" : undefined}
                  className={`rounded-md px-3 py-1.5 ${pathname === item.href ? "bg-wash font-medium text-ink" : "text-ink-2 hover:bg-wash"}`}
                >
                  {item.label}
                </Link>
              ))}
            </nav>
            <div className="ml-auto flex items-center gap-3 text-sm text-ink-2">
              <ConnectionBadge />
              <span>{session.username}</span>
              <button type="button" onClick={logout} className="rounded-md px-2 py-1 hover:bg-wash">
                Sign out
              </button>
            </div>
          </div>
        </header>
        <main className="mx-auto max-w-7xl space-y-4 px-4 py-6">{children}</main>
      </div>
    </LiveProvider>
  );
}
