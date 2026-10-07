"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";

import { StatusBadge } from "@/components/ui/status-badge";
import { useAuth, useRequireAuth } from "@/lib/auth";
import { LiveProvider, useLive } from "@/lib/live-feed";

type NavItem = { href: string; label: string; hint: string; icon: React.ReactNode };

const NAV: { heading: string; items: NavItem[] }[] = [
  {
    heading: "Monitoring",
    items: [
      { href: "/", label: "Overview", hint: "Is anything wrong right now", icon: <IconGrid /> },
      { href: "/alerts", label: "Alerts", hint: "Every suspicious connection", icon: <IconBell /> },
      { href: "/detectors", label: "AI detectors", hint: "How the AI team is doing", icon: <IconChip /> },
    ],
  },
  {
    heading: "Evaluation",
    items: [{ href: "/results", label: "Test results", hint: "How well it scores in tests", icon: <IconChart /> }],
  },
];

const TITLES: Record<string, string> = Object.fromEntries(
  NAV.flatMap((g) => g.items).map((i) => [i.href, i.label]),
);

function ConnectionBadge() {
  const { connection, activity } = useLive();
  if (connection !== "open") {
    return <StatusBadge tone="warning" label={connection === "connecting" ? "Connecting…" : "Reconnecting…"} />;
  }
  return <StatusBadge tone={activity === "running" ? "good" : "neutral"} label={activity === "running" ? "Watching traffic" : "Ready"} />;
}

function Sidebar({ pathname, username, collapsed, onNavigate, logout }: {
  pathname: string;
  username: string;
  collapsed: boolean;
  onNavigate: () => void;
  logout: () => void;
}) {
  return (
    <div className="flex h-full flex-col">
      <Link href="/" onClick={onNavigate}
            className={`flex items-center gap-2.5 py-4 ${collapsed ? "justify-center px-0" : "px-5"}`}>
        <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-accent text-sm font-bold text-white">N</span>
        {!collapsed && (
          <span className="leading-tight">
            <span className="block text-sm font-semibold text-ink">Counselor NIDS</span>
            <span className="block text-xs text-muted">Network attack detector</span>
          </span>
        )}
      </Link>

      <nav className={`flex-1 space-y-6 overflow-y-auto py-4 ${collapsed ? "px-2" : "px-3"}`}>
        {NAV.map((group) => (
          <div key={group.heading}>
            {collapsed ? (
              <div className="mx-auto mb-2 h-px w-6 bg-line" />
            ) : (
              <p className="px-3 pb-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted">{group.heading}</p>
            )}
            <ul className="space-y-0.5">
              {group.items.map((item) => {
                const active = pathname === item.href;
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      onClick={onNavigate}
                      aria-current={active ? "page" : undefined}
                      title={collapsed ? item.label : item.hint}
                      className={`flex items-center gap-3 rounded-lg py-2 text-sm ${collapsed ? "justify-center px-0" : "px-3"} ${
                        active ? "bg-wash font-semibold text-ink" : "text-ink-2 hover:bg-wash hover:text-ink"
                      }`}
                    >
                      <span className={active ? "text-accent" : "text-muted"}>{item.icon}</span>
                      {!collapsed && item.label}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      <div className={`border-t border-line py-3 ${collapsed ? "px-2" : "px-3"}`}>
        {collapsed ? (
          <div className="flex flex-col items-center gap-1">
            <span className="grid size-8 place-items-center rounded-full bg-wash text-xs font-semibold text-ink-2" title={username}>
              {username.slice(0, 2).toUpperCase()}
            </span>
            <button type="button" onClick={logout} title="Sign out"
                    className="rounded-md p-1.5 text-muted hover:bg-wash hover:text-ink">
              <IconLogout />
            </button>
          </div>
        ) : (
          <div className="flex items-center gap-2.5 px-2 py-1.5">
            <span className="grid size-8 shrink-0 place-items-center rounded-full bg-wash text-xs font-semibold text-ink-2">
              {username.slice(0, 2).toUpperCase()}
            </span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-sm text-ink">{username}</span>
              <span className="block text-xs text-muted">Signed in</span>
            </span>
            <button type="button" onClick={logout} title="Sign out"
                    className="rounded-md p-1.5 text-muted hover:bg-wash hover:text-ink">
              <IconLogout />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const session = useRequireAuth();
  const { logout } = useAuth();
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return typeof window !== "undefined" && localStorage.getItem("nids.sidebar") === "collapsed";
    } catch {
      return false;
    }
  });

  function toggleCollapsed() {
    setCollapsed((c) => {
      const next = !c;
      try {
        localStorage.setItem("nids.sidebar", next ? "collapsed" : "open");
      } catch {
        /* private mode / storage blocked — collapse still works for this session */
      }
      return next;
    });
  }

  if (session.state !== "signed-in") {
    return <p className="p-8 text-sm text-muted">Loading…</p>;
  }

  const title = TITLES[pathname] ?? "Dashboard";

  return (
    <LiveProvider onSessionEnd={logout}>
      <div className="flex min-h-screen">
        {/* Sidebar — fixed column on desktop, width animates on collapse */}
        <aside
          className={`sticky top-0 hidden h-screen shrink-0 border-r border-line bg-surface transition-[width] duration-200 print:!hidden lg:block ${
            collapsed ? "lg:w-16" : "lg:w-64"
          }`}
        >
          <Sidebar pathname={pathname} username={session.username} collapsed={collapsed}
                   onNavigate={() => {}} logout={logout} />
        </aside>

        {/* Sidebar — slide-over drawer on mobile (always full width) */}
        {open && (
          <div className="fixed inset-0 z-30 lg:hidden">
            <div className="absolute inset-0 bg-black/40" onClick={() => setOpen(false)} aria-hidden />
            <aside className="absolute inset-y-0 left-0 w-64 border-r border-line bg-surface shadow-xl">
              <Sidebar pathname={pathname} username={session.username} collapsed={false}
                       onNavigate={() => setOpen(false)} logout={logout} />
            </aside>
          </div>
        )}

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-10 flex items-center gap-3 border-b border-line bg-surface/95 px-4 py-3 backdrop-blur print:hidden lg:px-6">
            <button
              type="button"
              onClick={() => (window.matchMedia("(min-width: 1024px)").matches ? toggleCollapsed() : setOpen(true))}
              title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
              aria-label="Toggle sidebar"
              className="-ml-1.5 rounded-md p-1.5 text-ink-2 hover:bg-wash hover:text-ink"
            >
              <IconSidebar />
            </button>
            <span className="h-5 w-px bg-line" aria-hidden />
            <h1 className="text-base font-semibold text-ink">{title}</h1>
            <div className="ml-auto">
              <ConnectionBadge />
            </div>
          </header>

          <main className="mx-auto w-full max-w-7xl flex-1 space-y-4 px-4 py-6 lg:px-6">{children}</main>
        </div>
      </div>
    </LiveProvider>
  );
}

/* --- inline icons (currentColor, 18px) --- */
function IconGrid() {
  return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>;
}
function IconBell() {
  return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/></svg>;
}
function IconChip() {
  return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2"/></svg>;
}
function IconChart() {
  return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 3v18h18"/><rect x="7" y="12" width="3" height="6"/><rect x="12" y="8" width="3" height="10"/><rect x="17" y="5" width="3" height="13"/></svg>;
}
function IconSidebar() {
  return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M9 4v16"/></svg>;
}
function IconLogout() {
  return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5M21 12H9"/></svg>;
}
