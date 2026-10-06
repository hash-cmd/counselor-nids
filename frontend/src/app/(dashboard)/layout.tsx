"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { useAuth, useRequireAuth } from "@/lib/auth";

const NAV = [
  { href: "/", label: "Live" },
  { href: "/results", label: "Results" },
];

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const session = useRequireAuth();
  const { logout } = useAuth();
  const pathname = usePathname();

  if (session.state !== "signed-in") {
    return <p className="p-8 text-sm text-muted">Loading…</p>;
  }

  return (
    <div className="min-h-screen">
      <header className="border-b border-line bg-surface">
        <div className="mx-auto flex max-w-7xl items-center gap-6 px-4 py-3">
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
            <span>{session.username}</span>
            <button type="button" onClick={logout} className="rounded-md px-2 py-1 hover:bg-wash">
              Sign out
            </button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-7xl space-y-4 px-4 py-6">{children}</main>
    </div>
  );
}
