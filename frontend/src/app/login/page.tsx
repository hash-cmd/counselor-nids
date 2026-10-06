"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";

export default function LoginPage() {
  const { session, login } = useAuth();
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (session.state === "signed-in") router.replace("/");
  }, [session.state, router]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username, password);
    } catch (e) {
      setError(
        e instanceof ApiError && e.status === 401
          ? "Wrong username or password."
          : "Cannot reach the API. Is the Django server running?",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center p-4">
      <form onSubmit={submit} className="w-full max-w-sm rounded-xl border border-line bg-surface p-6">
        <h1 className="text-lg font-semibold text-ink">Counselor NIDS</h1>
        <p className="mb-6 text-sm text-ink-2">Sign in to watch the detectors.</p>
        <label className="mb-3 block text-sm text-ink-2">
          Username
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
            className="mt-1 block w-full rounded-md border border-line bg-raised px-3 py-2 text-ink"
          />
        </label>
        <label className="mb-4 block text-sm text-ink-2">
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
            className="mt-1 block w-full rounded-md border border-line bg-raised px-3 py-2 text-ink"
          />
        </label>
        {error && <p className="mb-3 text-sm text-critical">{error}</p>}
        <button
          type="submit"
          disabled={busy}
          className="w-full rounded-md bg-accent px-4 py-2 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </main>
  );
}
