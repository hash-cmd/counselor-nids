"use client";

import { useRouter } from "next/navigation";
import { createContext, useCallback, useContext, useEffect, useState } from "react";

import { api, login as loginRequest, logout as logoutRequest } from "./api";

type Session = { state: "loading" } | { state: "signed-out" } | { state: "signed-in"; username: string };

type AuthContextValue = {
  session: Session;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
};

const AuthContext = createContext<AuthContextValue | null>(null);

/** The session cookie is httpOnly, so ask the API who we are. */
async function resolveSession(): Promise<Session> {
  try {
    const { username } = await api<{ username: string }>("/auth/me/");
    return { state: "signed-in", username };
  } catch {
    return { state: "signed-out" };
  }
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  // Start in "loading" on both server and client so hydration matches, then ask the API.
  const [session, setSession] = useState<Session>({ state: "loading" });

  useEffect(() => {
    let cancelled = false;
    resolveSession().then((resolved) => {
      if (!cancelled) setSession(resolved);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const name = await loginRequest(username, password);
    setSession({ state: "signed-in", username: name });
  }, []);

  const logout = useCallback(() => {
    setSession({ state: "signed-out" });
    void logoutRequest();
  }, []);

  return <AuthContext.Provider value={{ session, login, logout }}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider");
  return value;
}

/** Redirect to /login when signed out; returns the session for the page to gate on. */
export function useRequireAuth() {
  const { session } = useAuth();
  const router = useRouter();
  useEffect(() => {
    if (session.state === "signed-out") router.replace("/login");
  }, [session.state, router]);
  return session;
}
