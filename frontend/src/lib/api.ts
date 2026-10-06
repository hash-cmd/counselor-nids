export const API_URL = (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000").replace(/\/$/, "");
export const WS_URL = API_URL.replace(/^http/, "ws");

const ACCESS = "nids.access";
const REFRESH = "nids.refresh";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

export const tokens = {
  access: () => (typeof window === "undefined" ? null : localStorage.getItem(ACCESS)),
  refresh: () => (typeof window === "undefined" ? null : localStorage.getItem(REFRESH)),
  set(access: string, refresh?: string) {
    localStorage.setItem(ACCESS, access);
    if (refresh) localStorage.setItem(REFRESH, refresh);
  },
  clear() {
    localStorage.removeItem(ACCESS);
    localStorage.removeItem(REFRESH);
  },
};

async function detail(response: Response): Promise<string> {
  try {
    const body = await response.json();
    return body.detail ?? JSON.stringify(body);
  } catch {
    return response.statusText;
  }
}

export async function login(username: string, password: string): Promise<void> {
  const response = await fetch(`${API_URL}/api/auth/token/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!response.ok) throw new ApiError(response.status, await detail(response));
  const body = await response.json();
  tokens.set(body.access, body.refresh);
}

/** Get a new access token with the refresh token; false when the session is over. */
export async function refreshAccess(): Promise<boolean> {
  const refresh = tokens.refresh();
  if (!refresh) return false;
  const response = await fetch(`${API_URL}/api/auth/token/refresh/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh }),
  });
  if (!response.ok) {
    tokens.clear();
    return false;
  }
  tokens.set((await response.json()).access);
  return true;
}

/** Authenticated JSON request; retries once after refreshing an expired access token. */
export async function api<T>(path: string, init: RequestInit = {}, retry = true): Promise<T> {
  const response = await fetch(`${API_URL}/api${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${tokens.access()}`,
      ...init.headers,
    },
  });
  if (response.status === 401 && retry && (await refreshAccess())) {
    return api<T>(path, init, false);
  }
  if (!response.ok) throw new ApiError(response.status, await detail(response));
  return response.json();
}
