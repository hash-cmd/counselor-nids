export const API_URL = (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000").replace(/\/$/, "");
export const WS_URL = API_URL.replace(/^http/, "ws");

/* The session lives in httpOnly cookies set by the API: this code never sees a token.
 * Every request sends the cookies (credentials: "include"), and state-changing ones
 * add the X-NIDS-Client header the API requires as a CSRF guard. */

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function detail(response: Response): Promise<string> {
  try {
    const body = await response.json();
    return body.detail ?? JSON.stringify(body);
  } catch {
    return response.statusText;
  }
}

function send(path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(`${API_URL}/api${path}`, {
    ...init,
    credentials: "include",
    headers: { "Content-Type": "application/json", "X-NIDS-Client": "web", ...init.headers },
  });
}

export async function login(username: string, password: string): Promise<string> {
  const response = await send("/auth/login/", { method: "POST", body: JSON.stringify({ username, password }) });
  if (!response.ok) throw new ApiError(response.status, await detail(response));
  return (await response.json()).username;
}

export async function logout(): Promise<void> {
  await send("/auth/logout/", { method: "POST" }).catch(() => undefined);
}

/** Renew the access cookie from the refresh cookie; false when the session is over. */
export async function refreshAccess(): Promise<boolean> {
  const response = await send("/auth/refresh/", { method: "POST" }).catch(() => null);
  return response?.ok ?? false;
}

/** Authenticated JSON request; retries once after renewing an expired access cookie. */
export async function api<T>(path: string, init: RequestInit = {}, retry = true): Promise<T> {
  const response = await send(path, init);
  if (response.status === 401 && retry && (await refreshAccess())) {
    return api<T>(path, init, false);
  }
  if (!response.ok) throw new ApiError(response.status, await detail(response));
  return response.json();
}
