// Thin REST client for the NetGuard backend. Handles the auth token,
// JSON encoding and turns error responses into readable exceptions.

const TOKEN_KEY = "netguard.token";
const USER_KEY = "netguard.user";
const API_BASE = "/api";

export class ApiError extends Error {
  constructor(status, detail, code) {
    super(detail || `Request failed (${status})`);
    this.status = status;
    this.code = code;
  }
}

export const session = {
  get token() {
    return localStorage.getItem(TOKEN_KEY);
  },
  get user() {
    try {
      return JSON.parse(localStorage.getItem(USER_KEY) || "null");
    } catch {
      return null;
    }
  },
  save(token, user) {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  },
  clear() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  },
};

export function redirectToLogin() {
  session.clear();
  const next = encodeURIComponent(window.location.pathname + window.location.search);
  window.location.replace(`/login?next=${next}`);
}

async function request(method, path, body) {
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (session.token) headers.Authorization = `Bearer ${session.token}`;

  let response;
  try {
    response = await fetch(API_BASE + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, "Cannot reach the NetGuard server. Is the backend running?", "network_error");
  }

  if (response.status === 204) return null;
  const payload = await response.json().catch(() => null);

  if (!response.ok) {
    if (response.status === 401 && path !== "/auth/login") {
      redirectToLogin();
    }
    throw new ApiError(response.status, payload?.detail, payload?.error);
  }
  return payload;
}

/** Download a server-generated file (report export) with the session token. */
async function download(path, filename) {
  const headers = session.token ? { Authorization: `Bearer ${session.token}` } : {};
  let response;
  try { response = await fetch(API_BASE + path, { headers }); }
  catch { throw new ApiError(0, "Cannot reach the NetGuard server. Is the backend running?", "network_error"); }
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    if (response.status === 401) redirectToLogin();
    throw new ApiError(response.status, payload?.detail, payload?.error);
  }
  const url = URL.createObjectURL(await response.blob());
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export const api = {
  download,
  get: (path) => request("GET", path),
  post: (path, body = {}) => request("POST", path, body),
  put: (path, body = {}) => request("PUT", path, body),
  del: (path) => request("DELETE", path),
};
