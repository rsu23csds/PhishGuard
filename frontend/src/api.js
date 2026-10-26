const API_BASE = import.meta.env.VITE_API_URL || "";

function authHeaders() {
  const token = localStorage.getItem("pg_token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...authHeaders(),
      ...(options.headers || {}),
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    let msg = "Request failed";
    if (typeof data.detail === "string") {
      msg = data.detail;
    } else if (Array.isArray(data.detail)) {
      msg = data.detail.map((d) => d.msg || JSON.stringify(d)).join(", ");
    } else if (data.detail && typeof data.detail === "object") {
      msg = JSON.stringify(data.detail);
    }
    throw new Error(msg);
  }
  return data;
}

export const api = {
  register: (body) => request("/api/auth/register", { method: "POST", body: JSON.stringify(body) }),
  login: (body) => request("/api/auth/login", { method: "POST", body: JSON.stringify(body) }),
  me: () => request("/api/auth/me"),
  scan: (body) => request("/api/scan", { method: "POST", body: JSON.stringify(body) }),
  scans: () => request("/api/scans"),
  stats: () => request("/api/stats"),
};
