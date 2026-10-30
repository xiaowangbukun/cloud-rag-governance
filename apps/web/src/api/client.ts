const API_BASE = import.meta.env.VITE_API_BASE || "/api/v1";

export interface ApiError {
  code: string;
  message: string;
  request_id?: string;
  details?: Record<string, unknown>;
}

/**
 * 访问令牌只存在内存里，刷新令牌存在 HttpOnly Cookie（JS 读不到）。
 *
 * 为什么不再用 localStorage：那里放的东西任何一次 XSS 都能直接读走，
 * 等于把「拿到令牌即可冒充用户」变成「拿到令牌 + 再读一次 localStorage」。
 * 代价是刷新页面后内存态丢失——用一次静默 refresh 换回来（见 tryRefresh）。
 */
let accessToken = "";

export const tokenStore = {
  get access(): string {
    return accessToken;
  },
  set access(value: string) {
    accessToken = value || "";
  },
  get hasRefreshCookie(): boolean {
    // HttpOnly Cookie 对 JS 不可见，只能靠「是否登录过」间接判断；
    // 真正的判定交给 /auth/refresh 的结果。
    return true;
  },
  clear(): void {
    accessToken = "";
  },
};

async function request<T>(
  path: string,
  options: RequestInit = {},
  retry = true
): Promise<T> {
  const headers = new Headers(options.headers || {});
  if (!headers.has("Content-Type") && options.body) {
    headers.set("Content-Type", "application/json");
  }
  if (tokenStore.access) headers.set("Authorization", `Bearer ${tokenStore.access}`);

  // 同源默认就会带 Cookie；显式 include 是为了让跨域部署（VITE_API_BASE 指向
  // 独立域名）也能拿到刷新令牌 Cookie。
  const resp = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
    credentials: "include",
  });

  if (resp.status === 401 && retry && tokenStore.access) {
    const refreshed = await tryRefresh();
    if (refreshed) return request<T>(path, options, false);
  }
  if (!resp.ok) {
    let payload: ApiError = { code: "unknown", message: `HTTP ${resp.status}` };
    try {
      payload = (await resp.json()) as ApiError;
    } catch {
      /* 保留默认错误结构 */
    }
    throw Object.assign(new Error(payload.message), payload);
  }
  if (resp.status === 204) return undefined as unknown as T;
  return (await resp.json()) as T;
}

/** 用 HttpOnly Cookie 里的刷新令牌换一个新的访问令牌。 */
async function tryRefresh(): Promise<boolean> {
  try {
    const data = await request<{ access_token: string }>(
      "/auth/refresh",
      { method: "POST" },
      false
    );
    tokenStore.access = data.access_token;
    return true;
  } catch {
    tokenStore.clear();
    return false;
  }
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: body ? JSON.stringify(body) : undefined }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "PATCH", body: body ? JSON.stringify(body) : undefined }),
  del: <T>(path: string) => request<T>(path, { method: "DELETE" }),
  postRaw: <T>(path: string, options: RequestInit = {}) => request<T>(path, { ...options, method: "POST" }),
  refreshSession: () => tryRefresh(),
  logout: () => request<{ ok: boolean }>("/auth/logout", { method: "POST" }, false),
};

export function query(params: Record<string, string | number | undefined>): string {
  const usp = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== "") usp.set(k, String(v));
  });
  const s = usp.toString();
  return s ? `?${s}` : "";
}