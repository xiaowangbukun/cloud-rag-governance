import { defineStore } from "pinia";
import { api, tokenStore } from "@/api/client";

export interface UserProfile {
  id: string;
  subject: string;
  display_name: string;
  role: string;
  org_id: string | null;
  classification_ceiling: string;
  project_ids: string[];
  auth_mode?: string;
}

export interface AuthConfig {
  mode: string;
  oidc_enabled: boolean;
  dev_login_enabled: boolean;
  directory_mode: string;
}

interface TokenPayload {
  access_token: string;
  user: UserProfile;
}

export const useAuthStore = defineStore("auth", {
  state: () => ({
    user: null as UserProfile | null,
    config: null as AuthConfig | null,
    loading: false,
    error: "" as string,
  }),
  getters: {
    isAuthenticated: (s) => !!s.user,
    isAdmin: (s) => s.user?.role === "admin",
    canAudit: (s) => ["admin", "governance", "auditor"].includes(s.user?.role || ""),
  },
  actions: {
    async loadConfig() {
      this.config = await api.get<AuthConfig>("/auth/config");
      return this.config;
    },
    /**
     * 应用启动时用一次静默 refresh 换回内存态。
     *
     * 访问令牌不再落持久化存储，刷新页面后内存是空的；刷新令牌在 HttpOnly
     * Cookie 里由浏览器自动带上，所以这里不需要（也不该）拿到它本身。
     */
    async restoreSession() {
      try {
        const ok = await api.refreshSession();
        if (!ok) return null;
        this.user = await api.get<UserProfile>("/auth/me");
      } catch {
        this.user = null;
      }
      return this.user;
    },
    async login(username: string, password: string) {
      this.loading = true;
      this.error = "";
      try {
        const data = await api.post<TokenPayload>("/auth/login", { username, password });
        tokenStore.access = data.access_token;
        this.user = data.user;
      } catch (e) {
        this.error = (e as Error).message || "登录失败";
        throw e;
      } finally {
        this.loading = false;
      }
    },
    async startOidc() {
      // state 由服务端落库校验；浏览器只负责把它原样带回回调页。
      const data = await api.get<{ authorize_url: string; state: string }>("/auth/oidc/authorize");
      window.location.href = data.authorize_url;
    },
    /**
     * OIDC 回调：只把 code 与 state 交给后端。
     *
     * 前端**不再**比对 state、也不再保管 PKCE verifier / nonce——
     * 那两样都由服务端保管，浏览器不持有就无法被篡改，
     * 而前端比对只能挡住一半攻击面。
     */
    async handleOidcCallback(code: string, state: string) {
      if (!state) {
        this.error = "回调缺少 state";
        throw new Error("回调缺少 state");
      }
      const data = await api.post<TokenPayload>("/auth/oidc/callback", { code, state });
      tokenStore.access = data.access_token;
      this.user = data.user;
    },
    async fetchMe() {
      if (!tokenStore.access) return null;
      try {
        this.user = await api.get<UserProfile>("/auth/me");
      } catch {
        tokenStore.clear();
        this.user = null;
      }
      return this.user;
    },
    async logout() {
      try {
        await api.logout();
      } finally {
        // 无论服务端是否成功，本地内存态都要清掉
        tokenStore.clear();
        this.user = null;
      }
    },
  },
});