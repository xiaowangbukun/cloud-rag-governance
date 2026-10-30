import { createRouter, createWebHistory } from "vue-router";
import { tokenStore } from "@/api/client";
import { useAuthStore } from "@/stores/auth";

const routes = [
  { path: "/login", name: "login", component: () => import("@/views/LoginView.vue") },
  {
    path: "/auth/callback",
    name: "oidc-callback",
    component: () => import("@/views/OidcCallbackView.vue"),
  },
  {
    path: "/",
    component: () => import("@/components/AppLayout.vue"),
    meta: { requiresAuth: true },
    children: [
      { path: "", name: "overview", component: () => import("@/views/OverviewView.vue") },
      { path: "resources", name: "resources", component: () => import("@/views/ResourcesView.vue") },
      { path: "diffs", name: "diffs", component: () => import("@/views/DiffsView.vue") },
      { path: "attribution", name: "attribution", component: () => import("@/views/AttributionView.vue") },
      { path: "governance", name: "governance", component: () => import("@/views/GovernanceView.vue") },
      { path: "knowledge", name: "knowledge", component: () => import("@/views/KnowledgeView.vue") },
      { path: "collection", name: "collection", component: () => import("@/views/CollectionView.vue") },
      { path: "models", name: "models", component: () => import("@/views/ModelGatewayView.vue") },
      { path: "audit", name: "audit", component: () => import("@/views/AuditView.vue") },
      { path: "admin", name: "admin", component: () => import("@/views/AdminView.vue") },
    ],
  },
];

export const router = createRouter({
  history: createWebHistory(),
  routes,
});

/**
 * 访问令牌只在内存里，刷新页面后必然为空——这正是「不落 localStorage」的代价。
 * 这里用 HttpOnly Cookie 静默换一次会话，因此刷新页面不会把人踢回登录页。
 * 顺带这也是启动时恢复会话的唯一入口（只在进入受保护路由时触发一次，
 * 避免启动与守卫各 refresh 一次）。
 */
router.beforeEach(async (to) => {
  if (!to.meta.requiresAuth) return true;
  if (tokenStore.access) return true;
  const auth = useAuthStore();
  await auth.restoreSession();
  if (!auth.isAuthenticated) {
    return { name: "login", query: { redirect: to.fullPath } };
  }
  return true;
});
