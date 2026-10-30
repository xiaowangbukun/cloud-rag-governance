<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { RouterLink, RouterView, useRoute, useRouter } from "vue-router";
import { useAuthStore } from "@/stores/auth";

const auth = useAuthStore();
const route = useRoute();
const router = useRouter();
const projects = ref<{ id: string; name: string; code: string }[]>([]);
const selectedProject = ref<string>("");

const navItems = computed(() => {
  const items = [
    { to: "/", label: "概览" },
    { to: "/resources", label: "资源台账" },
    { to: "/diffs", label: "差异清单" },
    { to: "/attribution", label: "语义归因" },
    { to: "/governance", label: "治理闭环" },
    { to: "/knowledge", label: "知识库检索" },
    { to: "/collection", label: "采集任务" },
  ];
  if (auth.isAdmin) items.push({ to: "/models", label: "模型网关" });
  if (auth.canAudit) items.push({ to: "/audit", label: "审计" });
  if (auth.isAdmin) items.push({ to: "/admin", label: "系统配置" });
  return items;
});

onMounted(async () => {
  // 访问令牌只在内存：直接刷新本页时先用 HttpOnly Cookie 静默换回会话
  if (auth.user) await auth.fetchMe();
  else await auth.restoreSession();
  try {
    const { api } = await import("@/api/client");
    projects.value = await api.get("/resources/projects");
  } catch {
    projects.value = [];
  }
});

async function logout() {
  await auth.logout();
  router.push({ name: "login" });
}

defineExpose({ selectedProject });
</script>

<template>
  <div class="layout">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-title">资源治理平台</div>
        <div class="brand-sub muted">多云采集 · 安全 RAG 归因</div>
      </div>

      <div class="project-picker">
        <label class="muted">当前项目</label>
        <select v-model="selectedProject">
          <option value="">全部（按授权范围）</option>
          <option v-for="p in projects" :key="p.id" :value="p.id">
            {{ p.name }} ({{ p.code }})
          </option>
        </select>
      </div>

      <nav>
        <RouterLink
          v-for="item in navItems"
          :key="item.to"
          :to="item.to"
          class="nav-item"
          :class="{ active: route.path === item.to }"
        >
          {{ item.label }}
        </RouterLink>
      </nav>

      <div class="user-box">
        <div class="mono">{{ auth.user?.display_name || "未登录" }}</div>
        <div class="muted" style="font-size: 12px">
          角色 {{ auth.user?.role }} · 密级 {{ auth.user?.classification_ceiling }}
        </div>
        <button class="secondary" style="margin-top: 8px; width: 100%" @click="logout">
          退出登录
        </button>
      </div>
    </aside>

    <main class="content">
      <RouterView v-slot="{ Component }">
        <component :is="Component" :project-id="selectedProject" />
      </RouterView>
    </main>
  </div>
</template>

<style scoped>
.layout { display: flex; min-height: 100vh; }
.sidebar {
  width: 216px;
  background: #fff;
  border-right: 1px solid var(--border);
  padding: 16px 12px;
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.brand-title { font-size: 15px; font-weight: 600; }
.brand-sub { font-size: 12px; }
.project-picker label { display: block; font-size: 12px; margin-bottom: 4px; }
nav { display: flex; flex-direction: column; gap: 2px; flex: 1; }
.nav-item {
  padding: 7px 10px;
  border-radius: 6px;
  color: var(--text);
  font-size: 13px;
}
.nav-item:hover { background: #f4f5f7; }
.nav-item.active { background: var(--brand-soft); color: var(--brand); font-weight: 500; }
.user-box { border-top: 1px solid var(--border); padding-top: 10px; font-size: 13px; }
.content { flex: 1; padding: 18px 22px; overflow-x: hidden; }
</style>
