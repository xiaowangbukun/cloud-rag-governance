<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { useAuthStore } from "@/stores/auth";

const auth = useAuthStore();
const router = useRouter();
const route = useRoute();
const username = ref("governance@corp.local");
const password = ref("Gov@2026");
const error = ref("");
const submitting = ref(false);

onMounted(() => auth.loadConfig());

async function submit() {
  error.value = "";
  submitting.value = true;
  try {
    await auth.login(username.value, password.value);
    const redirect = (route.query.redirect as string) || "/";
    router.push(redirect);
  } catch (e) {
    error.value = (e as Error).message || "登录失败";
  } finally {
    submitting.value = false;
  }
}

async function oidc() {
  try {
    await auth.startOidc();
  } catch (e) {
    error.value = (e as Error).message || "OIDC 未就绪";
  }
}
</script>

<template>
  <div class="login-page">
    <div class="card login-card">
      <h2 style="margin-bottom: 4px">多云资源治理与安全归因平台</h2>
      <p class="muted" style="margin-top: 0; font-size: 13px">
        内网部署 · 数据分级受控 · 向量与模型上下文隔离
      </p>

      <div v-if="error" class="alert error">{{ error }}</div>

      <div v-if="auth.config?.oidc_enabled" class="field">
        <button style="width: 100%" @click="oidc">使用企业统一身份登录（OIDC）</button>
      </div>

      <div v-if="auth.config?.dev_login_enabled">
        <div class="divider muted">或使用本地账号（仅开发/演示环境）</div>
        <form @submit.prevent="submit">
          <div class="field">
            <label>账号</label>
            <input v-model="username" autocomplete="username" />
          </div>
          <div class="field">
            <label>口令</label>
            <input v-model="password" type="password" autocomplete="current-password" />
          </div>
          <button style="width: 100%" :disabled="submitting">
            {{ submitting ? "登录中..." : "登录" }}
          </button>
        </form>
        <div class="muted" style="margin-top: 10px; font-size: 12px">
          演示账号：admin@corp.local / Admin@2026（管理员）、pm@corp.local / Pm@2026（仅核心承保）、
          viewer@corp.local / View@2026（无项目授权，用于验证越权拦截）
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.login-page { display: flex; justify-content: center; align-items: center; min-height: 100vh; }
.login-card { width: 420px; }
.divider {
  font-size: 12px;
  margin: 14px 0;
  border-top: 1px solid var(--border);
  padding-top: 10px;
}
</style>
