<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { useAuthStore } from "@/stores/auth";

const auth = useAuthStore();
const router = useRouter();
const message = ref("正在完成统一身份认证...");

onMounted(async () => {
  const params = new URLSearchParams(window.location.search);
  const code = params.get("code");
  const state = params.get("state");
  if (!code) {
    message.value = "未获取到授权码";
    return;
  }
  if (!state) {
    // IdP 没回传 state：直接失败，不做任何「前端兜底比对」——
    // state 的权威副本在服务端，前端比对只能挡一半攻击面。
    message.value = "回调缺少 state，已拒绝";
    return;
  }
  try {
    await auth.handleOidcCallback(code, state);
    router.push("/");
  } catch (e) {
    message.value = (e as Error).message || "OIDC 回调处理失败";
  }
});
</script>

<template>
  <div class="wrap">
    <div class="card">
      <p>{{ message }}</p>
      <RouterLink to="/login">返回登录</RouterLink>
    </div>
  </div>
</template>

<style scoped>
.wrap { display: flex; justify-content: center; align-items: center; min-height: 100vh; }
</style>
