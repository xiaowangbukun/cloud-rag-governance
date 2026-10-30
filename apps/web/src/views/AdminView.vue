<script setup lang="ts">
import { onMounted, ref } from "vue";
import { api } from "@/api/client";

interface RuntimeConfig {
  app_env: string;
  auth_mode: string;
  directory_mode: string;
  collector_mode: string;
  embedding_backend: string;
  embedding_model: string;
  security: Record<string, number | boolean>;
  model: { allow_public: boolean; allowed_hosts: string[] };
}
interface DirectoryState {
  provider: string;
  status: string;
  cursor: string | null;
  last_sync_at: string | null;
  message: string | null;
  stats: Record<string, unknown> | null;
}

const config = ref<RuntimeConfig | null>(null);
const directory = ref<DirectoryState | null>(null);
const error = ref("");
const success = ref("");
const syncResult = ref("");

const BOOL_KEYS = new Set(["canary_enabled", "mask_entities", "coarse_buckets", "redact_owner"]);
const SECURITY_LABEL: Record<string, string> = {
  max_span_days: "最大时间跨度（天）",
  query_budget_per_hour: "每小时查询预算",
  export_limit: "单次导出行数上限",
  canary_enabled: "诱饵数据开关",
  mask_entities: "实体脱敏",
  coarse_buckets: "数值区间泛化",
  redact_owner: "负责人字段隐去",
};

async function load() {
  error.value = "";
  try {
    config.value = await api.get<RuntimeConfig>("/admin/config");
  } catch (e) {
    error.value = (e as Error).message || "运行时配置加载失败（需管理员权限）";
  }
  try {
    directory.value = await api.get<DirectoryState>("/admin/directory/sync");
  } catch {
    directory.value = null;
  }
}

async function triggerSync() {
  syncResult.value = "";
  error.value = "";
  try {
    const data = await api.post<{ status: string; message: string }>("/admin/directory/sync");
    syncResult.value = `${data.status}：${data.message}`;
    await load();
  } catch (e) {
    error.value = (e as Error).message || "目录同步触发失败";
  }
}

onMounted(load);
</script>

<template>
  <div>
    <h2>系统管理</h2>
    <p class="muted" style="font-size: 13px">
      展示当前生效的运行时配置与安全策略基线；密钥等敏感项不在此返回。
    </p>

    <div v-if="error" class="alert error">{{ error }}</div>
    <div v-if="syncResult" class="alert info">{{ syncResult }}</div>

    <div v-if="config" class="grid grid-2" style="margin-top: 12px">
      <div class="card">
        <h3 style="font-size: 14px; margin-bottom: 10px">运行时</h3>
        <table>
          <tbody>
            <tr><td class="muted">环境</td><td class="mono">{{ config.app_env }}</td></tr>
            <tr><td class="muted">认证模式</td><td class="mono">{{ config.auth_mode }}</td></tr>
            <tr><td class="muted">目录模式</td><td class="mono">{{ config.directory_mode }}</td></tr>
            <tr><td class="muted">采集模式</td><td class="mono">{{ config.collector_mode }}</td></tr>
            <tr><td class="muted">向量后端</td><td class="mono">{{ config.embedding_backend }}</td></tr>
            <tr><td class="muted">向量模型</td><td class="mono">{{ config.embedding_model }}</td></tr>
            <tr><td class="muted">允许公网模型</td><td class="mono">{{ config.model.allow_public ? "是" : "否" }}</td></tr>
            <tr>
              <td class="muted">模型主机白名单</td>
              <td class="mono">{{ config.model.allowed_hosts?.join(", ") || "未限制" }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <h3 style="font-size: 14px; margin-bottom: 10px">安全策略基线</h3>
        <table>
          <tbody>
            <tr v-for="(value, key) in config.security" :key="key">
              <td class="muted">{{ SECURITY_LABEL[key] || key }}</td>
              <td class="mono">
                <span v-if="BOOL_KEYS.has(key)" class="tag" :class="value ? 'ok' : 'muted'">
                  {{ value ? "启用" : "关闭" }}
                </span>
                <span v-else>{{ value }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="card" style="margin-top: 12px">
      <h3 style="font-size: 14px; margin-bottom: 8px">组织目录同步</h3>
      <p class="muted" style="font-size: 13px">
        预留公司统一身份校验接口：接入后在此触发增量同步，写入用户的组织、部门与项目归属。
      </p>
      <table v-if="directory" style="margin: 10px 0">
        <tbody>
          <tr><td class="muted">提供方</td><td class="mono">{{ directory.provider }}</td></tr>
          <tr><td class="muted">状态</td><td class="mono">{{ directory.status }}</td></tr>
          <tr><td class="muted">最近同步</td><td class="mono">{{ directory.last_sync_at || "-" }}</td></tr>
          <tr><td class="muted">说明</td><td>{{ directory.message || "-" }}</td></tr>
        </tbody>
      </table>
      <button @click="triggerSync">触发目录同步</button>
    </div>
  </div>
</template>
