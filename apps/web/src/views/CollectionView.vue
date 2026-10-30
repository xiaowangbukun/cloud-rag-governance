<script setup lang="ts">
import { onMounted, ref } from "vue";
import { api } from "@/api/client";

interface Account {
  id: string;
  platform: string;
  name: string;
  region: string | null;
  enabled: boolean;
  credential_ref: string | null;
}
interface Snapshot {
  id: string;
  platform: string;
  taken_at: string;
  status: string;
  source_mode: string;
  resource_count: number;
  error_message: string | null;
}

const accounts = ref<Account[]>([]);
const snapshots = ref<Snapshot[]>([]);
const mode = ref("");
const error = ref("");
const msg = ref("");
const running = ref(false);
const dryRun = ref(true);
const accountId = ref("");

async function load() {
  error.value = "";
  try {
    accounts.value = await api.get<Account[]>("/collection/accounts");
    snapshots.value = await api.get<Snapshot[]>("/collection/snapshots?limit=20");
    const cfg = await api.get<Record<string, string>>("/admin/config").catch(() => null);
    mode.value = cfg?.collector_mode || "simulated";
  } catch (e) {
    error.value = (e as Error).message || "加载失败";
  }
}

async function run() {
  running.value = true;
  error.value = "";
  msg.value = "";
  try {
    const data = await api.post<Record<string, unknown>>("/collection/run", {
      dry_run: dryRun.value,
      account_id: accountId.value || undefined,
    });
    msg.value = JSON.stringify(data);
    await load();
  } catch (e) {
    error.value = (e as Error).message || "采集失败";
  } finally {
    running.value = false;
  }
}

onMounted(load);
</script>

<template>
  <div>
    <h2>采集任务</h2>
    <p class="muted" style="font-size: 13px">
      适配器已按四家云平台真实 API 定义（蓝鲸 / 青云 / 华为云 / 腾讯云）；当前采集模式：
      <span class="tag">{{ mode || "加载中" }}</span>
      。真实凭证通过环境变量注入，不入库、不写日志。
    </p>

    <div v-if="error" class="alert error">{{ error }}</div>
    <div v-if="msg" class="alert info mono">{{ msg }}</div>

    <div class="card">
      <div class="row">
        <select v-model="accountId" style="width: 240px">
          <option value="">全部云账号</option>
          <option v-for="a in accounts" :key="a.id" :value="a.id">{{ a.name }}（{{ a.platform }}）</option>
        </select>
        <label class="row" style="width: auto; gap: 4px">
          <input v-model="dryRun" type="checkbox" style="width: auto" />
          <span style="font-size: 13px">试运行（不落库）</span>
        </label>
        <button :disabled="running" @click="run">{{ running ? "执行中..." : "执行采集" }}</button>
      </div>
      <p class="muted" style="font-size: 12px; margin-bottom: 0">
        首次采集仅建立基线不产出差异，第二次采集起输出增量 diff，避免大量误报。
      </p>
    </div>

    <div class="grid grid-2" style="margin-top: 12px">
      <div class="card">
        <h3 style="font-size: 14px; margin-bottom: 8px">云账号</h3>
        <table>
          <thead><tr><th>名称</th><th>平台</th><th>地域</th><th>凭证引用</th><th>状态</th></tr></thead>
          <tbody>
            <tr v-for="a in accounts" :key="a.id">
              <td>{{ a.name }}</td>
              <td>{{ a.platform }}</td>
              <td>{{ a.region || "-" }}</td>
              <td class="mono">{{ a.credential_ref || "-" }}</td>
              <td><span class="tag" :class="a.enabled ? 'ok' : 'muted'">{{ a.enabled ? "启用" : "停用" }}</span></td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <h3 style="font-size: 14px; margin-bottom: 8px">最近快照</h3>
        <table>
          <thead><tr><th>平台</th><th>采集时间</th><th>资源数</th><th>状态</th></tr></thead>
          <tbody>
            <tr v-for="s in snapshots" :key="s.id">
              <td>{{ s.platform }}</td>
              <td class="mono">{{ s.taken_at?.slice(0, 19).replace("T", " ") }}</td>
              <td>{{ s.resource_count }}</td>
              <td><span class="tag" :class="s.status === 'success' ? 'ok' : 'warn'">{{ s.status }}</span></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>
