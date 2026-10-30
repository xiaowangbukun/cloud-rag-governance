<script setup lang="ts">
import { onMounted, ref } from "vue";
import { api, query } from "@/api/client";

interface LogEntry {
  id: string;
  ts: string;
  actor_id: string | null;
  action: string;
  outcome: string;
  project_id: string | null;
  resource_type: string | null;
  resource_id: string | null;
  reason: string | null;
  request_id: string | null;
}
interface SecurityEvent {
  id: string;
  ts: string;
  event_type: string;
  severity: string;
  actor_id: string | null;
  project_id: string | null;
  detail: string | null;
}
interface Budget {
  user_id: string;
  used: number;
  limit: number;
  window_seconds: number;
  remaining: number;
}

const logs = ref<LogEntry[]>([]);
const events = ref<SecurityEvent[]>([]);
const budget = ref<Budget | null>(null);
const action = ref("");
const outcome = ref("");
const eventType = ref("");
const error = ref("");
const tab = ref<"logs" | "events">("logs");

const OUTCOME_TAG: Record<string, string> = {
  allowed: "ok",
  denied: "danger",
  filtered: "warn",
  blocked: "danger",
  failed: "danger",
  redacted: "warn",
};
const SEVERITY_TAG: Record<string, string> = {
  info: "muted",
  warn: "warn",
  high: "danger",
  critical: "danger",
};

async function loadLogs() {
  error.value = "";
  try {
    const q = query({ action: action.value, outcome: outcome.value, limit: 50 });
    const data = await api.get<{ items: LogEntry[] }>(`/audit/logs${q}`);
    logs.value = data.items || [];
  } catch (e) {
    error.value = (e as Error).message || "审计日志加载失败";
  }
}

async function loadEvents() {
  error.value = "";
  try {
    const q = query({ event_type: eventType.value, limit: 50 });
    const data = await api.get<{ items: SecurityEvent[] }>(`/audit/security-events${q}`);
    events.value = data.items || [];
  } catch (e) {
    error.value = (e as Error).message || "安全事件加载失败";
  }
}

async function loadBudget() {
  try {
    budget.value = await api.get<Budget>("/audit/budget");
  } catch {
    budget.value = null;
  }
}

onMounted(async () => {
  await Promise.all([loadLogs(), loadEvents(), loadBudget()]);
});
</script>

<template>
  <div>
    <h2>审计与安全事件</h2>
    <p class="muted" style="font-size: 13px">
      所有资源访问、检索、模型调用、策略判定均留痕；非全局角色仅可查看自身范围内的记录。
    </p>

    <div v-if="error" class="alert error">{{ error }}</div>

    <div v-if="budget" class="metric" style="margin: 12px 0; max-width: 320px">
      <div class="label">本小时查询预算</div>
      <div class="value">{{ budget.remaining }} / {{ budget.limit }}</div>
      <div class="muted" style="font-size: 12px">已用 {{ budget.used }} 次</div>
    </div>

    <div class="row" style="margin-bottom: 12px">
      <button :class="tab === 'logs' ? '' : 'secondary'" @click="tab = 'logs'">操作审计</button>
      <button :class="tab === 'events' ? '' : 'secondary'" @click="tab = 'events'">安全事件</button>
    </div>

    <div v-if="tab === 'logs'" class="card">
      <div class="grid grid-3" style="margin-bottom: 12px">
        <div class="field" style="margin: 0">
          <label>动作关键字</label>
          <input v-model="action" placeholder="如 resource:read" @keyup.enter="loadLogs" />
        </div>
        <div class="field" style="margin: 0">
          <label>结果</label>
          <select v-model="outcome">
            <option value="">全部</option>
            <option value="allowed">allowed</option>
            <option value="denied">denied</option>
            <option value="filtered">filtered</option>
            <option value="redacted">redacted</option>
          </select>
        </div>
        <div class="field" style="margin: 0; display: flex; align-items: flex-end">
          <button @click="loadLogs">查询</button>
        </div>
      </div>

      <table v-if="logs.length">
        <thead>
          <tr>
            <th>时间</th><th>操作者</th><th>动作</th><th>结果</th>
            <th>项目</th><th>对象</th><th>原因</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in logs" :key="row.id">
            <td class="mono">{{ row.ts }}</td>
            <td class="mono">{{ row.actor_id || "-" }}</td>
            <td class="mono">{{ row.action }}</td>
            <td><span class="tag" :class="OUTCOME_TAG[row.outcome] || 'muted'">{{ row.outcome }}</span></td>
            <td class="mono">{{ row.project_id || "-" }}</td>
            <td class="mono">{{ row.resource_type || "-" }}</td>
            <td>{{ row.reason || "-" }}</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="muted">暂无审计记录</p>
    </div>

    <div v-else class="card">
      <div class="row" style="margin-bottom: 12px">
        <div class="field" style="margin: 0; max-width: 260px">
          <label>事件类型</label>
          <input v-model="eventType" placeholder="如 canary_leak" @keyup.enter="loadEvents" />
        </div>
        <div style="align-self: flex-end"><button @click="loadEvents">查询</button></div>
      </div>

      <table v-if="events.length">
        <thead>
          <tr><th>时间</th><th>类型</th><th>级别</th><th>操作者</th><th>项目</th><th>详情</th></tr>
        </thead>
        <tbody>
          <tr v-for="row in events" :key="row.id">
            <td class="mono">{{ row.ts }}</td>
            <td class="mono">{{ row.event_type }}</td>
            <td><span class="tag" :class="SEVERITY_TAG[row.severity] || 'muted'">{{ row.severity }}</span></td>
            <td class="mono">{{ row.actor_id || "-" }}</td>
            <td class="mono">{{ row.project_id || "-" }}</td>
            <td style="max-width: 340px">{{ row.detail || "-" }}</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="muted">暂无安全事件</p>
    </div>
  </div>
</template>
