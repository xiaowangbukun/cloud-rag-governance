<script setup lang="ts">
import { onMounted, ref, watch } from "vue";
import { api, query } from "@/api/client";

const props = defineProps<{ projectId?: string }>();

interface Board {
  total: number;
  by_status: Record<string, number>;
  by_kind: Record<string, number>;
  cost_impact_cny: number;
  items: Record<string, unknown>[];
}
interface Summary {
  total: number;
  by_kind: Record<string, number>;
  cost_impact_cny: number;
}

const board = ref<Board | null>(null);
const summary = ref<Summary | null>(null);
const error = ref("");
const loading = ref(false);

const KIND_LABEL: Record<string, string> = {
  NEW: "新增",
  REMOVED: "释放",
  SPEC_CHANGED: "规格变更",
  STATE_CHANGED: "状态变更",
  TAG_CHANGED: "标签变更",
  OWNER_CHANGED: "责任人变更",
};

async function load() {
  loading.value = true;
  error.value = "";
  try {
    const q = query({ project_id: props.projectId });
    board.value = await api.get<Board>(`/governance/board${q}`);
    summary.value = await api.get<Summary>(`/resources/diffs/summary${q}`);
  } catch (e) {
    error.value = (e as Error).message || "加载失败";
  } finally {
    loading.value = false;
  }
}

onMounted(load);
watch(() => props.projectId, load);
</script>

<template>
  <div>
    <h2>概览</h2>
    <p class="muted" style="font-size: 13px">
      数据受授权边界约束：以下统计只包含当前身份可见的项目与密级范围。
    </p>

    <div v-if="error" class="alert error">{{ error }}</div>

    <div class="grid grid-4" style="margin: 12px 0">
      <div class="metric">
        <div class="label">差异总数</div>
        <div class="value">{{ board?.total ?? "-" }}</div>
      </div>
      <div class="metric">
        <div class="label">待处理</div>
        <div class="value">{{ board?.by_status?.open ?? "-" }}</div>
      </div>
      <div class="metric">
        <div class="label">已处理</div>
        <div class="value">
          {{ (board?.total ?? 0) - (board?.by_status?.open ?? 0) }}
        </div>
      </div>
      <div class="metric">
        <div class="label">成本影响（元/月）</div>
        <div class="value">{{ board?.cost_impact_cny?.toFixed(2) ?? "-" }}</div>
      </div>
    </div>

    <div class="grid grid-2">
      <div class="card">
        <h3 style="font-size: 14px; margin-bottom: 8px">按差异类型</h3>
        <table v-if="summary">
          <thead>
            <tr><th>类型</th><th>数量</th></tr>
          </thead>
          <tbody>
            <tr v-for="(v, k) in summary.by_kind" :key="k">
              <td>{{ KIND_LABEL[k] || k }}</td>
              <td>{{ v }}</td>
            </tr>
          </tbody>
        </table>
        <p v-else class="muted">{{ loading ? "加载中..." : "暂无数据" }}</p>
      </div>

      <div class="card">
        <h3 style="font-size: 14px; margin-bottom: 8px">最近差异（已脱敏展示）</h3>
        <table v-if="board?.items?.length">
          <thead>
            <tr><th>资源</th><th>类型</th><th>成本变化</th><th>状态</th></tr>
          </thead>
          <tbody>
            <tr v-for="item in board.items.slice(0, 10)" :key="String(item.id)">
              <td class="mono">{{ item.resource_name }}</td>
              <td><span class="tag">{{ KIND_LABEL[String(item.diff_kind)] || item.diff_kind }}</span></td>
              <td>{{ Number(item.cost_delta_cny ?? 0).toFixed(2) }}</td>
              <td><span class="tag muted">{{ item.status }}</span></td>
            </tr>
          </tbody>
        </table>
        <p v-else class="muted">暂无数据</p>
      </div>
    </div>
  </div>
</template>
