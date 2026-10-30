<script setup lang="ts">
import { onMounted, ref, watch } from "vue";
import { api, query } from "@/api/client";

const props = defineProps<{ projectId?: string }>();

interface Item {
  id: string;
  project_id: string;
  platform_label: string;
  resource_name: string | null;
  diff_kind: string;
  cost_delta_cny: number | null;
  status: string;
  rule_hint: string | null;
  detected_at: string;
}
interface Board {
  total: number;
  by_status: Record<string, number>;
  cost_impact_cny: number;
  items: Item[];
  // 服务端只返回最新 item_cap 条；truncated=true 表示清单被截断（汇总数字仍是全量口径）
  truncated?: boolean;
  item_cap?: number;
}
interface CostItem {
  diff_kind: string;
  cost_delta_cny: number;
  count: number;
}

const KIND_LABEL: Record<string, string> = {
  NEW: "新增",
  REMOVED: "释放",
  SPEC_CHANGED: "规格变更",
  STATE_CHANGED: "状态变更",
  TAG_CHANGED: "标签变更",
  OWNER_CHANGED: "责任人变更",
};

const board = ref<Board | null>(null);
const cost = ref<{ items: CostItem[]; total_cny: number } | null>(null);
const note = ref("");
const error = ref("");
const success = ref("");

async function load() {
  error.value = "";
  try {
    const q = query({ project_id: props.projectId });
    board.value = await api.get<Board>(`/governance/board${q}`);
    cost.value = await api.get<{ items: CostItem[]; total_cny: number }>(
      `/governance/cost-impact${q}`
    );
  } catch (e) {
    error.value = (e as Error).message || "加载失败";
  }
}

async function resolve(id: string, status: string) {
  error.value = "";
  success.value = "";
  try {
    await api.post(`/governance/diff/${id}/resolve`, { status, note: note.value || undefined });
    success.value = "已更新处置状态并写入审计";
    note.value = "";
    await load();
  } catch (e) {
    error.value = (e as Error).message || "处置失败";
  }
}

onMounted(load);
watch(() => props.projectId, load);
</script>

<template>
  <div>
    <h2>治理闭环</h2>
    <p class="muted" style="font-size: 13px">
      确认 / 忽略 / 处置全链路留痕；导出受行数与频次双重限制，且导出内容不含负责人与项目内部信息。
    </p>

    <div v-if="error" class="alert error">{{ error }}</div>
    <div v-if="success" class="alert ok">{{ success }}</div>

    <div class="grid grid-3" style="margin: 12px 0">
      <div class="metric"><div class="label">差异总数</div><div class="value">{{ board?.total ?? "-" }}</div></div>
      <div class="metric"><div class="label">待处理</div><div class="value">{{ board?.by_status?.open ?? 0 }}</div></div>
      <div class="metric">
        <div class="label">成本影响合计（元/月）</div>
        <div class="value">{{ cost?.total_cny?.toFixed(2) ?? "-" }}</div>
      </div>
    </div>

    <div class="card">
      <h3 style="font-size: 14px; margin-bottom: 8px">待处置清单</h3>
      <table v-if="board?.items?.length">
        <thead>
          <tr><th>资源</th><th>类型</th><th>成本变化</th><th>规则初判</th><th>处置</th></tr>
        </thead>
        <tbody>
          <tr v-for="item in board.items.slice(0, 20)" :key="item.id">
            <td class="mono">{{ item.resource_name }}</td>
            <td><span class="tag">{{ KIND_LABEL[item.diff_kind] || item.diff_kind }}</span></td>
            <td>{{ Number(item.cost_delta_cny ?? 0).toFixed(2) }}</td>
            <td style="max-width: 300px">{{ item.rule_hint || "-" }}</td>
            <td>
              <div class="row">
                <button style="padding: 3px 8px" @click="resolve(item.id, 'confirmed')">确认</button>
                <button class="secondary" style="padding: 3px 8px" @click="resolve(item.id, 'dismissed')">忽略</button>
                <button class="secondary" style="padding: 3px 8px" @click="resolve(item.id, 'remediated')">已处置</button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
      <p v-else class="muted">暂无待处置项</p>
      <p v-if="board?.truncated" class="muted" style="font-size: 12px; margin-top: 6px">
        清单仅显示最新 {{ board.item_cap ?? board.items.length }} 条，共 {{ board.total }} 条；上方汇总数字为全量口径。
      </p>
      <div class="field" style="margin-top: 10px; max-width: 480px">
        <label>处置说明（可选，随状态一同留痕）</label>
        <input v-model="note" placeholder="例如：已与项目组确认，属计划内下线" />
      </div>
    </div>
  </div>
</template>
