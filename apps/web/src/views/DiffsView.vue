<script setup lang="ts">
import { onMounted, ref, watch } from "vue";
import { api, query } from "@/api/client";

const props = defineProps<{ projectId?: string }>();

interface Diff {
  id: string;
  project_id: string;
  platform_label: string;
  native_id: string;
  resource_name: string | null;
  kind: string;
  diff_kind: string;
  detected_at: string;
  cost_delta_cny: number | null;
  rule_hint: string | null;
  summary: string | null;
  status: string;
  classification: string;
}

const KIND_LABEL: Record<string, string> = {
  NEW: "新增",
  REMOVED: "释放",
  SPEC_CHANGED: "规格变更",
  STATE_CHANGED: "状态变更",
  TAG_CHANGED: "标签变更",
  OWNER_CHANGED: "责任人变更",
};

const rows = ref<Diff[]>([]);
const error = ref("");
const diffKind = ref("");
const status = ref("open");

async function load() {
  error.value = "";
  try {
    const q = query({
      project_id: props.projectId,
      diff_kind: diffKind.value,
      status: status.value,
      limit: 100,
    });
    rows.value = await api.get<Diff[]>(`/resources/diffs${q}`);
  } catch (e) {
    error.value = (e as Error).message || "加载失败";
    rows.value = [];
  }
}

onMounted(load);
watch(() => [props.projectId, diffKind.value, status.value], load);
</script>

<template>
  <div>
    <h2>差异清单</h2>
    <p class="muted" style="font-size: 13px">
      差异来自增量 diff 引擎：指纹比对避免时间戳抖动造成的假差异；规则初判先行，模型仅做语义补充。
    </p>

    <div v-if="error" class="alert error">{{ error }}</div>

    <div class="row" style="margin: 12px 0">
      <select v-model="diffKind" style="width: 160px">
        <option value="">全部类型</option>
        <option v-for="(label, key) in KIND_LABEL" :key="key" :value="key">{{ label }}</option>
      </select>
      <select v-model="status" style="width: 160px">
        <option value="open">待处理</option>
        <option value="confirmed">已确认</option>
        <option value="dismissed">已忽略</option>
        <option value="remediated">已处置</option>
      </select>
      <span class="muted">共 {{ rows.length }} 条</span>
    </div>

    <div class="card">
      <table v-if="rows.length">
        <thead>
          <tr>
            <th>资源</th><th>平台</th><th>类型</th><th>成本变化</th><th>规则初判</th><th>密级</th><th>发现时间</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in rows" :key="r.id">
            <td class="mono">{{ r.resource_name || r.native_id }}</td>
            <td>{{ r.platform_label }}</td>
            <td><span class="tag">{{ KIND_LABEL[r.diff_kind] || r.diff_kind }}</span></td>
            <td>{{ r.cost_delta_cny?.toFixed(2) ?? "-" }}</td>
            <td style="max-width: 320px">{{ r.rule_hint || "-" }}</td>
            <td><span class="tag muted">{{ r.classification }}</span></td>
            <td class="mono">{{ r.detected_at?.slice(0, 10) }}</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="muted">暂无差异记录</p>
    </div>
  </div>
</template>
