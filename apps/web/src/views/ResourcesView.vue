<script setup lang="ts">
import { onMounted, ref, watch } from "vue";
import { api, query } from "@/api/client";

const props = defineProps<{ projectId?: string }>();

interface Resource {
  id: string;
  platform_label: string;
  project_id: string;
  name: string;
  kind: string;
  spec: string | null;
  status: string | null;
  monthly_cost_cny: number | null;
  classification: string;
}

interface Stats {
  by_platform: { platform_label: string; count: number; monthly_cost_cny: number }[];
  by_kind: { kind: string; count: number }[];
  total_monthly_cost_cny: number;
}

const rows = ref<Resource[]>([]);
const stats = ref<Stats | null>(null);
const error = ref("");
const kind = ref("");
const status = ref("");
const total = ref(0);

async function load() {
  if (!props.projectId) {
    rows.value = [];
    stats.value = null;
    error.value = "请先在左侧选择项目（资源查询必须限定项目范围）";
    return;
  }
  error.value = "";
  try {
    const q = query({ project_id: props.projectId, kind: kind.value, status: status.value, limit: 100 });
    rows.value = await api.get<Resource[]>(`/resources${q}`);
    total.value = rows.value.length;
    stats.value = await api.get<Stats>(`/resources/stats?project_id=${props.projectId}`);
  } catch (e) {
    error.value = (e as Error).message || "加载失败";
    rows.value = [];
  }
}

onMounted(load);
watch(() => [props.projectId, kind.value, status.value], load);
</script>

<template>
  <div>
    <h2>资源台账</h2>
    <p class="muted" style="font-size: 13px">
      精确资源数据属事实域，不进入向量库；查询强制限定项目并下推行级过滤。
    </p>

    <div v-if="error" class="alert error">{{ error }}</div>

    <div class="row" style="margin: 12px 0">
      <select v-model="kind" style="width: 160px">
        <option value="">全部类型</option>
        <option value="vm">云主机</option>
        <option value="disk">云硬盘</option>
        <option value="database">数据库</option>
        <option value="loadbalancer">负载均衡</option>
        <option value="object_storage">对象存储</option>
        <option value="public_ip">公网 IP</option>
      </select>
      <select v-model="status" style="width: 160px">
        <option value="">全部状态</option>
        <option value="running">运行中</option>
        <option value="stopped">已停止</option>
        <option value="expired">已到期</option>
      </select>
      <span class="muted">共 {{ total }} 条</span>
    </div>

    <div v-if="stats" class="grid grid-4" style="margin-bottom: 12px">
      <div class="metric">
        <div class="label">月度成本合计（元）</div>
        <div class="value">{{ stats.total_monthly_cost_cny.toFixed(0) }}</div>
      </div>
      <div class="card" style="grid-column: span 3">
        <div class="muted" style="font-size: 12px">分平台分布</div>
        <table>
          <thead><tr><th>平台</th><th>数量</th><th>月度成本（元）</th></tr></thead>
          <tbody>
            <tr v-for="p in stats.by_platform" :key="p.platform_label">
              <td>{{ p.platform_label }}</td>
              <td>{{ p.count }}</td>
              <td>{{ p.monthly_cost_cny.toFixed(2) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <table v-if="rows.length">
        <thead>
          <tr>
            <th>名称</th><th>平台</th><th>类型</th><th>规格</th><th>状态</th><th>月成本</th><th>密级</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in rows" :key="r.id">
            <td class="mono">{{ r.name }}</td>
            <td>{{ r.platform_label }}</td>
            <td>{{ r.kind }}</td>
            <td>{{ r.spec || "-" }}</td>
            <td><span class="tag muted">{{ r.status || "-" }}</span></td>
            <td>{{ r.monthly_cost_cny?.toFixed(2) ?? "-" }}</td>
            <td><span class="tag">{{ r.classification }}</span></td>
          </tr>
        </tbody>
      </table>
      <p v-else class="muted">暂无数据或当前身份无该项目权限</p>
    </div>
  </div>
</template>
