<script setup lang="ts">
import { onMounted, ref } from "vue";
import { api } from "@/api/client";

interface Gateway {
  id: string;
  name: string;
  provider: string;
  base_url: string;
  model: string;
  api_key_ref: string | null;
  api_key_masked: string | null;
  enabled: boolean;
  is_default: boolean;
  sanitize_before_send: boolean;
  temperature: number;
  max_tokens: number;
  timeout_seconds: number;
}

const rows = ref<Gateway[]>([]);
const error = ref("");
const msg = ref("");
const testResult = ref<Record<string, unknown> | null>(null);
const testing = ref("");

const form = ref({
  id: "",
  name: "",
  provider: "internal",
  base_url: "",
  model: "",
  api_key_ref: "",
  api_key_value: "",
  enabled: true,
  is_default: false,
  sanitize_before_send: true,
  temperature: 0.1,
  max_tokens: 2048,
  timeout_seconds: 120,
});

async function load() {
  error.value = "";
  try {
    rows.value = await api.get<Gateway[]>("/admin/gateways");
  } catch (e) {
    error.value = (e as Error).message || "加载失败（可能缺少管理员权限）";
  }
}

function edit(row: Gateway) {
  form.value = {
    id: row.id,
    name: row.name,
    provider: row.provider,
    base_url: row.base_url,
    model: row.model,
    api_key_ref: row.api_key_ref || "",
    api_key_value: "",
    enabled: row.enabled,
    is_default: row.is_default,
    sanitize_before_send: row.sanitize_before_send,
    temperature: row.temperature,
    max_tokens: row.max_tokens,
    timeout_seconds: row.timeout_seconds,
  };
}

async function save() {
  error.value = "";
  msg.value = "";
  try {
    const body = {
      name: form.value.name,
      provider: form.value.provider,
      base_url: form.value.base_url,
      model: form.value.model,
      api_key_ref: form.value.api_key_ref || null,
      api_key_value: form.value.api_key_value || undefined,
      enabled: form.value.enabled,
      is_default: form.value.is_default,
      sanitize_before_send: form.value.sanitize_before_send,
      temperature: form.value.temperature,
      max_tokens: form.value.max_tokens,
      timeout_seconds: form.value.timeout_seconds,
    };
    if (form.value.id) await api.patch(`/admin/gateways/${form.value.id}`, body);
    else await api.post("/admin/gateways", body);
    msg.value = "配置已保存（密钥仅保存引用与掩码）";
    await load();
  } catch (e) {
    error.value = (e as Error).message || "保存失败";
  }
}

async function test(id: string) {
  testing.value = id;
  testResult.value = null;
  try {
    testResult.value = await api.post<Record<string, unknown>>(`/admin/gateways/${id}/test`);
  } catch (e) {
    error.value = (e as Error).message || "测试失败";
  } finally {
    testing.value = "";
  }
}

onMounted(load);
</script>

<template>
  <div>
    <h2>模型网关配置</h2>
    <p class="muted" style="font-size: 13px">
      支持「内网推理服务」与「外部 OpenAI 兼容 API」两种模式；外部调用受主机白名单约束，
      出网前强制脱敏与注入检测。密钥只保存环境变量引用名，不明文入库。
    </p>

    <div v-if="error" class="alert error">{{ error }}</div>
    <div v-if="msg" class="alert ok">{{ msg }}</div>
    <div v-if="testResult" class="alert info mono">{{ JSON.stringify(testResult) }}</div>

    <div class="card">
      <h3 style="font-size: 14px; margin-bottom: 8px">已配置网关</h3>
      <table v-if="rows.length">
        <thead>
          <tr><th>名称</th><th>类型</th><th>地址</th><th>模型</th><th>密钥</th><th>默认</th><th>操作</th></tr>
        </thead>
        <tbody>
          <tr v-for="g in rows" :key="g.id">
            <td>{{ g.name }}</td>
            <td><span class="tag">{{ g.provider === "internal" ? "内网推理" : "外部 API" }}</span></td>
            <td class="mono">{{ g.base_url }}</td>
            <td class="mono">{{ g.model }}</td>
            <td class="mono">{{ g.api_key_masked || g.api_key_ref || "-" }}</td>
            <td><span v-if="g.is_default" class="tag ok">默认</span><span v-else class="muted">-</span></td>
            <td>
              <div class="row">
                <button class="secondary" style="padding: 3px 8px" @click="edit(g)">编辑</button>
                <button class="secondary" style="padding: 3px 8px" :disabled="testing === g.id" @click="test(g.id)">
                  {{ testing === g.id ? "测试中" : "测试连接" }}
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
      <p v-else class="muted">暂无配置</p>
    </div>

    <div class="card" style="margin-top: 12px">
      <h3 style="font-size: 14px; margin-bottom: 8px">{{ form.id ? "编辑网关" : "新增网关" }}</h3>
      <div class="grid grid-3">
        <div class="field">
          <label>名称</label>
          <input v-model="form.name" />
        </div>
        <div class="field">
          <label>类型</label>
          <select v-model="form.provider">
            <option value="internal">内网推理服务</option>
            <option value="openai_compatible">外部 OpenAI 兼容 API</option>
          </select>
        </div>
        <div class="field">
          <label>模型名</label>
          <input v-model="form.model" placeholder="deepseek-r1-distill-qwen-14b-int4" />
        </div>
      </div>
      <div class="field">
        <label>服务地址</label>
        <input v-model="form.base_url" placeholder="http://vllm.inference.svc.cluster.local:8000" />
      </div>
      <div class="grid grid-3">
        <div class="field">
          <label>密钥环境变量名（引用）</label>
          <input v-model="form.api_key_ref" placeholder="INTERNAL_INFERENCE_API_KEY" />
        </div>
        <div class="field">
          <label>密钥值（仅在更新时填写）</label>
          <input v-model="form.api_key_value" type="password" placeholder="留空保持不变" />
        </div>
        <div class="field">
          <label>超时（秒）</label>
          <input v-model.number="form.timeout_seconds" type="number" />
        </div>
      </div>
      <div class="row">
        <label class="row" style="width: auto; gap: 4px">
          <input v-model="form.enabled" type="checkbox" style="width: auto" /><span style="font-size: 13px">启用</span>
        </label>
        <label class="row" style="width: auto; gap: 4px">
          <input v-model="form.is_default" type="checkbox" style="width: auto" /><span style="font-size: 13px">设为默认</span>
        </label>
        <label class="row" style="width: auto; gap: 4px">
          <input v-model="form.sanitize_before_send" type="checkbox" style="width: auto" />
          <span style="font-size: 13px">出网前强制脱敏</span>
        </label>
        <div class="spacer"></div>
        <button @click="save">保存配置</button>
      </div>
    </div>
  </div>
</template>
