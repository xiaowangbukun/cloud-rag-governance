<script setup lang="ts">
import { onMounted, ref, watch } from "vue";
import { api, query } from "@/api/client";

const props = defineProps<{ projectId?: string }>();

interface Diff {
  id: string;
  resource_name: string | null;
  diff_kind: string;
  classification: string;
  project_id: string;
}
interface AttributionResult {
  id: string;
  diff_id: string;
  project_id: string;
  task_id: string;
  cause: string;
  confidence: number;
  explanation: string;
  recommended_action: string;
  evidence_level: string;
  provider: string;
  model_name: string;
  citations: { index: number; text: string }[];
  blocked: boolean;
  created_at: string;
  security: Record<string, unknown>;
}

const diffs = ref<Diff[]>([]);
const selected = ref("");
const question = ref("");
const provider = ref("");
const result = ref<AttributionResult | null>(null);
const error = ref("");
const running = ref(false);

async function loadDiffs() {
  try {
    const q = query({ project_id: props.projectId, status: "open", limit: 50 });
    diffs.value = await api.get<Diff[]>(`/resources/diffs${q}`);
    if (diffs.value.length && !selected.value) selected.value = diffs.value[0].id;
  } catch (e) {
    error.value = (e as Error).message || "差异加载失败";
  }
}

async function run() {
  if (!selected.value) return;
  running.value = true;
  error.value = "";
  result.value = null;
  try {
    result.value = await api.post<AttributionResult>("/attribution/run", {
      diff_id: selected.value,
      question: question.value || undefined,
      provider: provider.value || undefined,
      top_k: 6,
    });
  } catch (e) {
    error.value = (e as Error).message || "归因失败";
  } finally {
    running.value = false;
  }
}

onMounted(loadDiffs);
watch(() => props.projectId, loadDiffs);
</script>

<template>
  <div>
    <h2>语义归因</h2>
    <p class="muted" style="font-size: 13px">
      安全顺序：授权校验 → 安全投影脱敏 → 受控检索 → 金丝雀扫描 → 出网白名单 → 模型调用 → 输出 DLP → 审计。
      每次分析使用独立任务上下文，禁止跨任务复用。
    </p>

    <div v-if="error" class="alert error">{{ error }}</div>

    <div class="card">
      <div class="grid grid-2">
        <div class="field">
          <label>选择差异</label>
          <select v-model="selected">
            <option v-for="d in diffs" :key="d.id" :value="d.id">
              {{ d.resource_name || d.id }} · {{ d.diff_kind }} · {{ d.classification }}
            </option>
          </select>
        </div>
        <div class="field">
          <label>模型提供方（留空使用默认）</label>
          <select v-model="provider">
            <option value="">默认配置</option>
            <option value="internal">内网推理</option>
            <option value="openai_compatible">外部 API（需白名单）</option>
          </select>
        </div>
      </div>
      <div class="field">
        <label>补充问题（可选）</label>
        <input v-model="question" placeholder="例如：这个资源释放是否属于计划内下线？" />
      </div>
      <button :disabled="running || !selected" @click="run">
        {{ running ? "分析中..." : "执行归因" }}
      </button>
    </div>

    <div v-if="result" class="card" style="margin-top: 12px">
      <div class="row" style="margin-bottom: 8px">
        <h3 style="font-size: 14px">{{ result.cause }}</h3>
        <span class="tag" :class="result.blocked ? 'danger' : 'ok'">
          {{ result.blocked ? "输出被拦截" : "通过安全检查" }}
        </span>
        <span class="tag muted">置信度 {{ (result.confidence * 100).toFixed(0) }}%</span>
        <span class="tag muted">{{ result.evidence_level }}</span>
        <span class="tag muted">{{ result.provider }} / {{ result.model_name }}</span>
        <div class="spacer"></div>
        <span class="mono muted">task {{ result.task_id }}</span>
      </div>

      <p style="white-space: pre-wrap">{{ result.explanation }}</p>
      <p v-if="result.recommended_action" class="muted">
        建议动作：{{ result.recommended_action }}
      </p>

      <div class="grid grid-2" style="margin-top: 10px">
        <div>
          <div class="muted" style="font-size: 12px">安全投影（进入模型上下文的脱敏摘要）</div>
          <pre class="mono" style="background:#fafbfc;padding:8px;border-radius:6px">{{ result.security?.projection }}</pre>
          <div class="muted" style="font-size: 12px">
            金丝雀扫描：{{ result.security?.canary_scanned ? "已启用" : "未启用" }} ·
            命中 {{ result.security?.canary_hits }} ·
            输出 DLP：{{ result.security?.output_dlp }} ·
            引用片段 {{ result.security?.hits }}
          </div>
        </div>
        <div>
          <div class="muted" style="font-size: 12px">引用证据</div>
          <ul style="margin: 4px 0; padding-left: 18px">
            <li v-for="c in result.citations" :key="c.index" style="font-size: 12px">{{ c.text }}</li>
            <li v-if="!result.citations?.length" class="muted" style="font-size: 12px">无引用</li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>
