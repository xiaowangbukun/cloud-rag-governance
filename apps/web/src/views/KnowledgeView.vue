<script setup lang="ts">
import { ref } from "vue";
import { api } from "@/api/client";

const props = defineProps<{ projectId?: string }>();

interface Hit {
  chunk_id: string;
  document_id: string;
  project_id: string | null;
  classification: string;
  score: number;
  text: string;
}

const queryText = ref("资源新增需要核对什么");
const hits = ref<Hit[]>([]);
const security = ref<Record<string, unknown> | null>(null);
const error = ref("");
const searching = ref(false);

const title = ref("");
const content = ref("");
const writeMsg = ref("");

async function search() {
  searching.value = true;
  error.value = "";
  hits.value = [];
  security.value = null;
  try {
    const data = await api.post<{ hits: Hit[]; security: Record<string, unknown> }>(
      "/knowledge/search",
      { query: queryText.value, project_id: props.projectId || null, top_k: 6 }
    );
    hits.value = data.hits;
    security.value = data.security;
  } catch (e) {
    error.value = (e as Error).message || "检索失败（可能被防枚举或权限策略拦截）";
  } finally {
    searching.value = false;
  }
}

async function createDoc() {
  error.value = "";
  writeMsg.value = "";
  try {
    const data = await api.post<{ id: string; chunks: number; vectorizable: boolean }>(
      "/knowledge/documents",
      { title: title.value, content: content.value, project_id: props.projectId || null }
    );
    writeMsg.value = `已写入并生成 ${data.chunks} 个净化分片（可向量化：${data.vectorizable}）`;
    title.value = "";
    content.value = "";
  } catch (e) {
    error.value = (e as Error).message || "写入失败";
  }
}
</script>

<template>
  <div>
    <h2>知识库检索</h2>
    <p class="muted" style="font-size: 13px">
      向量库只保存净化后的治理规则与脱敏案例；检索先按授权过滤候选分片，再计算相似度。
      L4 原始事实禁止向量化，全量枚举意图会被直接拒绝。
    </p>

    <div v-if="error" class="alert error">{{ error }}</div>
    <div v-if="writeMsg" class="alert ok">{{ writeMsg }}</div>

    <div class="card">
      <div class="row">
        <input v-model="queryText" placeholder="输入检索问题" style="flex: 1; min-width: 260px" />
        <button :disabled="searching" @click="search">{{ searching ? "检索中..." : "检索" }}</button>
      </div>

      <div v-if="hits.length" style="margin-top: 12px">
        <table>
          <thead><tr><th>相似度</th><th>密级</th><th>内容（已净化）</th></tr></thead>
          <tbody>
            <tr v-for="h in hits" :key="h.chunk_id">
              <td class="mono">{{ h.score.toFixed(3) }}</td>
              <td><span class="tag muted">{{ h.classification }}</span></td>
              <td>{{ h.text }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-else class="muted" style="margin-top: 10px">暂无命中结果</p>

      <div v-if="security" class="muted" style="margin-top: 10px; font-size: 12px">
        授权密级范围：{{ (security.allowed_levels as string[])?.join(", ") }} ·
        预过滤：{{ security.prefiltered ? "已启用" : "全局角色" }} ·
        金丝雀命中：{{ security.canary_hits }} ·
        本小时检索次数：{{ (security.budget as Record<string, number>)?.retrievals_last_hour }}
      </div>
    </div>

    <div class="card" style="margin-top: 12px">
      <h3 style="font-size: 14px; margin-bottom: 8px">写入治理规则（写入即脱敏）</h3>
      <div class="grid grid-2">
        <div class="field">
          <label>标题</label>
          <input v-model="title" placeholder="例如：测试环境资源保留期限规则" />
        </div>
      </div>
      <div class="field">
        <label>内容</label>
        <textarea v-model="content" placeholder="写入前会自动执行脱敏、泛化与注入检测" />
      </div>
      <button :disabled="!title || !content" @click="createDoc">写入知识库</button>
    </div>
  </div>
</template>
