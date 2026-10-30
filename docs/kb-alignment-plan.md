# 知识库能力对齐方案（面向信创运维知识库 MVP 的差距补齐）

- 制定日期：2026-10-18
- 制定依据：《信创运维大模型知识库 MVP》需求 spec 与现有 `cloud-rag-governance` 的逐项差距核对
- 适用范围：**在现有 Python 工程内补齐知识库能力**。不切换技术栈（Java/Spring 是该新项目的选型，不是本项目的改造目标），不改变已有安全模型。

---

## 1. 定位调整（一句话）

现有项目从"**多云资源治理 + 安全 RAG 归因**"扩展为"**带密级治理能力的运维知识库**"：保留治理闭环与安全防线，补齐"文档→切块→混合检索→带出处回答"这条知识库主链路的**完整度与质量**。

边界不变：
- 不做通用 RAG 平台，不做多租户 SaaS，不与 Dify/RAGFlow 对标功能完整度。
- 差异化仍是**密级治理 + 审计 + 离线可部署**，而不是 RAG 本身。

---

## 2. 差距矩阵

| # | 能力 | 现状（已核实） | 目标 | 阶段 |
|---|---|---|---|---|
| 1 | Markdown 摄取 | 仅接受 JSON 里的文本字符串 | 文件级摄取，保留标题结构 | P1 |
| 2 | 文本型 PDF 摄取 | **无任何 PDF 解析** | `pypdf` 抽取文本 + 页码；扫描件显式拒绝 | P1 |
| 3 | 标题感知切块 | `_split` 按分号 + 260 字符机械切 | 按 Markdown 标题层级分节，节内按段落/句子聚包 | P1 |
| 4 | 出处粒度 | `KnowledgeChunk` 只有 `ordinal` | 增加 `section_path` / `page_no`，回答带"文档+章节+页码" | P1 |
| 5 | BM25 关键词检索 | **无**（全仓无 bm25/tsvector） | 应用层 BM25（中文 bigram），与向量融合 | P2 |
| 6 | 混合检索 + 重排 | 纯向量（pgvector `<=>` 下推） | RRF 融合 + 可插拔 Reranker（默认融合，HTTP 重排可选） | P2 |
| 7 | StoragePort 抽象 | SQLAlchemy + 自定义 `Vector` 类型，pgvector 与业务耦合 | 独立端口接口 + pgvector 参考实现 | P3 |
| 8 | CLI | 仅 `scripts/` 运维脚本 | `rg ingest/search/ask/serve` 一等公民入口 | P3 |
| 9 | Apache 2.0 | **根目录无 LICENSE** | LICENSE + README 许可章节 | P3 |
| 10 | 4C8G 离线演示 | docker-compose 是 SQLite 演示形态 | PG + 应用 + （可选）TEI 的离线 compose | P3 |
| 11 | 真实文档验收 | 演示种子（合成数据） | 领域示例语料 + 20 组问答的检索命中/引用正确率 | P4 |

---

## 3. 阶段一：摄取、切块与出处

### 3.1 数据模型（`packages/contracts/src/rg_contracts/db/models.py`）

`KnowledgeDocument` 增加：
- `source_type`：`md` / `pdf` / `text`（区分摄取通道）
- `source_path`：原始文件名（不含绝对路径，避免泄露目录结构）
- `page_count`：PDF 页数，其余为 0

`KnowledgeChunk` 增加：
- `section_path`：章节路径，如 `3 部署 > 3.2 数据库`（Markdown 由标题栈生成；PDF 由编号型标题启发式识别，识别不到则为 `None`）
- `page_no`：PDF 页码（从 1 起），Markdown 为 `None`
- `char_start` / `char_end`：在原文中的字符偏移，便于前端高亮定位

> 迁移说明：项目尚未引入 alembic，沿用 `create_all` + 幂等 `_migrate_*` 的做法；生产升级需手工 ALTER（写入 runbook，属 R7 治理项）。

### 3.2 切块算法（`packages/contracts/src/rg_contracts/knowledge/chunking.py`，新增）

1. **分节**：按 `^(#{1,6})\s+(.+)$` 识别标题，维护标题栈生成 `section_path`；代码块（``` 围栏）内的 `#` 不视为标题。
2. **节内聚包**：按空行切段落 → 按句末标点（`。！？；.!?`）切句 → 贪心装包到 `CHUNK_TARGET_CHARS`（默认 600），相邻块保留 `CHUNK_OVERLAP_CHARS`（默认 80）重叠。
3. **硬边界**：不跨章节；单句超 `CHUNK_MAX_CHARS`（默认 1200）时才硬切。
4. **PDF**：逐页抽取文本，按页切块并写 `page_no`；页内按段落聚包。**无文本层（扫描件）直接拒绝**，返回明确错误码 `scanned_pdf_unsupported`，不静默跳过。
5. **切块质量断言**（单测）：不产生空块；MD 块不跨章节；块首不落在句中标点；重叠区不重复计入 token 数。

### 3.3 摄取接口

- 新增 `POST /api/v1/knowledge/documents/upload`（multipart：`file` + `project_id` + `classification`），按扩展名判定 `source_type`；`python-multipart` 与 `pypdf` 已在运行环境，需写入 `pyproject.toml` 依赖。
- 保留原 JSON 文本接口（向后兼容）。
- 摄取链路顺序不变：**净化 → 切块 → 向量化 → 入库**；标题同样过 `sanitize_text`（P1-15 已修）。
- 新增 `GET /api/v1/knowledge/documents/{id}/chunks`（带密级校验），用于人工检查切块质量。

---

## 4. 阶段二：混合检索与重排

### 4.1 安全不变式（最高优先级，不得破坏）

```
授权预过滤（SQL，密级 + 项目范围）→ candidate_ids → 向量排序 / 关键词打分 → 融合 → top_k
```

- BM25 **只能**在 `candidate_ids` 集合内计算，绝不引入未授权分片；
- `unrestricted` 只放开项目范围，不放开密级（P0-5 已修，回归测试守护）；
- 融合后仍执行 `RAG_MIN_SCORE` 与金丝雀扫描、拼图防护、DLP，顺序不变。

### 4.2 BM25 实现（`packages/contracts/src/rg_contracts/ai/bm25.py`，新增）

不引入 `jieba`/`rank_bm25`（离线环境装包成本高、且分词器在信创库侧不可移植），自实现：
- 分词：ASCII 词（`[a-z0-9_.-]+`，保留错误码/配置键形态）+ 中文 **bigram**（无词典分词，避免 OOV）+ 单字兜底（短查询）。
- 打分：标准 BM25（`k1=1.5, b=0.75`），IDF 在授权候选集内统计；文档长度用 token 数。
- 复杂度控制：候选集上限 `RAG_CANDIDATE_LIMIT`（默认 500），超限时按向量分数截断后再算 BM25（需在响应元数据中标注 `keyword_scope=truncated`，避免误判召回）。

### 4.3 融合与重排

**已实现（与本节的原始设计有偏离，原因见下）**：线性 alpha 加权
`final = alpha * vector_norm + (1 - alpha) * bm25_norm`（`RAG_HYBRID_ALPHA`，默认 0.6），
两侧都归一化到 `[0,1]` 后加权；开关 `RAG_HYBRID_ENABLED` 默认关闭。

偏离原因（不做 RRF，也不保留 RRF 配置键）：
- 线性加权的分数尺度依赖归一化方式，而 `RAG_MIN_SCORE` 作用在**最终融合分**上，
  alpha 与阈值存在耦合（alpha=0.6 时对余弦的隐含下限是 `RAG_MIN_SCORE/alpha`）；
  RRF 只吃名次不吃分值，与现有阈值语义不兼容，硬套会让阈值含义含混。
- RRF 配置键（`RAG_HYBRID_VECTOR_WEIGHT` / `RAG_HYBRID_BM25_WEIGHT` / `RAG_RRF_K`）
  曾随本节写入 `config.py` 但**无任何代码消费**，已删除（删除前已全仓 grep 取证，
  含 `apps/web` / `.env*` / CI / deploy）。
- **RRF 作为后续选项保留在方案里**：等真实 embedding（BGE-M3）的 recall 对照数据
  出来再决定切换；切换时要同时重新定义阈值语义，不要只换融合公式。
- 可插拔 `Reranker` 接口（原计划的 `HttpReranker` 对接 TEI `/rerank`）**未实现**，
  `RAG_RERANK_ENABLED` 一并删除；需要时按本节重新引入，不要凭空加回空键。
- **已实现**：检索响应新增顶层 `retrieval` 元数据，当前含 `keyword_scope`（`truncated` / `full`，
  候选集被 `RAG_CANDIDATE_LIMIT` 或预取量截短时标 `truncated`，避免调用方误判"库里没有"）。
- **已实现**：每个命中新增 `vector_score` / `keyword_score` / `fused_score`。
  融合关闭时 `keyword_score` 与 `fused_score` 为 **`None`**（None = 通道未启用；
  不能用 0 冒充 —— 0 是合法分数，会让人误以为通道跑了但打了 0 分）。
- **已实现**：命中新增 `source` 字段 `{document_title, section_path, page_no, ordinal}`。
  `document_title` 出库前再净化一次（兜历史未脱敏标题）；`section_path` 优先取
  `knowledge_chunk.section_path` 列、回退 `metadata_json.section_path`；
  `page_no` 只有 PDF 摄取才有——**当前产品尚无 PDF 摄取路由**，故实际恒为 `None`。

---

## 5. 阶段三：抽象与工程

### 5.1 StoragePort（`packages/contracts/src/rg_contracts/storage/port.py`，新增）

```python
class StoragePort(Protocol):
    def ensure_schema(self) -> None: ...
    def authorized_candidate_ids(self, *, allowed_levels, allowed_project_ids, unrestricted, limit) -> list[str]: ...
    def fetch_chunks(self, ids) -> list[ChunkRecord]: ...
    def vector_rank(self, ids, query_vector, top_n) -> list[tuple[str, float]]: ...
    def keyword_scores(self, ids, query) -> dict[str, float]: ...
```

- `PgVectorStorage` 为参考实现；业务层（retriever/routes）只依赖端口。
- **必须保留**：授权过滤是端口的第一个动作，任何实现都不得先召回后过滤。
- 替换 openGauss/金仓/达梦时只需实现该端口；**本项目只交付 pgvector 实现 + 接口**，国产库适配需在客户环境实测（显式声明，不宣称已支持）。

### 5.2 CLI（`apps/cli`，新增）

`rg ingest <path> [--project] [--classification]` / `rg search "<q>"` / `rg ask "<q>"` / `rg serve`，argparse 实现（零新增依赖），`pyproject.toml` 声明 `[project.scripts] rg = "rg_cli.main:main"`。

### 5.3 许可与部署

- 根目录新增 `LICENSE`（Apache 2.0 全文）+ README 许可与"数据不出域"部署说明。
- `deploy/docker-compose.yml` 增加 PG + 应用（+ 可选 TEI）的离线形态；4C8G 参数写入注释（PG shared_buffers、应用堆、TEI 线程数）。

---

## 6. 阶段四：验收

- **语料**：`samples/ops-docs/`（**已交付 6 篇**自撰运维文档：K8s 排障、Nginx 502/504、PostgreSQL 备份 PITR、监控告警处置、网络排查、安全基线；每篇 212–310 行，共切出 115 块、中位 242–377 字），**非客户数据**，明确标注来源。行数按"真实命令 + 判定标准 + 处置步骤"的信息密度定，不迁就方案初稿的 80–150 行。
- **问答集**：`samples/ops-docs/README.md` 已预置 10 组 `question → 期望命中的 section_path`，P4 在该基础上扩到 20 组。
- **指标**：`recall@5 ≥ 0.8`；引用章节正确率 ≥ 0.8；切块边界人工抽查 20 块无跨章节/半句。
- **端到端**：`rg ingest samples/ops-docs` → `rg ask "Pod 一直 Pending 怎么排查"` → 输出带「文档名 + 章节」引用的回答。

---

## 7. 明确不做（显式声明，非静默跳过）

| 项 | 原因 |
|---|---|
| 扫描件/图片型 PDF、OCR | 需 OCR 引擎与额外模型，超出 4C8G 离线 MVP 预算 |
| 复杂表格高保真解析 | 需版面分析模型；Markdown 表格按纯文本处理 |
| 多租户 / 细粒度权限扩展 | 现有 L1–L4 + RBAC 已覆盖；不随本方案扩张 |
| 模型训练 / 微调 | 仅做检索增强，使用现成 BGE 系列模型 |
| openGauss/金仓/达梦的实际适配 | 只交付 StoragePort 接口 + pgvector 实现，国产库需客户环境实测 |
| 通用 RAG 平台功能（工作流编排、插件市场等） | 与定位不符 |

---

## 8. 风险与前置条件

1. **无 alembic**：本方案新增 6 个列，靠 `create_all` 覆盖新库；存量库升级需手工 ALTER（写入 runbook）。引入 alembic 属架构师清单 R7，建议在本阶段之前或同期完成。
2. **中文 BM25 无词典**：bigram 方案对"配置项名/错误码"命中好，对单字查询噪声大；验收集需覆盖两类查询。
3. **PDF 质量依赖文本层**：无文本层即拒绝，需在文档中明确告知用户。
4. **检索质量无真实客户语料**：先以领域示例语料验收，客户环境上线前需用其真实文档复测（列入交付验收项）。
5. **P2 的融合权重需要调参**：以验收集为基准，记录每组权重下的 recall@5，避免拍脑袋定值。
