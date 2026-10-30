# 同类项目对比与改进建议（2026-10）

> 目的：找出 GitHub 上与本项目功能重叠的项目，判断我们的相对位置，并把差距转成可落地的改进项。
> 观测方式：GitHub 仓库/代码检索 API，2026-10-28 快照。**star 数只是生态位置的参考，不代表质量**，会随时间变化。

## 1. 检索范围与结论先行

按五条线检索：RAG 平台、LLM 安全防护、数据治理目录、关系授权引擎、PG 备份工具。

**没有找到与本项目同构的项目。** 最接近的是两个方向：Onyx（权限随源系统同步的企业检索）与 RAGFlow（检索质量与文档理解）。其余项目各占我们能力的一部分：

| 类别 | 代表项目 | star（2026-10-28） | 与本项目重叠 | 明显不同 |
|---|---|---|---|---|
| 企业 RAG / 上下文层 | [onyx-dot-app/onyx](https://github.com/onyx-dot-app/onyx) | 33,044 | 权限过滤、SSO/SCIM、查询历史审计 | 权限来自源系统连接器；前端与多端接入完整 |
| RAG 引擎 | [infiniflow/ragflow](https://github.com/infiniflow/ragflow) | 93,002 | 检索、切块、Agentic RAG | 重文档理解（DeepDoc/OCR）；治理不是卖点 |
| 低代码 AI 应用 | [langgenius/dify](https://github.com/langgenius/dify) | 159,789 | RAG 管线、编排 | 面向应用搭建；无密级/拼图类治理 |
| 本地优先知识库 | [Mintplex-Labs/anything-llm](https://github.com/Mintplex-Labs/anything-llm) | 67,666 | 文档问答、多模型 | 桌面/单机形态；无细粒度授权 |
| 数据治理目录 | [open-metadata/OpenMetadata](https://github.com/open-metadata/OpenMetadata) / [datahub-project/datahub](https://github.com/datahub-project/datahub) | 15,608 / 12,908 | 元数据、血缘、治理流程 | 管"数据资产"不管"检索越权" |
| LLM 护栏 | [guardrails-ai/guardrails](https://github.com/guardrails-ai/guardrails) / [NVIDIA-NeMo/Guardrails](https://github.com/NVIDIA-NeMo/Guardrails) | 7,565 / 7,384 | 输入输出校验、注入检测 | 无数据侧授权模型 |
| LLM 安全工具箱 | [protectai/llm-guard](https://github.com/protectai/llm-guard) | 3,219（**已 archived**） | PII/注入/敏感内容扫描 | 已停更，不可作为长期依赖 |
| PII 识别 | [data-privacy-stack/presidio](https://github.com/data-privacy-stack/presidio)（原 microsoft/presidio） | 11,553 | 实体识别与脱敏（analyzer / anonymizer / image-redactor / structured） | 无检索侧集成 |
| 金丝雀 | [thinkst/canarytokens](https://github.com/thinkst/canarytokens) | 2,234 | 泄漏诱饵 | 面向网络/文件诱饵，不面向模型输出 |
| 关系授权 | [openfga/openfga](https://github.com/openfga/openfga) | 6,050 | 细粒度授权（ReBAC） | 需引入第二套授权事实源 |
| PG 备份 | [pgbackrest/pgbackrest](https://github.com/pgbackrest/pgbackrest) / [wal-g/wal-g](https://github.com/wal-g/wal-g) | 4,462 / 4,321 | 备份/恢复 | 只解决备份本体，不含密钥分离/演练留痕 |
| RAG 评测 | [langfuse/langfuse](https://github.com/langfuse/langfuse) / [onyx EnterpriseRAG-Bench](https://github.com/onyx-dot-app/EnterpriseRAG-Bench) | 36,630 / 607 | 观测与评测 | 独立平台，未与治理策略联动 |
| 权限泄漏实验 | [habib-analyst/vaultsearch](https://github.com/habib-analyst/vaultsearch) | 0（新仓，2026-10-23） | RLS vs 应用层过滤的实测对比 | 是实验/示例，不是产品 |

## 2. 能力矩阵

图例：✅ 有且是核心 / ➖ 有但粗粒度或需自建 / ❌ 无。

| 维度 | 本项目 | Onyx | RAGFlow | Dify/AnythingLLM | OpenMetadata/DataHub | Guardrails 系 | pgBackRest |
|---|---|---|---|---|---|---|---|
| 密级分级 + 项目双层上限 | ✅ | ➖ | ➖ | ❌ | ➖ | ❌ | ❌ |
| 检索**前**授权过滤（SQL 下推） | ✅ | ➖ | ➖ | ❌ | ❌ | ❌ | ❌ |
| 行级安全（RLS 兜底） | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| 拼图/马赛克防护（覆盖率、维度共现） | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| 出网金丝雀检测 | ✅ | ❌ | ❌ | ❌ | ❌ | ➖ | ❌ |
| 提示注入拦截（入库 + 出网） | ✅ | ➖ | ➖ | ❌ | ❌ | ✅ | ❌ |
| 输出 DLP / 实体掩码 | ✅（规则） | ➖（自定义钩子） | ❌ | ❌ | ❌ | ✅（组件） | ❌ |
| 只追加审计 + 安全事件 | ✅ | ➖（查询历史） | ➖ | ❌ | ✅（活动流） | ❌ | ❌ |
| 查询预算 / 枚举意图识别 | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| 保留策略与自动清理 | ✅ | ➖ | ➖ | ❌ | ➖ | ❌ | ➖（策略） |
| 备份 + WORM + 密钥分离 + 演练留痕 | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ➖（仅备份） |
| 检索评测基线 | ❌ | ✅（Bench 仓） | ➖ | ❌ | ❌ | ❌ | ❌ |
| 连接器权限同步（源系统吊销） | ❌ | ✅ | ➖ | ❌ | ➖ | ❌ | ❌ |
| 模型出网主机白名单 | ✅ | ➖ | ❌ | ➖ | ❌ | ❌ | ❌ |
| 多副本运行期状态一致性 | ✅（落库） | ➖ | ➖ | ❌ | ➖ | ❌ | ❌ |
| MCP / SDK 接入面 | ❌（仅 REST） | ✅ | ✅ | ✅ | ✅ | ➖ | ❌ |

说明：「行级安全（RLS 兜底）」一行只统计**数据库原生 RLS 作为第二道防线**，不含各项目自己的应用层权限系统；除 vaultsearch 明示使用 RLS 外，其余项目的该格依据是其公开文档与 README，未逐一读源码验证。

## 3. 我们的优势（有代码证据）

1. **治理在检索主路径里，不是外挂**：`SecureRetriever` 先按项目/密级下推 SQL 再排序（`packages/contracts/src/rg_contracts/ai/retrieval.py`），不存在"先召回后裁剪"的旁路。Onyx 的权限靠源系统元数据同步，RAGFlow 是知识库/租户级——两者都不做"密级 × 项目"双重上限。
2. **拼图防护是真正的差异化**：`security/jigsaw.py` 同时用「窗口内唯一分片数 / 覆盖率 / 敏感维度共现数」判定，并按 coarsen/deny 处置。旁证：在 GitHub 检索 `"mosaic attack"` 只命中 2 个仓库（一个 0 star 的 LoRA 研究仓、一个 1 star 的课程作业），都不是产品级 RAG 防护；按 prompt injection 检索到的仓库绝大多数是输入侧检测或资料汇总。
3. **金丝雀闭环到输出**：`security/canary.py` + `SECURITY_JIGSAW_SILENT` 静默模式，命中即拦且不回显风险细节。canarytokens 面向文件/网络诱饵，不做模型输出扫描。
4. **审计不可篡改的接口面**：`audit/service.py` 只暴露 `record / security_event / query / security_events` 四个方法，没有 update/delete；拒绝额外产生安全事件（威胁模型 T14）。
5. **备份是完整合规链**：WORM `COMPLIANCE` + X25519 密钥分离 + 每周演练 Job + 备份/演练审计（`apps/api/src/rg_api/backup.py`、`deploy/k8s/09~11`）。pgBackRest/WAL-G 只保证"能备份能恢复"，不解决"谁能在保留期内删除、私钥在哪、演练有没有做"。
6. **威胁模型是文档化资产**：`docs/threat-model.md` T1–T17 每条都有代码位置与测试名，可直接作为内审/等保材料；生态里极少有项目做到这个粒度。
7. **双方言测试 + 生产 fail-fast**：`RG_TEST_DIALECT=sqlite|postgresql` 全量 251 项，密钥占位符/弱值/SSLMODE 降级在启动即拒（`config.py`）。

## 4. 劣势与差距（含对比依据）

1. **没有行级安全（RLS）兜底**。授权完全在应用层：一次漏写 `where`、一个新加的聚合接口、一次 `select count(*)` 就是越权。
   旁证：`vaultsearch` 在 2026-10-23 发布，其仓库描述给出同一 schema 上的对抗测试结果——RLS 泄漏 0/16，应用层过滤泄漏 7/16，其中 10/10 外部文档能通过向量检索取出（habib-analyst）。这条实验直接对应我们当前的形态。
2. **没有检索质量与泄漏评测**。`RAG_HYBRID_ENABLED` 的注释写着"没有 recall 对照数据，无法证明收益"，于是混合检索停在关闭（`packages/contracts/src/rg_contracts/config.py` L172–179）。对比：onyx 有独立 Bench 仓、Langfuse 有评测平台。我们无法回答"改了召回会不会把不该给的分片给出去"。
3. **权限不随源系统吊销**。Onyx 在 README 中把权限随源数据同步、SSO（OIDC/SAML）、SCIM 目录同步与查询历史列为企业能力。我们的 `directory_sync_state` 只同步组织与人员，没有文档级 ACL 快照与吊销传播；员工调岗后已入库内容的可见性靠人工。
4. **PII/实体识别是自研规则**。Presidio 的识别器体系成熟；同时 `llm-guard` 已 archived——这提示"LLM 安全工具箱"这类中间层寿命短，我们的做法（自研 + 可选插件）反而更稳，但覆盖面不够。
5. **备份只到"每小时全量"**。pgBackRest 支持 incremental/delta + WAL 归档；我们 README 写了切换阈值（dump >5min 或库 >50GB），但代码里没有增量路径，也没有 PITR 演练。
6. **接入面窄**。只有 REST：没有 SDK、没有 MCP、没有 UI。2026 年 MCP 已成为标准分发口（Onyx、OpenMetadata、DataHub 都提供），我们缺这一层会降低被集成的概率。
7. **可观测性只有业务审计**。没有 trace/span 级数据（检索耗时、token 成本、命中 top-k 分布），排障与容量规划只能靠日志。

## 5. 改进建议

### P0（1–2 周，直接降低"被证明不安全"的风险）

**P0-1 PostgreSQL RLS 作为第二道防线**
- 做法：连接建立后 `SET LOCAL app.subject_id / app.project_ids / app.ceiling`，对 `resource / knowledge_chunk / knowledge_document / attribution` 建 `CREATE POLICY`；**保留**现有应用层过滤（两道，不替换）。
- 落地：`packages/contracts/src/rg_contracts/db/session.py`（会话变量）、`apps/api/src/rg_api/services/access.py`（策略装配）、迁移放进 `ensure_schema` 的 PG 分支。
- 验收：新增对抗用例 16 条（跨项目、跨密级、向量 top-k、`count(*)` 聚合、导出、差异详情），**全部 0 泄漏**；SQLite 走应用层过滤（skipif）。
- 已知交互：`pg_restore` 到演练库需超级用户（我们已满足），RLS 不会挡住备份/演练。

**P0-2 评测基线：把"我们说安全"变成"我们测过"**（已落地，实际口径见 `docs/eval.md`）
- 落地形态与本文最初的设想不同：评测是 `packages/contracts/src/rg_contracts/eval/` + 命令
  `python -m rg_api.eval`，题库 74 题（62 正向 / 12 越权），指标为
  `recall@3/8`、MRR、**未授权分片泄漏率**、拒答正确率，并按 `global` / `project`
  切片；语料 22 文档 / 54 分片（已不饱和）。
- 新增**决策级判定**：报告带机器可读的 `decision_grade.blockers`，`--require-decision-grade`
  下不达标退出码 4，把「没变差」与「数字可信」分成两个结论。
- 现状：安全闸门与基线回归在 CI 生效；`blockers` 只剩 `offline_embedding`
  （本机无真实 embedding 服务），因此**尚未**取得决策级数据，`RAG_HYBRID_ENABLED`
  仍不翻转。

### P1（1 个月）

3. **连接器 ACL 同步与吊销 TTL**：把 `directory_sync_state` 扩成 per-document ACL 快照；源不可达时 **fail-closed**（该源文档不可见），而不是沿用上次快照。
4. **PII 后端可切换**：`SECURITY_PII_BACKEND=regex|presidio`，默认 regex 保证离线可用；不替换现有 `security/dlp.py`。
5. **备份增量路径**：库 >50GB 或 dump >5min 时切 pgBackRest（对象存储 + 同样的 WORM 保留），演练 Job 复用不变；补一次 PITR 演练记录。

### P2（季度）

6. **只读 MCP server**：把 `board / cost-impact / audit` 包成 MCP 工具，复用同一套 policy；只读，不做写操作。
7. **OTel 导出**：audit 事件 + 检索 span → Langfuse/Phoenix（自建可选），补 trace 级盲区。
8. **SDK**：从 OpenAPI 生成 TS/Python 客户端，配合已有契约层做兼容性断言。

## 6. 明确不做（防止范围膨胀）

- **Dify 式低代码编排**：我们的价值是"受控检索 + 可证明"，编排会带来大量状态与权限缝隙。
- **RAGFlow 的 DeepDoc/OCR**：除非知识库确有扫描件；当前 `knowledge/pdf.py` 只取文本层是有意为之（无文本层直接判失败，不猜）。
- **AnythingLLM 的桌面形态**、**OpenMetadata 的全量元数据目录**：解决的不是我们的问题。
- **引入 OpenFGA**：ReBAC 引擎成熟，但会形成第二套授权事实源与同步成本；现有"项目 + 密级"两级模型用 RLS 兜底更划算。若将来出现"按文档授权给个人"的需求，再评估。

## 7. 结论

在"RAG 平台/检索质量"这条线上，我们比主流开源落后一代（没有 OCR/重排/评测/UI）。
在"治理与合规闭环"这条线上，我们比主流开源更完整——尤其拼图防护、出网金丝雀、WORM + 密钥分离 + 演练留痕、以及文档化的威胁模型，这些在本次检索的项目里都没有等价实现。

因此建议**不打正面仗**：把资源投在"可证明"上。P0 两项（RLS 兜底 + 泄漏评测基线）是把安全声明从"设计如此"升级为"测得如此"的最小投入，也正好补上对比中最刺眼的两格 ❌。

## 8. 参考来源（MLA）

检索方式：GitHub REST 搜索 API（仓库检索与代码检索），快照时间 2026-10-28。以下条目按 MLA 第 9 版格式著录，访问日期统一为 2026-10-28。

- habib-analyst. "vaultsearch." *GitHub*, 23 Oct. 2026, github.com/habib-analyst/vaultsearch.
- Onyx. "Onyx." *GitHub*, github.com/onyx-dot-app/onyx.
- Onyx. "EnterpriseRAG-Bench." *GitHub*, github.com/onyx-dot-app/EnterpriseRAG-Bench.
- Infiniflow. "RAGFlow." *GitHub*, github.com/infiniflow/ragflow.
- LangGenius. "Dify." *GitHub*, github.com/langgenius/dify.
- Mintplex Labs. "AnythingLLM." *GitHub*, github.com/Mintplex-Labs/anything-llm.
- OpenMetadata. "OpenMetadata." *GitHub*, github.com/open-metadata/OpenMetadata.
- DataHub Project. "DataHub." *GitHub*, github.com/datahub-project/datahub.
- Guardrails AI. "Guardrails." *GitHub*, github.com/guardrails-ai/guardrails.
- NVIDIA. "NeMo Guardrails." *GitHub*, github.com/NVIDIA-NeMo/Guardrails.
- Protect AI. "LLM Guard." *GitHub*, github.com/protectai/llm-guard.
- Data Privacy Stack. "Presidio." *GitHub*, github.com/data-privacy-stack/presidio.
- Thinkst Applied Research. "Canarytokens." *GitHub*, github.com/thinkst/canarytokens.
- OpenFGA. "OpenFGA." *GitHub*, github.com/openfga/openfga.
- "pgBackRest." *GitHub*, github.com/pgbackrest/pgbackrest.
- "WAL-G." *GitHub*, github.com/wal-g/wal-g.
- Langfuse. "Langfuse." *GitHub*, github.com/langfuse/langfuse.

本项目内部引用均为仓库内文件路径（`packages/contracts/src/rg_contracts/**`、`apps/api/src/rg_api/**`、`deploy/k8s/**`、`docs/threat-model.md`），不另列条目。
