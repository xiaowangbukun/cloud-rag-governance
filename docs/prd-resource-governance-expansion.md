# 增量 PRD：资源治理维度扩展（含 MLOps 与 AI Infra）

- 制定日期：2026-10-21
- 文档性质：**增量 PRD**——只描述相对现状的「变化部分」，不重写已有能力。
- 适用范围：在现有 `cloud-rag-governance`（内网多云资源治理 + 安全 RAG 归因平台）内，将治理对象从「主机 + 云主机」扩展到「含 MLOps 与 AI infra 的全域资源」，并将治理维度从「差异（diff）」扩展到「利用率 / 配额容量 / 成本归属 / 生命周期 / 合规基线 / 健康 SLA / 版本漂移」。
- 安全模型：**不可回退、且必须覆盖所有新增资源类型**。

---

## 1. 产品目标（一句话）

把平台从「比对昨天和今天资源有什么不同」升级为「**对数以万计的主机、GPU、训练作业、模型服务、数据集、向量库实例做持续纳管、合规基线与成本归属，并在越权/泄漏风险下安全支撑 AI infra 的检索归因**」。

差异化仍是**密级治理 + 审计 + 离线可部署**，不是再做一个 Kubeflow / 监控 / 成本平台。

---

## 2. 现状边界（复用，不重写）

| 复用项 | 说明 | 本 PRD 对它的增量 |
|---|---|---|
| 域模型 | `Project → CloudAccount → Resource(platform/kind/status/classification/monthly_cost_cny) → ResourceDiff(drift/new/deleted/cost_change) → Attribution` | 扩展 `kind` 枚举 + 新增资源专属属性通道 + 新增差异/告警类型 |
| 采集器 | 4 个真实 Provider（蓝鲸 CMDB / 青云 / 华为 / 腾讯）+ `simulated` 兜底 | 新增「AI infra 采集 Provider」组（见 §8） |
| 治理闭环 | 采集 → 差异计算 → 看板(board / cost-impact) → 人工处置(`/governance/diff/{id}/resolve`) | 新增差异/告警类型复用同一处置闭环；新增看板维度 |
| 安全模型 | L1–L4 密级、`ceiling_for=min(全局上限, 项目内上限)`、RBAC、拒绝类审计留痕、拼图防护、金丝雀、受控 RAG | **全部覆盖新增资源类型**（见 §6，硬约束） |
| 知识库能力 | 标题感知切块 / PDF / BM25+向量混合检索 / 出处字段（P1+P2 已交付，待接入） | 运维知识库天然成为「AI infra 排障 / 合规基线」的检索底座，本 PRD 不重复建设 |

---

## 3. 治理对象清单（新增 kind / 实体）

> 原则：新增对象**挂到现有 `Resource` 树下**（通过扩展 `kind` + 资源专属属性通道），不另起一套实体树；其 `classification` 一律走现有 `ceiling_for` 继承逻辑。

| # | 资源类型 | 建议 `kind` | 必管级 | 关键事实字段（示例） | 事实来源 |
|---|---|---|---|---|---|
| R1 | GPU 节点 / GPU 服务器 | `gpu_node` | **P0** | `gpu_model`(A100/H800…)、`total_gpus`、`allocated_gpus`、`utilization`、`driver_version`、`cuda_version`、`temperature` | K8s Device Plugin / DCGM / 厂商 API |
| R2 | GPU 集群 / 资源池 | `gpu_cluster` | **P0** | `total_gpus`、`free_gpus`、`mig_profiles`、`scheduler`(Volcano/Slurm) | K8s / 调度器 |
| R3 | 训练作业 | `training_job` | **P0** | `gpu_request`、`gpu_used`、`gpu_util_avg`、`status`(running/pending/completed)、`owner_team`、`duration_h`、`image`、`framework`(PyTorch/…) | Kubeflow / Ray / Volcano 标签 |
| R4 | 推理/模型服务端点 | `model_endpoint` | **P0** | `model_name`、`served_version`、`replicas`、`qps`、`p99_latency_ms`、`queue_len`、`source`(内部训练/外部下载)、`exposed`(出网?) | 推理网关 / K8s Service |
| R5 | 模型注册版本 | `model_version` | **P1** | `registry`(MLflow…)、`version`、`lineage_dataset`、`train_job_ref`、`approved`、`embedding_model_version`(若是嵌入模型) | MLflow / 模型仓库 |
| R6 | K8s 集群 / 命名空间 / Pod | `k8s_cluster`/`k8s_namespace`/`k8s_pod` | **P0** | `cpu_req/lim`、`mem_req/lim`、`phase`、`node`、`restart_count`、`owner_team` | K8s API |
| R7 | 数据集 | `dataset` | **P1** | `size_gb`、`lineage`、`contains_pii`、`classification`(可高于项目默认)、`owner_team`、`storage_backend` | 数据平台 / 对象存储清单 |
| R8 | 向量库实例 | `vector_db` | **P1** | `engine`(Milvus/PGVector…)、`index_count`、`dim`、`collection_count`、`storage_gb`、所属知识库分片 | 向量库 API / PG 目录 |
| R9 | Notebook / 交互式开发环境 | `notebook` | **P2** | `gpu_attached`、`idle_h`、`owner`、`image` | 平台 API |
| R10 | 主机 / 云主机（现状已有） | `host`/`vm` | 已有 | —— | 现有 4 Provider |

**必管（P0）**：R1、R2、R3、R4、R6 —— 这五类是「AI infra 治理刚需」，缺失即无法回答「我的 GPU 花在哪、训了什么、推理版本对不对、Pod 健不健康」。

**密级继承规则（强制）**：新增资源的 `classification` 默认取所属 `CloudAccount`/`Project` 的 `visible_ceiling` 下界；其中 R7 数据集允许**自带更高密级**（数据集本身可能含 L4），此时该数据集及其衍生（`model_version.lineage_dataset`、`vector_db` 若承载该数据集嵌入）上限被拉高到数据集密级。

---

## 4. 治理维度（除 diff 外的新增维度）

现有闭环只判「**差异**」（drift / new / deleted / cost_change）。本 PRD 新增以下判定维度，**每个维度都产出可被 `/governance/board` 展示、可被 `/governance/diff/{id}/resolve` 人工处置的对象**（复用现有处置闭环，不新建处置流程）。

| # | 维度 | 判定（judge） | 处置（dispose） | 级别 |
|---|---|---|---|---|
| D1 | 利用率 / 浪费 | GPU 节点 `utilization < 阈值(如10%)` 且已分配；训练作业 `gpu_util_avg < 阈值` 且 `status=running`（僵尸/空转）；Pod `cpu_req` 长期远低于 `cpu_used` 浪费 | 看板标红 + 治理项「闲置 GPU / 空转作业」→ 人工回收/缩容建议 | **P0** |
| D2 | 配额容量 | `gpu_cluster.free_gpus` 低于水位；**MIG 分区碎片化/未对齐**；`training_job` `pending` 超 N 分钟（抢不到卡/被抢占）；命名空间配额将满 | 容量预警 + 治理项「配额紧张」 | **P0** |
| D3 | 成本归属 | 按 `training_job`/`model_endpoint`/`gpu_node` 归属 `owner_team` 核算 GPU·小时；闲量成本 = 已分配未利用部分；训练 vs 推理成本拆分 | 看板「成本归属」+ 治理项「高闲置成本团队」 | **P1** |
| D4 | 生命周期 | 训练作业 `completed` 超 N 天未清理；Notebook `idle_h` 超阈值；向量库索引长期零命中 | 治理项「待回收资源」 | **P1** |
| D5 | 合规基线 | 驱动/CUDA 版本不在允许清单；推理端点 `source=外部下载` 且未经审批；出网端点未走 `MODEL_GATEWAY_ALLOW_PUBLIC`；数据集 `contains_pii` 但未登记密级 | 治理项「合规偏离」→ 人工处置（下线/补审批） | **P0** |
| D6 | 健康 SLA | Pod `restart_count` 高、`phase!=Running`；推理端点 `p99_latency` / `queue_len` 超 SLO；向量库 `index_count` 突增/突降（指标噪声按「资源 + 指标」维度去重收敛，避免看板洪水） | 治理项「健康异常」 | **P1** |
| D7 | 版本漂移 | `model_endpoint.served_version` ≠ `model_version`(approved 最新)；嵌入模型 `embedding_model_version` 漂移导致向量库需重建 | 治理项「版本漂移」→ 人工对齐/回滚 | **P0** |
| D8 | 血缘 / 密级 | 数据集 → 模型 → 向量库 → 知识库分片的密级传播链；任一环密级登记缺失 | 治理项「密级断链」 | **P1** |

> 差异（diff）维度保留并扩展：现有 `ResourceDiff` 类型从 `{drift,new,deleted,cost_change}` 扩展为含 `{version_drift, compliance_violation, capacity_warning, lifecycle_expiry, health_anomaly}`（具体枚举名由架构师定），统一进入现有 board / resolve 闭环。

---

## 5. 用户故事（按角色）

### 5.1 平台管理员（L4，全部项目）
- US-1：在一个看板上同时看到「主机/VM 闲置」「GPU 空转」「Pod 异常」「推理版本漂移」「合规偏离」，按项目/团队下钻。
  - 验收：看板聚合 5 类资源、7 个维度；可按 `project_id` / `owner_team` 过滤；越权项目不出现。
- US-2：对任一治理项（含新增类型）点「处置」并留痕，处置动作写入审计。
  - 验收：新增类型的处置同样产生 `audit_log` + 拒绝类 `security_event`（若越权）。

### 5.2 资源治理岗（L3，全部项目）
- US-3：一键识别「空闲超过 7 天的 GPU 节点 / 空转训练作业」并生成回收建议清单。
  - 验收：D1 维度正确算出 `utilization` 与 `gpu_util_avg` 低于阈值的资源；清单导出不含负责人明文（沿用现有导出脱敏）。
- US-4：发现某推理端点「线上版本 ≠ 注册审批版本」即告警。
  - 验收：D7 漂移检出；告警带 `served_version` 与 `approved_version` 对比。

### 5.3 业务团队负责人（L3，仅本团队项目）
- US-5：看到本团队 GPU·小时消耗与闲置成本拆分，定位「花了钱没用上」的作业。
  - 验收：D3 成本归属按 `owner_team` 正确分摊；只读本项目数据。
- US-6：提交训练作业前已知当前集群剩余配额，避免盲目提交后 `pending` 卡死。
  - 验收：D2 容量水位实时反映 `free_gpus`。

### 5.4 ML 工程师（L2–L3）
- US-7：查询「我的 Pod 为什么一直 Pending / 重启」得到带章节出处的运维知识回答。
  - 验收：知识库（P1+P2）检索返回 `document_title + section_path + page_no`；越权分片不进入召回。
- US-8：知道所用数据集/模型的密级，避免把 L4 数据集误接入出网端点。
  - 验收：D5/D8 在端点 `source=外部` 或数据集密级断链时告警。

### 5.5 运维 / SRE（L3）
- US-9：监控（可观测性）维度把「Pod 重启风暴 / 推理延迟劣化 / 向量库规模突变」汇总到治理看板，而非散落多个系统。
  - 验收：D6 健康 SLA 从 Prometheus/DCGM 拉取的指标正确落入治理项。

---

## 6. 安全模型扩展（硬约束，不可回退）★

**这是本 PRD 的最高优先级约束，任何实现都不得破坏。**

1. **密级继承全面覆盖**：所有新增 `kind`（R1–R9）的 `classification` 一律走现有 `ceiling_for = min(全局上限, 项目内上限)`；R7 数据集允许自带更高密级并向上传播（见 §3）。**不允许**任何新增资源「不继承、默认无密级」。
2. **授权预过滤不变式保持**：所有针对新增资源的列表/检索/归因，**必须先做授权预过滤（SQL 下推密级 + 项目范围），再召回/排序**。受控 RAG 的「先授权再召回」铁律覆盖知识库与归因链路，新增 AI infra 事实进入向量库前同样过净化层；L4 原始事实禁止向量化。
3. **拒绝类审计留痕覆盖**：对新增资源的所有治理/读取/处置接口的越权拒绝，必须产生独立事务的 `denied`/`failed` 审计（沿用 P0 修复的 `assert_capability` 增强）。新增端点（如 `/governance/ai/*`、`/resources/ai/*`）必须纳入 10 端点拒绝审计清单的回归守护。
4. **拼图防护覆盖**：跨查询累积视图（jigsaw）必须统计新增资源类型的分片（GPU 拓扑、训练作业归属、模型来源、数据集密级）。「A 团队的 GPU 拓扑 + B 团队的训练作业清单 + C 团队的数据集密级」同样构成高于授权的画像，须触发降密/拒绝。检索账本（`retrieval_ledger`）落地逻辑不变。
5. **金丝雀覆盖**：每个项目的诱饵数据须包含新增资源类型的伪装条目（伪装 GPU 节点、伪装模型端点、伪装数据集）。任何环节命中即 `critical` 安全事件并清空结果。
6. **出网合规（D5）**：推理端点若 `exposed=true` 或 `source=外部下载`，必须复用现有 `MODEL_GATEWAY_ALLOW_PUBLIC` 白名单 + 出网前 DLP + 提示词注入检测；外部模型来源未审批一律在配置/登记阶段拒绝。
7. **导出脱敏**：新增治理项的导出沿用现有「行数 + 频次双重限制，导出不含负责人与项目内部信息」；AI infra 导出自带 `owner_team` 但脱敏个人。

> 实现注意：上述不变式已由现有 `security/policy.py`、`services/access.py`、`ai/retrieval.py`、`security/jigsaw.py`、`security/canary.py`、`audit/service.py` 承载。扩展时**只增分支、不改用例**，并确保现有 138（SQLite）/136+2skip（PG）回归全绿不被破坏。

---

## 7. 需求池（P0 / P1 / P2，含「不做会怎样」）

### P0（上线必做）
| ID | 需求 | 不做会怎样 |
|---|---|---|
| P0-E1 | 扩展 `Resource.kind` 枚举 + 资源专属属性通道（建议 `resource_attrs` JSON 列或类型分表），落地 R1/R2/R3/R4/R6 五类 P0 对象 | 无法纳管 GPU/训练/推理/K8s，扩维度名存实亡 |
| P0-E2 | 新增「AI infra 采集 Provider」组（K8s / 模型注册 / 向量库 / 指标源），含 `simulated` 兜底 | 无事实来源，看板全空 |
| P0-E3 | 实现 D1（利用率/浪费）、D2（配额容量）、D5（合规基线）、D7（版本漂移）四个 P0 维度的判定 + 治理项生成，接入现有 board/resolve 闭环 | 核心治理价值缺失 |
| P0-E4 | §6 安全扩展全部落地 + 新增端点纳入拒绝审计回归守护 | 新增资源成为越权/泄漏突破口，安全模型开倒车 |
| P0-E5 | `model_endpoint` 与 `model_version` 的「线上 vs 审批版本」对账（D7 的数据基础） | 推理漂移检测无数据 |
| P0-E6 | 看板新增 AI infra 聚合视图（按项目/团队下钻） | 治理岗无法一眼看到全域风险 |

### P1
| ID | 需求 | 不做会怎样 |
|---|---|---|
| P1-E1 | D3 成本归属（GPU·小时按团队分摊、闲置成本、训练/推理拆分） | 成本黑洞，无法追责到团队 |
| P1-E2 | D4 生命周期（作业/Notebook/索引待回收） | 僵尸资源持续占用 |
| P1-E3 | D6 健康 SLA（Pod 重启、推理延迟、向量库规模突变）接入监控源 | 健康风险散落多系统 |
| P1-E4 | R5 模型注册版本、R7 数据集、R8 向量库实例纳管 + 血缘/密级链（D8） | 模型/数据/向量库成治理盲区 |
| P1-E5 | R7 数据集自带密级向上传播落地 | L4 数据集被低密级链路泄露 |

### P2
| ID | 需求 | 不做会怎样 |
|---|---|---|
| P2-E1 | R9 Notebook 纳管与闲置回收 | 交互式环境闲置浪费（影响较小） |
| P2-E2 | 成本预算与超预算自动告警（基于 D3；**是否升 P1 待 §9#4 单价口径确认后定**） | 预算失控只能事后发现 |
| P2-E3 | 向量库分片生命周期与知识库对账（R8 深化） | 知识库分片膨胀无管控 |

---

## 8. 采集接入（增量设计）

新增一组「AI infra Provider」，**与现有 4 个云 Provider 平级**，统一走 `Collector` 接口，产出 `Resource` 记录（带新 `kind`）。

| Provider | 产出 kind | 事实获取 | 兜底 |
|---|---|---|---|
| `k8s` | `gpu_node`/`gpu_cluster`/`k8s_cluster`/`k8s_namespace`/`k8s_pod`/`training_job`/`notebook` | K8s API（Node/GPU 标签、Pod、Job/SparkApplication 标签）+ 可选 DCGM exporter | `simulated` 同风格兜底 |
| `model_registry` | `model_version`/`model_endpoint` | MLflow API / 推理网关列表 | 兜底返回空 + 标记 `unmanaged` |
| `vector_db` | `vector_db` | Milvus/PGVector 目录查询 | 仅 PGVector 参考实现 |
| `metrics` | 指标（利用率/延迟/重启） | Prometheus 查询（或 DCGM），**只消费不部署采集器** | 指标缺失时维度判 `unknown` 而非误判 |

> 指标源只**消费**已有 Prometheus/DCGM，**不部署任何采集 agent**（见 §10 排除项）。

---

## 9. 待确认问题（开放项，需客户/用户回答）

1. 客户实际用哪些 ML 平台？Kubeflow / MLflow / Ray / Volcano / Slurm？决定 `k8s` provider 与 `training_job` 标签约定。
2. GPU 厂商与型号清单？决定 `gpu_model` 枚举与驱动/CUDA 合规基线（D5）的允许清单。
3. 是否已有 Prometheus / DCGM exporter 可直连？指标源地址与鉴权方式。
4. 成本单价口径：GPU·小时单价如何定（按卡型号？按集群？），闲置成本是否计入团队账单。
5. 模型来源策略：外部下载模型是否允许、走什么审批流（直接影响 D5 出网合规）。
6. 数据集密级是否由数据平台直接提供，还是本平台登记（影响 D8 血缘链起点的可信度）。
7. 向量库实际选型（Milvus / PGVector / 其他），决定 `vector_db` provider 实现范围。
8. 现有 4 个云 Provider 采集的数据，是否需要与 AI infra 资源做「同一物理机既跑 VM 又跑 GPU 作业」的关联（影响成本归属准确性）。
9. 客户是否**已有类似「分站点采集 → TiDB 存储 → Gate/API → Front」的 FinOps/监控平台**（含 CMDB、多站点 Zabbix、GPU·NPU 采集）？若有：其 Zabbix/TiDB 数据能否直接作为本平台 `metrics`/成本维度的**数据源**（我们只消费、不重复部署采集），成本归属是否以其账单口径为准——这决定 P0-E2 的 metrics provider 是对接 Prometheus/DCGM 还是对接既有 FinOps 库。

---

## 10. 排除项（显式声明，非静默跳过）

| 项 | 原因 / 边界 |
|---|---|
| **不替换 GPU 调度器 / 训练框架**（Kubeflow/Volcano/Ray/Slurm） | 本平台只**治理**，不接管调度；只消费其状态，不下发调度指令 |
| **不做模型训练 / 微调** | 仅做检索增强与治理；沿用现有 BGE 系列，不训练 |
| **不部署监控采集 agent / 通用 APM** | 监控维度只**消费**已有 Prometheus/DCGM，不部署 node-exporter/采集器；不做通用 APM 产品 |
| **不做自动缩容 / 自动驱逐** | 保持现有「告警 + 人工处置(`/resolve`)」闭环；自动动作风险高、责任边界不清 |
| **不接管向量库 / 数据库运维** | 只治理实例台账与规模（`index_count`/`storage_gb`），不接管 Milvus/PGVector 的运维操作 |
| **不做多租户 SaaS 化** | 沿用现有 L1–L4 + RBAC + 项目成员关系；不扩张权限模型 |
| **不做通用成本平台**（FinOps 全功能） | 只做与治理强相关的「GPU·小时归属 + 闲置成本 + 预算告警」，不做发票/计费 |
| **不重复建设知识库** | 切块/PDF/BM25/混合检索已交付（P1+P2），本 PRD 仅将其定位为 AI infra 排障/合规的检索底座 |

---

## 11. 验收主线（端到端，供架构师拆任务、QA 设计用例参考）

1. **纳管**：`POST /collection/run`（AI infra provider）后，`GET /resources` 能看到 R1–R6 五类 P0 资源，且 `classification` 正确继承项目 ceiling。
2. **判定**：构造「GPU 利用率 5% 的已分配节点」「pending 2 小时的训练作业」「线上版本≠审批版本的端点」「外部下载且未审批的端点」，`GET /governance/board` 分别出现 D1/D2/D7/D5 治理项。
3. **处置**：对上述治理项 `POST /governance/diff/{id}/resolve`，产生 `audit_log`；越权用户操作产生 `denied` 审计。
4. **安全**：低密级用户看不到高密级项目的新增资源；拼图防护对跨项目累积 GPU 拓扑/数据集密级生效；金丝雀在新增类型命中即 `critical`。
5. **检索**：`POST /knowledge/search` 查「Pod Pending 排查」返回带 `section_path`/`page_no` 的出处，且越权分片不进入召回。
6. **回归**：现有 138（SQLite）/136+2skip（PG）全绿不被破坏；新增拒绝审计端点纳入 10 端点守护的扩展回归。

> 基线说明：`138 / 136+2skip` 为**当前已验证**计数（含 demo 种子 PG 移植 M5 与知识库 P1+P2 模块交付后），非预测值；`fix-plan.md` 中早期的 66/74 为 M1/M3 里程碑的历史记录，不代表现状。

---

## 12. 给架构师的任务输入（下一棒）

- 域模型增量：`Resource.kind` 枚举扩展 + `resource_attrs` 通道（JSON 列 vs 类型分表的取舍）；`ResourceDiff` 类型枚举扩展（+version_drift/compliance_violation/capacity_warning/lifecycle_expiry/health_anomaly）。
- 判定引擎：把 D1–D8 做成可插拔的「治理规则」，复用现有 diff 计算与 board/resolve 闭环，避免每维度一套流程。
- 采集层：`Collector` 接口新增 AI infra provider 组，给出 `simulated` 兜底契约。
- 安全：列出所有新增端点，逐条挂接到现有 `policy.py`/`access.py`/`audit`/`jigsaw`/`canary` 的扩展点。
- 给出 P0/P1/P2 的任务分解与依赖顺序（建议 P0-E1→E2→E4→E3→E5→E6）。
