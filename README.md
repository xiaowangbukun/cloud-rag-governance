# 内网多云资源治理与安全 RAG 归因平台

面向企业内网的**多云资源治理平台**：采集多云资源事实 → 生成差异 → 安全投影脱敏 → 受控 RAG 检索 → 模型归因 → 治理闭环 → 全链路审计。

核心设计约束：**数据分级与最小披露**。项目真实名称、负责人姓名、精确日期、精确金额、IP、账号、密钥、进度排期，一律不进入向量库与模型上下文。

---

## 一、快速开始（本地，零外部依赖）

```bash
# 后端
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e packages/contracts
pip install -e "apps/api[dev]"

# 启动（应用运行时默认 SQLite + 演示数据 + 离线向量降级；测试默认方言见第四节）
uvicorn rg_api.main:app --reload --port 8000

# 前端
cd apps/web && npm install && npm run dev            # http://localhost:5173
```

预置演示账号（写入种子数据）：

| 账号 | 密码 | 角色 | 密级上限 | 项目范围 |
|---|---|---|---|---|
| admin@corp.local | Admin@2026 | 平台管理员 | L4 | 全部 |
| governance@corp.local | Gov@2026 | 资源治理岗 | L3 | 全部 |
| pm@corp.local | Pm@2026 | 项目经理 | L3 | 仅核心承保 |
| auditor@corp.local | Audit@2026 | 审计员 | L3 | 仅理赔平台 |
| viewer@corp.local | View@2026 | 只读 | L2 | 无 |

预置 4 个项目（核心承保 L3 / 理赔服务 L3 / 代理人移动端 L2 / 数据中台 L4）、4 个云账号（蓝鲸、青云、华为云、腾讯云）、资源与快照、差异记录、净化知识库、模型网关配置。

健康检查：

| 端点 | 语义 | 失败时 |
|---|---|---|
| `GET /health` | 存活探针：只证明进程还在，不碰任何依赖 | —（依赖故障不重启进程） |
| `GET /ready` | 就绪探针：执行 `SELECT 1` | 数据库不可达返回 **503**，由 LB 摘流量 |
| `GET /metrics` | Prometheus 抓取：请求数 + 耗时直方图 | 关闭时 404；**不鉴权，只能经集群内网访问** |

安全事件查询（`GET /audit/security-events`）需要 `security:read` 能力位，且按项目授权收口：非全局角色只能看到自己已授权项目的事件（事件 `project_id` 为空表示全局事件，仅全局角色可见）。

---

## 二、按你的要求逐条落地

### 1. 模型服务：页面可配置 API 或调用内网推理

- 页面路径：**模型网关配置**（`/models`）— 新增/编辑/测试连接
- 两种 Provider：`internal`（内网推理服务，如 vLLM）与 `openai_compatible`（外部 OpenAI 兼容 API）
- 密钥**只保存环境变量引用名**（`api_key_ref`）与掩码，真实值从环境变量读取，不明文入库
- 外部主机受白名单约束：`MODEL_GATEWAY_ALLOW_PUBLIC=false` 时，公网主机在**保存配置阶段**即被拒绝（422），运行期调用前再校验一次
- 出网前强制：提示词注入检测 + 出网 DLP；模型返回内容同样过输出 DLP
- 模型不可用时**降级为规则归因**，治理链路不中断

### 2. 向量模型内置 BGE-M3

- 默认 `EMBEDDING_MODEL=BAAI/bge-m3`，通过 TEI（Text Embeddings Inference）服务提供，compose 与 K8s 清单均已内置
- `EMBEDDING_BACKEND=offline` 时使用**确定性哈希降级向量**：本地开发、离线演示、单元测试全部可跑，无需 GPU
- 生产只需把 `EMBEDDING_BACKEND=http` 并指向 `EMBEDDING_HTTP_URL`，其余代码路径不变

### 3. 部署：本地可开发测试，生产可上 K8s

```bash
# 本地全栈（API + Web + TEI）
docker compose -f deploy/docker-compose.yml up --build

# 生产 K8s
kubectl apply -f deploy/k8s/     # 命名空间 → 配置/密钥 → PostgreSQL(pgvector) → schema-init Job → TEI → API → Web/Ingress → NetworkPolicy → PDB → 每日保留任务(CronJob)
```

**部署顺序有一处硬依赖**：`12-schema-job.yaml`（建表 + RLS 策略 + 向量索引 + 建
运行角色 `rg_app`）必须在 API 之前完成。API 用只 DML 的 `rg_app` 连接且
`DB_MIGRATE_ON_STARTUP=false`，启动时只校验 schema；Job 没跑完，API 会以
「schema 未就绪，缺少 N 张表」直接退出，不会带空库继续服务。

K8s 清单要点：只读根文件系统 + 非 root + 丢弃全部 Capabilities、readiness/liveness 探针、HPA、默认拒绝入站的 NetworkPolicy（仅放通 Ingress→Web→API→TEI/PG）、API 的 PodDisruptionBudget（`minAvailable: 1`，节点 drain 时不会把两个副本同时摘掉）、每日 `retention` CronJob（`concurrencyPolicy: Forbid`，网络策略中显式放通它到 PostgreSQL）。

### 4. 接入 OIDC，预留公司统一身份校验接口

- OIDC：授权码模式 + JWKS 验签 + issuer/audience/exp 校验，角色从 `roles` claim、组织从 `org_id` claim 提取
- 目录服务（**预留**）：`DIRECTORY_MODE` 支持 `static` / `http` / `ldap`，统一接口 `DirectoryProvider` 负责拉取用户组织、部门与项目归属；管理页**系统管理 → 组织目录同步**可手动触发
- 接入方式：实现 `rg_contracts.auth` 中的目录接口，把 `DIRECTORY_MODE` 切到对应值即可，业务层无需改动

### 5. 第一版就是真实 API + 预置演示数据

所有接口均为真实 REST 接口（FastAPI），无 mock 桩：

| 分组 | 接口 |
|---|---|
| 认证 | `POST /auth/login`、`POST /auth/refresh`、`GET /auth/me`、`GET /auth/oidc/authorize`、`POST /auth/oidc/callback` |
| 资源 | `GET /resources/projects`、`GET /resources`、`GET /resources/stats`、`GET /resources/{id}`、`GET /resources/diffs`、`GET /resources/diffs/summary` |
| 采集 | `POST /collection/run`（支持 dry_run）、`GET /collection/snapshots` |
| 知识 | `POST /knowledge/documents`、`POST /knowledge/search`、`POST /knowledge/reindex`、`GET /knowledge/documents` |
| 归因 | `POST /attribution/run`、`GET /attribution/{id}`、`GET /attribution` |
| 治理 | `GET /governance/board`、`POST /governance/diff/{id}/resolve`、`GET /governance/cost-impact`、`GET /governance/export` |
| 审计 | `GET /audit/logs`、`GET /audit/security-events`、`GET /audit/budget` |
| 管理 | `GET /admin/config`、`GET|POST /admin/gateways`、`PATCH /admin/gateways/{id}`、`POST /admin/gateways/{id}/test`、`GET|POST /admin/directory/sync` |

统一前缀 `/api/v1`，统一错误结构 `{code, message, request_id}`，响应带 `X-Request-ID`。

### 6. 采集侧的两条口径：按账号隔离密钥、指标缺失不等于 0

**凭据引用。** 密钥不入库，`cloud_account.credential_ref` 只保存引用名。账号配了引用名时，
适配器只认 `{REF}_{NAME}` 这一种环境变量名（如 `credential_ref=qy-acc-01` 读
`QY_ACC_01_QY_ACCESS_KEY_ID`），**不回落**到全局名 —— 否则两个账号会静默共用同一份密钥，
而「按账号隔离」既不会被验证也不会报错。未配引用名的单账号部署沿用历史口径
（`QY_ACCESS_KEY_ID` 或 `QINGCLOUD_QY_ACCESS_KEY_ID`）。命名细则见 `.env.example`。

**指标。** 采集结果里的利用率数值走独立的 `resource_metric` 表（`(resource_id, metric_name)`
唯一，每轮 upsert 覆盖为最新值），不再塞进 `resource.attributes`，避免同一份数据存两处。
`NormalizedResource.metrics` 为空字典的含义是「这一轮没采到指标」，不是 0 —— 利用率为 0 是
合法观测值，缺失必须让判定层落到 `unknown`。布尔值、`NaN`、`inf` 一律丢弃并留
`collection_metric_invalid` 日志，静默丢弃会让「判定说缺数据、日志里查不到原因」重演。

---

## 三、安全模型（这是本项目的重点）

### 数据分级

`L1_PUBLIC < L2_INTERNAL < L3_CONFIDENTIAL < L4_SECRET`。用户有密级上限，项目成员关系可再下调（取二者较小值）。L4 原始事实**禁止向量化**，仅登记不切片。

### 安全投影（进入模型前必须过这一层）

1. 标识符令牌化：HMAC-SHA256 + 盐，跨文档一致但不可逆（`PRJ-xxxx`、`OWN-xxxx`）
2. 日期泛化到季度（`2026-08-12 → 2026Q3`）
3. 金额按单位折算后区间化（`128万元 → 千万元级`）
4. 负责人姓名默认整体隐去
5. 进度/计划类语义改写为治理语义（`上线时间…` → `治理事项`）
6. 手机号/邮箱/IP/MAC/域名/证件号掩码，凭据直接移除
7. 提示词注入拦截

### 受控 RAG

**先授权预过滤，再召回**——绝不做「先召回再过滤」。项目范围与密级下推到 SQL，越权分片根本没有机会进入排序。

### 行级安全（RLS 兜底，第二道防线）

应用层过滤漏写一个 `WHERE` 就等于越权，而且不报错、不进日志。因此同一条边界在
PostgreSQL 里再写一次：`resource` / `resource_diff` / `snapshot_state` /
`knowledge_document` / `knowledge_chunk` / `attribution` 六张表启用
`ENABLE + FORCE ROW LEVEL SECURITY`，策略读会话变量 `app.rls_*`（`SET LOCAL`
语义，事务结束失效）。

三条口径，改动时必须与应用层一起改：

| 情形 | 策略判定 |
|---|---|
| 未设上下文 | 一行都读不到（fail-closed），不是看全部 |
| 全局知识（`project_id IS NULL`） | 按用户总体密级以上限；无项目授权的只读岗靠它工作 |
| 项目内知识 | 按「用户上限 ∩ 项目上限」，脏密级按 L4 处理 |

- **降级**：`DB_RLS_ENABLED=false` 可关闭；SQLite 无 RLS 等价物，自动走应用层。
- **系统通道**：迁移/种子/保留/备份走 `session_scope()`（`app.rls_mode=system`）；
  HTTP 请求走 `db_session()`，初始作用域是「什么都没有」，认证成功才升级——
  于是新接口漏写认证依赖只会返回空结果，不会落到系统通道。
- **前置条件**：连接角色不能是 `SUPERUSER` / `BYPASSRLS`，否则策略被绕过。
  部署已按「属主 / 运行」拆分：`governance` 只在 `12-schema-job.yaml` 与备份、
  演练 Job 里使用（需要 DDL），API 用只 `SELECT/INSERT/UPDATE/DELETE` 的
  `rg_app`，密码也是独立键（`DB_APP_PASSWORD`）。上线后启动日志应出现
  `schema_verified` 与 `rls_enforced`，出现 `rls_ineffective_superuser_role`
  说明角色拆分没生效。步骤见 `docs/rls.md`。
- **验证**：`apps/api/tests/test_rls.py` 用临时 `NOSUPERUSER NOBYPASSRLS` 角色
  `SET ROLE` 后执行，断言「不设上下文 = 0 行」「不带 WHERE 的全表查询 = 授权过滤结果」。

### 检索评测基线

`python -m rg_api.eval` 跑 74 题金标准（62 道正向，其中 30 道在项目上下文里提问；
12 道越权），输出 `recall@3/8`、**未授权泄漏率**、**拒答正确率**，并按
`global` / `project` 切片统计。泄漏或拒答不达标 → 退出码 2；与
`docs/eval-baseline.json` 比对召回变差 → 退出码 3；`--require-decision-grade`
下报告自报数字不可信 → 退出码 4。CI 的 `eval-gate` 作业执行退出码 2/3 这两档。

当前基线（干净种子库 `rgeval`，2026-10-28，`report_version=2`）：

| 口径 | hybrid 关（默认） | hybrid 开 |
|---|---|---|
| recall@3 | 0.9355 | 0.9677 |
| recall@8 | 0.9677 | 0.9677 |
| MRR | 0.9065 | 0.9516 |
| 未授权泄漏率 | 0.0（0/552） | 0.0（0/552） |
| 拒答正确率 | 1.0（12/12） | 1.0（12/12） |
| 项目切片 recall@8 | 0.9333（30 题） | 0.9333（30 题） |

语料 22 文档 / 54 分片（项目内 48），已大于 `top_k×4=32` 的下限，**不再饱和**。

**这仍不是「效果很好」的证据**：`decision_grade.blockers` 只剩 `offline_embedding`
——本机没有真实 embedding 服务，离线降级向量的排序近似噪声。决策级召回数据必须在
`EMBEDDING_BACKEND=HTTP`（BGE-M3）环境重跑 `--write` 后产生，本仓库不宣称自己已有。
评测本身已把两处静默降级量化出来并修掉（全局知识被早退挡掉、被配额压到 2 条），
详见 `docs/eval.md`。

### 防拼图 / 防枚举

**单点策略挡不住拼图攻击**：攻击者不越权，只用合法权限反复发起小范围检索，把「A 项目成本 + B 项目拓扑 + C 项目负责人」等碎片拼出高于授权密级的全貌。每次查询单独看都合规，所以必须做**跨查询累积视图**。

第一层（单次查询内）：
- 时间跨度上限（`SECURITY_MAX_SPAN_DAYS`）
- 每小时查询预算（`SECURITY_QUERY_BUDGET_PER_HOUR`）
- 单项目召回分片数上限
- 枚举意图识别（`列出所有项目` 等）直接拒绝
- 导出受行数 + 频次双重限制，导出内容不含负责人与项目内部信息

第二层（跨查询累积，`security/jigsaw.py`）：
- **检索账本**：`retrieval_ledger` 表记录「谁在什么时间看过哪个分片」，多副本部署下必须落库（进程内计数不成立）
- **累积覆盖度**：窗口内同一项目已见唯一分片数 / 可见分片数，超过阈值即判定在系统性拼图
- **敏感维度共现**：身份 / 凭据 / 时间 / 规模 / 位置五个维度跨查询累加，达到组合数即判定「手里已有一张可拼装的画像」
- **入库侧切片规避扫描**：旧实现「先切片再逐片净化」会让跨片边界的敏感值（手机号、IP）在两个分片里都不完整从而绕过检测；已改为**先净化再切片**，并对「敏感值被切片切断」「必须跨分片重组才构成敏感画像」做扫描留痕
- **处置**（`SECURITY_JIGSAW_ACTION`）：`coarsen` 降密级返回（只保留少量片段，文本降级为治理语义摘要）/ `deny` 拒绝 / `none` 仅记录
- **静默模式**（`SECURITY_JIGSAW_SILENT`）：命中后风险只写 `security_event` 与审计，响应体不回显，避免攻击者据此调整策略；管理员可在审计页的安全事件里查看

归因链路同样接入：一次归因就是一次合法检索，最容易被用来反复累积分片。

### 金丝雀

每个项目预置唯一诱饵数据（编码、人名、里程碑、金额、机密备注）。任何环节（入库、检索、模型输出）命中即记为 `critical` 安全事件并清空结果。

### 审计

资源访问、检索、模型调用、策略判定、配置变更全部落库；拒绝动作额外产生安全事件。非全局角色只能查看自身范围内的审计记录。

### 数据保留与归档（策略先行，部分未实现）

保留策略必须先定口径再写清理代码——「无限增长」和「随手删证据」在合规上都是问题。下表是**目标策略**，其中「状态」列明确区分已实现与待实现，未实现的部分当前表现为只增不减，不要误以为已被自动清理：

| 数据 | 表 / 位置 | 目标保留 | 状态 |
|---|---|---|---|
| 检索账本（拼图防护） | `retrieval_ledger` | 7 天（`SECURITY_JIGSAW_RETENTION_DAYS`） | ✅ 检索时顺带清理 + 保留任务兜底（`security/jigsaw.py` / `rg_api.retention`） |
| OIDC 登录 state | `oidc_login_state` | 5 分钟（`OIDC_STATE_TTL_SECONDS`） | ✅ 登录时批量清理过期行 + 保留任务兜底（`routes/auth.py`） |
| 运行期滑动窗口计数 | `runtime_counter` | 24 小时（`RETENTION_RUNTIME_STATE_HOURS`） | ✅ 保留任务删除；写入侧另有 2% 概率的兜底清理 |
| 操作审计 | `audit_log` | 在线 180 天，之后冷归档（对象存储/MinIO） | ⏳ 保留任务**只统计超期行数**，不删除（口径待定） |
| 安全事件 | `security_event` | 在线 365 天（取证需要更长），归档后仍可查 | ⏳ 同上：只统计、不删除 |
| 资源采集快照 | `snapshot` / `snapshot_state` | 保留最近 12 个月；更早月份每月只保留成功基线快照的明细 | ✅ 保留任务按 (云账号, 月份) 保留最后一份成功快照的 `snapshot_state`；**快照主体永不删除**（`resource_diff` 依赖基线） |
| 知识文档与分片 | `knowledge_document` / `knowledge_chunk` | 随业务生命周期；删除即物理删（无软删） | ⚠️ 现状：物理删除，不可恢复，需先备份 |
| 导出文件 | 无落盘（接口即时返回 JSON） | 不保留 | ✅ 现状即策略 |

执行方式：`deploy/k8s/08-retention-cronjob.yaml` 每日 03:30 跑一次
`python -m rg_api.retention`（`concurrencyPolicy: Forbid`，不并发）；本地核对规模用
`python -m rg_api.retention --dry-run`，只统计候选行、不删除。每次执行结果写入
`audit_log`（`action=retention_run`），清理动作本身也要留痕。

两条仍待业务确认的口径（不要凭直觉写死）：

1. **审计与安全事件能否被「清理」**：取证要求下通常「只能归档不能删」。清理任务目前
   对这两张表只报告 `rows_older_than_target`（超出目标保留期的行数），一行都不删。
2. **快照删细则的追溯边界**：已按月保留基线快照的明细，因此「当时有哪些资源」仍可重放；
   但同月内的中间快照明细会被清理，无法还原到分钟级。

检查是否误删：`grep -rn "delete(AuditLog\|delete(SecurityEvent" apps packages` 应为空。

### 运行期状态与可观测性（多副本）

安全控制的状态必须与副本数无关。以下计数全部落在 `runtime_counter` 表，而不是进程内 dict：

| 计数域 | 用途 | 不落库的后果（`replicas: 2`） |
|---|---|---|
| `retrieval` | 每小时检索预算（`SECURITY_QUERY_BUDGET_PER_HOUR`） | 实际额度变成 2 倍 |
| `retrieval_project` | 10 分钟内触及的不同项目数（防枚举） | 跨项目探测要扫到 26 个项目才触发 |
| `retrieval_blocked` | 被拦截次数（审计与响应体用） | 计数只反映单个副本 |
| `export` | 每小时导出次数上限 | 实际额度变成 2 倍 |
| `login_failure` | 登录失败锁定（5 次 / 5 分钟） | 锁定阈值退化为「第 11 次失败」 |

两条实现约束：**写入独立事务并立即提交**（预算/登录失败都会抛异常回滚业务会话，
复用业务会话会让计数随回滚消失）；**滑动窗口非原子**（并发请求可能同时读到「未超限」，
尾部会多放几条，这是有意接受的边界，做严格互斥需要行锁、代价不匹配）。

可观测性：`GET /metrics` 输出 `rg_http_requests_total` 与
`rg_http_request_duration_seconds`（Prometheus 文本格式，无第三方客户端依赖）。

- 标签取**路由模板**（`/resources/{id}` 而不是 `/resources/r_123`），否则时序基数会爆炸；
  未匹配路由统一记 `path="unmatched"`。
- 指标中间件在最外层：`TrustedHost` 的 400、CORS 预检、未捕获的 500 都会计入。
- 进程内计数在这里是**正确**的（Prometheus 按 Pod 抓取后聚合），与上面的跨副本计数相反。
- 端点不做鉴权（抓取器通常不便携带凭据）：Ingress 只路由 `/api` 与 `/`，`/metrics` 不会
  暴露到集群外；默认拒绝入站的 NetworkPolicy 也已生效。启用抓取时需在 06-networkpolicy
  中放通监控命名空间（文件末尾有注释好的模板）。
- `RATE_LIMIT_PER_MINUTE` 目前**尚未接线**：全局请求限速建议在 Ingress 层用
  `limit-rps` 注解实现，进程内限速在多副本下同样会被放大。

### 备份与恢复演练（RPO 1 小时 / WORM / 密钥分离）

实现：`apps/api/src/rg_api/backup.py`（加密、上传、下载、演练）、
`deploy/k8s/09-postgres-backup.yaml`（每小时 CronJob）、
`deploy/k8s/10-minio.yaml`（可选：内网单机 MinIO + WORM 桶）、
`deploy/k8s/11-restore-drill-cronjob.yaml`（每周演练）。

| 项 | 口径 |
|---|---|
| RPO | ≤ 1 小时（每小时 `pg_dump -Fc` 全量；库小的时候全量比增量更简单、恢复更直白） |
| RTO | 单库约百 MB 级，实测「取备份 + 解密 + restore + 校验」在分钟级；真正的 RTO 取决于磁盘与并发下载，演练时记录实测值 |
| 切换阈值 | 单次 dump 超过 **5 分钟**或库超过约 **50 GB** 时改增量（pgBackRest / WAL-G），不要等备份窗口挤爆后再改 |
| 存放 | S3 兼容对象存储（MinIO / Ceph RGW / 云 OBS），桶级 **Object Lock = COMPLIANCE** |
| 加密 | X25519 信封加密 + HKDF-SHA256 + AES-256-GCM；备份侧**只挂公钥** |
| 备份对象格式 | 自定义 `RGBAK1` 文件头，`pg_restore` 只接受解密后的 `.dump` |

分层与保留（前缀 + 保留期必须与 MinIO 生命周期规则逐一对齐）：

| 层 | 产生时机（UTC） | 对象前缀 | 对象保留 / 生命周期到期 |
|---|---|---|---|
| hourly | 每小时 :05 | `pg/hourly/` | 7 天 |
| daily | 每天 03:05（`DAILY_HOUR`） | `pg/daily/` | 30 天 |
| weekly | 周一 03:05 | `pg/weekly/` | 90 天 |
| monthly | 每月 1 号 03:05 | `pg/monthly/` | 365 天 |

- **CronJob 的 `timeZone` 必须是 UTC**：日/周/月层由 `now(UTC).hour == DAILY_HOUR` 判断，
  改成 `Asia/Shanghai` 会出现「小时层一直有、日层从来没有」。
- 四层天数在 `config.py`（`BACKUP_*_RETENTION_DAYS`）、09 的 ConfigMap、10 的 bootstrap
  作业里各写了一遍——**改一处必须改三处**，否则会出现「对象到期却删不掉、桶只增不减」。
- 小时层同时覆盖 RPO 与短期误操作；日/周/月层只做回溯，不做「按小时回滚」。

WORM（合规硬要求）的三个必要条件，缺一个就形同虚设：

1. 桶在**创建时**带 Object Lock（`mc mb --with-lock`）并开启版本化——事后补不开；
2. 备份程序对每个对象写入 `ObjectLockMode` + `RetainUntilDate`（09 已配置）；
3. 生命周期到期天数 ≥ 该层对象保留期（保留期更长会导致到期删不掉）。

两个必须提前接受的代价：`COMPLIANCE` 模式下**保留期内连存储管理员也删不掉**，误备份的
坏库同样删不掉，容量要按最坏情况留（10 的 PVC 默认 200Gi）；需要「可撤销」时只能用
`GOVERNANCE`（有 `s3:BypassGovernanceRetention` 权限者可提前删），但那等于放弃防内鬼。

密钥分离与轮换：

```bash
# 生成密钥对：公钥进备份侧 Secret，私钥离线/独立命名空间保管
python -m rg_api.backup keygen --out-dir ./backup-keys   # 打印公钥指纹，便于核对

# 备份侧只需要公钥：backup-public-key Secret 的 pubkey.pem
# 恢复侧才需要私钥：BACKUP_PRIVATE_KEY_PATH 指向私钥 PEM
```

- **私钥丢失 = 备份不可恢复**。私钥不与备份桶放在同一处，也不要放进业务命名空间长期保存。
- 轮换：生成新密钥对 → 公钥替换 `backup-public-key` → 旧私钥**必须保留到旧备份全部过期
  （最长 365 天）**，否则轮换当天就把过去一年的备份变成不可解密。旧私钥按到期日销毁。
- 备份 Pod 即使被攻破，拿走的也只是密文与公钥；`fetch` 在没有 `BACKUP_PRIVATE_KEY_PATH`
  时直接失败，不会悄悄退化成「不加密 / 不解密」。

恢复演练（默认**关闭**，因为私钥必须临时投放）：

```bash
# 1) 从离线保管处临时投放私钥（用完即删）
kubectl -n cloud-governance create secret generic backup-private-key \
  --from-file=privkey.pem=/secure/offline/backup-private.pem

# 2) 打开每周日 04:00（Asia/Shanghai）的演练，或立即手动跑一次
kubectl -n cloud-governance patch cronjob postgres-restore-drill \
  -p '{"spec":{"suspend":false}}'
kubectl -n cloud-governance create job drill-manual \
  --from=cronjob/postgres-restore-drill
kubectl -n cloud-governance logs job/drill-manual -c restore

# 3) 演练结束后删除私钥
kubectl -n cloud-governance delete secret backup-private-key
```

演练做的事：取该层最新对象 → 解密 → `createdb governance_drill` → `pg_restore
--no-owner --no-privileges --exit-on-error` → 校验 → `dropdb` → 写 `audit_log`。

- 目标库有两道闸门：名字必须含 `drill`，且不得等于 `DB_NAME`；残留库不自动删，先人工确认。
- 校验口径是「结构完整 + 核心表非空 + pgvector 可用」，**不比对行数**（dump 是快照，
  线上还在变，比对只会制造假失败）。非核心表缺失只报告，因为备份可能来自更早版本。
- 失败会写 `audit_log(action=backup_drill, outcome=failed)` 并删掉临时库；
  「连续几周没有成功演练记录」应当作为告警项，而不是等真恢复时才发现链路坏了。
- 演练身份需要 `CREATEDB`（当前部署用 `POSTGRES_USER=governance`，是超级用户）；
  换成受限账号时要显式授权，否则演练会在 `CREATE DATABASE` 一步失败。

真实恢复（不是演练）的原则：**先恢复到新库、校验通过后再切流量**，不要直接往线上库
`pg_restore`。恢复期间应停止写入（或接受这段时间的数据丢失），否则等于把旧快照覆盖回去。

```bash
python -m rg_api.backup fetch --tier hourly --out /work/pg.dump
createdb --host=postgres --username=governance governance_recover
pg_restore --no-owner --no-privileges --exit-on-error \
  --dbname=postgresql://governance@postgres:5432/governance_recover /work/pg.dump
```

本机最小验证（不需要对象存储）：`pytest apps/api/tests/test_backup.py -q` 覆盖加密往返、
错误私钥、篡改 1 字节、WORM 参数与保留天数、dry-run 不触网、演练闸门等；本机 PG 端到端
已实测「dump（110135 B）→ 加密（110202 B）→ 解密逐字节一致 → `pg_restore` 到临时库 →
21 张表 / `vector 0.8.6` / 核心表非空 → 删库」。`upload --dry-run` 可以在没有对象存储的
环境验证公钥与命名规则。

已有现成 MinIO / Ceph RGW 时**不要** apply `10-minio.yaml`，只执行其中 bootstrap 作业里的
等价命令（建桶带 `--with-lock`、版本化、四层生命周期、最小权限用户）；业务桶与备份桶
应是不同桶、不同凭证，网络策略也只放通 `app=backup` / `app=restore-drill` 到 9000。

#### 已用真实 MinIO 验证过的行为（22 项全过）

本机以 server 模式起 MinIO（验证后已关闭），走**真实 S3 协议**跑完整链路：带 Object Lock
建桶 → 写四层生命周期 → `pg_dump` → 加密上传四层 → 逐对象读回锁模式/保留期/元数据 →
尝试删除与缩短保留期 → `fetch` 解密比对 sha256 → 错误私钥拒绝 → `drill` 恢复到新库并校验
→ 审计落库。跑通这条链路后留下 4 个运维向的注意点：

- **MinIO 拒绝 WORM 违规时返回 `InvalidRequest` + "Object is WORM protected and cannot be
  overwritten"，不是 AWS 常见的 `AccessDenied`。** 判断「锁有没有生效」请看消息关键字，
  别按错误码过滤；否则会误判为「WORM 没生效」而去调策略。
- **`RetainUntilDate` 必须在未来。** 节点时钟比真实时间快/慢超过保留期时会直接报
  "the retain until date must be in the future"，整批备份失败——这条报错看起来像配置错误，
  实际是时钟漂移（检查 NTP，而不是改保留天数）。
- **不带 VersionId 的 `DeleteObject` 在版本化桶里是「加删除标记」**：实测返回
  `DeleteMarker: True`、`list_objects_v2` 的 `KeyCount=0`，但按 VersionId 仍能取回完整
  对象，`GET` 不带 VersionId 则 `NoSuchKey`。也就是说 **COMPLIANCE 不阻止删除标记**——
  它保护的是数据版本，不是「可见性」。后果：有管理员凭证者可让备份「从列表里消失」而
  不真正删除。
  初版恢复路径只读 `ListObjectsV2`，于是把「被隐藏」报成「没有可用备份」，会把人引向
  存储故障排查。现在 `latest_object_key` 改读 `ListObjectVersions`（过滤删除标记），
  被遮挡的备份仍能取回，并打一条 `backup_objects_hidden_by_delete_marker` 告警；
  只有当数据版本真的消失时才报「被删除标记遮挡」——那才是需要按安全事件查的情况。
  备份凭证需要 `s3:ListBucketVersions`（已在 `10-minio.yaml` 的策略里）；缺这条权限时
  会回落到 V2 并打 `backup_version_listing_unavailable`，**这条告警等于「读路径可能是近视眼」**。
- **`JsonDict` 的历史行曾以「JSON 字符串标量」存进 jsonb**：ORM 读回正常，所以单测全绿
  也发现不了；只有 `metadata_json->>'actor'` 这类 SQL 侧过滤恒为 NULL 才暴露。写入路径
  已修，存量行在 `ensure_schema()` 时按**模型推导出的全部 13 个 `JsonDict` 列**一次性还原
  （首版手写清单只覆盖 4 列——而保留字表 `user` 不加双引号还会直接语法错误）。回归见
  `apps/api/tests/test_json_dict_storage.py`：凡按元数据过滤的看板/导出，都该用这个形状
  验证一次，而不是只断言 ORM 读回值。

---

## 四、测试

**测试默认方言是 PostgreSQL**——即生产方言、唯一真相源。不设任何环境变量直接跑即连本机测试库：

```bash
pytest apps/api/tests -q        # 全量：脱敏、策略、拼图防护、端到端授权、审计
python scripts/smoke_api.py     # 15 项冒烟：健康、登录、资源、差异、检索、归因、治理、审计、采集
cd apps/web && npm run build    # 类型检查 + 构建
```

- 默认连接 `127.0.0.1:5432` 的 `rgtest` 库（角色 `rgtest` / 密码 `rgtest`）；库不存在时先建一次：`createdb -h 127.0.0.1 -U rgtest rgtest`
- 连接参数可用 `DB_HOST` / `DB_PORT` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` 覆盖；`DB_NAME` 为空会直接报错退出，不会静默连到未知库
- 每个 pytest 进程启动时都会先 `drop_all → create_all` 重建 schema 再灌种子，因此**不受上一轮残留数据影响**，也不需要手工清库

### 破坏性重建的两道闸门（PG 分支）

重建 schema 会 drop 目标库的全部表，而 `DB_NAME` 可能被开发机 shell 或 `.env` 残留成真实库名——所以 `conftest` 在 `drop_all` 之前必过两道闸门，并把清库坐标打进输出（`[pytest] destructive schema reset done: ...`），保证「谁把哪个库清了」在日志里可追溯：

| 闸门 | 触发条件 | 结果 | 绕过方式 |
|---|---|---|---|
| 目标库占用 | 该库正被另一个 pytest 进程持有（`pg_try_advisory_lock`，键为 `host:port/dbname`，按库区分） | 第二个进程立即报错退出，不会静默清库 | 等前一个进程结束，或换 `DB_NAME` |
| 目标库校验 | 实际库名（以 `SELECT current_database()` 为准，不只信环境变量）不含 `test` | 拒绝执行，报错退出 | 确知后果时显式 `RG_ALLOW_DESTRUCTIVE_DB=1` |

命名约定：**测试库名必须含 `test`**（`rgtest` / `rgtest_seed` / `rgtest_qa` / `corp_governance_test` 等）。CI 两个作业各用独立的 postgres service 容器，互不影响；本地并行跑请各指各的库。SQLite 分支的库建在临时目录，不涉及这两道闸门。

没有 PG 环境时可显式退回 SQLite 快速回路（`RG_TEST_DIALECT=sqlite`）。SQLite 是受控的方言垫片——JSON / 时间戳 / 向量的应用层编解码降级路径只在该分支被覆盖——用于秒级反馈，不是全量语义：

```bash
RG_TEST_DIALECT=sqlite pytest apps/api/tests -q                  # SQLite 全量
RG_TEST_DIALECT=sqlite pytest apps/api/tests/test_policy.py -q  # 秒级：纯逻辑模块
```

CI 与本地一致：`backend-pg` 作业跑 PG 全量，`backend-sqlite` 作业跑 Lint + 纯逻辑模块 + 冒烟。

覆盖的关键断言：
- 治理岗（L3）看不到数据中台（L4）的资源、差异与治理项
- 项目经理只能看到自己项目的资源与知识分片
- 只读用户无任何项目授权时一律 403
- 检索结果永远不出现金丝雀值
- 公网模型主机在配置保存阶段即被拒绝
- 每次访问都产生审计记录
- 反复小范围检索同一项目会触发拼图风险，返回降密级摘要且不回显风险
- 手机号被切片切断 / 文档需跨分片重组才能构成敏感画像时，写入安全事件

---

## 五、目录结构

```
cloud-rag-governance/
├── packages/contracts/         # 共享契约：模型、安全、采集、向量、OIDC、审计、种子数据
│   └── src/rg_contracts/
│       ├── knowledge/          # 知识库摄取：标题感知切块 + PDF 文本抽取
│       └── ai/bm25.py          # 应用层 BM25（中文 bigram，零第三方依赖）
├── apps/api/                   # FastAPI 服务 + 测试
├── apps/web/                   # Vue3 + TS 治理工作台
├── deploy/
│   ├── docker-compose.yml      # 本地全栈
│   └── k8s/                    # 生产 K8s 清单
├── samples/ops-docs/           # 自撰运维示例语料（非客户数据），用于检索验收
└── scripts/                    # 冒烟与调试脚本
```

---

## 六、已知限制与下一步

- 表结构由 SQLAlchemy 元数据 + 显式迁移注册表引导：`create_all` 只建缺失的表，后加列/索引由 `rg_contracts/db/schema_migrations.py` 的注册表按版本执行并登记到 `schema_version` 表（见 `docs/schema-bootstrap-governance.md` §8）。`python -m rg_contracts.db.migrate --plan` 可打印待执行清单供变更评审（dry-run，不执行）
- 未引入 Alembic（判据见 `docs/schema-bootstrap-governance.md` §3 方案 3）；`apps/api/pyproject.toml` 里原有的 `alembic>=1.13` 属预留声明、代码零调用，已连同其传递依赖从声明与本地环境移除（需要切换时按判据重新引入）
- PostgreSQL 生产环境滚动升级前仍需按 runbook 以属主身份执行 `python -m rg_contracts.db.migrate`（多 Pod 并发 DDL 与列级漂移校验尚未治理）
- `COLLECTOR_MODE=simulated` 为内置模拟数据；切到 `api` 需在各云适配器中填入真实凭证与分页/签名逻辑
- 指标只保留最新值：`resource_metric` 每轮采集 upsert 覆盖，没有历史序列；趋势分析需要另建明细表
- D1 利用率/浪费判定目前只有一条规则（`d1_gpu_utilization_waste`：`gpu_node` 的 `gpu_utilization` 低于阈值且 `allocated_gpus > 0`）；容量/合规/版本漂移等 D 系列尚未实现，阈值不支持按平台差异化
- `resource_metric` / `gpu_node` 已在 `RLS_TABLES` 内，用 `app.rls_anchor_ids`（锚点集合）在数据库层强制；残留风险是锚点集合由服务端代码授予（见 `docs/rls.md` 的「受保护对象」）
- 离线降级向量仅保证本地可跑与召回链路连通，语义质量不及 BGE-M3，上线前请启用 TEI
- 目录服务目前为 `static`，接入公司统一身份接口时实现对应 Provider 即可

---

## 七、知识库能力路线图

从「多云资源治理 + 安全 RAG 归因」补齐为「带密级治理能力的运维知识库」，分四阶段推进，详细差距矩阵见 [`docs/kb-alignment-plan.md`](docs/kb-alignment-plan.md)。

| 阶段 | 内容 | 状态 |
|---|---|---|
| **P1 摄取与切块** | 文件级摄取（Markdown/PDF）、标题感知切块、出处字段（`section_path` / `page_no` / 字符偏移） | 切块与 PDF 抽取模块、数据模型已落地 |
| **P2 混合检索** | 应用层 BM25（中文 bigram）+ 向量 RRF 融合 + 可插拔重排（默认融合，HTTP 重排可选） | BM25 模块已落地，融合与重排待接 |
| **P3 抽象与工程** | `StoragePort` 端口（授权过滤必须是第一个动作）、`rg` CLI（ingest/search/ask/serve）、离线部署形态、许可 | 许可已补齐 |
| **P4 语料验收** | 领域示例语料 + 问答集，指标：`recall@5 ≥ 0.8`、引用章节正确率 ≥ 0.8 | `samples/ops-docs/` 已备 6 篇 |

**明确不做**（显式声明，不是静默跳过）：

- **扫描件 / 图片型 PDF、OCR**：需 OCR 引擎与额外模型，超出 4C8G 离线 MVP 预算；无文本层的 PDF 在摄取阶段**显式报错**（`scanned_pdf_unsupported`），不静默入库
- **复杂表格高保真解析**：需版面分析模型；Markdown 表格按纯文本处理
- **多租户 / 细粒度权限扩展**：现有 L1–L4 + RBAC + 项目成员关系已覆盖，不随本路线图扩张
- **模型训练 / 微调**：只做检索增强，使用现成 BGE 系列模型
- **openGauss / 金仓 / 达梦的实际适配**：只交付 `StoragePort` 接口 + pgvector 参考实现，国产库需在客户环境实测后再声明支持
- **通用 RAG 平台功能**（工作流编排、插件市场等）：与定位不符

---

## 八、许可

本项目基于 **Apache License 2.0** 发布，全文见根目录 [`LICENSE`](LICENSE)。

```
Copyright 2026 The cloud-rag-governance Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

第三方依赖保持各自原有许可（SQLAlchemy MIT、FastAPI MIT、pypdf BSD-3-Clause、pgvector PostgreSQL License 等）。`samples/ops-docs/` 下的语料为本项目自撰，同样以 Apache 2.0 提供，**不含任何客户数据**。
