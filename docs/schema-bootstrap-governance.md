# Schema 引导治理风险评估：`ensure_schema()` / `create_all`

- 评估人：高见远（架构师）
- 日期：2026-10-23
- 性质：**只读评估，不改任何代码**
- 触发背景：资源治理维度扩展（`docs/architecture-expansion.md`）将新增 6–7 张表 + 3 个既有表新列，全部落在 `ensure_schema()` 路径上。该机制一旦有问题，风险随表数量线性放大。
- 相关决策记录：`docs/kb-alignment-plan.md` §8.1（无 alembic 已登记为风险 R7）

---

## 0. 结论摘要

### 直接回答 team-lead 的问题

> **「这次新增的 6–7 张表，应该继续走 `create_all`，还是必须引入显式迁移脚本？」**

**分两半回答，结论不同：**

| 变更类型 | 数量 | 结论 | 理由 |
|---|---|---|---|
| **新增表**（`gpu_node` / `gpu_cluster` / `training_job` / `model_endpoint` / `k8s_workload` / `resource_metric` / `model_version` / `dataset`） | 6–7 张 | ✅ **继续走 `create_all`** | `create_all` 对「建缺失的表」是幂等且语义正确的。新表代表全新治理对象，存量库上不存在语义歧义，**也没有历史数据需要迁移**。为其写迁移脚本是纯冗余。 |
| **既有表加列**（`resource.owner_team`、`resource.asset_tag`、`resource_diff.rule_code`） | 3 列 | ❌ **必须显式迁移** | `create_all` **不会给已存在的表加列**——这是 SQLAlchemy 的既定行为，不是配置问题。不写显式 ALTER，按 runbook 从旧版本升级上来的实例一读就报 `no such column`。 |

**因此：不是「二选一」，而是「新表零迁移 + 新列必须迁移」。把这两件事混成一个决策问，正是过去几次讨论没谈拢的原因。**

### 关于是否引入 alembic

> **P0 不引入 alembic；但必须引入 `schema_version` 表 + 显式迁移注册表（推荐方案 2）。**

- alembic 解决的是「有版本、有顺序、有回滚、能 autogenerate」；本项目当前**最致命的缺口是「无版本记录」**——它是回滚、漂移检测、升级可验证性三者的共同前提。
- `schema_version` + 注册表只需约 1.5 人日，且与现有 `_migrate_knowledge_columns` / `_migrate_legacy_vector_columns` 的写法**完全兼容、增量改造**；alembic 需要 2–3 人日 + 生成基线迁移 + 双方言 autogenerate 噪音治理，且在 6–7 张新表的窗口内收益不显著。
- **但 alembic 不应无限期推迟**：迁移函数数量超过约 8–10 个、或出现第一次「需要回滚」时，就是切换点。判据写在 §5.3。

### 三条必须立刻处理的事实（不依赖任何方案选型）

| # | 事实 | 文件:行 | 代价 |
|---|---|---|---|
| 1 | **`bootstrap()` 每个进程跑 2 次**：`create_app()` 经 `ensure_bootstrap()`（有 `_bootstrapped` 守卫），`lifespan` 直接调 `bootstrap()`（**无守卫**） | `apps/api/src/rg_api/main.py:31` vs `:38-40` | 每次启动 DDL 执行 2 遍、种子检查 2 遍、向量回填扫描 2 遍、`CREATE INDEX` 2 遍。不致命，但**把锁窗口与启动耗时翻倍**，且让「这次启动到底跑了什么」更难审计 |
| 2 | **`backfill_chunk_section_path()` 已定义但无任何生产调用点** | `apps/api/src/rg_api/startup.py:90-116`；全仓 grep 仅命中定义处与 `test_knowledge_section_path_migration.py` | **这是「静默漂移」的实证**：一次性回填函数不调用不会报错、不会告警、测试还是绿的（测试直接调函数），但生产数据永远不迁移。这个坑会在扩展期重演——新增的 `owner_team` 回填若不接线，一模一样 |
| 3 | **测试套件已经因为「结构漂移」被迫做破坏性重建** | `apps/api/tests/conftest.py:185-210`（`drop_all` + `ensure_schema`，带 advisory lock 与 destructive-reset 双闸门） | in-repo 注释自己写明：「③ 结构漂移——并行开发给模型加列后，`create_all` 能跟上，**存量库不会**」。测试用「每次推平重来」绕开了这个洞，**生产没有这个选项** |

---

## 1. 现状梳理

### 1.1 `ensure_schema()` 每次做了什么

```python
# packages/contracts/src/rg_contracts/db/session.py:65-85
def ensure_schema(engine=None) -> None:
    import rg_contracts.db.models          # 注册模型到 Base.metadata
    from rg_contracts.db.base import Base

    target = engine or get_engine()
    if target.dialect.name == "postgresql":
        with target.begin() as conn:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))   # ①
    Base.metadata.create_all(target)                                       # ②
    _migrate_knowledge_columns(target)                                     # ③
    if target.dialect.name == "postgresql":
        _migrate_legacy_vector_columns(target)                             # ④
```

| 步 | 动作 | 幂等性 | 覆盖的变更类型 |
|---|---|---|---|
| ① | `CREATE EXTENSION IF NOT EXISTS vector`（仅 PG） | ✅ | — |
| ② | `create_all` | ✅ | **只建缺失的表**；不动已存在的表 |
| ③ | `_migrate_knowledge_columns`：给存量库补 7 个知识库出处列 | ✅ 逐列 introspection | **加列**（可空 / 非空+常量默认） |
| ④ | `_migrate_legacy_vector_columns`：bytea → `vector(1024)` | ✅ 仅 `udt_name=='bytea'` 时执行 | **改列类型**（仅此一列，硬编码） |

`create_all` 的能力边界是理解全部风险的钥匙：

| 变更类型 | `create_all` 能否覆盖 |
|---|---|
| 新建表 | ✅ |
| 新建索引 | ✅（随表建；已存在表上的新索引需 `CREATE INDEX IF NOT EXISTS`） |
| 加列 | ❌ |
| 改列类型 | ❌ |
| 删列 | ❌ |
| 改约束 / 改唯一键 | ❌ |
| 数据回填 | ❌ |

**当前项目只有「新建表」和「加列」两类需求被覆盖，「改类型」靠 ④ 的硬编码单点覆盖，其余三类完全无覆盖。**

### 1.2 调用时机

| 调用点 | 时机 | 守卫 |
|---|---|---|
| `apps/api/src/rg_api/main.py:71`（模块级 `app = create_app()`） | 导入期 | ✅ `ensure_bootstrap` → `_bootstrapped` |
| `apps/api/src/rg_api/main.py:38-40`（`create_app()` 内） | 应用构造 | ✅ 同上 |
| `apps/api/src/rg_api/main.py:31`（`lifespan`） | uvicorn 启动 | ❌ **直接调 `bootstrap()`，无守卫** |
| `apps/api/tests/conftest.py:210` | 每个 pytest 进程 | `drop_all` 后重建 |
| `packages/contracts/tests/test_migrations.py` | 单测内 | — |

**生产时序（单次 Pod 启动）**：

```
容器启动 → CMD uvicorn rg_api.main:app（Dockerfile:37，无 --workers）
  → 导入 rg_api.main → 模块级 app = create_app()（main.py:71）
      → ensure_bootstrap → bootstrap()  ← 第 1 次
          → ensure_schema()
          → ensure_pgvector_index()   ← CREATE INDEX（非 CONCURRENT），异常则 rollback
          → seed_everything()（DEMO_SEED 时）
          → backfill_embeddings(limit=500)
  → uvicorn 触发 lifespan → bootstrap(settings)  ← 第 2 次（无守卫）
      → 以上全部再跑一遍
```

**并发放大**：`deploy/k8s/04-api.yaml:9` `replicas: 2`，HPA `minReplicas: 2 / maxReplicas: 10`。滚动更新与 HPA 扩容时，**每个 Pod 各自独立执行上述 DDL**。

### 1.3 失败处理

| 失败点 | 现有处理 | 评价 |
|---|---|---|
| `CREATE EXTENSION vector` 失败 | 无 try/except → 异常上抛 → 启动失败 | ✅ fail-fast，合理 |
| `create_all` 失败 | 无 try/except → 上抛 → 启动失败 | ✅ fail-fast，合理 |
| `_migrate_*` 失败 | 无 try/except → 上抛 → 启动失败；③ 内部「所有 ALTER 在同一事务内提交，中途失败整体回滚」（`session.py:129`） | ✅ 正确 |
| `ensure_pgvector_index` 失败 | `startup.py:49-61`：`except` → **`session.rollback()`** → `logger.error` → 降级继续 | ✅ 正确（P0-1 事故后的修复，见 §6 工程反思） |
| 种子 / 回填失败 | 无 try/except → 上抛 → 启动失败 | ⚠️ 可接受（fail-fast），但无重试与部分成功语义 |

**现状的失败处理整体是健全的**——尤其 `startup.py:49-61` 在吞异常前显式 `rollback()`，这正是 P0-1 事故后修对的那一处。问题不在失败处理，而在**「成功」这件事本身缺乏记录与版本**。

---

## 2. 风险逐条列（含「不改则需要承担什么」）

### R1｜每个进程重复执行 2 次 bootstrap

**证据**：`main.py:31`（`lifespan` 直接 `bootstrap(settings)`，无守卫）vs `main.py:38-40`（`ensure_bootstrap` 有守卫）。

**不改则承担**：
- 每次启动的 DDL 窗口、锁持有时长、向量回填扫描量**全部翻倍**；
- `ensure_pgvector_index` 执行 `CREATE INDEX IF NOT EXISTS` 两次（第二次是 no-op 但仍走一轮服务端解析与锁申请）；
- 更麻烦的是**审计困难**：日志里出现两份 `schema_ready` / `seed_done` / `embedding_backfill`，事后无法判断「这次升级实际跑了哪些 DDL」。

**修法**：`lifespan` 改调 `ensure_bootstrap(settings)`（一行）。风险：**低**。

---

### R2｜多 Pod 并发执行 DDL，无互斥

**证据**：`04-api.yaml:9` `replicas: 2`；HPA `maxReplicas: 10`；`bootstrap` 内无任何跨进程锁。

**后果分析**：

| 语句 | 并发执行是否安全 |
|---|---|
| `CREATE EXTENSION IF NOT EXISTS` | ✅ PG 内部有保护 |
| `CREATE TABLE IF NOT EXISTS` | ⚠️ 多数情况安全，但 PG 在极端并发下可能抛 `duplicate key value violates unique constraint "pg_type_typname_nsp_index"`（已知 PG 行为） |
| `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` | ⚠️ 同上，PG 9.6+ 支持 `IF NOT EXISTS`，并发下仍有小概率冲突 |
| `CREATE INDEX`（非 CONCURRENT） | ❌ **持 `SHARE` 锁阻塞写入**；两个 Pod 同时建索引会互相等待 |

**不改则承担**：滚动更新期间 2 个 Pod（HPA 时最多 10 个）同时执行 DDL，**低概率的 `duplicate key` 会导致某个 Pod 启动失败并 CrashLoopBackOff**；更常见的是启动抖动（互相等锁）。由于没有版本记录，运维无法判断失败的是哪个 Pod、跑到哪一步。

**修法**：见方案 2/3 的「一次性 Job」（推荐）或「advisory lock」（最小）。风险：**中**。

---

### R3｜`CREATE INDEX` 非 CONCURRENT，阻塞写入

**证据**：`ai/retrieval.py:197-217`（`ensure_pgvector_index`）执行 `CREATE INDEX IF NOT EXISTS ... USING hnsw (embedding vector_cosine_ops)`，在 `startup.py:50` 的事务性会话内调用。

**不改则承担**：
- 首次建索引（表大时）持 `SHARE` 锁，**阻塞该表所有写入**；启动期间的采集/写入会超时；
- `CREATE INDEX` 不能与 `CONCURRENTLY` 混在事务里，所以现状是「要么事务内阻塞式建，要么改成 autocommit + CONCURRENTLY」二选一，当前选的是前者；
- 扩展期新增 6–7 张表后，若后续还要给它们加索引，都会走同一条阻塞路径。

**注意**：这是**首次启动**才显著的问题（后续 `IF NOT EXISTS` 是 no-op），但离线客户升级时往往正是「首次建索引」+「有存量数据」的组合。

**修法**：改为 autocommit 连接 + `CREATE INDEX CONCURRENTLY IF NOT EXISTS`；或保留现状但在升级 runbook 中明确「首次启动需维护窗口」。风险：**中**。

---

### R4｜`create_all` 只加不删不改 → 「模型改了但库没变」的静默漂移 ★

**这是本次评估中最需要重视的一条。**

`create_all` 的能力边界（§1.1 表）意味着以下四类模型变更**在存量库上完全静默失效**：

| 变更类型 | `create_all` 行为 | 失效表现 |
|---|---|---|
| 改列类型 | 不执行 | 模型说 `Integer`，库里是 `VARCHAR` → 写入/比较行为不一致，且不报错 |
| 删列 | 不执行 | 模型没这列了，库里还在 → 表里留下永不清理的僵尸列（**若列内含敏感数据，等于留下一份没人管的副本**） |
| 改约束 / 改唯一键 | 不执行 | 约束只在新建库生效 → 存量库可写入违反唯一性的数据 |
| 数据回填 | 不执行 | 见 R7 |

**不改则承担**：
- **漂移不可观测**：项目没有任何机制比对「模型定义的 schema」与「库里实际的 schema」。新库与老库会静默分叉，且两者都能跑（因为 SQLAlchemy 按模型生成 SQL，类型不匹配要到边界数据才暴露）。
- **与安全相关的特殊风险**：本次扩展的 `resource_diff.classification`、密级传播等若将来语义调整需要「改列默认值」或「加约束」，存量库不会跟上 → 新建库与升级库的安全行为不一致，**而回归测试只跑新建库（conftest 每次 drop_all 重建）**。

**修法**：方案 2 的「启动期 schema 一致性校验」。风险：**高**（不修的话）。

---

### R5｜无版本记录 → 无法回答「这个库现在是哪个 schema 版本」

**证据**：全仓无 `schema_version` 表、无 `alembic_version`、无任何版本标记。`_migrate_*` 靠 introspection 判断，是「无状态的」。

**不改则承担**：
- 无法回答「这次升级跑了哪些迁移」「这台实例的库停在哪个版本」；
- **无法做回滚决策**（R6）；
- 无法在启动时断言「版本符合预期，可以启动」——只能盲跑；
- 横向扩展期会有 2–3 个里程碑各自加表加列，**版本数量超过人脑记忆时，迁移顺序问题必然出现**（例如：某个迁移函数依赖另一个迁移先执行，但两者都是无状态 introspection，顺序错了也不报错）。

**修法**：方案 2 的 `schema_version` 表。风险：**高**（不修的话）。

---

### R6｜无回滚路径，且当前无备份方案

**证据**：迁移是「一次性 DDL + 隐式提交」，无 down 迁移；`deploy/k8s/02-postgres.yaml` 无任何备份/WAL 归档/PITR 配置。

**不改则承担**：
- 升级失败只能靠备份恢复，**而备份方案本身不存在**；
- 离线客户环境尤其危险：无法临时拉补丁、无法在线查资料，一次失败的 DDL 可能就是长时间停服。

**修法**：至少把「升级前必须做一次全量备份」写进 runbook，并提供手工 SQL；方案 2 提供「版本号 + 已执行清单」让回滚目标可确定。风险：**高**。

---

### R7｜迁移/回填函数不调用不报错 ★（已有实证）

**证据**：`apps/api/src/rg_api/startup.py:90-116` 定义了 `backfill_chunk_section_path()`；全仓 grep 仅命中定义处与 `test_knowledge_section_path_migration.py:24,129,148,149`。**没有任何生产路径调用它。**

- 测试直接调函数 → 测试绿；
- 函数不接线 → 不报错、不告警；
- 结果：生产库的 `knowledge_chunk.section_path` 历史行**永远不会从 `metadata_json` 回填到列**。

这条是 D1（task #29）正在处理的内容，**但它暴露的是一个模式级缺陷，不是单个 bug**：

> **一次性幂等函数 + 无人调用 = 静默失效，且所有测试都是绿的。**

**不改则承担**：本次扩展若需要任何回填（例如 `resource.owner_team` 从 `attributes` 回填、dataset 密级传播回刷），只要接线漏掉，症状是「功能看起来正常但数据没到位」，且**没有任何信号**。这类缺陷的发现周期以月计。

**修法**：
1. 迁移注册表（方案 2）把「定义」与「执行」绑在一起——注册即执行，不存在"定义了没调"；
2. 新增一条 CI 检查：所有 `def _migrate_*` / `def backfill_*` 必须在注册表或 `bootstrap()` 中被引用。

风险：**高**。

---

### R8｜迁移常量与模型定义是两份手工同步的真相源

**证据**：`session.py:95-107` 的 `_KNOWLEDGE_COLUMN_UPGRADES`（裸 DDL 字符串常量）与 `db/models.py` 的模型列定义必须手工保持一致。`session.py:88-94` 的注释解释了为什么用裸 DDL（SQLite 的 `ALTER TABLE ADD COLUMN` 限制），并说明「这里 7 个列全部满足该限制……不会出现新建库与迁移后的老库类型不同」——**这个保证靠人守，不靠工具守**。

**不改则承担**：
- 模型改了列名/类型而常量没改 → 新建库与升级库 schema 分叉（R4 的具体成因）；
- 本次扩展新增 3 个列后，`_KNOWLEDGE_COLUMN_UPGRADES` 式常量会变成 `_EXPANSION_COLUMN_UPGRADES`，**两份清单**（知识库 7 列 + 扩展 3 列）手工维护，出错面翻倍。

**修法**：保留裸 DDL 常量，但加一条单测：**从模型元数据渲染出「应有列清单」，与常量清单比对**，不一致即失败。这样"手工同步"变成"手工同步 + 自动校验"。风险：**中**。

---

### R9｜双方言（SQLite / PG）的迁移约束不一致

**证据**：
- `session.py:109-110` `_SUPPORTED_MIGRATION_DIALECTS = {"postgresql", "sqlite"}`，其他方言**只告警跳过，不失败**（`session.py:136-143`）；
- SQLite 的 `ALTER TABLE ADD COLUMN` 只接受「可空」或「非空 + 常量默认」（`session.py:90-93` 注释）；
- SQLite 是单写者模型，`ALTER TABLE` 会持写锁——`services/audit.py:128-157` 的 `_is_lock_error` 正是为处理这种竞争而写；
- `db/base.py` 的 `TS()` / `JsonDict()` 用 `with_variant` 处理方言差异，但**迁移 DDL 里的类型要自己写对**。

**不改则承担**：
- 迁移在 PG 上通过、在 SQLite 上失败（或反之）→ 双方言 CI 能拦住，但**只在 CI 覆盖到的方言上**；
- SQLite 写锁竞争会让「启动期迁移」与「业务写入」互相阻塞——`_is_lock_error` 目前只保护**审计**路径，不保护迁移路径。

**修法**：扩展期的 3 个新列必须满足「可空 / 非空+常量默认」，且双方言 CI 全量跑；迁移路径的锁竞争需评估是否复用 `_is_lock_error` 的语义。风险：**中**。

---

### R10｜离线部署下的升级窗口受限 ★（客户视角）

这是量化客户场景的特殊约束：

| 约束 | 影响 |
|---|---|
| 内网不一定允许长事务在线 DDL | 现状的「应用启动时跑 DDL」在维护窗口内没问题，但**HPA 自动扩容时也会跑**——扩容发生在业务高峰期，DDL 与业务流量撞车 |
| 无外网，迁移失败无法临时查资料/拉补丁 | 一次失败的 DDL = 长时间停服，且**当前无回滚路径**（R6） |
| 客户运维需要「这次升级跑了什么」的清单做变更审批 | 现状无法提供：DDL 分散在 `create_all` 与两个 `_migrate_*` 里，且**执行两次**（R1），没有可交付的清单 |
| 客户需要能预演 | 现状不能 dry-run；`create_all` 的结果只能在跑完后看 |

**不改则承担**：升级流程无法通过客户的变更评审（拿不出 DDL 清单、拿不出回滚方案、无法预演）。这对金融/运营商口径的客户往往是**硬性阻断项**。

**修法**：方案 2 的「一次性 Job + 版本记录 + runbook 手工 SQL」天然产出这三样东西。风险：**高**。

---

### R11｜`ondelete="CASCADE"` 的级联删除与证据保留

**证据**：本次扩展的属性表设计为 `resource_id` 作 PK+FK 且 `ondelete="CASCADE"`（`architecture-expansion.md` §1.2）。

**不改则承担**：删除 `Resource` 会级联删除属性行与指标行。若既有回收逻辑依赖「软删除后保留数据」（`resource.decommissioned_at` 已存在，暗示可能有此意图），级联会**静默删掉证据**，而 `snapshot_state` 是否保留了等价历史需逐一核对。

**修法**：确认 `resource` 的删除路径与 `snapshot_state` 的证据保留范围；若需要保留，改为软删除 + 定期归档。风险：**中**（属扩展设计待办，已记入 `impl-plan-expansion-p0.md` S1）。

---

## 3. 候选改造方案

### 方案 1：维持现状 + 最小强化（**否决**）

仅修 `main.py:31` 的重复调用 + 为新列补 `_EXPANSION_COLUMN_UPGRADES`。

- **优点**：约 0.5 人日，零架构改动。
- **否决理由**：它一条都没解决 R4（漂移不可观测）、R5（无版本）、R6（无回滚）、R7（不调用不报错）、R10（离线升级拿不出清单）。**这五条才是本次评估的价值所在**，方案 1 相当于宣布「本次扩展不接受任何 schema 治理」。

---

### 方案 2（**推荐**）：`schema_version` 表 + 显式迁移注册表 + 一次性 Job

三个可独立交付的组件，按优先级排序：

#### 组件 A：`schema_version` 表 + 迁移注册表（约 1.5 人日，解决 R5 / R7 / R4-部分）

```python
# packages/contracts/src/rg_contracts/db/schema_migrations.py（新增）

@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    ddl: tuple[str, ...]        # 可选：提供给 runbook 的等价手工 SQL（离线客户用）
    def apply(self, conn, dialect) -> None: ...   # 幂等


_MIGRATIONS: tuple[Migration, ...] = (
    # 既有两条迁移收编进来，保留原函数体，只加 version/name 元信息
    Migration(version=1, name="knowledge_columns",   apply=_migrate_knowledge_columns),
    Migration(version=2, name="pgvector_column_type", apply=_migrate_legacy_vector_columns),
    Migration(version=3, name="expansion_columns",   apply=_migrate_expansion_columns),  # 本次新增
)


def apply_migrations(engine) -> list[int]:
    """建 schema_version 表 → 读当前版本 → 按顺序执行未应用的迁移 → 逐条记录。

    - 每条迁移在**独立事务**内执行并提交，version 行同事务写入（要么都成要么都不成）
    - 已记录的 version 跳过，因此天然幂等
    - 返回本次实际应用的 version 列表（供启动日志与 /ready 展示）
    """
```

`schema_version` 表：`version PK / name / applied_at / dialect / duration_ms`。

**关键设计点**：
- **"注册即执行"** —— 迁移函数进了 `_MIGRATIONS` 元组就一定会跑，**从结构上消灭 R7 的「定义了没调用」**；
- `schema_version` 表放入 `Base.metadata`，由 `create_all` 自动建（无鸡生蛋问题）；
- 保留原 `_migrate_*` 函数体与 `test_migrations.py` 的 5 条测试（增量改造，不推倒）。

#### 组件 B：启动期 schema 一致性校验（约 1 人日，解决 R4）

```python
def verify_schema(engine) -> list[str]:
    """比对「模型元数据」与「库里实际列」，返回差异描述（空 = 一致）。"""
    # 对每个模型：inspect(engine).get_columns(table) 与 model.__table__.columns 比对
    # 差异分三类：missing_column（可自动加）、type_mismatch（不可自动改，需人工）、
    #             extra_column（模型已删，库里还在）
```

- **在 prod 下** `type_mismatch` / `extra_column` → `logger.error` 并写入 `/ready` 的 `schema_drift` 字段（**不 fail-fast**，避免存量库直接起不来）；
- **在 test 下** 断言 `verify_schema() == []`，让漂移在 CI 就暴露。

#### 组件 C：把 bootstrap 挪出 Pod 启动路径（约 1.5 人日，解决 R2 / R3 / R10）

- 新增 `apps/cli`（`kb-alignment-plan.md` §5.2 已规划了 `apps/cli`）或 `scripts/migrate.py`，提供：
  - `migrate` —— 执行 `ensure_schema()` + `apply_migrations()`，打印应用的 version 列表后退出
  - `migrate --plan` —— **dry-run**：只打印将要执行的 DDL 与 version，**不执行**（离线客户拿去做变更审批）
  - `verify` —— 跑 `verify_schema()`，返回码非 0 表示有漂移
- K8s 侧：新增一次性 `Job`（或 `initContainer` + 幂等），`Job` 成功后再滚动更新 Deployment。
- 最小替代（若不想动部署结构）：在 `bootstrap` 开头取 **PG advisory lock**（`pg_try_advisory_lock`），抢不到就跳过迁移直接启动（假定别的 Pod 正在做），抢到才执行。**conftest.py:208 已经用了 `pg_try_advisory_lock`，可直接复用这套写法**——约 0.5 人日。

**对离线部署的影响（正面）**：
- Job 模式让「这次升级跑了什么 DDL」成为**可打印、可存档、可预演**的产物，直接满足客户变更评审要求；
- `--plan` 让离线客户在维护窗口前就拿到 DDL 清单；
- 滚动更新时不再有 N 个 Pod 同时跑 DDL；
- **代价**：多一个部署步骤，若客户漏跑 Job 会导致应用起不来——因此应用启动时应**校验版本**，版本不符则给出清晰报错（而不是默默跑 DDL）。

---

### 方案 3：引入 alembic（**P0 不采纳，但设明确切换点**）

**优点**：版本/顺序/回滚/autogenerate 全套；社区标准，新人零学习成本。

**P0 不采纳的理由**：
1. **双方言 autogenerate 噪音**：`TS()` 的 `with_variant`、`JsonDict()` 的 `String↔JSONB`、`Vector` 的 `JSON↔vector(1024)` 会让 autogenerate 每次都产生无意义 diff，需要大量 `% ignore` 配置——在当前 2 人团队下是持续负担。
2. **基线迁移是工作量不是魔法**：已有库需要生成一个"假装从零建起"的基线 revision，再让存量库 `stamp head`。这步出错会让后续所有迁移错位。
3. **当前最致命的缺口是「无版本」，不是「没有工具」**：方案 2 的 1.5 人日就能补上版本，alembic 的 2–3 人日主要花在"工具化"上。
4. **窗口内收益不显著**：本次变更只有 3 个新列 + 6–7 张新表（新表不需要迁移），alembic 的能力用不上。

**切换判据（满足任一即切）**：
- 迁移数量 > 8–10 个；
- 出现第一次「需要回滚」的实际需求；
- 出现「需要改列类型 / 删列 / 改约束」的需求（此时手写 DDL 的风险显著上升）；
- 团队规模 ≥ 3 人且有并行 schema 变更。

---

### 方案 4：声明式 schema diff + 自动生成迁移（**否决**）

用 `alembic.autogenerate` 或 `sqlalchemy-utils` 在启动时自动 diff 并应用。

- **否决理由**：自动生成 + 自动应用 = **在无人审阅的情况下让程序改生产库结构**。本项目的客户是金融/运营商口径，「DDL 必须可评审」是硬要求。自动应用与 §2-R10 的离线变更评审要求直接冲突。

---

### 方案对比

| | 方案 1（现状+） | **方案 2（推荐）** | 方案 3（alembic） | 方案 4（自动 diff） |
|---|---|---|---|---|
| 工作量 | 0.5 人日 | **约 4 人日**（A 1.5 + B 1 + C 1.5） | 2–3 人日 + 基线 | 3–5 人日 |
| 解决 R4 漂移可观测 | ❌ | ✅ | ⚠️（需额外写校验） | ✅ |
| 解决 R5 版本记录 | ❌ | ✅ | ✅ | ✅ |
| 解决 R6 回滚 | ❌ | ⚠️（版本可确定，down 仍需手写） | ✅ | ⚠️ |
| 解决 R7 不调用不报错 | ❌ | ✅（注册即执行） | ✅ | ✅ |
| 解决 R10 离线升级清单 | ❌ | ✅（`--plan`） | ✅ | ❌（自动应用，不可评审） |
| 与现有 `_migrate_*` 兼容 | ✅ | ✅（增量，保留原函数体） | ❌（需收编） | ❌ |
| 双方言负担 | 低 | 低 | **高**（autogenerate 噪音） | 中 |

---

## 4. 明确回答与落地清单

### 4.1 问题的答案

| 问题 | 答案 |
|---|---|
| 新增 6–7 张表走 `create_all` 还是显式迁移？ | **继续走 `create_all`**。`create_all` 对「建缺失的表」幂等且语义正确，新表无历史数据要迁移，写迁移脚本是纯冗余。**但ubernate 前提**：表必须注册进 `Base.metadata`（自动满足），且**索引随表定义**（不能事后单独 `CREATE INDEX` 而不幂等）。 |
| 3 个既有表新列呢？ | **必须显式迁移**，写法沿用 `_migrate_knowledge_columns`（`session.py:113-165`）的「逐列 introspection + 缺哪补哪 + 幂等 + 单事务」模式，并满足 SQLite 的「可空 / 非空+常量默认」限制。 |
| 引入 alembic 吗？ | **P0 不引入**。先上方案 2 的 `schema_version` + 注册表（1.5 人日），把「无版本」这个最致命缺口补上。切换判据见 §3-方案 3。 |
| 本次扩展必须同步做的？ | ① 修 `main.py:31` 重复 bootstrap（1 行）；② 3 个新列进迁移注册表；③ 加「模型列清单 ↔ 迁移常量清单」一致性单测（防 R8）；④ runbook 提供等价手工 SQL。 |

### 4.2 落地顺序（可拆成独立工单，互不阻塞）

| 序 | 任务 | 人日 | 解决 | 是否阻塞本次扩展 |
|---|---|---:|---|---|
| 1 | `main.py:31` 改调 `ensure_bootstrap`（消除重复 bootstrap） | 0.1 | R1 | 否，但建议同批做 |
| 2 | 新增 `_migrate_expansion_columns`（3 列，双方言幂等）+ `test_migrations` 扩展 | 1.0 | §4.1 第二行 | **是** |
| 3 | `schema_version` 表 + 迁移注册表，收编既有 2 条迁移 | 1.5 | R5、R7、R8 | 否，但**强烈建议** |
| 4 | `verify_schema()` + 测试断言 + `/ready` 暴露 `schema_drift` | 1.0 | R4 | 否 |
| 5 | `scripts/migrate.py`（`--plan` / `verify`）+ K8s Job 或 advisory lock | 1.5 | R2、R3、R10 | 否 |
| 6 | runbook：升级前备份 + 手工 SQL + 回滚步骤 | 0.5 | R6 | **是**（客户交付必需） |
| | **合计** | **约 5.6 人日** | | |

> **如果窗口紧张**：任务 1 + 2 + 6（约 1.6 人日）是**本次扩展的必做项**；任务 3–5 可排到扩展之后。但请注意：任务 3–5 解决的问题（版本、漂移、离线清单）在**第二次、第三次扩展时会以更高的代价回来**——本次已有 8 个迁移函数与 2 份手工同步清单，下一次不会更少。

---

## 5. 与扩展设计的交叉引用

| 本文风险 | 对应扩展文档位置 |
|---|---|
| R2 多 Pod 并发 / R3 DDL 锁 | `architecture-expansion.md` §6.6 |
| R11 级联删除 | `impl-plan-expansion-p0.md` S1「可能破坏的既有安全语义」 |
| 新表走 `create_all` 的零迁移论证 | `architecture-expansion.md` §1.6-A′「迁移路径」栏 |
| 3 个新列的迁移需求 | `impl-plan-expansion-p0.md` S1 改动第 5 点 |

---

## 6. 工程反思：`ensure_pgvector_index` 的 try/except（正面案例）

与本次评估相关的一处**已修好的设计**，值得作为后续改造的参照：

```
apps/api/src/rg_api/startup.py:49-61
    try:
        ensure_pgvector_index(session, settings.EMBEDDING_DIM)
    except Exception:
        session.rollback()          # ← 关键
        logger.error("pgvector_index_failed", extra={"extra_fields": {
            "dim": ..., "impact": "向量检索退化为顺序扫描，功能可用、性能下降"}})
```

P0-1 事故时这里的 `except` **没有 `rollback()`**，导致失败的 DDL 把事务置于 aborted 状态，后续 `SELECT` 连环报 `InFailedSqlTransaction`，最终表现为「应用在 PG 上完全无法启动」——报错位置从 `CREATE INDEX`（有列名、有算子名）漂移到毫不相干的 `SELECT ... LIMIT 500`。

**可复用的三条教训（适用于本文所有改造）**：

1. **吞异常必须连带处理副作用**。在数据库会话上吞异常而不 `rollback()`，等于把「可诊断的失败」改造成「出现在千里之外的失败」。
2. **「降级继续」必须显式声明降级后的不变量**。现在日志里写了 `impact: "向量检索退化为顺序扫描，功能可用、性能下降"` —— 这才是可接受的降级。
3. **降级要可见**。当前索引缺失的唯一信号是一条 ERROR 日志。建议（已记入 `arch-quant-assessment-2026-10-17.md` §7.1）：把索引状态暴露到 `/ready` + 一个 gauge 指标 + 首次出现告警。**这一条与本文 R4 的 `schema_drift` 是同一个模式：降级/漂移不可见，就等于没有治理。**

---

## 7. 已知局限（显式记录）

| # | 局限 | 说明 |
|---|---|---|
| 1 | 本文未实测多 Pod 并发 DDL 的失败率 | R2 的「低概率 `duplicate key`」基于 PG 已知行为推导，未在本项目环境复现。真实概率与客户数据量、启动时序相关 |
| 2 | 方案 2 的 4 人日为估算 | 未包含 `apps/cli` 的既有基础（`kb-alignment-plan.md` §5.2 已规划），若可复用则组件 C 可减至约 1 人日 |
| 3 | 未评估 `resource` 表现有数据量对加列的影响 | PG 11+ 的 fast default 对「非空+常量默认」是 O(1)，但如果客户 PG 版本 < 11 或列定义含 volatile 默认值，`ALTER TABLE` 会重写全表。**需在 runbook 中按客户 PG 版本分别说明** |
| 4 | 未覆盖 SQLite → PG 的一次性数据搬迁 | 本文只讨论「同一方言内的升级」。若客户从 SQLite 试点迁到 PG 生产，是一次独立的数据迁移工程，不在本文范围 |
| 5 | R11 级联删除的结论待确认 | 需核对 `snapshot_state` 是否保留了等价历史证据，本文只标为风险，未给结论 |

---

## 8. 实现状态（2026-10-30 更新）

本节记录本文各方案的**实际落地情况**，避免读者把设计文档当成现状。

### 8.1 已落地：方案 2 部件 A（`schema_version` + 注册表）

| 项 | 落点 | 说明 |
|---|---|---|
| 版本表 | `rg_contracts/db/models.py::SchemaVersion` | 表 `schema_version`（`version` PK / `name` / `applied_at` / `dialect` / `duration_ms`）。**放在 ORM 元数据里**，由 `create_all` 顺带建出，避免「记版本要先有版本表、版本表又只能靠迁移建」的鸡生蛋问题 |
| 迁移注册表 | `rg_contracts/db/schema_migrations.py::registry()` | 4 条迁移（`knowledge_columns` / `expansion_columns` / 两条 PG 专属），按 version 升序；函数体仍是 `session.py` 里原有的 `_migrate_*`（未推倒重写，`test_migrations.py` 的 5 条测试继续有效） |
| 唯一执行入口 | `session.py::ensure_schema` → `schema_migrations.apply_pending` | 原来 4 处逐个点名调用改成走注册表，**注册即执行**（R7）；`ensure_schema` 现在返回本次实际应用的 version 列表 |
| 幂等 | `applied_versions` / `pending_migrations` | 已登记的 version 跳过，二次调用返回 `[]` |
| 测试 | `packages/contracts/tests/test_schema_migrations.py` | 11 条：版本唯一升序、**注册表恰好覆盖 session 里全部 `_migrate_*`**（防「写了没接线」）、首次无表时返回空、方言过滤（SQLite 只跑 2 条）、新库登记 + 二次空操作、`describe_plan` 不建表、CLI 退出码 |

关于「原子性」的取舍：迁移函数自带事务，「执行 DDL」与「写 version 行」**不在同一事务**。这是刻意选择，因为 4 条迁移全部幂等（先 introspection 再 ALTER）：万一两步之间进程被杀，下次运行会重放同一条迁移（空操作）并补登记，结果收敛。若将来出现**不幂等**的迁移（例如数据回填 + 删列），必须先补「同事务登记」再写那条迁移。

### 8.2 已落地：部件 C 的 CLI 部分

`python -m rg_contracts.db.migrate` 现在有三个模式（`packages/contracts/src/rg_contracts/db/migrate.py`）：

| 命令 | 行为 | 退出码 |
|---|---|---|
| `python -m rg_contracts.db.migrate` | 建表 + 执行未登记迁移 + （PG）建向量索引/RLS 策略，打印 `applied=[...]` | 0 / 异常非零 |
| `python -m rg_contracts.db.migrate --plan` | **dry-run**：只打印待执行清单（version / 名称 / 方言 / 说明），不执行任何 DDL | 0 |
| `python -m rg_contracts.db.migrate --verify` | 只校验缺表，不建表 | 0 通过 / 1 缺表 |

`--plan` 与 `apply_pending` 共用 `pending_migrations` 这一个判定，因此「打印的清单」与「实际执行」不会分叉 —— 这正是 R10 离线变更评审要的性质。

### 8.3 未落地（仍是本文的开放项）

| 项 | 状态 | 缺口 |
|---|---|---|
| 部件 B：列级漂移比对 | **未做** | 现有 `verify_schema` 只比对**表是否存在**，不比对列/类型；`type_mismatch` / `extra_column` 仍不可见（R4 未关闭） |
| `/ready` 暴露 `schema_drift` | **未做** | 漂移目前没有任何信号（与 §6 教训 3 同一个模式） |
| K8s Schema-init Job / advisory lock | **未做** | 部署结构未改；多 Pod 同时启动仍可能并发跑 DDL（R2 / R3 未关闭） |
| runbook 手工 SQL / 回滚步骤 | **未做** | R6 未关闭；`Migration` 数据类预留了 `description`，但还没有等价手工 DDL 字段 |
| 「一次性」语义带来的变化 | **已知，已记录** | 迁移只在「本条 version 未登记」时执行。旧实现是每次启动都跑一遍全部 `_migrate_*`，所以 `_migrate_json_string_scalars` 那类**数据修复**迁移过去会自愈，现在不会。影响面是滚动更新窗口内旧 Pod 写入的历史坏形态行不再被自动修复；补救办法是删掉 `schema_version` 里对应 version 行后重跑 `python -m rg_contracts.db.migrate`（迁移本身幂等）。收益是每次启动少 13 次全表 `UPDATE`（`jsonb_typeof(...)='string'` 无法走索引） |

### 8.4 关于 alembic

`apps/api/pyproject.toml` 曾声明 `alembic>=1.13`，但仓库里**没有任何代码调用它**：没有 `alembic.ini`、没有 `migrations/` 目录、全仓无 `import alembic`。本轮核实后已把这条依赖（连同只有它使用的传递依赖 Mako / MarkupSafe）从 `pyproject.toml` 与本地 venv 中移除，避免依赖审计把它当成在用组件。按 §3 方案 3 的判据（迁移数 > 8–10、首次需要回滚、改列类型/删列/改约束、团队 ≥3 人并行），当前只有 4 条迁移，一条都没满足，因此维持「P0 不采纳」。将来满足判据要接入时，必须先生成基线 revision 并让存量库 `stamp head`，否则后续迁移会全部错位。
