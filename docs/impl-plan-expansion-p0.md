# P0 实施计划：资源治理维度扩展（R1 GPU 节点主线）

- 配套文档：`docs/prd-resource-governance-expansion.md`、`docs/architecture-expansion.md`
- 制定日期：2026-10-23
- 执行原则：**先跑通 R1 GPU 节点一类端到端，再横向复制**。目标是让闭环设计的问题最早暴露、返工成本最小。
- 闭环方案：**方案 A′（锚点唯一 + 属性分表）**，见 `architecture-expansion.md` §1.6。本文所有步骤均按该方案编写。
- R2 / R3 / R4 / R6 不重复写完整分步，只在 §3 给「复制清单」。

---

## 0. 读前必读：本计划依赖的既有安全机制（不可绕过、不可重造）

以下机制**已经修复并有回归测试守护**。扩展时必须**挂接**，不得另写一套：

| 机制 | 位置 | 守护测试 |
|---|---|---|
| 密级过滤恒生效（`unrestricted` 只放宽项目范围） | `packages/contracts/src/rg_contracts/ai/retrieval.py` `_candidate_ids` | `test_retrieval_level_filter.py` |
| 聚合与明细同口径密级过滤 | `apps/api/src/rg_api/routes/resources.py` `_apply_level_filter` | `test_resource_stats_level_filter.py` |
| 拒绝/失败审计走**独立事务** | `apps/api/src/rg_api/services/audit.py` `_INDEPENDENT_OUTCOMES` | `test_audit_denied_persistence.py` |
| 能力拒绝补 `denied` 审计 | `apps/api/src/rg_api/services/access.py` `assert_capability(request=…, session=…)` | `test_capability_denial_audit.py` |
| 采集密级唯一来源 = 项目目录，未知项目失败关闭 | `apps/api/src/rg_api/routes/collection.py` `_project_classifications` | `test_collection_classification.py` |

**回归基线**：138（SQLite）/ 136+2skip（PG）必须全绿。每一步结束时都要跑全量。

---

## 1. R1 主线分步（采集 → 判定 → 看板 → 处置）

> 每步格式：文件清单 → 改动内容 → 依赖 → 验收测试点 → **可能破坏的既有安全语义**

### S0｜契约层：枚举与常量扩展

**文件（1）**
- `packages/contracts/src/rg_contracts/enums.py`

**改动**
```python
class ResourceKind(str, Enum):
    # 既有：VM/DISK/DATABASE/LOADBALANCER/OBJECT_STORAGE/CONTAINER/PUBLIC_IP/CACHE/OTHER
    GPU_NODE = "gpu_node"
    GPU_CLUSTER = "gpu_cluster"
    TRAINING_JOB = "training_job"
    MODEL_ENDPOINT = "model_endpoint"
    K8S_CLUSTER = "k8s_cluster"
    K8S_NAMESPACE = "k8s_namespace"
    K8S_POD = "k8s_pod"
    DATASET = "dataset"
    VECTOR_DB = "vector_db"
    NOTEBOOK = "notebook"

class DiffKind(str, Enum):
    # 既有：NEW/REMOVED/SPEC_CHANGED/STATE_CHANGED/TAG_CHANGED/OWNER_CHANGED
    UTILIZATION_WASTE = "UTILIZATION_WASTE"      # D1
    CAPACITY_WARNING = "CAPACITY_WARNING"        # D2
    COMPLIANCE_VIOLATION = "COMPLIANCE_VIOLATION"# D5
    VERSION_DRIFT = "VERSION_DRIFT"              # D7
    LIFECYCLE_EXPIRY = "LIFECYCLE_EXPIRY"        # D4 (P1 启用)
    HEALTH_ANOMALY = "HEALTH_ANOMALY"            # D6 (P1 启用)
```

**依赖**：无（可先行）

**验收**
- `python -c "from rg_contracts.enums import ResourceKind, DiffKind"` 通过
- 既有 138/136+2skip 全绿（枚举扩展不应改变任何行为）

**可能破坏的安全语义**：无。枚举扩展是纯增量。⚠️ 唯一风险是 `ResourceKind` 若被 `Base.metadata` 之外的白名单硬编码引用（如前端下拉框、导出字段校验），漏改会导致新 kind 走 `OTHER` 分支而**绕过 kind 级过滤**——本步需 grep `ResourceKind\.` 全量确认无硬编码白名单。

---

### S1｜域模型：`gpu_node` 表 + `resource` 两列 + `resource_diff.rule_code` + 幂等迁移

**文件（2）**
- `packages/contracts/src/rg_contracts/db/models.py`
- `packages/contracts/src/rg_contracts/db/session.py`

**改动**

1. `Resource` 加两列：
```python
owner_team: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
asset_tag:  Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
__table_args__ += (
    Index("ix_resource_project_kind", "project_id", "kind"),
    Index("ix_resource_project_level", "project_id", "classification"),
)
```

2. `ResourceDiff` 加一列：
```python
rule_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
__table_args__ += (Index("ix_diff_project_status_detected", "project_id", "status", "detected_at"),)
```

3. 新增 `gpu_node`（**主键即外键**）：
```python
class GpuNode(Base):
    """R1 GPU 节点属性表。刻意不持有 project_id / classification —— 密级只在锚点行。"""
    __tablename__ = "gpu_node"
    resource_id: Mapped[str] = mapped_column(
        ForeignKey("resource.id", ondelete="CASCADE"), primary_key=True
    )
    gpu_model:      Mapped[str | None] = mapped_column(String(64), nullable=True)
    total_gpus:     Mapped[int | None] = mapped_column(Integer, nullable=True)
    allocated_gpus: Mapped[int | None] = mapped_column(Integer, nullable=True)
    driver_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cuda_version:   Mapped[str | None] = mapped_column(String(32), nullable=True)
    mig_enabled:    Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    asset_tag:      Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    updated_at:     Mapped[str] = TS()
```

4. 新增 `resource_metric`（**同样不持有密级列**）：
```python
class ResourceMetric(Base):
    __tablename__ = "resource_metric"
    id:          Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("rm"))
    resource_id: Mapped[str] = mapped_column(ForeignKey("resource.id", ondelete="CASCADE"), nullable=False)
    metric_name: Mapped[str] = mapped_column(String(64), nullable=False)
    value:       Mapped[float] = mapped_column(Float, nullable=False)
    unit:        Mapped[str | None] = mapped_column(String(16), nullable=True)
    ts:          Mapped[str] = TS(index=True)
    __table_args__ = (UniqueConstraint("resource_id", "metric_name", name="uq_metric_resource_name"),)
```

5. `db/session.py` 新增幂等迁移（沿用 `_migrate_legacy_vector_columns` 模式）：
```python
def _migrate_expansion_columns(engine: Engine) -> None:
    """逐列 introspection + 缺哪补哪 + 幂等。PG 用 ADD COLUMN IF NOT EXISTS，
    SQLite 用 PRAGMA table_info。新表由 create_all 自动建，无需在此处理。"""
```
`ensure_schema()` 末尾调用之。

**依赖**：S0

**验收**
- 双方言（SQLite + PG）`ensure_schema()` 后 `gpu_node` / `resource_metric` 表存在，索引齐全
- **重复执行幂等**：`ensure_schema()` 连跑 3 次无异常、无重复列
- PG 上 `information_schema.columns` 确认 `resource.owner_team` / `resource.asset_tag` / `resource_diff.rule_code` 已加
- `GpuNode.resource_id` 与 `ResourceMetric.resource_id` 的 FK 与 `ON DELETE CASCADE` 生效（插入无锚点的属性行应报错）
- 既有 138/136+2skip 全绿

**可能破坏的既有安全语义**
- 🔴 **`ensure_schema()` 在每个 Pod 启动都会跑**（`main.py:29-40` + `startup.py:41`）。新增的 `ALTER TABLE ADD COLUMN` 在 SQLite 上会短暂持写锁——这正是 `services/audit.py::_is_lock_error` 处理的那种竞争。必须确认新迁移不放大 SQLite 锁竞争（PG 的 MVCC 不受影响）。
- 🔴 **`ondelete="CASCADE"` 是一把双刃剑**：删除 `Resource` 会级联删除属性行与指标行。若既有回收逻辑（`decommissioned_at`）依赖软删除后保留数据，级联会**静默删掉证据**。本步需确认 `resource` 的删除路径只有"物理删除"一种，且 `snapshot_state` 已保留历史证据。
- 🟡 新增索引会改变查询计划，可能让既有 board 查询走不同索引——性能回归风险，需跑一次全量对比。

---

### S2｜对象仓库层 + CI 裸查禁令 ★ 防漏关键基建

**文件（2，其中 1 新建）**
- `apps/api/src/rg_api/services/objects.py`（**新建**）
- `.github/workflows/ci.yml`（新增静态检查步骤）

**改动**
```python
# services/objects.py —— 唯一允许裸查属性表/指标表的地方

def load_details(session, model, resource_ids: Sequence[str]) -> dict[str, Any]:
    """入参必须是**已经过密级 + 项目过滤**的锚点 ID 集合。空集直接返回 {}。"""
    if not resource_ids:
        return {}
    rows = session.execute(
        select(model).where(model.resource_id.in_(list(resource_ids)))
    ).scalars().all()
    return {row.resource_id: row for row in rows}


def load_metrics(session, resource_ids: Sequence[str],
                 metric_names: Sequence[str] | None = None) -> dict[str, dict[str, float]]:
    """同上。返回 {resource_id: {metric_name: value}}。"""
    if not resource_ids:
        return {}
    stmt = select(ResourceMetric).where(ResourceMetric.resource_id.in_(list(resource_ids)))
    if metric_names:
        stmt = stmt.where(ResourceMetric.metric_name.in_(list(metric_names)))
    out: dict[str, dict[str, float]] = {}
    for row in session.execute(stmt).scalars().all():
        out.setdefault(row.resource_id, {})[row.metric_name] = row.value
    return out


def upsert_governed_object(session, *, resource: Resource, detail: Base | None = None,
                           metrics: dict[str, float] | None = None) -> Resource:
    """锚点 + 属性 + 指标的**唯一写入入口**：单事务内完成，杜绝"锚点写了属性没写"。"""
```

CI 新增一条静态检查（正则/ast）：
> `routes/*.py`、`collector/*.py`、`governance/*.py` 中不得出现 `select(GpuNode)` / `select(ResourceMetric)` / `select(ModelEndpoint)` / `select(TrainingJob)` / `select(GpuCluster)` / `select(K8sWorkload)`；仅 `services/objects.py` 白名单。

**依赖**：S1

**验收**
- 单元：`load_details(session, GpuNode, [])` 返回 `{}` 且不发 SQL
- **防漏回归（本步核心）**：插入一个 L4 项目的 `gpu_node`，用 `load_details(session, GpuNode, [l4_resource_id])` 直接查——**必须能查到**（证明该函数本身不做过滤，过滤责任在调用方传入的锚点集上）；同时断言调用方传入的集合来自 `_apply_level_filter` 后的结果
- CI 规则：在 `routes/` 里临时加一行 `select(GpuNode)` → CI 应失败（验证规则生效后再删除）

**可能破坏的既有安全语义**
- 🔴 **本层不过滤，是最容易被误解为"有漏洞"的地方**。`load_details` 拿到什么 ID 就查什么。安全性**完全依赖调用方传入已过滤的锚点集**。因此：
  - 函数 docstring 必须写明这条契约；
  - CI 规则必须同时禁止"绕过 `_apply_level_filter` 直接构造 `resource_id` 列表"的写法（如 `select(Resource.id).where(Resource.kind=='gpu_node')` 不带密级条件）；
  - S5 的判定引擎、S6 的看板必须各自有回归测试证明入参已过滤。
- 🟡 `upsert_governed_object` 若被绕过（采集器直接 `session.add(Resource)`），会产生"有锚点无属性"的孤儿——本层无法强制，靠 CI 规则 + code review。

---

### S3｜采集：k8s Provider 的 `gpu_node` 分支 + `simulated` 兜底 + 指纹扩展

**文件（3）**
- `packages/contracts/src/rg_contracts/collector/providers.py`（新增 `K8sProvider`，或新建 `collector/ai_infra.py` 后由其继承 `CloudProvider`）
- `packages/contracts/src/rg_contracts/enums.py`（`Platform` 增加 `K8S = "k8s"`，`PLATFORM_LABELS` 同步）
- `apps/api/src/rg_api/routes/collection.py`（`build_provider` 分支 + 写入改走 `upsert_governed_object`）

**改动**
- `K8sProvider.fetch_resources()`：K8s API 拉 Node（含 `nvidia.com/gpu` 标签与 Device Plugin 信息）→ `NormalizedResource(kind="gpu_node", …)`，异构属性放 `attributes`（仅作为**传递载体**，落库时由 `upsert_governed_object` 拆到 `gpu_node` 表）。
- `simulated` 兜底：同风格确定性合成数据（`SimulatedProvider` 已有 `random.Random(sha256(seed))` 的确定性写法，照抄）。
- **指纹扩展**（关键）：`NormalizedResource.fingerprint` 现含 `platform/native_id/kind/spec/status/region/tags/vpc`，**不含** `gpu_model`/`driver_version` 等新属性。若不扩展，`gpu_model` 变化不会产生 diff。扩展方式：
```python
_ATTR_FINGERPRINT_KEYS = {"gpu_model": ("gpu_node",), "driver_version": ("gpu_node",),
                          "cuda_version": ("gpu_node",), "served_version": ("model_endpoint",)}
# 仅当 self.kind 在对应元组内时，把该属性纳入指纹
```
- 采集写入改走 `upsert_governed_object()`（S2 提供），锚点行 + 属性行在同一事务。
- **密级契约不变**：仍走 `_project_classifications()`；`kind="gpu_node"` 不引入任何默认密级。

**依赖**：S1、S2

**验收**
- `POST /collection/run`（`provider=k8s`，`COLLECTOR_MODE=simulated`）后 `resource` 出现 `kind=gpu_node` 行，`gpu_node` 表有对应属性行，两者一对一
- **`classification` 继承项目目录**：造一个已知项目 + 一个未知项目，后者必须 `FAILED` + `project_not_in_directory` 审计（沿用 `test_collection_classification.py` 的断言形态）
- `dry_run=true` 不落库（既有契约）
- **指纹扩展生效**：同一 `native_id` 改 `gpu_model` 后再次采集 → 产生 `SPEC_CHANGED` diff
- 既有 138/136+2skip 全绿

**可能破坏的既有安全语义**
- 🔴 **指纹扩展会改变既有资源的 diff 行为**：`_ATTR_FINGERPRINT_KEYS` 若误包含 `kind` 之外类型也会用到的 key，会让既有的 host/vm 产生大量假 diff（看板洪水）。本步必须限定 key 的生效范围为其所属 kind。
- 🔴 **采集密级唯一来源不得被稀释**：新增 Provider 若图省事在 `NormalizedResource` 上带一个 `classification` 默认值，会直接推翻 P0-2 的修复。本步的 code review 重点。
- 🟡 `build_provider` 新增分支后，`POST /collection/run` 不带 `provider` 参数时会遍历**全部** Provider（含新的 k8s）——在客户未配 K8s 的环境下会全部失败并写 `failed` 审计。需确认 `COLLECTOR_MODE=api` 且凭证缺失时的失败是**显式报错**而非静默跳过（`credential()` 已是"缺失即报错"，不静默降级，符合预期）。

---

### S4｜指标：`resource_metric` 落库（承载 D1 利用率）

> **实现状态**：已落地。生产写入方是 `collector/metrics.py::upsert_metrics`（空字典不写行、脏值丢弃并留日志）；读取入口是 `apps/api/src/rg_api/services/objects.py::load_metrics`（先过锚点，再读表）。表内确无 `project_id` / `classification`（见 `test_expansion_s1_schema.py` 的 DDL 断言）。

**文件（2）**
- `packages/contracts/src/rg_contracts/collector/providers.py`（`MetricsProvider` 或 `K8sProvider` 的指标分支）
- `apps/api/src/rg_api/routes/collection.py`（指标 upsert 调用）

**改动**
- 采集时对 `gpu_utilization` / `gpu_memory_util` / `temperature_c` 等指标做 **upsert**（`UniqueConstraint(resource_id, metric_name)`，冲突则更新 `value` + `ts`）。
- **指标缺失 → 判 `unknown`，不误判**（PRD §8）：`resource_metric` 查不到该指标时，D1 规则跳过该对象，不得当作"利用率为 0"。
- 写入走 `upsert_governed_object(metrics=...)`，与锚点同事务。

**依赖**：S1、S3

**验收**
- 采集后 `resource_metric` 有 `(gpu_node_id, "gpu_utilization")` 行；重复采集更新值而非新增行
- 指标缺失场景：造一个无指标的 `gpu_node` → D1 规则**不产出**治理项（而非产出"利用率 0%"的误判）
- `resource_metric` 表**无** `project_id` / `classification` 列（DDL 断言）

**可能破坏的既有安全语义**
- 🔴 **指标值本身是敏感信号**（QPS 反推策略活跃度、利用率反推训练规模）。`resource_metric` 不持有密级列 → **任何读取必须先过锚点**。本步最大的出错点是"为图方便给指标表冗余 `project_id`"，一旦冗余就必须保证与主表一致（多一个双写点），且不一致时会被绕过。**明确禁止冗余。**
- 🟡 `resource_metric` 与 `resource` 同事务写入，会拉长采集事务时长——叠加 S3 后采集事务更重。若后续采集异步化（P1），此处需一并重构。

---

### S5｜判定引擎 + D1 规则 + 治理项写入

> **实现状态**：已落地，与下方草案的差异是「不把 `Session` 与 `settings` 传进规则」——`RuleAnchor` 只带已过滤的锚点 + 属性 + 指标，规则是纯函数（`governance/rules.py`）；阈值作为 `RuleContext` 字段传入，默认取 `GOVERNANCE_GPU_IDLE_UTIL_THRESHOLD`。编排与去重（同一 `(resource_id, rule_code)` 已有 open 项则不重复产出）在 `apps/api/src/rg_api/services/governance.py`。`DiffRecord.payload` 记录命中时的值，便于复核误判。

**文件（3，其中 2 新建）**
- `packages/contracts/src/rg_contracts/governance/__init__.py`（**新建**）
- `packages/contracts/src/rg_contracts/governance/rules.py`（**新建**：`GovernanceRule` 协议 + `D1UtilizationWasteRule`）
- `apps/api/src/rg_api/services/governance.py`（**新建**：编排，或合并进 `services/`）

**改动**
```python
@dataclass(frozen=True)
class RuleContext:
    """规则上下文。**刻意只承载单个 project_id / classification** ——
    规则天然无法跨项目聚合，从结构上杜绝"规则层拼出跨项目画像"。"""
    session: Session
    project_id: str
    classification: str          # 治理项密级 = 对象有效密级（含 dataset 传播值）
    anchors: list[Resource]      # 已过 _apply_level_filter 的锚点行
    details: dict[str, Any]      # objects.load_details(GpuNode, [a.id for a in anchors])
    metrics: dict[str, dict[str, float]]
    settings: Settings

class GovernanceRule(Protocol):
    dim: str          # "D1"
    code: str         # "d1_gpu_utilization_waste"
    def evaluate(self, ctx: RuleContext) -> list[DiffRecord]: ...
```

`D1UtilizationWasteRule` 判定：
```
allocated_gpus > 0
AND metrics["gpu_utilization"] 存在
AND metrics["gpu_utilization"] < settings.GOVERNANCE_GPU_IDLE_UTIL_THRESHOLD (默认 10.0)
→ DiffRecord(diff_kind=UTILIZATION_WASTE, rule_code="d1_gpu_utilization_waste",
             project_id=ctx.project_id, classification=ctx.classification, …)
```

编排层：
1. `project_ids = scoped_project_ids(subject, project_id)`
2. 逐项目：锚点集 = `_apply_level_filter(select(Resource).where(project_id==pid, kind=="gpu_node"), subject, pid)`
3. 构造 `RuleContext`（**密级 = 对象有效密级，不是调用者上限**——这点极易写错，见下）
4. 跑 D1 规则 → `DiffRecord`
5. `_to_diff_model(record, snapshot_id, classification)` 落 `resource_diff`

**依赖**：S1、S3、S4

**验收**
- 构造「`allocated_gpus=4` 且 `gpu_utilization=5.0`」的节点 → 产出 1 条 `UTILIZATION_WASTE` 治理项，带 `rule_code`
- 构造「`allocated_gpus=4` 且 `gpu_utilization=85.0`」→ **不产出**
- 构造「无指标」→ **不产出**（不误判）
- **越权回归（核心）**：L3 用户 + L4 项目的 `gpu_node` → 规则**不得**产出该对象的治理项（锚点集已为空）
- `resource_diff` 行的 `classification` 与锚点行一致（`diff_scope_clause` 依赖此字段）
- 既有 138/136+2skip 全绿

**可能破坏的既有安全语义**
- 🔴 **`classification` 字段取值的两个陷阱**：
  1. 治理项的 `classification` 必须是**对象的有效密级**（可被 `dataset` 传播抬升），不是**调用者的密级上限**。若误写为调用者上限，则低密级用户触发的治理项会带低密级，随后高密级用户就能看到本不该对他隐藏的对象存在性——反之亦然。
  2. 若治理项密级低于对象密级，`diff_scope_clause` 会放行 → **以治理项形态泄漏高密级对象存在性**。
- 🔴 **规则层不得重查全表**。若规则内部为省事写了 `session.execute(select(GpuNode).where(...))`，就绕过了锚点过滤——这正是 S2 的 CI 规则要拦的。规则签名已把 `anchors`/`details`/`metrics` 作为入参，从签名上就不给 `session` 全表查询的便利（但 `ctx.session` 仍在，靠 CI + review）。
- 🟡 **跨项目聚合禁止下沉到规则层**：`RuleContext` 单项目的设计就是为了这条。若后续 D2 容量水位需要"全集群视角"，必须在 board 层做，不能在规则层做——规则层一旦能做跨项目聚合，就等价于给了攻击者一个"跨项目拼图"的合法出口。

---

### S6｜看板 + 处置 + 导出

> **实现状态**：board / export / `DiffOut` 已补 `rule_code`（前端据此区分「变化」与「规则命中」），处置接口零改动已生效。`GET /resources/{id}` 详情端点已实现（`routes/resources.py::get_resource_detail`）：按「先 `check_project` → 再 `check_level` → 最后经 `services/objects.py` 按锚点读属性/指标/GPU」的顺序，越权请求在召回之前就被拒；未采到的指标不补 0（缺 = unknown）。

**文件（2）**
- `apps/api/src/rg_api/routes/governance.py`（board / cost-impact 支持新 `diff_kind`；export 增 `owner_team`）
- `apps/api/src/rg_api/routes/resources.py`（新增 `GET /resources/{id}` 详情端点，含属性投影）

**改动**
- `board` / `cost-impact`：**零改动**即可展示新 `diff_kind`（走 `diff_scope_clause`，按 `diff_kind` 分组）。（原计划的 `.limit(200)` 截断问题已修：汇总改全量聚合，列表上限 50 + `truncated` 提示，见 §4 已知局限第 2 行）
- 新增 `GET /resources/{id}`：
  1. `_engine.check_project(subject, row.project_id)`
  2. `_engine.check_level(subject, row.project_id, row.classification)`
  3. `objects.load_details(session, GpuNode, [id])` + `objects.load_metrics(session, [id])`
  4. 拒绝时 `audit_action(..., "denied", ...)`（自动走独立事务）
- 导出：`owner_team` **保留**（团队粒度是治理必需），个人 `owner` 仍脱敏；行数/频次限制不变。
- **人工处置零改动**：`POST /governance/diff/{id}/resolve` 已有 `assert_project_access` + `check_level`，新 `diff_kind` 自动覆盖。

**依赖**：S5

**验收**
- `GET /governance/board` 出现 D1 治理项
- **越权回归**：L3 用户对 L4 项目的治理项调用 `resolve` → 403 + `denied` 审计落库（走独立事务，回滚不丢）
- `POST /governance/diff/{id}/resolve` 对 D1 治理项 → 200 + `audit_log` 有 `governance:resolve` / `allowed`
- `GET /resources/{id}`：L3 用户访问 L4 资源 → 403；访问本密级资源 → 200 且带属性与指标
- 导出结果含 `owner_team`、不含个人 `owner`
- 既有 138/136+2skip 全绿

**可能破坏的既有安全语义**
- 🔴 **`GET /resources/{id}` 是新增端点，是本次扩展的唯一"新入口"**。三个必须写全：`check_project` + `check_level` + `denied` 审计。漏任何一个都会成为新的越权口。特别注意：**必须先 `check_level` 再 `load_details`**——若先查了属性再校验，虽然不影响返回值，但会把属性读进内存，违反"先授权后召回"的精神。
- 🔴 **导出新增 `owner_team` 的边界**：`owner_team` 是团队粒度（保留），`owner` 是个人（脱敏）。若实现时图省事把 `resource.owner` 一并带上，直接违反 PRD §6.7 导出脱敏。
- 🟢 `board` 的列表截断问题**已修**：汇总改为对全量行做聚合，列表只返回最新 50 条并以 `truncated` / `item_cap` 明示（旧实现是 `limit(200)` 后在内存累加，超过 200 时汇总数字本身偏小）。

---

### S7｜安全挂接与守护

**文件（5，其中 3 新建）**
- `packages/contracts/src/rg_contracts/seed/demo.py`（演示种子加 `gpu_node` + 指标）
- `packages/contracts/src/rg_contracts/security/canary.py` + `seed/demo.py::build_canaries()`（新增 `gpu_node` 伪装诱饵）
- `apps/api/tests/test_expansion_r1_closed_loop.py`（**新建**：端到端闭环）
- `apps/api/tests/test_expansion_r1_level_filter.py`（**新建**：越权回归）
- `apps/api/tests/test_expansion_r1_audit_denied.py`（**新建**：拒绝审计守护，扩展既有清单）

**改动**
- **金丝雀**：`build_canaries()` 目前是唯一的诱饵来源（`startup.py:31-36`）。P0 必须至少补 `gpu_node` 伪装条目（伪装卡型/驱动版本/项目代号），否则金丝雀对 AI infra 事实完全空转。
- **拼图账本**：`jigsaw.py` 的 `detect_dimensions` 覆盖的文本里若含 GPU 拓扑/驱动版本，需确认新增类型被纳入敏感维度统计；`RetrievalLedger` 按 `chunk_id` 记账，AI infra 事实入向量库后自动覆盖——**本步需验证一条**：知识库写入 `gpu_node` 相关文档后，检索账本能记到。
- **拒绝审计守护**：把新增端点（`/resources/{id}`、`/resources/ai/*`）加入「端点 Δdenied==1」的回归清单。
- 演示种子：`gpu_node` × N + 对应指标，供 `simulated` 与看板演示。

**依赖**：S6

**验收**
- 新增端点的越权请求 → `AuditLog` 有 `denied` 且 `SecurityEvent` 有 `access_denied:*`（**独立事务，业务回滚不丢**）
- 金丝雀：构造含伪装 `gpu_node` 诱饵值的文本 → `canary_registry.scan()` 命中
- 端到端：采集 → D1 规则 → board → resolve 全链路跑通，`audit_log` 齐全
- 既有 138/136+2skip 全绿

**可能破坏的既有安全语义**
- 🔴 **金丝雀诱饵若做成"每个项目自动生成"会与 P1-05 冲突**：当前诱饵仅来自演示数据。P0 只补 `gpu_node` 类型的演示诱饵，**不要**在这里尝试做"项目级自动生成"（那是 P1-E5 的范围）。若本次把诱饵写死进 `build_canaries()` 而客户项目无诱饵，金丝雀仍空转——这一点必须在验收标准里**显式标注为已知局限**，不要假装已解决。
- 🟡 演示种子新增数据会让既有测试的"计数类断言"失败（如 `test_api.py` 里断言资源总数）。本步需逐个复核并调整。

---

### 步骤总览与文件数

| 步骤 | 内容 | 文件数 | 依赖 | 可并行 |
|---|---|---:|---|---|
| S0 | 枚举扩展 | 1 | — | ✅ 可先行 |
| S1 | 域模型 + 幂等迁移 | 2 | S0 | |
| S2 | 对象仓库层 + CI 裸查禁令 ★ | 2（1 新建） | S1 | ✅ 与 S3 部分并行 |
| S3 | k8s Provider + 指纹扩展 | 3 | S1、S2 | |
| S4 | `resource_metric` 落库 | 2 | S1、S3 | |
| S5 | 判定引擎 + D1 规则 | 3（2 新建） | S1、S3、S4 | |
| S6 | 看板 + 新增详情端点 + 导出 | 2 | S5 | |
| S7 | 安全挂接 + 3 个回归测试 | 5（3 新建） | S6 | |

**合计：约 20 个文件**（其中新建 7 个）。后端核心（S0–S6）约 13 个文件。

> S8 前端看板（`apps/web/src/views/*`、`api/client.ts`，约 3 个文件）**不在端到端闭环的必要路径上**——API 层验收通过即可证明闭环成立。建议放在 R1 主线之后、横向复制之前做，或与客户确认是否可延后。

---

## 2. 横向复制清单（R2 / R3 / R4 / R6）

四类对象**复用 S0–S7 的同一套骨架**，只替换「表字段 / 判定规则 / Provider」三处。下表给出每类的差异点，**不重复写分步**。

### 通用复制步骤（四类都适用）
1. S1 建表（PK=`resource_id`，不持有 `project_id`/`classification`）
2. S2 `services/objects.py` 的 `load_details` 已泛化（入参是 model），**只需在 CI 白名单加新模型名**
3. S3 Provider 分支 + `simulated` 兜底 + `_ATTR_FINGERPRINT_KEYS` 补该 kind 的属性键
4. S4 指标名补进采集清单
5. S5 新增一条 `GovernanceRule` 子类（**复制 `D1UtilizationWasteRule` 的结构**）
6. S6 board/export **零改动**（除非新增端点）
7. S7 金丝雀补该类型诱饵 + 拒绝审计清单扩展

### 各类差异点

| | **R2 GPU 集群** | **R3 训练任务** | **R4 模型端点** | **R6 K8s 负载** |
|---|---|---|---|---|
| 表名 | `gpu_cluster` | `training_job` | `model_endpoint` | `k8s_workload` |
| 关键字段 | `scheduler`、`total_gpus`、`free_gpus`、`mig_profiles`(JSON) | `framework`、`image`、`gpu_request`、`gpu_used`、`status`、`queue_wait_min`、`dataset_ids`(JSON 数组) | `model_name`、`served_version`(→`model_version.id`)、`replicas`、`source`、`exposed`、`approved` | `workload_kind`(cluster/namespace/pod)、`cpu_req/lim`、`mem_req/lim`、`phase`、`node`、`owner_team` |
| 判定规则 | **D2 容量水位**：`free_gpus / total_gpus < 阈值` → `CAPACITY_WARNING` | **D1**：`status=running` 且 `gpu_util_avg < 阈值` → `UTILIZATION_WASTE` | **D7 版本漂移**：`served_version` ≠ 最新 `approved` 的 `model_version.id` → `VERSION_DRIFT`；**D5 合规**：`source=external_download` 且 `approved=false` → `COMPLIANCE_VIOLATION` | **D1**：`cpu_req` 长期远高于 `cpu_used` → `UTILIZATION_WASTE` |
| Provider | `k8s`（调度器 API / Volcano / Slurm） | `k8s`（Job / SparkApplication 标签） | `model_registry`（MLflow / 推理网关） | `k8s`（Node / Namespace / Pod API） |
| 指纹键 | `scheduler`、`mig_profiles` | `framework`、`image`、`status` | **`served_version`**（D7 的命脉，必须入指纹） | `phase`、`cpu_req`、`mem_req` |
| **额外依赖** | 无 | **`dataset` 表 + 密级向上传播**（`training_job.dataset_ids` → 有效密级 = max(继承密级, dataset 上限)） | **`model_version` 表**（D7 对账基线）；**独立表已拍板**，仍需锚点行承载密级 | 无 |
| **特殊安全点** | `free_gpus` 是跨作业聚合值 → 只能在本项目内聚合，**规则层天然单项目**已保证 | 🔴 **dataset 传播后 `classification` 可能抬升到 L4** → 该对象事实**禁止向量化**（`VECTORIZABLE_MAX_LEVEL=L3_CONFIDENTIAL`） | 🔴 **出网合规（D5）**：`exposed=true` 或 `source=external_download` 必须复用 `MODEL_GATEWAY_ALLOW_PUBLIC` 白名单 + 出网前 DLP + 注入检测 | `owner_team` 是团队粒度，导出保留；`node` 字段可能隐含物理位置，导出需评估 |
| 新增端点 | 无（board 聚合即可） | 无 | 可能需 `/model-registry/*`（若需人工审批模型来源） | 无 |

### 复制顺序建议

```
R1（主线，S0–S7）
  → R4 模型端点   ← 第二优先：D7 + D5 覆盖"版本漂移 + 出网合规"，价值密度最高，
                     且能最早验证 model_version 对账与"独立表 + 锚点"的磨合
  → R6 K8s 负载   ← 第三：复用 k8s Provider，字段同构，复制成本最低
  → R3 训练任务   ← 第四：需要 dataset 密级传播先落地（可并入 P1-E4）
  → R2 GPU 集群   ← 第五：依赖 R1/R6 的聚合基础，且容量水位需要真实调度器数据
```

---

## 3. 最容易被做砸的三个点

### 🥇 第一：`resource_diff.classification` 取错值 —— 以治理项形态泄漏高密级对象存在性

治理项落库时的 `classification` 必须是**对象的有效密级**（可被 dataset 传播抬升），**不是调用者的密级上限**。

- 写错成调用者上限的后果：L3 用户触发的治理项带 L3 密级，但对象实际是 L4 → 该治理项对**其他 L3 用户**可见 → 以"某项目有一台 L4 GPU 节点闲置"的形态泄漏对象存在性，而 `diff_scope_clause` 完全拦不住（它只信 diff 行自己的 `classification`）。
- 更隐蔽的是：这个错误**不会让任何既有测试失败**，因为既有测试没有"跨密级治理项"的场景。
- **缓解**：S5 的验收里必须有一条跨密级断言（L3 用户对 L4 项目不得产出治理项），且 S5 落库前断言 `diff.classification == resource.classification`。

### 🥈 第二：`upsert_governed_object()` 被绕过 —— 产生"有锚点无属性"的孤儿

`resource` 表加行与 `gpu_node` 表加行是两次 `session.add`。虽然 PK=FK 保证了"属性行不可能指向不存在的锚点"，但**反向**（锚点有、属性没有）数据库管不了。

- 后果：看板显示 GPU 节点但点开无详情；D1 规则读不到 `allocated_gpus` 而静默跳过 → **治理盲区比报错更危险**（看起来在管，其实没管）。
- 最可能的触发场景：后续复制 R2/R3/R4/R6 时，工程师照抄 S3 但漏了属性写入那一步；或 P1 做"采集异步化"重构时把两次写入拆到了不同事务。
- **缓解**：
  1. `upsert_governed_object()` 是唯一入口，CI 规则禁止 `routes/` 与 `collector/` 直接 `session.add(Resource)`；
  2. 加一条**孤儿巡检**：统计 `resource.kind IN (新类型) AND NOT EXISTS(对应属性行)` 的计数，暴露为 `/ready` 的一个字段 + 告警（比只在测试里断言更持久）；
  3. 复制清单里把"属性写入"单列一步，不要让它淹没在"Provider 实现"里。

### 🥉 第三：把"密级过滤"继续当成人人都记得写的东西 —— 在新增 6 张表后重蹈 P0-5 / P0-6

本项目已经实证过两次"漏过滤"：
- `/resources/stats` 两个聚合漏 `_apply_level_filter` → L3 读到 L4 项目月成本
- `_candidate_ids` 把密级过滤写进 `if not unrestricted` → L2 治理岗检索到 L3 分片原文

两次的根因都不是"不知道要过滤"，而是**"过滤靠每个查询自觉调用，没有结构约束"**。这次扩展新增 6 张表 + 至少 2 个新查询入口（`/resources/{id}`、`/resources/ai/*`），如果还是只靠 review 记得，第三次是必然的。

- **结构性防线（必须三条同时上，缺一条都不算做完）**：
  1. **物理约束**：属性表与指标表**不持有** `project_id` / `classification` —— 漏了也构造不出越权查询（S1）
  2. **入口收敛**：唯一裸查点是 `services/objects.py`，CI 静态规则禁止他处裸查（S2）
  3. **契约测试**：参数化的"低密级账号 × 高密级对象 × 所有新入口"越权回归（S7）
- **不要**指望 P1 的"全局 ORM 行级过滤"（方案 C）来兜底——它对 `select(func.count(...))` 这类 Core 聚合语句**不生效**，而聚合恰恰是我们已经漏过的那类查询。

---

## 4. 已知局限（显式记录，不静默跳过）

| # | 局限 | 影响 | 计划 |
|---|---|---|---|
| 1 | 金丝雀诱饵仍只来自 `build_canaries()` 演示数据，客户新建项目无诱饵（P1-05 未修） | 金丝雀对客户真实 AI infra 数据空转 | P1-E5 做项目级自动生成 |
| 2 | `board` 的列表上限（原 `.limit(200)` 硬编码） | 已修：汇总改为对全量行做 `GROUP BY` / `SUM`，列表只返回最新 50 条并在响应里用 `truncated` / `item_cap` 明示；旧实现的「超 200 后汇总数字本身偏小且无提示」不再存在（`apps/api/tests/test_governance_board_aggregates.py` 守） | 已落地；若客户需要翻页再补 offset/cursor 参数 |
| 3 | 预算（跨项目探测合成键用序号、进程内 dict）未修；`check_export` 已接入 | `enforce_export` 现在同时调用策略引擎的行数上限与 `QueryBudget.check_export`（小时频次），导出双闸门真实生效；跨项目探测的合成键与进程内 dict 仍是已知局限 | 频次闸门已生效；多副本下预算不共享，需外部计数存储才能全局一致 |
| 4 | 锚点是否泛化为 `governed_object` 尚未定论（见 `architecture-expansion.md` §7.1） | 若客户坚持"model_endpoint 完全不进 `resource`"，需一次全量迁移 | P1 独立议题，R1 端到端跑通后再评估 |
| 5 | 前端看板（S8）未在本计划内 | API 层闭环成立，但用户不可见 | R1 主线后补，或与客户确认延后 |
