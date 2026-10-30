# 架构设计（增量）：资源治理维度扩展（含 MLOps 与 AI Infra）

- 配套文档：`docs/prd-resource-governance-expansion.md`
- 设计原则：**只做增量，不改现有契约语义**。复用 `packages/contracts → apps/api → apps/web` 三层、现有域模型树、安全模型、采集接口与治理闭环。
- 安全不变式（PRD §6）是本设计的硬约束，任何模块不得破坏。

> **修订说明（2026-10-23，架构师高见远）**
> 依据用户拍板结果修订，三处变更：
> 1. **§1 域模型增量**整体重写 —— 存储方案由「`Resource.attrs` JSONB 宽列」改为「**锚点 + 类型专属表**」（分表）。
> 2. **新增 §1.6 治理闭环锚点选型（A/B/C 三方案对比）** —— 本次修订的**最高优先级**章节，闭环方案由此节结论决定。
> 3. **§7 由「待拍板开放决策」改为「已拍板决策」** —— 含决策依据、代价与被否决方案的致命缺陷。
>
> §2 判定引擎 / §3 采集层 / §4 安全扩展点 / §5 任务分解 / §6 回归与迁移 / §8 知识库衔接**内容保留**（按 §1.6 结论做必要的一致性修正）。
>
> 术语：**锚点（anchor）** = 治理闭环唯一指向的对象行，即 `resource` 表的一行；**属性表（detail table）** = 类型专属表。

---

## 1. 域模型增量

### 1.0 设计主轴：锚点唯一 + 属性分表

用户已拍板「扩展字段走各自专属表」。本设计把这句话落成一条可执行的数据库级约束：

> **治理闭环只认一个锚点表（`resource`）。类型专属表与指标表刻意不持有 `project_id` 与 `classification`，因此物理上无法被单独过滤——也物理上无法被绕过。**

这一条是整个扩展的安全基座，论证见 §1.6。

### 1.1 `Resource`（锚点表，改动：+2 列 +2 索引）

现有 `Resource`：`id / platform / account_id / project_id / native_id / name / kind / region / spec / status / monthly_cost_cny / classification / owner / first_seen_date / last_seen_date / decommissioned_at / attributes`。

| 变更 | 字段 | 类型 | 用途 |
|---|---|---|---|
| 新增列 | `owner_team` | `String(64)`，可空，索引 | D3 成本归属与按团队过滤的**高频聚合列**，提升为独立列而非塞进 JSON |
| 新增列 | `asset_tag` | `String(64)`，可空，索引 | **CMDB 资产编号**（已拍板决策 #5）：物理机与云主机的关联键，不引入新指纹算法 |
| 枚举扩展 | `kind` | `String(32)` | 增加 `gpu_node`/`gpu_cluster`/`training_job`/`model_endpoint`/`k8s_cluster`/`k8s_namespace`/`k8s_pod`/`dataset`/`vector_db`/`notebook`（见 PRD §3） |
| 新增索引 | `ix_resource_project_kind` | `(project_id, kind)` | 跨类型聚合与按 kind 列表的主路径 |
| 新增索引 | `ix_resource_project_level` | `(project_id, classification)` | 密级过滤主路径（与 `_apply_level_filter` 的条件顺序一致） |

**不新增 `attrs` JSONB 列** —— 已被用户否决（异构属性走专属表）。既有 `attributes`（`JsonDict()`）保留，仅服务 `tags` 与 `compute_diff` 的既有契约，**不作为新对象的属性通道**。

**密级语义不变**：`classification` 仍由采集侧 `_project_classifications()` 从项目目录取（P0-2 已修复的「唯一事实源 + 失败关闭」），新增 kind 不引入任何新的密级默认值。

### 1.2 类型专属表（属性投影，全部新增）

五类 P0 对象各一张表。**主键即外键**（`resource_id` 作 PK + FK `resource.id`）：

```python
class GpuNode(Base):
    __tablename__ = "gpu_node"
    resource_id: Mapped[str] = mapped_column(
        ForeignKey("resource.id", ondelete="CASCADE"), primary_key=True
    )
    ...
```

| 表 | R# | 字段（除 `resource_id` 外键外） | 说明 |
|---|---|---|---|
| `gpu_node` | R1 | `gpu_model`(A100/H800…)、`total_gpus`、`allocated_gpus`、`driver_version`、`cuda_version`、`mig_enabled`、`asset_tag` | 利用率/温度走 `resource_metric`（时序），不落本表 |
| `gpu_cluster` | R2 | `scheduler`(Volcano/Slurm)、`total_gpus`、`free_gpus`、`mig_profiles`(JSON) | `free_gpus` 为快照值，容量水位由 D2 读 |
| `training_job` | R3 | `framework`(PyTorch/…)、`image`、`gpu_request`、`gpu_used`、`status`(running/pending/completed)、`queue_wait_min`、`dataset_ids`(JSON 数组) | `gpu_util_avg`/`duration_h` 走指标 |
| `model_endpoint` | R4 | `model_name`、`served_version`(→`model_version.id`)、`replicas`、`source`(internal/external_download)、`exposed`(bool)、`approved`(bool) | `qps`/`p99_latency_ms`/`queue_len` 走指标 |
| `k8s_workload` | R6 | `workload_kind`(cluster/namespace/pod)、`cpu_req`、`cpu_lim`、`mem_req`、`mem_lim`、`phase`、`node`、`owner_team` | `restart_count` 走指标；三 kind 合并一张表 + `workload_kind` 区分（字段同构，避免为 P0 建三张表） |

**关键约束（不可省略）**：

1. **不持有 `project_id` / `classification`** —— 密级只在锚点行上。「裸查属性表」无法构造出任何密级条件，**只能在物理上被迫先过锚点**。
2. **PK = FK + `ondelete="CASCADE"`** —— 数据库强制 1:1：`resource` 删除则属性行级联删除；属性行不可能指向不存在的锚点。**这消除了「双写不一致」里的孤儿问题**（详见 §1.6-A′ 代价栏）。
3. **写入必须走统一入口** `upsert_governed_object()`（见 §1.8），禁止采集器/路由分别 `session.add(Resource)` 与 `session.add(GpuNode)`。

### 1.3 指标通道 `resource_metric`（承载 D1 / D6，已拍板：落库）

```text
resource_metric(
  id, resource_id FK(resource.id, ondelete=CASCADE),
  metric_name, value REAL, unit, ts TIMESTAMP,
  UNIQUE(resource_id, metric_name)          # 最新值表
)
```

- **最新值 + 历史分离**：本表按 `(resource_id, metric_name)` 唯一，采集时 upsert 最新值；历史明细走 `resource_metric_history`（P1，可选）或按 `ts` 滚动保留 N 天。P0 只落最新值，判定引擎读最新值做阈值比较。
- **不直查 Prometheus/Zabbix**（已拍板）：离线部署下判定链路不能受监控系统可用性牵制，且要可审计、可回放。Prometheus/DCGM 只在**采集器侧被消费一次**。
- **指标缺失 → 判 `unknown`，不误判**（沿用 PRD §8 兜底契约）。
- **同样不持有 `project_id` / `classification`** —— 与属性表同一约束。

### 1.4 结构化实体（需结构化对比 / 密级传播）

| 表 | 时机 | 字段 |
|---|---|---|
| `model_version` | **P0**（D7 是 P0 维度，需其作为数据基础） | `id / registry / name / version / approved / lineage_dataset_id / embedding_model_version / created_at` |
| `dataset` | **P0 建表，P1 接采集**（密级传播链是安全项，不能延后到 P1 才建表） | `id / project_id / name / size_gb / contains_pii / classification / owner_team / storage_backend / created_at` |

- `model_endpoint.served_version` 存 `model_version.id`。D7 漂移 = `served_version` ≠ 该 endpoint 下最新 `approved` 的 `model_version`。
- **`dataset` 自带密级，可高于所属项目**（PRD §3 R7）。

### 1.5 数据集密级向上传播（已拍板：确认）

传播规则（**保守方向，取高不取低**）：

```
effective_level(training_job | model_endpoint)
    = max( 自身继承的项目密级, 其输入 dataset 的密级上限 )
```

即：训练任务/模型端点的**有效密级不低于**其引用数据集的最高密级，防止「低密级任务引用高密级数据集」绕过密级。

**落地点只有一处：写入期**。采集/登记时计算 `effective_level` 并写回锚点行 `resource.classification`（一次计算，查询期无需 join）。

> **刻意不在 `ceiling_for`（`security/policy.py:85-92`）里加 dataset 分支**——原 §7.4 曾考虑这条路，予以否决。理由：① 把「密级」与「授权」耦合，语义混乱；② 每次请求都要查 dataset 表，热路径加查询；③ `ceiling_for` 是既有安全不变式的核心，改动它的回归风险远大于在写入期抬升密级。

**回归守护**：新增测试「L4 dataset 被 L2 项目内的 training_job 引用 → 该 training_job 锚点行 `classification == L4_SECRET` → L3 用户不可见」。

### 1.6 治理闭环锚点选型（A / B / C 三方案对比）★ 最高优先级

> 现有闭环是**单表**的：`Resource → ResourceDiff → board → resolve`。
> 密级过滤（`_apply_level_filter` / `diff_scope_clause`）、授权预过滤（`scoped_project_ids`）、统计聚合全部围绕 `resource` 这张表写。
> 分表后闭环怎么走？以下三方案逐项评估。

---

#### 方案 A′（**推荐**）：锚点唯一 + 属性分表（`ResourceDiff` 零改动）

- 每类新对象在 `resource` 登记一行（`kind` 扩展）+ 在专属表存属性（PK=FK）。
- `ResourceDiff.resource_id` 仍指向 `resource.id`，**`ResourceDiff` 与 board / cost-impact / resolve / export 全部零改动**。
- 属性表与指标表**不持有密级列**，只能通过 `resource_id IN (已过滤锚点集)` 访问。

| 评估项 | 结论 |
|---|---|
| **改动面** | 最小。`ResourceDiff` 不动；board/cost-impact/export/resolve 不动；`diff_scope_clause` / `_apply_level_filter` / `scoped_project_ids` 不动。新增：5 属性表 + 1 指标表 + 2 实体表 + `resource` 2 列 + 1 个仓库层 + 1 个规则层。 |
| **安全过滤漏点** | **1 处**（新增 detail/metric 端点）。且该处**无法绕过**——属性表无密级列，漏了也构造不出越权查询，只会「查不到」。 |
| **跨对象聚合** | 单行 SQL：`SELECT kind, COUNT(*), SUM(monthly_cost_cny) FROM resource WHERE <密级+项目> GROUP BY kind`。过滤只写一次。 |
| **迁移路径** | **零迁移代码**：新表由 `create_all` 自动建（模型注册进 `Base.metadata`）；仅 `resource` 的 2 个新列与 `resource_diff.rule_code` 需要幂等 ALTER。 |
| **代价** | ① `resource` 行数随新对象膨胀（列数不变，索引可覆盖）；② 双写由 PK=FK + 事务保证，但需 `upsert_governed_object()` 统一入口；③ 与用户决策「model_endpoint = 独立表」的字面表述需对齐（见 §7.1）。 |

---

#### 方案 B（**否决**）：闭环按类型分派（`ResourceDiff` 多态 `(object_type, object_id)`）

- 每类对象一张独立表，**各自持有 `project_id` + `classification`**；`ResourceDiff` 扩 `(object_type, object_id)`，`resource_id` 退化为「仅 host/vm 用」的弱引用；判定引擎按类型分派；board 聚合改为 UNION 多路。

**致命缺陷（具体到「会漏哪条安全过滤」，不是"改动面大"这种程度）：**

| # | 致命缺陷 | 具体后果 |
|---|---|---|
| **B-1** | **密级过滤从「写 1 次」变成「写 5×N 次」** | `gpu_node`/`gpu_cluster`/`training_job`/`model_endpoint`/`k8s_workload` 五张表各要一套 `or_(and_(project_id==pid, classification.in_(levels_at_or_below(ceiling_for(pid)))))` 分支。**本项目历史上已经因「每个查询自觉调用 helper」漏了两次并实证泄露**：① `/resources/stats` 两个聚合查询漏 `_apply_level_filter`（L3 账号读到 L4 项目月成本 42114.49）；② `_candidate_ids` 把密级过滤写进 `if not unrestricted` 分支（L2 治理岗检索到 L3 分片原文）。把这种「自觉」从 17 个端点放大到 `17 + 5×N` 个查询，是拿已修复的 P0 去赌不会第三次犯同样的错。 |
| **B-2** | **UNION 聚合是最难 review 的漏过滤形态** | 成本看板会是 `SELECT … FROM gpu_node WHERE <过滤A> UNION ALL SELECT … FROM model_endpoint WHERE <过滤B> …`。五路过滤「看起来都有」（复制粘贴而来），review 极难发现其中一路写成了 `classification == ceiling` 而非 `in_(levels_at_or_below(ceiling))`，或漏了 `ceiling_for(pid)` 的 per-project 分支。而 UNION 的语义是**任何一路漏了，整个看板就整体泄露**。 |
| **B-3** | **外键退化 → 孤儿数据只能靠应用层发现** | `ResourceDiff.resource_id` 从 FK 降级为弱引用字符串，`resource_metric.resource_id` 同样。对象被删而 diff 仍在时数据库不会报错，只能靠应用层一致性检查——而这类检查最容易被跳过。 |
| **B-4** | **diff 行冗余密级与对象实际密级可能不一致，泄漏存在性** | `diff_scope_clause` 只按 `ResourceDiff.classification` 过滤。若对象密级被 dataset 传播抬高（§1.5）而 diff 行冗余值未同步刷新，diff 就会以低密级形态泄漏**高密级对象的存在性**。方案 A′ 因为密级只在锚点一处，不存在这个问题。 |
| **B-5** | **改动面直接冲击既有回归基线** | `ResourceDiff` 加列 + board / cost-impact / export / 归因 / 前端全改；既有 138（SQLite）/136+2skip（PG）中涉及 diff 的用例需逐条复核。在「先跑通一类端到端」的窗口内，这是不可承受的返工面。 |
| **B-6** | **迁移多一步数据回填** | 新表虽可由 `create_all` 建，但 `ResourceDiff` 加 `object_type`/`object_id` 后需**回填既有 diff 行**（`object_type='resource'`）——多一个数据迁移步骤，多一处出错点。A′ 无此步。 |

---

#### 方案 C（**否决为 P0 基础，采纳为 P1 增强**）：ORM 层全局强制行级过滤

- 用 SQLAlchemy 2.0 的 `do_orm_execute` + `with_loader_criteria` 注册全局钩子：对所有声明了 `LevelScoped` mixin 的模型，**自动**注入 `classification IN (…) AND project_id IN (…)`。
- 吸引力：新增表只要声明 mixin 就自动获得过滤，不依赖调用方自觉——**理论上根治了 B-1**。

**为什么不作为 P0 基础：**

| # | 缺陷 | 说明 |
|---|---|---|
| **C-1（决定性）** | **覆盖不了聚合查询——而聚合恰恰是我们已经漏过的那类** | `do_orm_execute` 只对 **ORM** 语句生效。`session.execute(select(func.count(Resource.id)))` 是 **Core** 语句，不触发 ORM 事件。本项目 `/resources/stats` 与 `/governance/cost-impact` 正是这种写法——**也就是实证泄露过的那条路径**。用覆盖不了最危险查询的机制做安全基座，是虚假安全感。 |
| **C-2** | 需把 `subject` 经 ContextVar 注入 ORM 事件层 | 现有 `request.state.subject` 在 ORM 层拿不到，需新增 ContextVar + 中间件。任何一处上下文未绑定（脚本、后台任务、测试）会导致「注入了空条件」或「注入了错误条件」，**失败模式是静默的**。 |
| **C-3** | `unrestricted` 语义（放开项目范围、**不放开密级**）要在钩子内分支 | 与已修复的 P0-5 是同一处逻辑，但被搬进隐式全局钩子，排错时看不见。 |
| **C-4** | 既有 138 测试的 SQL 行为会被隐式改变 | 回归风险高，失败现象是「某条 SQL 突然多了一个 WHERE」，不易定位。 |

**采纳方式**：P1 阶段（P1-E5）在 A′ 稳定后，把 C 作为**第二道防线**叠加。但**安全基座永远是 A′ 的「属性表物理上不持有密级列」这一约束**，C 只是锦上添花。

---

#### 结论

> **采用方案 A′。** 一句话理由：**把「密级过滤要写 N 遍」变成「属性表物理上没有密级列，只能经锚点访问」——用数据库结构消除漏过滤的可能，而不是靠人的自觉或框架的隐式注入。**

| | A′ | B | C |
|---|---|---|---|
| 闭环改动 | **零** | 大（多态 + UNION） | 中 |
| 密级过滤书写次数 | **1 次**（锚点） | 5×N 次 | 0 次（但聚合覆盖不到） |
| 漏过滤的失败方向 | **fail-safe**（漏了=查不到） | **fail-open**（漏了=泄露） | fail-open 且不可见 |
| 跨类型聚合 | 单行 SQL | UNION 五路 | 同 A′ |
| 迁移代码量 | **0**（新表 create_all） | ALTER + 回填 | 同 A′ |
| 与既有回归基线冲突 | 小 | **大** | 中 |

---

### 1.7 `ResourceDiff` 变更（最小）

**更正**：现有枚举的实际值为 `{NEW, REMOVED, SPEC_CHANGED, STATE_CHANGED, TAG_CHANGED, OWNER_CHANGED}`（见 `packages/contracts/src/rg_contracts/enums.py:63-70`），并非 PRD §4 注释中的 `{drift, new, deleted, cost_change}`。**以代码为准。**

| 变更 | 字段 | 说明 |
|---|---|---|
| 新增列 | `rule_code` | `String(64)`，可空。判定规则标识（`d1_gpu_utilization_waste` / `d2_capacity` / `d5_compliance` / `d7_version_drift`），便于规则级回归与看板分组 |
| 枚举扩展 | `diff_kind` | 新增 `UTILIZATION_WASTE`（D1）、`CAPACITY_WARNING`（D2）、`COMPLIANCE_VIOLATION`（D5）、`VERSION_DRIFT`（D7）、`LIFECYCLE_EXPIRY`（D4，P1 启用）、`HEALTH_ANOMALY`（D6，P1 启用） |
| 新增索引 | `ix_diff_project_status_detected` | `(project_id, status, detected_at)` —— board 主查询路径 |

**所有新 `diff_kind` 复用现有 `board` 展示与 `resolve` 处置闭环，不新建处置流程**（PRD §4）。`classification` 继承对象的**有效密级**（含 dataset 传播后的值），保证 `diff_scope_clause` 过滤口径不变。

### 1.8 对象访问仓库层（新增，防漏关键基建）

新增 `apps/api/src/rg_api/services/objects.py`，**唯一允许裸查属性表/指标表的地方**：

```python
def load_details(session, model, resource_ids: Sequence[str]) -> dict[str, Any]:
    """入参必须是**已经过密级 + 项目过滤**的锚点 ID 集合。空集直接返回 {}。"""
    if not resource_ids:
        return {}
    rows = session.execute(
        select(model).where(model.resource_id.in_(list(resource_ids)))
    ).scalars().all()
    return {row.resource_id: row for row in rows}


def load_metrics(session, resource_ids, metric_names=None) -> dict[str, dict[str, float]]:
    """同上：入参必须是已过滤锚点集。返回 {resource_id: {metric_name: value}}。"""


def upsert_governed_object(session, *, resource, detail=None, metrics=None) -> Resource:
    """锚点 + 属性 + 指标的**唯一写入入口**：单事务内完成，杜绝「锚点写了属性没写」。"""
```

**CI 强制规则**：
> `routes/*.py`、`collector/*.py` 中不得出现 `select(GpuNode)` / `select(ResourceMetric)` / `select(ModelEndpoint)` / `select(TrainingJob)` / `select(GpuCluster)` / `select(K8sWorkload)`；仅 `services/objects.py` 在白名单内。

这条规则把 §1.6-A′ 唯一的那处漏点也堵死了。

---

## 2. 判定引擎（GovernanceRule 可插拔）★

现状 diff 计算是「资源快照 A vs B」的单一逻辑。本设计把**治理判定抽象为规则**：

```python
class GovernanceRule(Protocol):
    dim: str                      # D1..D8
    def evaluate(self, resources, metrics) -> list[ResourceDiff]: ...
```

- `D1 利用率/浪费`、`D2 配额容量`、`D5 合规基线`、`D7 版本漂移` 等作为首批规则实现。
- 规则输出统一为 `ResourceDiff`（扩展 `diff_kind` + `rule_code`），直接进入现有 `board` / `resolve`。
- **优点**：每新增一个治理维度 = 新增一个规则文件，不产生第二套看板/处置链路；回归测试可针对单规则写。
- 现有「资源快照 diff」本身也是一条规则（`snapshot_diff`），不动其语义。
- **硬约束（本次补充，见 `impl-plan-expansion-p0.md` S5）**：
  1. 规则的**输入必须是已过滤的锚点集**（由调用方先过 `_apply_level_filter`），规则内部不得重新查询全表；
  2. **`RuleContext` 刻意只承载单个 `project_id` / `classification`** —— 规则天然无法跨项目聚合，从结构上杜绝「规则层拼出跨项目画像」；跨项目视角只能在 board 层做；
  3. 规则产出的 `ResourceDiff` 必须携带**对象的有效密级**（非调用者上限），否则 `diff_scope_clause` 会以治理项形态泄漏存在性。

---

## 3. 采集层（AI infra Provider 组）

扩展现有 `Collector` 接口，新增一组 Provider，与蓝鲸/青云/华为/腾讯平级，**统一产出锚点行 + 属性行**（经 `upsert_governed_object()`），并写入 `resource_metric`：

| Provider | 产出 kind | 事实获取 | `simulated` 兜底 |
|---|---|---|---|
| `k8s` | `gpu_node`/`gpu_cluster`/`k8s_*`/`training_job`/`notebook` | K8s API（Node/GPU 标签、Pod、Job/SparkApplication）+ 可选 DCGM | 同风格合成数据 |
| `model_registry` | `model_version`/`model_endpoint` | MLflow API / 推理网关列表 | 返回 `unmanaged` 标记 + 空 |
| `vector_db` | `vector_db` | Milvus/PGVector 目录 | 仅 PGVector 参考实现 |
| `metrics` | 写入 `resource_metric` | Prometheus/DCGM 查询（**只消费**） | 指标缺失 → 判 `unknown` 非误判 |

- 采集入口仍走 `POST /collection/run`（扩展 `provider` 参数），`dry_run` 保留。
- `simulated` 兜底保证无真实 K8s/Prometheus 时全链路可跑、可回归（沿用现有 CI 策略）。
- **密级契约不变**：仍走 `_project_classifications()` 以项目目录为唯一来源，未知项目**失败关闭**；新增 kind 不引入任何默认密级（P0-2 修复的语义不得被稀释）。
- **指纹契约（新增风险点）**：`NormalizedResource.fingerprint` 现含 `platform/native_id/kind/spec/status/region/tags/vpc`，**不含** `gpu_model`/`served_version` 等新属性 → 属性变化不产生 diff。需按 kind 白名单扩展 `_ATTR_FINGERPRINT_KEYS`（`gpu_model`/`driver_version`/`cuda_version` 仅对 `gpu_node` 生效，`served_version` 仅对 `model_endpoint` 生效），否则 D7 版本漂移会漏判；反之若不限定 kind，既有 host/vm 会产生大量假 diff。

---

## 4. 安全扩展点（逐端点挂接，PRD §6）

> **现状基准（已修复并经回归守护，扩展时只增分支、不改用例）**：
> - `ai/retrieval.py` `_candidate_ids`：密级过滤**恒生效**，`unrestricted` 只放宽项目范围 —— `test_retrieval_level_filter.py`
> - `routes/resources.py` `resource_stats`：两个聚合均套 `_apply_level_filter` —— `test_resource_stats_level_filter.py`
> - `services/audit.py`：`denied`/`failed` 走**独立事务**落库（`_INDEPENDENT_OUTCOMES`）—— `test_audit_denied_persistence.py`
> - `services/access.py` `assert_capability`：拒绝时补 `denied` 审计 —— `test_capability_denial_audit.py`

| 现有模块 | 扩展动作 |
|---|---|
| `security/policy.py` / `services/access.py` | 新增端点（`/resources/{id}`、`/resources/ai/*`、`/collection` 的 k8s 分支、`/model-registry`）复用同一 `project_id` + 密级下推；**属性表/指标表不参与过滤**（无密级列，经 `services/objects.py` 访问） |
| `services/objects.py`（新增） | 唯一入口；入参为已过滤锚点集；CI 规则禁止他处裸查 |
| `services/audit.py` | 新增端点纳入拒绝审计；现有「端点 Δdenied==1」守护清单扩展 |
| `security/jigsaw.py` | 检索账本统计新增 kind 的分片（GPU 拓扑、训练作业归属、数据集密级）；累积覆盖度/敏感维度共现含新增类型 |
| `security/canary.py` | ⚠️ **当前诱饵仅来自 `seed/demo.py::build_canaries()`（`startup.py:31-36`），客户项目无诱饵（既有 P1-05 未修）**。P0 必须至少为新增类型补 `gpu_node`/`model_endpoint`/`dataset` 伪装条目，否则金丝雀对 AI infra 事实完全空转 |
| `ai/retrieval.py` / `routes/knowledge.py` | 受控 RAG 不变式覆盖 AI infra 事实入库净化；经 dataset 传播抬升到 L4 的对象事实**禁止向量化** |
| `routes/governance.py` 导出 | 新增 `owner_team` **保留**（团队粒度是治理必需），个人 `owner` 仍脱敏；行数/频次限制不变 |

### 4.1 逐表 / 逐入口的密级与授权责任矩阵（不留「待实现」）

**按表点名：**

| 表 | 持有 `project_id`/`classification`? | 过滤责任 | 漏过滤后果 |
|---|---|---|---|
| `resource`（锚点） | ✅ 持有 | 所有查询必须 `_apply_level_filter`（明细/聚合）或 `scoped_project_ids` + `diff_scope_clause`（diff） | 越密级资源可见（已实证两次） |
| `resource_diff` | ✅ 持有（**须与对象有效密级一致**） | `diff_scope_clause` | 治理项越权可见；密级不一致时泄漏**存在性** |
| `gpu_node` / `gpu_cluster` / `training_job` / `model_endpoint` / `k8s_workload` | ❌ **刻意不持有** | 只能 `resource_id IN (已过滤锚点集)`，经 `services/objects.py` | 裸查会暴露 GPU 卡型/拓扑/框架/端点来源 —— **物理上被迫先过锚点** |
| `resource_metric` | ❌ **刻意不持有** | 同上 | 裸查会暴露 QPS/延迟/利用率 —— 可反推业务活跃度，对量化客户是敏感信号 |
| `model_version` | ❌ 不持有（随 endpoint） | 经 `model_endpoint` 锚点 | 模型名/版本越权可见 |
| `dataset` | ✅ 持有（自带密级，可高于项目） | 自身 `project_id` + `classification` 过滤；并**向上传播**到引用它的对象锚点行 | L4 数据集被低密级链路引用后泄露 |

**按查询入口点名：**

| 查询入口 | 过滤方式 | 状态 |
|---|---|---|
| `GET /resources`（含新 kind） | `check_project` + `_apply_level_filter` | 现状已满足，零改动 |
| `GET /resources/stats`（by_kind 含新类型） | `_apply_level_filter` ×2 | 现状已满足（P0-6 已修） |
| `GET /resources/{id}`（含属性投影） | `check_project` + `check_level` **之后**才 `objects.load_details([id])` | **新增**，必须写 |
| `GET /resources/ai/board`（新增 AI 看板） | `_apply_level_filter` 后 join 属性表 | **新增**，必须写 |
| `GET /resources/ai/capacity`（D2 容量水位） | 同上；**跨 gpu_cluster 聚合，最易漏** | **新增**，必须写 |
| `GET /resources/diffs` / `diffs/summary` | `diff_scope_clause` | 现状已满足，零改动 |
| `GET /governance/board` / `cost-impact` | `diff_scope_clause` | 现状已满足，零改动 |
| `GET /governance/export` | `assert_project_access` + `classification.in_(ceiling)` | 现状已满足；新增 `owner_team` 保留、个人脱敏 |
| `POST /governance/diff/{id}/resolve` | `assert_project_access` + `check_level` | 现状已满足，零改动 |
| `POST /attribution/run` / `POST /knowledge/search` | 先授权后召回；L4 禁向量化 | 现状已满足（P0-5 已修） |
| 判定引擎内部 | 输入为已过滤锚点集，规则内不得重查全表；`RuleContext` 单项目 | **新增约束**，必须写并测试 |
| `GET /collection/snapshots` | 无密级维度（快照元数据） | 可接受，不扩 |

**不变式回归基线**：现有 138（SQLite）/136+2skip（PG）必须全绿；新增端点拒绝审计作为扩展守护加入。

---

## 5. 任务分解与依赖（P0 → P1 → P2）

> 沿用 kb-builder 的「文件边界」做法：每个任务标注**主要改动文件**，避免多工人互踩。CI 默认方言 PG，迁移沿用 `_migrate_*` 幂等 ALTER 模式（参照 `_migrate_knowledge_columns`）。
>
> **P0 执行顺序已按用户拍板（先跑通 R1 端到端，再横向复制）重排 —— 完整分步见 `docs/impl-plan-expansion-p0.md`**。本节为完整 P0/P1/P2 清单。

### P0（上线必做）
| ID | 任务 | 主要改动文件 | 依赖 |
|---|---|---|---|
| P0-E1 | 域模型扩展：`resource` 加 `owner_team`+`asset_tag` 列与 2 索引；5 张属性表 + `resource_metric` + `model_version` + `dataset`；`resource_diff` 加 `rule_code` + `diff_kind` 枚举扩展；幂等迁移 | `packages/contracts/.../db/models.py`、`session.py` | 无 |
| P0-E1b | 对象仓库层 `services/objects.py` + CI 裸查禁令规则 | `apps/api/.../services/objects.py`、CI 配置 | P0-E1 |
| P0-E2 | AI infra Provider 组（k8s / model_registry / vector_db / metrics）+ `simulated` 兜底；`/collection/run` 接入；`upsert_governed_object()` 统一写入 | `packages/contracts/.../collector/`、`routes/collection.py` | P0-E1b |
| P0-E4 | 安全扩展：新增端点挂接 policy/access/audit/jigsaw/canary；拒绝审计守护清单扩展 | `security/*`、`services/audit.py`、`services/objects.py`、`routes/*` | P0-E1b |
| P0-E3 | 判定引擎 `GovernanceRule` + D1/D2/D5/D7 四条规则 + 治理项生成 | `services/governance.py`、`governance/rules.py` | P0-E1、P0-E2 |
| P0-E5 | `model_endpoint` ↔ `model_version` 对账（D7 数据基础） | `routes/model_registry.py`、`seed/demo.py`(演示) | P0-E1、P0-E2 |
| P0-E6 | 看板新增 AI infra 聚合视图（按项目/团队下钻） | `routes/governance.py`、`apps/web` 看板组件 | P0-E3 |
| P0-E7 | 数据集密级向上传播（写入期抬升 + 回归守护） | `collector/`、`services/objects.py`、测试 | P0-E1、P0-E4 |

### P1
| ID | 任务 | 依赖 |
|---|---|---|
| P1-E1 | D3 成本归属（GPU·小时按团队分摊、闲置成本、训练/推理拆分） | P0-E3 |
| P1-E2 | D4 生命周期（作业/Notebook/索引待回收） | P0-E3 |
| P1-E3 | D6 健康 SLA 接入监控源 | P0-E2、P0-E3 |
| P1-E4 | R5/R7/R8 纳管 + D8 血缘/密级链（数据集密级向上传播的完整链） | P0-E1、P0-E4、P0-E7 |
| P1-E5 | **方案 C 全局 ORM 行级过滤作为第二道防线叠加**（§1.6-C） | P0-E1b、P0-E4 |
| P1-E6 | 指标历史明细 `resource_metric_history` 与回放能力 | P0-E1 |

### P2
| ID | 任务 | 依赖 |
|---|---|---|
| P2-E1 | R9 Notebook 纳管与闲置回收 | P0-E3 |
| P2-E2 | 成本预算与超预算自动告警 | P1-E1 |
| P2-E3 | 向量库分片生命周期与知识库对账深化 | P1-E4 |

---

## 6. 回归与迁移策略

1. **现有套件零回归**：138（SQLite）/136+2skip（PG）是硬基线（**当前已验证值**，含 demo 种子 PG 移植与知识库模块，非预测）；任何改动先跑全量，新增规则/端点不得破它。
2. **增量迁移**：
   - **新增表：零迁移代码**。模型注册进 `Base.metadata` 后由 `ensure_schema()` 的 `create_all` 自动建；双方言均可（新表不使用方言特化类型，时间列走 `TS()`、JSON 走 `JsonDict()`，二者已处理 SQLite/PG 差异）。
   - **既有表加列**（`resource.owner_team`、`resource.asset_tag`、`resource_diff.rule_code`）：沿用 `_migrate_knowledge_columns` 的「逐列 introspection + 缺哪补哪 + 幂等」模式；PG 走 `ALTER TABLE … ADD COLUMN IF NOT EXISTS`（PG 9.6+ 支持），SQLite 走 `PRAGMA table_info` introspection。提供等价手工 SQL 写入 runbook。
   - **新增索引**：`CREATE INDEX IF NOT EXISTS`（PG / SQLite 均支持）。
3. **拒绝审计守护**：把 P0 修复的「端点 Δdenied==1」清单扩展为含新增端点的回归测试。
4. **属性表裸查禁令**：CI 静态规则（见 §1.8），`routes/` 与 `collector/` 下禁止出现 `select(GpuNode)` 等。
5. **离线可跑**：`simulated` 兜底覆盖所有新 Provider，无真实 K8s/Prometheus 时 CI 仍全绿。
6. **⚠️ `ensure_schema()` 每 Pod 启动都会跑**（`main.py:29-40` + `startup.py:41`）：新增的 `ALTER TABLE ADD COLUMN` 在 SQLite 上会短暂持写锁——与 `services/audit.py::_is_lock_error` 处理的是同一种竞争。需确认新迁移不放大 SQLite 锁竞争（PG 的 MVCC 不受影响）。另：`ondelete="CASCADE"` 会让删除 `Resource` 级联删除属性行与指标行，需确认既有回收路径依赖软删除保留证据的假设仍成立。

---

## 7. 已拍板决策（原「待拍板开放决策」，2026-10-23 关闭）

| # | 议题 | 决策 | 依据 | 代价 / 需承受项 |
|---|---|---|---|---|
| 1 | `attrs` JSONB 列 vs 类型分表 | **分表（类型专属表）** | 用户拍板推翻原「JSONB 宽列」默认值。GPU 卡型/显存、训练框架、端点 QPS 等异构属性在 JSONB 下无法建索引、无法做类型化对比、无法支撑 D7 版本对账 | 新增 5 张表；`resource` 行数膨胀；需 `upsert_governed_object()` 统一写入入口 |
| 2 | 指标落库 vs 查询时拉取 | **落库 `resource_metric`** | 用户拍板。离线部署下判定链路不能受监控系统可用性牵制；且要可审计、可回放 | 指标有采集延迟（非实时）；需设计保留期与清理；判定要用「最新值 + 采集时刻」而非「此刻」 |
| 3 | `model_endpoint` 是否独立表 | **独立表** | 用户拍板。D7 版本对账需要 `served_version` 与 `model_version` 的结构化关联，非 JSON 可承载 | 维护锚点行 + 属性行两处；由 PK=FK 与事务保证一致性（字面张力见 §7.1） |
| 4 | 数据集密级向上传播 | **确认采纳**（保守方向：有效密级 = max(自身继承密级, 输入 dataset 密级上限)） | 用户确认。防止「低密级任务引用高密级数据集」绕过密级 | 写入期需计算抬升并有刷新机制（dataset 密级变更时回刷引用对象）；**刻意不改 `ceiling_for`**（见 §1.5） |
| 5 | 物理机与云主机关联 | **CMDB 资产编号（`asset_tag`）关联，不引入新指纹算法** | 用户确认。避免为关联再造一套指纹，复用客户 CMDB 已有主键 | 依赖客户 CMDB 提供稳定资产编号；编号缺失时关联能力降级（D3 成本归属精度下降，**不影响安全**） |
| 6 | 治理闭环锚点选型 | **方案 A′（锚点唯一 + 属性分表）**；否决 B（多态分派）、C（全局 ORM 过滤） | 见 §1.6 完整对比 | 见 §1.6-A′ 代价栏 |

### 7.1 关于决策 #3 与方案 A′ 的字面张力（显式记录，不静默处理）

用户决策「`model_endpoint` = 独立表（不复用 `Resource` 表）」与方案 A′「每类对象在 `resource` 登记锚点行」存在字面张力。本设计的解读与处理：

- **解读**：决策 #3 否定的是「把 `model_name`/`served_version`/`qps`/`source`/`exposed` 塞进 `Resource.attrs` JSONB」这一原方案，即**要求 model_endpoint 的字段以类型化列存在于专属表** —— 这一点 A′ 完全满足。
- **A′ 额外要求**：`model_endpoint` 在 `resource` 中有一行**锚点**（只含 `project_id`/`classification`/`name`/`native_id`/`kind`/`monthly_cost_cny` 等治理必需字段），用于承载治理闭环与密级过滤。
- **若坚持「model_endpoint 在 `resource` 中完全不出现」**，则需把锚点泛化为独立的 `governed_object` 表，并将 `ResourceDiff.resource_id`、`resource_metric.resource_id` 全部改指新锚点 —— **这是一次全量数据迁移，与「先跑通一类端到端」的目标直接冲突**。
- **建议**：P0 按 A′ 落地，把「锚点是否泛化」作为 P1 独立议题，在 R1 端到端跑通并有真实数据后再评估。

---

## 8. 与知识库路线的衔接

P1+P2 已交付的切块/PDF/BM25/混合检索是**本扩展的检索底座**：AI infra 排障（Pod Pending、GPU 空转、推理延迟）与合规基线（驱动/CUDA 版本、出网合规）的运维知识，经同一摄取链路进入知识库，`/knowledge/search` 返回带 `section_path`/`page_no` 的出处，受控 RAG 不变式天然覆盖。本扩展**不重复建设**知识库，仅在采集层把 AI infra 事实纳入治理，在检索层复用既有能力。

> **补充约束**：AI infra 事实进入向量库前必须过净化层（`security/sanitize.py`），且 `classification` 高于 `VECTORIZABLE_MAX_LEVEL`（当前 = `L3_CONFIDENTIAL`，见 `enums.py:33`）的原始事实**禁止向量化** —— 即经 dataset 密级传播抬升到 `L4_SECRET` 的对象，其事实不得进入向量库。
