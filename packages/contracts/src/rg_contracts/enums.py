from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    """Platform roles. Resource visibility is always scoped by project/level."""

    ADMIN = "admin"
    GOVERNANCE = "governance"
    PM = "pm"
    AUDITOR = "auditor"
    VIEWER = "viewer"


class Classification(str, Enum):
    """Data classification levels (企业数据分级)."""

    L1_PUBLIC = "L1_PUBLIC"
    L2_INTERNAL = "L2_INTERNAL"
    L3_CONFIDENTIAL = "L3_CONFIDENTIAL"
    L4_SECRET = "L4_SECRET"


CLASSIFICATION_ORDER: dict[str, int] = {
    Classification.L1_PUBLIC.value: 1,
    Classification.L2_INTERNAL.value: 2,
    Classification.L3_CONFIDENTIAL.value: 3,
    Classification.L4_SECRET.value: 4,
}

# 允许进入向量库的等级上限：L4 原始事实禁止向量化
VECTORIZABLE_MAX_LEVEL = Classification.L3_CONFIDENTIAL


class Platform(str, Enum):
    BK = "bluking"
    QINGCLOUD = "qingcloud"
    HUAWEI = "huawei"
    TENCENT = "tencent"


PLATFORM_LABELS: dict[str, str] = {
    Platform.BK.value: "蓝鲸",
    Platform.QINGCLOUD.value: "青云",
    Platform.HUAWEI.value: "华为云",
    Platform.TENCENT.value: "腾讯云",
}


class ResourceKind(str, Enum):
    """资源类型。

    扩展说明（P0 资源治理维度扩展，见 ``docs/architecture-expansion.md`` §1.1）：
    新增 AI infra / MLOps 类型。**新增类型不引入任何新的密级默认值**——密级仍由
    采集侧按项目目录取得（P0-2），`kind` 只决定「属性落在哪张专属表」。

    ⚠️ 改动本枚举时须确认：全仓没有把 `ResourceKind` 当白名单硬编码的地方，
    否则新 kind 会被静默归到 `OTHER` 而绕过 kind 级过滤。已 grep 确认：现有引用
    全部是 `ResourceKind.X.value` 取值（seed / providers / diff），无白名单分支。
    """

    VM = "vm"
    DISK = "disk"
    DATABASE = "database"
    LOADBALANCER = "loadbalancer"
    OBJECT_STORAGE = "object_storage"
    CONTAINER = "container"
    PUBLIC_IP = "public_ip"
    CACHE = "cache"
    OTHER = "other"
    # ---- P0 扩展（AI infra / MLOps，锚点行 + 类型专属属性表）
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
    """差异/治理项类型。

    前 6 项是「快照 A vs B」的既有时序 diff；后 6 项是治理规则产出的治理项
    （D1/D2/D4/D5/D6/D7）。两者共用 `resource_diff` 与既有 board / resolve 闭环，
    因此**治理项不新建处置流程**（见 ``docs/architecture-expansion.md`` §1.7）。
    治理项的 `classification` 必须取**对象有效密级**（可被 dataset 传播抬升），
    不能取调用者上限——否则 `diff_scope_clause` 会以治理项形态泄漏存在性。
    """

    NEW = "NEW"
    REMOVED = "REMOVED"
    SPEC_CHANGED = "SPEC_CHANGED"
    STATE_CHANGED = "STATE_CHANGED"
    TAG_CHANGED = "TAG_CHANGED"
    OWNER_CHANGED = "OWNER_CHANGED"
    # ---- P0 治理维度
    UTILIZATION_WASTE = "UTILIZATION_WASTE"  # D1 利用率/浪费
    CAPACITY_WARNING = "CAPACITY_WARNING"  # D2 容量水位
    COMPLIANCE_VIOLATION = "COMPLIANCE_VIOLATION"  # D5 合规基线
    VERSION_DRIFT = "VERSION_DRIFT"  # D7 版本漂移
    LIFECYCLE_EXPIRY = "LIFECYCLE_EXPIRY"  # D4 生命周期（P1 启用）
    HEALTH_ANOMALY = "HEALTH_ANOMALY"  # D6 健康异常（P1 启用）


class SnapshotStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class GovernanceStatus(str, Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    DISMISSED = "dismissed"
    REMEDIATED = "remediated"


class ModelProvider(str, Enum):
    INTERNAL = "internal"
    OPENAI_COMPATIBLE = "openai_compatible"


class EvidenceLevel(str, Enum):
    RULE = "rule"
    RAG = "rag"
    LLM = "llm"
    MANUAL = "manual"


def classification_rank(level: str) -> int:
    """密级排序值；**未知密级按最高密级（L4）处理**（失败关闭）。

    旧实现 ``CLASSIFICATION_ORDER.get(level, 1)`` 把未知串当 L1 公开：
    ``"L3_CONFIDENTIAL "``（尾部空格）、``"L3-CONFIDENTIAL"``（分隔符写错）这类
    常见的录入/复制错误会被静默降密，L3 文档对 L2 用户可见。而入库侧的 SQL
    过滤按枚举白名单走（未知串直接不可见），两条路径对同一个脏值一个放宽一个
    收紧——放宽的那条先命中就是泄漏。

    现在两侧口径一致：未知 = 最高密级 = 默认拒绝。调用方若要区分「非法值」，
    用 ``is_valid_classification`` 显式校验（写入口应当这么做）。
    """
    return CLASSIFICATION_ORDER.get(level, CLASSIFICATION_ORDER[Classification.L4_SECRET.value])


def is_valid_classification(level: object) -> bool:
    """是否为合法密级字面量（写入口的输入校验用）。"""
    return isinstance(level, str) and level in CLASSIFICATION_ORDER


def level_allows(user_ceiling: str, doc_level: str) -> bool:
    """密级向下兼容：用户密级上限 >= 文档密级 才允许访问。"""
    return classification_rank(user_ceiling) >= classification_rank(doc_level)
