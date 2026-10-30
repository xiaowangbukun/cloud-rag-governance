"""ORM models.

信任边界说明:
- `resource` / `snapshot_state` 是「事实域」，保存精确资源数据，禁止直接进入向量库。
- `knowledge_document` / `knowledge_chunk` 是「知识域」，只保存净化后的语义文本与向量。
- 两域通过 `project_id` + `classification` 关联，检索时先做权限预过滤，再查向量。
- 时间戳统一使用 TS()/TS_NULL()：SQLite 存 ISO-8601 文本，PostgreSQL 存 timestamptz。
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import (
    Boolean,
    Date,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from rg_contracts.db.base import (
    TS,
    TS_NULL,
    Base,
    JsonDict,
    StrIdMixin,
    TimestampCodec,
    TimestampMixin,
    utcnow,
)
from rg_contracts.db.vector import Vector


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:20]}"


def ts(value: datetime | None = None) -> str:
    """时间戳写入统一入口：默认取当前 UTC 时间，返回 ISO-8601 字符串。"""
    return str(TimestampCodec.encode(value or utcnow()))


class Organization(StrIdMixin, TimestampMixin, Base):
    __tablename__ = "organization"

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    code: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    parent_id: Mapped[str | None] = mapped_column(
        ForeignKey("organization.id"), nullable=True
    )


class User(StrIdMixin, TimestampMixin, Base):
    __tablename__ = "user"

    subject: Mapped[str] = mapped_column(String(190), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    email: Mapped[str | None] = mapped_column(String(190), nullable=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="viewer")
    org_id: Mapped[str | None] = mapped_column(
        ForeignKey("organization.id"), nullable=True
    )
    classification_ceiling: Mapped[str] = mapped_column(
        String(32), nullable=False, default="L2_INTERNAL"
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_login_at: Mapped[str | None] = TS_NULL()
    attributes: Mapped[dict] = JsonDict()


class Project(StrIdMixin, TimestampMixin, Base):
    __tablename__ = "project"

    code: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    org_id: Mapped[str | None] = mapped_column(
        ForeignKey("organization.id"), nullable=True
    )
    classification: Mapped[str] = mapped_column(
        String(32), nullable=False, default="L3_CONFIDENTIAL"
    )
    business_criticality: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    pm_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    monthly_budget_cny: Mapped[float | None] = mapped_column(Float, nullable=True)


class ProjectMember(Base):
    __tablename__ = "project_member"
    __table_args__ = (
        UniqueConstraint("user_id", "project_id", name="uq_project_member_user_project"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("pm"))
    user_id: Mapped[str] = mapped_column(ForeignKey("user.id"), nullable=False)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), nullable=False)
    # 项目内可见密级上限（ABAC）
    visible_ceiling: Mapped[str] = mapped_column(
        String(32), nullable=False, default="L3_CONFIDENTIAL"
    )
    created_at: Mapped[str] = TS()


class CloudAccount(StrIdMixin, TimestampMixin, Base):
    __tablename__ = "cloud_account"

    platform: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    endpoint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    region: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # 凭证不入库，仅保存引用名；真实密钥走环境变量/密钥管理
    credential_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    options: Mapped[dict] = JsonDict()


class Resource(StrIdMixin, TimestampMixin, Base):
    """事实域：资源台账当前状态（精确值，受行级策略保护）。"""

    __tablename__ = "resource"

    platform: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    account_id: Mapped[str] = mapped_column(
        ForeignKey("cloud_account.id"), nullable=False, index=True
    )
    project_id: Mapped[str] = mapped_column(
        ForeignKey("project.id"), nullable=False, index=True
    )
    native_id: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(190), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    region: Mapped[str | None] = mapped_column(String(64), nullable=True)
    spec: Mapped[str | None] = mapped_column(String(190), nullable=True)
    status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    monthly_cost_cny: Mapped[float | None] = mapped_column(Float, nullable=True)
    classification: Mapped[str] = mapped_column(
        String(32), nullable=False, default="L3_CONFIDENTIAL", index=True
    )
    # 负责人姓名属敏感字段：向量化与对外输出前必须脱敏
    owner: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # 团队粒度（D3 成本归属 / 按团队下钻）：治理必需，导出保留；与个人的 owner 区分
    owner_team: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # CMDB 资产编号：物理机与云主机的关联键（不引入新指纹算法）
    asset_tag: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    first_seen_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    last_seen_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    decommissioned_at: Mapped[str | None] = TS_NULL()
    attributes: Mapped[dict] = JsonDict()

    __table_args__ = (
        UniqueConstraint(
            "platform", "account_id", "native_id", name="uq_resource_platform_native"
        ),
        # 跨类型聚合与按 kind 列表的主路径
        Index("ix_resource_project_kind", "project_id", "kind"),
        # 密级过滤主路径：与 _apply_level_filter 的条件顺序一致
        Index("ix_resource_project_level", "project_id", "classification"),
    )


class Snapshot(TimestampMixin, Base):
    __tablename__ = "snapshot"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("snap"))
    platform: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    account_id: Mapped[str] = mapped_column(
        ForeignKey("cloud_account.id"), nullable=False
    )
    taken_at: Mapped[str] = TS(index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    source_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="api")
    resource_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    checksum: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_uri: Mapped[str | None] = mapped_column(String(512), nullable=True)


class SnapshotState(Base):
    """事实域：快照内的资源精确状态，用于 diff 与证据回溯。"""

    __tablename__ = "snapshot_state"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("ss"))
    snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("snapshot.id"), nullable=False, index=True
    )
    resource_id: Mapped[str] = mapped_column(
        ForeignKey("resource.id"), nullable=False, index=True
    )
    project_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    platform: Mapped[str] = mapped_column(String(32), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    monthly_cost_cny: Mapped[float | None] = mapped_column(Float, nullable=True)
    payload: Mapped[dict] = JsonDict()


class ResourceDiff(TimestampMixin, Base):
    __tablename__ = "resource_diff"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("diff"))
    project_id: Mapped[str] = mapped_column(
        ForeignKey("project.id"), nullable=False, index=True
    )
    platform: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    resource_id: Mapped[str | None] = mapped_column(
        ForeignKey("resource.id"), nullable=True
    )
    native_id: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_name: Mapped[str | None] = mapped_column(String(190), nullable=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    diff_kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    base_snapshot_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_snapshot_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detected_at: Mapped[str] = TS(index=True)
    cost_delta_cny: Mapped[float | None] = mapped_column(Float, nullable=True)
    classification: Mapped[str] = mapped_column(
        String(32), nullable=False, default="L3_CONFIDENTIAL"
    )
    # 规则化初判，LLM 仅做语义补充
    rule_hint: Mapped[str | None] = mapped_column(String(190), nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload: Mapped[dict] = JsonDict()
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    assignee: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resolved_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved_at: Mapped[str | None] = TS_NULL()
    # 判定规则标识（d1_gpu_utilization_waste / d2_capacity / d5_compliance /
    # d7_version_drift …）：时序 diff 为 None，治理项才有值。
    # 便于规则级回归与看板按规则分组。
    rule_code: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        # board 主查询路径
        Index("ix_diff_project_status_detected", "project_id", "status", "detected_at"),
    )


class GpuNode(Base):
    """R1 GPU 节点属性表（锚点 + 属性分表方案 A′）。

    **刻意不持有 `project_id` / `classification` 列** —— 密级只在锚点行
    （`resource`）上，因此裸查本表**物理上构造不出密级条件**，只能经
    `resource_id IN (已过滤锚点集)` 访问（见 `services/objects.py`）。
    这是整套扩展的安全基座：把「密级过滤靠调用方自觉」换成「漏了也只会查不到」。

    PK 即 FK（`ondelete="CASCADE"`）：属性行不可能指向不存在的锚点；
    锚点删除时属性行级联删除（历史证据由 `snapshot_state` 保留）。
    """

    __tablename__ = "gpu_node"

    resource_id: Mapped[str] = mapped_column(
        ForeignKey("resource.id", ondelete="CASCADE"), primary_key=True
    )
    gpu_model: Mapped[str | None] = mapped_column(String(64), nullable=True)
    total_gpus: Mapped[int | None] = mapped_column(Integer, nullable=True)
    allocated_gpus: Mapped[int | None] = mapped_column(Integer, nullable=True)
    driver_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cuda_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    mig_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    asset_tag: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    updated_at: Mapped[str] = TS()


class ResourceMetric(Base):
    """资源指标最新值表（承载 D1 利用率等阈值判定）。

    与属性表同一约束：**不持有 `project_id` / `classification`** —— 指标值本身
    是敏感信号（QPS 可反推策略活跃度、利用率可反推训练规模），任何读取必须先过锚点。

    `(resource_id, metric_name)` 唯一：采集时 upsert 最新值，历史明细不在 P0 范围。
    指标缺失时判定层须判 `unknown`，不得当 0 处理（PRD §8）。
    """

    __tablename__ = "resource_metric"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("rm"))
    resource_id: Mapped[str] = mapped_column(
        ForeignKey("resource.id", ondelete="CASCADE"), nullable=False, index=True
    )
    metric_name: Mapped[str] = mapped_column(String(64), nullable=False)
    value: Mapped[float] = mapped_column(Float, nullable=False)
    unit: Mapped[str | None] = mapped_column(String(16), nullable=True)
    ts: Mapped[str] = TS(index=True)

    __table_args__ = (
        UniqueConstraint("resource_id", "metric_name", name="uq_metric_resource_name"),
    )


class KnowledgeDocument(StrIdMixin, TimestampMixin, Base):
    """知识域：治理规则、脱敏案例、原因模板。原始事实文档不落此表。"""

    __tablename__ = "knowledge_document"

    title: Mapped[str] = mapped_column(String(190), nullable=False)
    doc_type: Mapped[str] = mapped_column(String(32), nullable=False, default="rule")
    project_id: Mapped[str | None] = mapped_column(
        ForeignKey("project.id"), nullable=True, index=True
    )
    platform: Mapped[str | None] = mapped_column(String(32), nullable=True)
    classification: Mapped[str] = mapped_column(
        String(32), nullable=False, default="L2_INTERNAL", index=True
    )
    source_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    sanitized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # 摄取通道：md / pdf / text。回答时要能说清「这条知识是上传的文档还是粘贴的文本」，
    # 也决定 section_path / page_no 是否有语义（pdf 有页码，md 有章节）。
    # 默认 text 让存量 JSON 文本接口写入的行保持自洽（都是直接提交的文本），无需回填。
    source_type: Mapped[str] = mapped_column(
        String(16), nullable=False, default="text", server_default="text"
    )
    # 原始文件名（只存 basename，不含目录）：出处展示需要「文档名」，
    # 但落绝对路径会泄露服务器目录结构，违反最小披露。
    source_path: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # PDF 页数；非 PDF 恒为 0（不用 NULL，便于统计与前端直接展示「0 页」=  非 PDF）
    page_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    metadata_json: Mapped[dict] = JsonDict()


class KnowledgeChunk(Base):
    """知识域：净化后的向量分片。安全投影由 security 层生成并校验后写入。"""

    __tablename__ = "knowledge_chunk"
    __table_args__ = (
        UniqueConstraint("document_id", "ordinal", name="uq_knowledge_chunk_doc_ordinal"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("kc"))
    document_id: Mapped[str] = mapped_column(
        ForeignKey("knowledge_document.id"), nullable=False, index=True
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    project_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    platform: Mapped[str | None] = mapped_column(String(32), nullable=True)
    classification: Mapped[str] = mapped_column(
        String(32), nullable=False, default="L2_INTERNAL", index=True
    )
    # 送入 embedding 的文本：必须已脱敏、泛化、去标识
    embedding_text: Mapped[str] = mapped_column(Text, nullable=False)
    # 展示用文本：仍经过最小披露裁剪
    display_text: Mapped[str] = mapped_column(Text, nullable=False)
    token_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    embedding_model: Mapped[str] = mapped_column(String(128), nullable=False)
    embedding = mapped_column(Vector, nullable=True)
    # 章节路径，如 `3 部署 > 3.2 数据库`：出处引用的核心字段。
    # Markdown 由标题栈生成（含自身标题）；PDF 由页内编号型标题启发式识别，
    # 识别不到为 NULL（不编造章节，宁可缺省）。
    section_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # PDF 页码（从 1 起）；Markdown / 纯文本为 NULL。
    # 出处要能指到「哪一页」，否则 PDF 类长文档无法人工复核。
    page_no: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # 在原文中的字符偏移，供前端高亮定位。Markdown 为全文偏移，
    # PDF 为页内偏移（PDF 无稳定的全文线性化表示）。NULL 表示未记录。
    char_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    char_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    metadata_json: Mapped[dict] = JsonDict()
    created_at: Mapped[str] = TS()


class Attribution(Base):
    __tablename__ = "attribution"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("attr"))
    diff_id: Mapped[str] = mapped_column(
        ForeignKey("resource_diff.id"), nullable=False, index=True
    )
    project_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # 任务隔离：每次调用生成独立上下文，禁止跨任务复用
    task_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    cause: Mapped[str] = mapped_column(String(190), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_level: Mapped[str] = mapped_column(String(32), nullable=False, default="rule")
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="internal")
    model_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    prompt_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    citations: Mapped[dict] = JsonDict()
    blocked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    block_reason: Mapped[str | None] = mapped_column(String(190), nullable=True)
    created_at: Mapped[str] = TS()


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("aud"))
    ts: Mapped[str] = TS(index=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    actor_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    actor_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    project_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    reason_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(190), nullable=True)
    metadata_json: Mapped[dict] = JsonDict()


class SecurityEvent(Base):
    """安全事件。

    ``project_id`` 是**读取侧的授权维度**：安全事件常常带命中文本（金丝雀内容、
    被拦截的查询），没有项目归属就无法按项目授权收口，任何拿到 ``security:read``
    的角色都能看到全部项目的安全事件。项目无关的全局事件（登录失败等）保持为空。
    """

    __tablename__ = "security_event"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("sec"))
    ts: Mapped[str] = TS(index=True)
    actor_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    project_id: Mapped[str | None] = mapped_column(
        ForeignKey("project.id"), nullable=True, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[dict] = JsonDict()


class ModelGatewayConfig(StrIdMixin, TimestampMixin, Base):
    """页面可配置的模型网关：外部 OpenAI 兼容 API 或内网推理服务。"""

    __tablename__ = "model_gateway_config"

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="internal")
    base_url: Mapped[str] = mapped_column(String(512), nullable=False)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    # 密钥只存引用，真实值从环境变量/密钥管理读取
    api_key_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    api_key_masked: Mapped[str | None] = mapped_column(String(32), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    sanitize_before_send: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    temperature: Mapped[float] = mapped_column(Float, nullable=False, default=0.1)
    max_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=2048)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=120)
    extra_headers: Mapped[dict] = JsonDict()
    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)


class RetrievalLedger(Base):
    """检索账本：拼图防护的累积视图。

    记录「谁在什么时间看过哪个分片」，用于计算跨查询的累积覆盖度与敏感维度共现。
    多副本部署下必须落库，进程内计数在多实例间不成立。
    """

    __tablename__ = "retrieval_ledger"
    __table_args__ = (
        UniqueConstraint("actor_id", "chunk_id", name="uq_retrieval_ledger_actor_chunk"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("rl"))
    ts: Mapped[str] = TS(index=True)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    chunk_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    document_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    project_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    classification: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # 命中的敏感维度（identity/timing/scale/location/credential），用于共现累加
    dimensions: Mapped[dict] = JsonDict()
    query_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # 本次检索是否为降密级返回
    downgraded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class DirectorySyncState(StrIdMixin, TimestampMixin, Base):
    __tablename__ = "directory_sync_state"

    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    cursor: Mapped[str | None] = mapped_column(String(190), nullable=True)
    last_sync_at: Mapped[str | None] = TS_NULL()
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="idle")
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    stats: Mapped[dict] = JsonDict()


class OidcLoginState(Base):
    """OIDC 登录 state：服务端一次性校验的凭据（登录 CSRF / 重放 / 超期防护）。

    为什么必须落库而不是进程内 dict：``deploy/k8s/04-api.yaml`` 是
    ``replicas: 2`` + HPA，进程内 state 会在多副本间随机失效；项目当前用
    ``create_all`` 建表（未上 alembic），新增表由启动引导自动创建。
    """

    __tablename__ = "oidc_login_state"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("ols"))
    # 只存 state 的 sha256：即使库被读也无法直接拿去当 state 用（一次性 + 短 TTL）
    state_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    # PKCE verifier 与 nonce 一律服务端保管，不再下发浏览器
    code_verifier: Mapped[str] = mapped_column(String(128), nullable=False)
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    redirect_uri: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # 消费该 state 的用户标识（authorize 阶段还不知道用户，回调时回填）
    subject: Mapped[str | None] = mapped_column(String(190), nullable=True)
    created_at: Mapped[str] = TS(index=True)
    consumed_at: Mapped[str | None] = TS_NULL()
    expires_at: Mapped[str] = TS(index=True)


class RuntimeCounter(Base):
    """跨副本运行期计数：查询预算 / 登录锁定共用的滑动窗口表。

    为什么必须落库：``deploy/k8s/04-api.yaml`` 是 ``replicas: 2`` + HPA，
    进程内计数会把阈值按副本数放大——小时预算变成「每副本 60」、登录锁定从
    「第 6 次失败」退化成「第 11 次」。这些是安全控制，不能随副本数漂移。

    行级 TTL 由 ``rg_api.retention`` 定时清理；写入侧另有低频概率清理，
    避免两次定时任务之间被刷爆。``value`` 只承载附加维度（如 project_id），
    「短时间扫了多少个项目」靠 distinct ``value`` 统计。
    """

    __tablename__ = "runtime_counter"
    __table_args__ = (
        Index("ix_runtime_counter_scope_subject_ts", "scope", "subject", "ts"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("rc"))
    # 计数域：retrieval / retrieval_project / retrieval_blocked / export / login_failure
    scope: Mapped[str] = mapped_column(String(32), nullable=False)
    subject: Mapped[str] = mapped_column(String(190), nullable=False)
    value: Mapped[str | None] = mapped_column(String(190), nullable=True)
    ts: Mapped[str] = TS()


class SchemaVersion(Base):
    """schema 迁移版本记录（``docs/schema-bootstrap-governance.md`` 方案 2 部件 A）。

    为什么这张表放在 ORM 元数据里而不是迁移脚本里：``create_all`` 会顺带把它
    建出来，从而避免「要先记录版本、但版本表本身只能靠迁移创建」的鸡生蛋问题；
    老库第一次跑迁移时它会被建出来、随后把已执行的迁移逐条登记。

    一行 = 一次成功执行的迁移。``version`` 直接当主键（迁移版本号即事实来源），
    ``dialect`` 记下执行方言，便于排查「同版本在不同库上表现不同」的问题。
    """

    __tablename__ = "schema_version"

    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    applied_at: Mapped[str] = TS()
    dialect: Mapped[str] = mapped_column(String(16), nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)


__all__ = [
    "Attribution",
    "AuditLog",
    "Base",
    "CloudAccount",
    "DirectorySyncState",
    "KnowledgeChunk",
    "KnowledgeDocument",
    "ModelGatewayConfig",
    "OidcLoginState",
    "Organization",
    "Project",
    "ProjectMember",
    "Resource",
    "ResourceDiff",
    "RetrievalLedger",
    "RuntimeCounter",
    "SchemaVersion",
    "SecurityEvent",
    "Snapshot",
    "SnapshotState",
    "TS",
    "TS_NULL",
    "TimestampCodec",
    "User",
    "new_id",
    "ts",
]
