"""采集任务：触发多云采集、生成快照、计算增量 diff。"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from rg_contracts.collector import metrics as metric_writer
from rg_contracts.collector import objects as object_writer
from rg_contracts.collector.diff import compute_diff, diff_summary
from rg_contracts.collector.providers import build_provider
from rg_contracts.config import get_settings
from rg_contracts.db import rls
from rg_contracts.db.models import (
    CloudAccount,
    Project,
    Resource,
    Snapshot,
    SnapshotState,
    new_id,
    ts,
)
from rg_contracts.db.session import db_session
from rg_contracts.enums import ResourceKind, SnapshotStatus
from rg_contracts.errors import NotFoundError
from rg_contracts.logging_setup import get_logger
from rg_contracts.security.policy import Subject
from sqlalchemy import select
from sqlalchemy.orm import Session

from rg_api.routes.auth import current_subject
from rg_api.services.access import assert_capability
from rg_api.services.audit import audit_action
from rg_api.services.governance import run_rules, to_diff_model

logger = get_logger(__name__)
router = APIRouter(prefix="/collection", tags=["collection"])


class CollectRequest(BaseModel):
    platform: str | None = None
    account_id: str | None = None
    dry_run: bool = False
    note: str | None = Field(default=None, max_length=200)


@router.get("/accounts")
def list_accounts(
    request: Request,
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> list[dict]:
    """云账号清单含 credential_ref / endpoint，属于采集配置而非普通资源数据。

    只返回治理/管理角色可读的字段；无 ``collection:read`` 的角色直接拒绝，
    避免任意登录用户拿到全部云账号与凭据引用。
    """
    assert_capability(subject, "collection:read", request=request, session=session)
    rows = session.execute(select(CloudAccount)).scalars().all()
    return [
        {
            "id": row.id,
            "platform": row.platform,
            "name": row.name,
            "region": row.region,
            "enabled": row.enabled,
            "credential_ref": row.credential_ref,
            "endpoint": row.endpoint,
        }
        for row in rows
    ]


@router.post("/run")
def run_collection(
    payload: CollectRequest,
    request: Request,
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> dict:
    assert_capability(subject, "collection:run", request=request, session=session)
    settings = get_settings()

    stmt = select(CloudAccount).where(CloudAccount.enabled.is_(True))
    if payload.account_id:
        stmt = stmt.where(CloudAccount.id == payload.account_id)
    if payload.platform:
        stmt = stmt.where(CloudAccount.platform == payload.platform)
    accounts = session.execute(stmt).scalars().all()
    if not accounts:
        raise NotFoundError("未找到可用的云账号")

    started = datetime.now(timezone.utc)
    snapshots: list[Snapshot] = []
    dry_run_records: list[dict] = []
    total_resources = 0
    total_diffs = 0
    total_metrics = 0
    total_rule_diffs = 0
    baselines_ready = 0

    for account in accounts:
        snapshot = Snapshot(
            id=new_id("snap"),
            platform=account.platform,
            account_id=account.id,
            taken_at=ts(started),
            status=SnapshotStatus.RUNNING.value,
            source_mode=settings.COLLECTOR_MODE,
        )
        session.add(snapshot)
        session.flush()
        snapshots.append(snapshot)

        try:
            provider = build_provider(account, settings)
            normalized = provider.fetch_resources()
        except Exception as exc:  # noqa: BLE001
            snapshot.status = SnapshotStatus.FAILED.value
            snapshot.error_message = str(exc)[:500]
            # 失败关闭终态先落库：denied/failed 审计走独立事务，
            # 需要业务会话先释放写锁（SQLite 单写者）才能提交
            session.commit()
            audit_action(
                request, session, subject, "collection:run", "failed", None, "collector_error",
                resource_type="cloud_account", resource_id=account.id, metadata={"error": str(exc)[:200]},
            )
            continue

        # P0-2：采集数据密级唯一来源是项目目录（与 Subject.ceiling_for 的 min 语义对齐：
        # 数据密级永远不高于项目密级）。未知项目失败关闭，绝不默认 L3 重新打开泄露缺口。
        levels = _project_classifications(session, {item.project_id for item in normalized})
        unknown = {item.project_id for item in normalized} - set(levels)
        if unknown:
            snapshot.status = SnapshotStatus.FAILED.value
            snapshot.error_message = f"project_not_in_directory: {sorted(unknown)[:3]}"
            # 同 collector_error 分支：终态先提交，释放写锁供独立审计事务落库
            session.commit()
            audit_action(
                request, session, subject, "collection:run", "failed", None, "project_not_in_directory",
                resource_type="cloud_account", resource_id=account.id,
                metadata={"unknown_projects": sorted(unknown)[:5]},
            )
            continue

        previous = _previous_states(session, account.id)
        has_baseline = bool(previous)
        current: dict[str, dict] = {}
        resource_ids: dict[str, str] = {}
        for item in normalized:
            resource = _upsert_resource(session, item, levels[item.project_id])
            resource_ids[item.native_id] = resource.id
            current[item.native_id] = {
                "fingerprint": item.fingerprint,
                "name": item.name,
                "kind": item.kind,
                "project_id": item.project_id,
                "spec": item.spec,
                "status": item.status,
                "tags": item.attributes.get("tags", {}),
                "owner": item.owner,
                "monthly_cost_cny": item.monthly_cost_cny,
                "resource_id": resource.id,
            }
            session.add(
                SnapshotState(
                    id=new_id("ss"),
                    snapshot_id=snapshot.id,
                    resource_id=resource.id,
                    project_id=item.project_id,
                    platform=item.platform,
                    kind=item.kind,
                    fingerprint=item.fingerprint,
                    monthly_cost_cny=item.monthly_cost_cny,
                    # owner/name 必须进快照：基线与增量都从快照取值，
                    # 否则责任人变更在下一轮永远比不出来（Resource 行已被覆盖）
                    payload={
                        "spec": item.spec,
                        "status": item.status,
                        "tags": item.attributes.get("tags", {}),
                        "owner": item.owner,
                        "name": item.name,
                    },
                )
            )

        # 属性/指标表（``resource_metric`` / ``gpu_node``）刻意没有项目列（见
        # ``db/models.py``），PG 策略只认「本事务已授权的锚点集合」。所以必须
        # 先让本账号的锚点全部落库，再一次性授予，最后才写属性行——顺序反过来
        # 在运行角色下会被策略的 WITH CHECK 拒绝。SQLite 没有 RLS，这一步是空操作。
        rls.scope_anchor_ids(session, resource_ids.values())
        for item in normalized:
            resource_id = resource_ids[item.native_id]
            total_metrics += metric_writer.upsert_metrics(
                session,
                resource_id=resource_id,
                metrics=item.metrics,
                units=item.metric_units,
                observed_at=started,
            )
            # GPU 专属属性走 ``gpu_node`` 分表（与指标同一理由：分表存类型属性，
            # 锚点 attributes 只留通用属性；读取必须经锚点）。
            if item.kind == ResourceKind.GPU_NODE.value:
                object_writer.upsert_gpu_node(
                    session,
                    resource_id=resource_id,
                    attributes=item.attributes,
                    asset_tag=item.attributes.get("asset_tag"),
                )

        snapshot.resource_count = len(normalized)
        snapshot.status = SnapshotStatus.SUCCESS.value
        total_resources += len(normalized)

        if payload.dry_run:
            # 预演不落库：回滚本账号暂存数据，逐账号累计后统一返回
            # （此前 return 写在循环内，多账号只返回第一个，其余账号被静默丢弃）
            session.rollback()
            records = compute_diff(previous, current, account.platform) if has_baseline else []
            dry_run_records.append(
                {
                    "account_id": account.id,
                    "platform": account.platform,
                    "resources": len(normalized),
                    "diffs": len(records),
                    "baseline_ready": has_baseline,
                    "summary": diff_summary(records),
                }
            )
            continue

        if has_baseline:
            baselines_ready += 1
            records = compute_diff(previous, current, account.platform)
            # 差异密级来自项目目录；**被释放**的资源所属项目可能已不在当前采集结果里
            # （项目下线、整项目资源清空），直接 levels[pid] 会 KeyError 打断整次采集。
            # 与上方的未知项目分支一致：失败关闭，绝不给差异兜底密级。
            diff_projects = {record.project_id for record in records}
            missing = diff_projects - set(levels)
            if missing:
                snapshot.status = SnapshotStatus.FAILED.value
                snapshot.error_message = f"project_not_in_directory: {sorted(missing)[:3]}"
                session.commit()
                audit_action(
                    request, session, subject, "collection:run", "failed", None,
                    "project_not_in_directory",
                    resource_type="cloud_account", resource_id=account.id,
                    metadata={"unknown_projects": sorted(missing)[:5], "stage": "diff"},
                )
                continue
            for record in records:
                session.add(to_diff_model(record, snapshot.id, levels[record.project_id]))
            total_diffs += len(records)
        else:
            # 首次采集没有基线，直接把全部资源记为差异会造成大量误报
            records = []
            logger.warning("collection_baseline_missing", extra={"extra_fields": {"account": account.id}})

        # 治理规则（D1…）与「快照 A vs B」的时序 diff 是两条独立口径：
        # 治理项不依赖基线，首轮采集就应该产出（"这台机器一直闲置"不需要
        # 第二次快照才能证明）。去重与落库都在 services/governance.py。
        rule_diffs = run_rules(
            session,
            items=normalized,
            resource_ids=resource_ids,
            levels=levels,
            snapshot_id=snapshot.id,
            settings=settings,
        )
        if rule_diffs:
            total_rule_diffs += rule_diffs
            total_diffs += rule_diffs

    if payload.dry_run:
        # 预演路径不落库、不审计（与修复前一致），在循环后统一返回全部账号
        return {
            "dry_run": True,
            "accounts": len(dry_run_records),
            "resources": sum(record["resources"] for record in dry_run_records),
            "diffs": sum(record["diffs"] for record in dry_run_records),
            "baselines_ready": sum(1 for record in dry_run_records if record["baseline_ready"]),
            "per_account": dry_run_records,
        }

    session.commit()
    audit_action(
        request, session, subject, "collection:run", "allowed", None, None,
        resource_type="snapshot", resource_id=snapshots[0].id if snapshots else None,
        metadata={"accounts": len(accounts), "resources": total_resources, "mode": settings.COLLECTOR_MODE},
    )
    return {
        "dry_run": False,
        "accounts": len(accounts),
        "resources": total_resources,
        "diffs": total_diffs,
        "metrics": total_metrics,
        # 治理项条数（D1…）：``diffs`` 里包含它，这里单列是为了让运维一眼看出
        # "本轮新增的是时序差异还是规则命中的治理项"。
        "rule_diffs": total_rule_diffs,
        "baselines_ready": baselines_ready,
        "hint": "首次采集仅建立基线不产出差异，第二次采集开始输出增量 diff"
        if baselines_ready < len(accounts)
        else None,
        "snapshots": [s.id for s in snapshots],
        "mode": settings.COLLECTOR_MODE,
    }


@router.get("/snapshots")
def list_snapshots(
    request: Request,
    limit: int = 20,
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> list[dict]:
    assert_capability(subject, "collection:read", request=request, session=session)
    rows = session.execute(
        select(Snapshot).order_by(Snapshot.taken_at.desc()).limit(max(1, min(limit, 100)))
    ).scalars().all()
    return [
        {
            "id": row.id,
            "platform": row.platform,
            "account_id": row.account_id,
            "taken_at": row.taken_at if isinstance(row.taken_at, str) else "",
            "status": row.status,
            "source_mode": row.source_mode,
            "resource_count": row.resource_count,
            "error_message": row.error_message,
        }
        for row in rows
    ]


def _previous_states(session: Session, account_id: str) -> dict[str, dict]:
    """取上一份成功快照作为比对基线。"""
    previous_snapshot = (
        session.execute(
            select(Snapshot)
            .where(Snapshot.account_id == account_id, Snapshot.status == SnapshotStatus.SUCCESS.value)
            .order_by(Snapshot.taken_at.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )
    if previous_snapshot is None:
        return {}
    rows = session.execute(
        select(SnapshotState).where(SnapshotState.snapshot_id == previous_snapshot.id)
    ).scalars().all()
    out: dict[str, dict] = {}
    for row in rows:
        resource = session.get(Resource, row.resource_id)
        if resource is None:
            continue
        payload = row.payload or {}
        out[resource.native_id] = {
            "fingerprint": row.fingerprint,
            # 基线快照的 payload 才是「上一轮的真实值」；Resource 行已经是本轮
            # 覆盖后的值，用它当基线会让责任人/名称变更永远检测不到。
            # 旧快照没有这些字段时回退到 Resource，保持向后兼容。
            "name": payload.get("name", resource.name),
            "kind": row.kind,
            "project_id": row.project_id,
            "spec": payload.get("spec"),
            "status": payload.get("status"),
            "tags": payload.get("tags", {}),
            "owner": payload.get("owner", resource.owner),
            "monthly_cost_cny": row.monthly_cost_cny,
            "resource_id": row.resource_id,
        }
    return out


def _project_classifications(session: Session, project_ids: set[str]) -> dict[str, str]:
    """项目密级目录：采集数据的数据分级唯一来源。

    项目目录为唯一事实源（假设 A5）：采集到的资源/差异密级一律继承所属项目，
    不允许在采集侧默认任何密级。
    """
    if not project_ids:
        return {}
    rows = session.execute(
        select(Project.id, Project.classification).where(Project.id.in_(project_ids))
    ).all()
    return {pid: level for pid, level in rows}


def _resource_attributes(item) -> dict:
    """``Resource.attributes`` 只保留属性：指标值单独入 ``resource_metric``。

    同一份利用率不重复存两处，避免"改了指标表却没改 attributes"时两个事实源
    互相矛盾（且 JSON 列无法做唯一约束）。剥离逻辑放这里而不是调用方，
    是为了让直调 ``_upsert_resource`` 的路径也遵守同一条不变量。
    """
    attributes = dict(getattr(item, "attributes", None) or {})
    for key in ("metrics", "metric_units"):
        attributes.pop(key, None)
    # 类型专属属性同样分表存放（当前只有 ``gpu_node``）：锚点行留通用属性，
    # 否则属性表与 attributes 会成为两个会漂移的事实源。
    for key in object_writer.GPU_ATTRIBUTE_KEYS:
        attributes.pop(key, None)
    return attributes


def _upsert_resource(
    session: Session, item, classification: str, attributes: dict | None = None
) -> Resource:
    if attributes is None:
        attributes = _resource_attributes(item)
    existing = session.execute(
        select(Resource).where(
            Resource.platform == item.platform,
            Resource.account_id == item.account_id,
            Resource.native_id == item.native_id,
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.spec = item.spec
        existing.status = item.status
        existing.monthly_cost_cny = item.monthly_cost_cny
        existing.last_seen_date = datetime.now(timezone.utc).date()
        existing.attributes = attributes
        # 名称/责任人/归属会随调拨、改名变化；只更新规格与状态会让 owner 永久陈旧
        existing.name = item.name
        existing.kind = item.kind
        existing.region = item.region
        existing.project_id = item.project_id
        existing.owner = item.owner
        # 项目密级变更时同步刷新（项目目录为唯一事实源）
        existing.classification = classification
        return existing
    resource = Resource(
        id=new_id("res"),
        platform=item.platform,
        account_id=item.account_id,
        project_id=item.project_id,
        native_id=item.native_id,
        name=item.name,
        kind=item.kind,
        region=item.region,
        spec=item.spec,
        status=item.status,
        monthly_cost_cny=item.monthly_cost_cny,
        classification=classification,
        owner=item.owner,
        first_seen_date=datetime.now(timezone.utc).date(),
        last_seen_date=datetime.now(timezone.utc).date(),
        attributes=attributes,
    )
    session.add(resource)
    session.flush()
    return resource


__all__ = ["router"]
