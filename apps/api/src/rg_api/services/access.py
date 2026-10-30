"""授权边界与审计的公共能力：路由层只做编排，不重复实现策略。"""

from __future__ import annotations

from typing import Any, Sequence

from fastapi import Request
from rg_contracts.config import get_settings
from rg_contracts.errors import PermissionDeniedError
from rg_contracts.security.policy import AccessScope, Subject, default_engine, levels_at_or_below
from sqlalchemy.orm import Session

_engine = default_engine()


def resolve_scope(subject: Subject) -> AccessScope:
    return _engine.build_scope(subject)


def scoped_project_ids(subject: Subject, project_id: str | None = None) -> list[str]:
    """把 subject + 可选 project_id 收敛为可下推到 SQL 的项目 ID 列表。"""
    scope = resolve_scope(subject)
    if project_id:
        if not scope.allows_project(project_id):
            # 不泄露项目是否存在
            raise PermissionDeniedError("无该项目访问权限")
        return [project_id]
    if scope.unrestricted:
        return []
    return list(scope.project_ids)


def allowed_levels(subject: Subject, project_id: str | None = None) -> list[str]:
    ceiling = subject.ceiling_for(project_id) if project_id else subject.classification_ceiling
    return levels_at_or_below(ceiling)


def diff_scope_clause(subject: Subject, project_ids: Sequence[str]) -> Any:
    """资源差异的行级安全条件：项目范围 × 该项目密级上限。

    返回 None 表示当前主体无任何可见差异（调用方应直接返回空结果）。
    注意：unrestricted 只放开项目范围，**不放开密级**。
    """
    from rg_contracts.db.models import ResourceDiff
    from sqlalchemy import and_, or_

    candidates = list(project_ids)
    if not candidates and _engine.build_scope(subject).unrestricted:
        # 未指定项目时收敛到目录中有可见密级的项目，不做全库扫描
        candidates = sorted(subject.visible_ceilings)

    if not candidates:
        if _engine.build_scope(subject).unrestricted:
            return ResourceDiff.classification.in_(levels_at_or_below(subject.classification_ceiling))
        return None

    return or_(
        *[
            and_(
                ResourceDiff.project_id == pid,
                ResourceDiff.classification.in_(levels_at_or_below(subject.ceiling_for(pid))),
            )
            for pid in candidates
        ]
    )


def assert_project_access(subject: Subject, project_id: str | None) -> None:
    if not project_id:
        raise PermissionDeniedError("请求必须限定到具体项目")
    decision = _engine.check_project(subject, project_id)
    if not decision.allowed:
        raise PermissionDeniedError(decision.message)


def assert_capability(
    subject: Subject,
    capability: str,
    *,
    request: Request | None = None,
    session: Session | None = None,
) -> None:
    """能力校验；拒绝时若给了 request+session 就补一条 denied 审计。

    此前签名只有 (subject, capability)，拒绝路径**零审计留痕**——QA 实测
    13 条拒绝路径里有 6 条没有任何 AuditLog 记录，「谁被拒绝了」不可见。

    request/session 均为可选关键字：两者齐备才写审计（走独立事务，
    不受业务回滚牵连）；缺省时保持原样只抛异常，避免影响无 HTTP 上下文的
    调用方（如脚本、后台任务）。
    """
    decision = _engine.check_capability(subject, capability)
    if decision.allowed:
        return
    if request is not None and session is not None:
        # 函数内延迟导入：audit 模块依赖本模块的 client_meta，模块级互相
        # 导入会形成循环（access → audit → access）。
        from rg_api.services.audit import audit_action

        audit_action(
            request,
            session,
            subject,
            capability,
            "denied",
            None,
            decision.reason_code,
            metadata={"capability": capability},
        )
    raise PermissionDeniedError(decision.message)


def client_meta(request: Request) -> tuple[str | None, str | None]:
    ip = request.client.host if request.client else None
    user_agent = request.headers.get("User-Agent")
    return ip, (user_agent or "")[:190] or None


def enforce_export(subject: Subject, row_count: int) -> None:
    """导出双重闸门：单次行数上限（策略引擎）+ 每小时导出次数（预算）。

    此前只查了行数，``QueryBudget.check_export`` 全代码库无人调用 ——
    「每小时最多 10 次导出」这条限制实际上没有生效，攻击者可以反复导出
    小批量数据慢慢拼全貌。
    """
    from rg_contracts.errors import RateLimitedError
    from rg_contracts.security.budget import get_budget

    settings = get_settings()
    decision = _engine.check_export(subject, row_count, settings.SECURITY_EXPORT_LIMIT)
    if not decision.allowed:
        raise PermissionDeniedError(decision.message)
    ok, reason = get_budget().check_export(subject.user_id, row_count)
    if not ok:
        raise RateLimitedError(
            "导出频次超出小时预算" if reason == "export_budget_exceeded" else "单次导出行数超限",
            reason=reason,
            limit=settings.SECURITY_EXPORT_LIMIT,
        )
