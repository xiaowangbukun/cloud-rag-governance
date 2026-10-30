"""访问策略测试：RBAC 能力边界 + ABAC 项目/密级边界 + 拼图与导出限制。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from conftest import make_subject
from rg_contracts.enums import Classification, Role
from rg_contracts.security.policy import (
    PolicyEngine,
    default_engine,
    levels_at_or_below,
    normalize_levels,
)

engine = default_engine()


def test_role_capability_boundary():
    viewer = make_subject(Role.VIEWER.value, Classification.L2_INTERNAL.value)
    assert engine.check_capability(viewer, "resource:read").allowed
    assert not engine.check_capability(viewer, "attribution:run").allowed
    assert not engine.check_capability(viewer, "admin:config").allowed
    assert engine.check_capability(viewer, "admin:config").reason_code == "missing_capability"


def test_admin_has_config_capability():
    admin = make_subject(Role.ADMIN.value, Classification.L4_SECRET.value)
    assert engine.check_capability(admin, "admin:config").allowed
    assert engine.check_capability(admin, "export:standard").allowed


def test_governance_scope_is_unrestricted_but_level_bounded():
    gov = make_subject(Role.GOVERNANCE.value, Classification.L3_CONFIDENTIAL.value)
    assert engine.build_scope(gov).unrestricted
    assert not engine.check_level(gov, "prj_data", Classification.L4_SECRET.value).allowed


def test_pm_cannot_access_other_project():
    pm = make_subject(Role.PM.value, Classification.L3_CONFIDENTIAL.value, ["prj_core_policy"])
    assert engine.check_project(pm, "prj_core_policy").allowed
    decision = engine.check_project(pm, "prj_claim")
    assert not decision.allowed
    assert decision.reason_code == "project_out_of_scope"


def test_viewer_without_project_is_denied():
    viewer = make_subject(Role.VIEWER.value, Classification.L2_INTERNAL.value, [])
    assert engine.check_project(viewer, "prj_agent").reason_code == "project_out_of_scope"
    assert engine.check_project(viewer, None).reason_code == "project_required"


def test_time_span_guard():
    start = datetime.now(timezone.utc) - timedelta(days=400)
    end = datetime.now(timezone.utc)
    decision = engine.check_time_span(start, end, 180)
    assert not decision.allowed
    assert decision.reason_code == "span_too_large"


def test_invalid_range_guard():
    start = datetime.now(timezone.utc)
    end = start - timedelta(days=5)
    assert engine.check_time_span(start, end, 180).reason_code == "invalid_range"


def test_scope_request_requires_project_for_limited_role():
    pm = make_subject(Role.PM.value, Classification.L3_CONFIDENTIAL.value, ["prj_core_policy"])
    assert engine.check_scope_request(pm, None, None).reason_code == "project_required"
    assert engine.check_scope_request(pm, ["prj_core_policy"], None).allowed
    assert not engine.check_scope_request(pm, ["prj_claim"], None).allowed


def test_scope_request_rejects_level_above_ceiling():
    pm = make_subject(Role.PM.value, Classification.L2_INTERNAL.value, ["prj_core_policy"])
    decision = engine.check_scope_request(pm, ["prj_core_policy"], [Classification.L4_SECRET.value])
    assert not decision.allowed
    assert decision.reason_code == "level_exceeded"


def test_export_limits():
    gov = make_subject(Role.GOVERNANCE.value, Classification.L3_CONFIDENTIAL.value)
    assert engine.check_export(gov, 10, 200).allowed
    assert engine.check_export(gov, 500, 200).reason_code == "export_limit_exceeded"
    viewer = make_subject(Role.VIEWER.value, Classification.L2_INTERNAL.value)
    assert engine.check_export(viewer, 1, 200).reason_code == "export_forbidden"


def test_project_ceiling_is_min_of_user_and_project():
    pm = make_subject(
        Role.PM.value,
        Classification.L4_SECRET.value,
        ["prj_core_policy"],
        visible_ceilings={"prj_core_policy": Classification.L2_INTERNAL.value},
    )
    assert pm.ceiling_for("prj_core_policy") == Classification.L2_INTERNAL.value
    assert pm.ceiling_for("prj_unknown") == Classification.L4_SECRET.value


def test_level_helpers():
    assert levels_at_or_below(Classification.L2_INTERNAL.value) == [
        Classification.L1_PUBLIC.value,
        Classification.L2_INTERNAL.value,
    ]
    assert normalize_levels(None, Classification.L2_INTERNAL.value) == [
        Classification.L1_PUBLIC.value,
        Classification.L2_INTERNAL.value,
    ]
    # 超出上限的请求被过滤掉，而不是报错放行
    assert normalize_levels(
        [Classification.L4_SECRET.value], Classification.L2_INTERNAL.value
    ) == [Classification.L1_PUBLIC.value, Classification.L2_INTERNAL.value]


def test_custom_engine_overrides_capabilities():
    custom = PolicyEngine({"tester": {"resource:read"}})
    subject = make_subject("tester", Classification.L1_PUBLIC.value)
    assert custom.check_capability(subject, "resource:read").allowed
    assert not custom.check_capability(subject, "audit:read").allowed
