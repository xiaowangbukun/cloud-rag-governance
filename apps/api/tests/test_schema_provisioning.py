"""schema 初始化与运行角色拆分（P0-1 部署前提）的回归。

背景：RLS 只在「连接角色不绕过策略」时才成立，而属主/超级用户会绕过策略。
因此生产必须用只有 DML 权限的 ``rg_app`` 连接，建表/建策略这些 DDL 改由属主
身份的一次性 Job 完成。这组用例守三件事：

1. ``verify_schema`` 在缺表时 fail-fast，而不是让应用带着空库启动；
2. ``DB_MIGRATE_ON_STARTUP`` 真的决定「初始化」还是「只校验」；
3. 迁移关闭时启动路径**不会尝试任何 DDL**（运行角色没有权限，尝试只会刷错误日志）。
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from pathlib import Path

import pytest
from rg_contracts.config import get_settings
from rg_contracts.db import migrate
from rg_contracts.db.session import get_engine, required_tables, verify_schema
from sqlalchemy import create_engine

import rg_api.startup as startup


def test_verify_schema_passes_on_initialized_database():
    """测试库由 conftest 建好 schema，校验必须放行（否则整套测试都起不来）。"""
    verify_schema(get_engine())


def test_required_tables_cover_selected_tables():
    """清单从 ORM 元数据推导：易漏的新表也在其中（手写清单会静默过期）。"""
    tables = set(required_tables())
    for name in ("resource", "knowledge_chunk", "attribution", "snapshot_state", "audit_log"):
        assert name in tables, f"必需表清单漏了 {name}"


def test_verify_schema_fails_fast_on_empty_database(tmp_path):
    """空库必须直接报错，并给出表名与修复命令，而不是静默继续。"""
    empty = create_engine(f"sqlite:///{tmp_path / 'empty.db'}", future=True)
    with pytest.raises(RuntimeError) as excinfo:
        verify_schema(empty)
    message = str(excinfo.value)
    assert "schema 未就绪" in message
    assert "audit_log" in message, "错误信息应列出缺失的表名"
    assert "rg_contracts.db.migrate" in message, "错误信息应给出可执行的修复命令"


def _settings(migrate_on_startup: bool):
    return get_settings().model_copy(update={"DB_MIGRATE_ON_STARTUP": migrate_on_startup})


def test_prepare_schema_initializes_when_enabled(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(startup, "ensure_schema", lambda: calls.append("ensure"))
    monkeypatch.setattr(startup, "verify_schema", lambda: calls.append("verify"))

    startup._prepare_schema(_settings(True))

    assert calls == ["ensure"], "开启迁移时只应初始化 schema"


def test_prepare_schema_only_verifies_when_disabled(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(startup, "ensure_schema", lambda: calls.append("ensure"))
    monkeypatch.setattr(startup, "verify_schema", lambda: calls.append("verify"))

    startup._prepare_schema(_settings(False))

    assert calls == ["verify"], "关闭迁移时绝不能执行任何 DDL"


def test_bootstrap_skips_vector_index_ddl_when_migrate_disabled(monkeypatch):
    """索引 DDL 也不能在应用启动时尝试：运行角色没有权限，只会在日志里刷错误。"""
    ddl_calls: list[str] = []

    @contextmanager
    def _fake_scope():
        yield object()

    monkeypatch.setattr(startup, "_prepare_schema", lambda settings: None)
    monkeypatch.setattr(startup, "_check_rls_enforcement", lambda settings: None)
    monkeypatch.setattr(startup, "session_scope", _fake_scope)
    monkeypatch.setattr(
        startup, "ensure_pgvector_index", lambda *args, **kwargs: ddl_calls.append("index")
    )
    monkeypatch.setattr(startup, "backfill_embeddings", lambda *args, **kwargs: 0)

    startup.bootstrap(_settings(False).model_copy(update={"DEMO_SEED": False}))

    assert ddl_calls == [], "DB_MIGRATE_ON_STARTUP=false 时启动路径不得尝试建索引"


def test_migrate_entry_point_runs_and_is_idempotent(monkeypatch):
    """迁移命令可重复执行（部署重跑 Job 是常态），且返回 0。"""
    assert migrate.main() == 0
    assert migrate.main() == 0


# ---------------------------------------------------------------- 部署清单守卫
#
# 用文本断言而不是 yaml.safe_load：PyYAML 只是本仓库的间接依赖（uvicorn 带入），
# 未在 dev extras 里声明；为了让测试的依赖面与声明面一致，这里不引入它。

_K8S = Path(__file__).resolve().parents[3] / "deploy" / "k8s"


def _manifest(name: str) -> str:
    return (_K8S / name).read_text(encoding="utf-8")


def test_api_runs_as_dml_only_role_with_a_separate_password():
    """api 必须用 rg_app + DB_APP_PASSWORD：用属主凭据会让 RLS 彻底失效。

    缺陷形态（改回去最容易犯的错）：直接改 ``01-config.yaml`` 的 ``DB_USER``，
    那会连 09/11/12 的运维 Job 一起变成运行角色——它们需要 DDL，反而立刻失败。
    所以拆分只能发生在 ``04-api.yaml`` 的容器级覆盖里。
    """
    config = _manifest("01-config.yaml")
    assert re.search(r"^\s*DB_USER:\s*\"governance\"", config, re.MULTILINE), (
        "configMap 的 DB_USER 应保留为属主（运维 Job 需要 DDL）"
    )
    assert re.search(r"^\s*DB_MIGRATE_ON_STARTUP:\s*\"false\"", config, re.MULTILINE), (
        "生产应用不得执行 DDL"
    )
    assert 'DB_APP_PASSWORD: "REPLACE_VIA_EXTERNAL_SECRET"' in config

    api = _manifest("04-api.yaml")
    assert re.search(r"- name: DB_USER\s*\n\s*value: rg_app", api), "api 必须用只 DML 的运行角色"
    assert re.search(r"- name: DB_PASSWORD\s*\n\s*valueFrom:", api), (
        "api 的密码必须从 Secret 注入，不能留在 configMap"
    )
    assert re.search(r"key: DB_APP_PASSWORD", api), (
        "api 的密码必须走独立键；复用属主的 DB_PASSWORD 等于把绕过 RLS 的凭据交给业务进程"
    )


def test_schema_job_migrates_with_owner_before_granting_role():
    """schema-init Job 必须「先迁移、后建角色」，且迁移容器用属主身份。"""
    job = _manifest("12-schema-job.yaml")
    assert 'command: ["python", "-m", "rg_contracts.db.migrate"]' in job
    assert re.search(r"- name: DB_USER\s*\n\s*value: governance", job), (
        "迁移容器必须用属主（运行角色没有 DDL 权限）"
    )
    assert "REVOKE CREATE ON SCHEMA public" in job, "运行角色不得有建表权限"
    # initContainers 天然先于 containers；断言顺序，避免有人把授权挪到迁移之前
    assert job.index("initContainers:") < job.index("- name: grant")


def test_schema_job_pod_is_allowed_by_network_policy():
    """Job 的 Pod 标签必须在 NetworkPolicy 的 allow 列表里，否则连不上 PG。

    缺陷形态：默认拒绝入站时，没有对应 ``app`` 标签的 Pod 无法连接 PostgreSQL，
    Job 只会表现为「连接超时」——排障方向会被误导到数据库本身。这已知坑在
    ``06-networkpolicy.yaml`` 的注释里对备份/演练记录过一次，schema-init 同样适用。
    """
    job = _manifest("12-schema-job.yaml")
    policy = _manifest("06-networkpolicy.yaml")
    assert re.search(r"^\s+app: schema-init$", job, re.MULTILINE), "Job Pod 缺少 app 标签"
    # 只截取 allow-api-to-postgres 这段，避免误命中其它策略里的同名标签
    postgres_policy = policy.split("name: allow-api-to-postgres", 1)[1]
    assert re.search(r"- podSelector:\s*\n\s*matchLabels:\s*\n\s*app: schema-init",
                     postgres_policy), "NetworkPolicy 未放通 schema-init 访问 PostgreSQL"
