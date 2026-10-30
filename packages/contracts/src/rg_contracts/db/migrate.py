"""schema 初始化入口：以**属主身份**执行，供部署 Job 使用。

为什么单独做成一个命令，而不是继续让应用启动时建表：生产应用的连接角色
（``rg_app``）按最小权限只拿 DML、没有 DDL 权限——这是 RLS 兜底能成立的前提
（属主/超级用户会绕过策略）。因此建表、补列、建 RLS 策略、建向量索引这些 DDL
必须由另一个身份完成，应用启动时只做 ``verify_schema`` 校验。

用法::

    python -m rg_contracts.db.migrate            # 建表 + 执行未登记迁移（默认）
    python -m rg_contracts.db.migrate --plan     # dry-run：只打印待执行迁移，不执行
    python -m rg_contracts.db.migrate --verify   # 只校验 schema 是否就绪，不建表

``--plan`` 是给离线客户做变更评审用的（``docs/schema-bootstrap-governance.md``
方案 2 部件 C / R10）：它走与 ``apply_pending`` 完全相同的判定
（``schema_migrations.pending_migrations``），只打印不执行。

退出码：0 成功；``--verify`` 检测到缺表返回 1；其余异常直接以非零退出
（Job 失败即中止发布，不把半成品放行）。
"""

from __future__ import annotations

import argparse
import sys

from rg_contracts.ai.retrieval import ensure_pgvector_index
from rg_contracts.config import DbDialect, get_settings
from rg_contracts.db.rls import policy_rows
from rg_contracts.db.schema_migrations import applied_versions, describe_plan
from rg_contracts.db.session import ensure_schema, get_engine, session_scope, verify_schema


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m rg_contracts.db.migrate",
        description="schema 初始化 / 迁移（必须由属主身份执行，运行角色没有 DDL 权限）",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--plan",
        action="store_true",
        help="dry-run：只打印待执行的迁移清单（version / 名称 / 说明），不执行任何 DDL",
    )
    mode.add_argument(
        "--verify",
        action="store_true",
        help="只校验：缺表即返回非零退出码，不建表、不跑迁移",
    )
    return parser


def _cmd_plan(engine) -> int:  # type: ignore[no-untyped-def]
    rows = describe_plan(engine)
    done = applied_versions(engine)
    print(f"plan: dialect={engine.dialect.name} applied={sorted(done) or '[]'}")
    if not rows:
        print("plan: 无待执行迁移（schema_version 已覆盖当前注册表）")
        return 0
    print(f"plan: 待执行 {len(rows)} 条（dry-run，未执行任何 DDL）")
    for row in rows:
        print(
            f"  [{row['version']}] {row['name']} (dialect={row['dialect']}) "
            f"- {row['description']}"
        )
    return 0


def _cmd_verify(engine) -> int:  # type: ignore[no-untyped-def]
    try:
        verify_schema(engine)
    except RuntimeError as exc:
        print(f"verify failed: {exc}", file=sys.stderr)
        return 1
    done = applied_versions(engine)
    print(f"verify ok: dialect={engine.dialect.name} applied={sorted(done) or '[]'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """三个模式的统一入口。

    ``argv`` 为 ``None`` 时按「无参数」处理（默认建表 + 迁移），**不读**
    ``sys.argv``：``main()`` 也会被测试与部署脚本当函数直接调用，若隐式解析
    ``sys.argv``，pytest 自己的参数（``-q`` / ``--junitxml=...``）会被当成
    migrate 的未知参数直接报错。命令行参数由 ``__main__`` 显式传进来。
    """
    args = _build_parser().parse_args([] if argv is None else argv)
    settings = get_settings()
    engine = get_engine(settings)

    if args.plan:
        return _cmd_plan(engine)
    if args.verify:
        return _cmd_verify(engine)

    applied = ensure_schema(engine)
    if settings.DB_DIALECT is not DbDialect.POSTGRES:
        print(f"migrate ok: dialect=sqlite applied={applied}（RLS 只在 PostgreSQL 生效）")
        return 0
    # 索引也是 DDL：运行角色建不了，必须在这里一并建好，否则应用侧只能退化为
    # 顺序扫描（且每次启动都会因为权限不足而报错）。
    with session_scope() as session:
        ensure_pgvector_index(session, settings.EMBEDDING_DIM)
    policies = len(policy_rows(engine)) if settings.DB_RLS_ENABLED else 0
    done = sorted(applied_versions(engine))
    print(
        f"migrate ok: dialect=postgresql applied={applied} versions={done} "
        f"vector_index=ok rls_policies={policies}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
