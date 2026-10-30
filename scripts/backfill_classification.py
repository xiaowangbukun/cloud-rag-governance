"""P0-2 存量数据修正：把 resource / resource_diff 的密级对齐到项目目录密级。

背景：修复前采集器硬编码 classification="L3_CONFIDENTIAL"（P0-2），导致 L4 项目的
采集数据被打成 L3，低密级岗位可越权读取。本脚本把存量污染数据对齐到项目真实密级。

安全性：
- 对齐方向是「向项目真实密级对齐」（可能升密级），本身是收敛而非扩大暴露面；
- 幂等：执行后残留不一致计数为 0，重复执行为空操作；
- 默认 dry-run 只报告，--apply 才写库；执行前建议先备份。

用法：
    python scripts/backfill_classification.py            # 预演：只报告不一致数量
    python scripts/backfill_classification.py --apply    # 执行修正
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text

from rg_contracts.db.session import get_engine

# 残留不一致检查（两种方言通用）
_RESIDUAL_SQL = text(
    "SELECT "
    "(SELECT COUNT(*) FROM resource r JOIN project p ON r.project_id = p.id "
    " WHERE r.classification <> p.classification) "
    "+ (SELECT COUNT(*) FROM resource_diff d JOIN project p ON d.project_id = p.id "
    " WHERE d.classification <> p.classification)"
)

# 修正语句：PG 用 UPDATE ... FROM，SQLite 用关联子查询
_UPDATE_PG = {
    "resource": text(
        "UPDATE resource r SET classification = p.classification FROM project p "
        "WHERE r.project_id = p.id AND r.classification <> p.classification"
    ),
    "resource_diff": text(
        "UPDATE resource_diff d SET classification = p.classification FROM project p "
        "WHERE d.project_id = p.id AND d.classification <> p.classification"
    ),
}
_UPDATE_SQLITE = {
    "resource": text(
        "UPDATE resource SET classification = "
        "(SELECT p.classification FROM project p WHERE p.id = resource.project_id) "
        "WHERE classification <> "
        "(SELECT p.classification FROM project p WHERE p.id = resource.project_id)"
    ),
    "resource_diff": text(
        "UPDATE resource_diff SET classification = "
        "(SELECT p.classification FROM project p WHERE p.id = resource_diff.project_id) "
        "WHERE classification <> "
        "(SELECT p.classification FROM project p WHERE p.id = resource_diff.project_id)"
    ),
}


def main() -> int:
    parser = argparse.ArgumentParser(description="P0-2 存量密级对齐修正")
    parser.add_argument("--apply", action="store_true", help="执行写库（默认仅预演）")
    args = parser.parse_args()

    engine = get_engine()
    dialect = engine.dialect.name
    updates = _UPDATE_PG if dialect == "postgresql" else _UPDATE_SQLITE
    print(f"dialect={dialect} apply={args.apply}")

    with engine.begin() as conn:
        residual_before = conn.execute(_RESIDUAL_SQL).scalar_one()
        print(f"residual_mismatch_before={residual_before}")
        if residual_before == 0:
            print("nothing to do")
            return 0
        if not args.apply:
            print("dry-run: 加 --apply 执行修正")
            return 0
        for table, stmt in updates.items():
            result = conn.execute(stmt)
            print(f"updated {table}: rowcount={result.rowcount}")

    with engine.begin() as conn:
        residual_after = conn.execute(_RESIDUAL_SQL).scalar_one()
    print(f"residual_mismatch_after={residual_after}")
    if residual_after != 0:
        print("ERROR: 修正后仍存在不一致，请检查项目目录数据", file=sys.stderr)
        return 1
    print("OK: resource/resource_diff 密级已全部对齐项目目录")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
