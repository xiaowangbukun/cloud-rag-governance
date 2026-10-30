"""``/ready`` 暴露 schema 漂移快照（第三批）。

覆盖的是「漂移能被看见」这条链路，而不是比对算法本身（算法在
``packages/contracts/tests/test_schema_drift.py`` 用独立引擎跑）：

- 启动时采样的漂移必须出现在探针响应里，新库必须为空（否则探针长期假红）；
- 采样结果只来自启动期缓存：``/ready`` 每 10 秒一次，不能在探针里做列级
  introspection（那会把就绪检查变成数据库负载）；
- 生产方言（PG）上「同义类型写法」不得产生假阳性，这条只能在这里验证。
"""

from __future__ import annotations

import pytest
from rg_contracts.db.session import DRIFT_EXTRA_COLUMN, DRIFT_TYPE_MISMATCH, schema_drift

from rg_api import startup


def test_ready_exposes_empty_drift_on_fresh_schema(client):
    """全新 schema：``schema_drift`` 必须是空列表，且采样时间非空。"""
    body = client.get("/ready").json()

    assert body["status"] == "ok"
    assert body["schema_drift"] == []
    checked_at = body["schema_drift_checked_at"]
    assert isinstance(checked_at, str) and checked_at, "启动期必须留下采样时间"


def test_live_database_schema_has_no_drift():
    """生产方言上不得有假阳性：``CHARACTER VARYING``、``DOUBLE PRECISION`` 等
    同义写法必须被归一，否则 ``/ready`` 会一直挂着并不存在的漂移。

    这条用应用真实引擎（PG 分支即生产方言），与 ``test_ready_exposes_empty_drift_on_fresh_schema``
    的「缓存」断言是两件事：前者证明启动采样结论为空，后者证明此刻再比对仍为空。
    """
    assert schema_drift() == []


def test_ready_reflects_drift_recorded_at_startup(client):
    """启动期记录的多余列/类型不一致必须原样出现在探针响应里。

    这里直接调用 ``_record_schema_drift`` 注入清单，而不对共享测试库做 DDL：
    被测的是「快照 → 探针」的接线，真实漂移检测已由 ``test_live_database_schema_has_no_drift``
    与契约层用例覆盖。注入后立刻用原快照还原，避免污染后续用例。
    """
    original = startup.schema_drift_snapshot()
    synthetic = [
        {
            "table": "resource_diff",
            "kind": DRIFT_EXTRA_COLUMN,
            "column": "legacy_probe",
            "detail": "库内 VARCHAR(32)",
        },
        {
            "table": "resource",
            "kind": DRIFT_TYPE_MISMATCH,
            "column": "asset_tag",
            "detail": "元数据 VARCHAR(64) / 库内 VARCHAR(32)",
        },
    ]
    try:
        startup._record_schema_drift(synthetic)  # noqa: SLF001 —— 被测的就是这个接线点
        body = client.get("/ready").json()
        assert body["schema_drift"] == synthetic
        assert body["schema_drift_checked_at"]
    finally:
        startup._record_schema_drift(original["schema_drift"])  # noqa: SLF001


@pytest.mark.parametrize("kind", [DRIFT_TYPE_MISMATCH, DRIFT_EXTRA_COLUMN])
def test_serious_drift_kinds_are_logged_as_error(client, caplog, kind):
    """``type_mismatch`` / ``extra_column`` 记 ERROR（其余类别只记 WARNING）。

    分级的意义：ERROR 能进告警规则，WARNING 只进日志检索。若两类都只打
    WARNING，「类型被改掉」就会和「历史多余列」一样沉底。
    """
    import logging

    original = startup.schema_drift_snapshot()
    entry = {"table": "resource", "kind": kind, "column": "probe", "detail": "探针"}
    try:
        with caplog.at_level(logging.ERROR, logger="rg_api.startup"):
            startup._record_schema_drift([entry])  # noqa: SLF001
        error_records = [r for r in caplog.records if r.levelno == logging.ERROR]
        assert any("schema_drift_detected" in r.getMessage() for r in error_records)
    finally:
        startup._record_schema_drift(original["schema_drift"])  # noqa: SLF001
