"""采集侧凭据引用（``credential_ref``）与指标写入（``resource_metric``）。

这两条此前都是"字段/表存在、链路没接"的静默缺口：

* ``cloud_account.credential_ref`` 只在接口里被返回，采集器实际按**写死的**
  环境变量名取密钥，于是同平台多账号必然共用同一份密钥，而调用方看不出来。
* ``resource_metric`` 只有 schema 测试写过，生产采集从不写，D1 利用率判定
  永远拿不到数据。

本文件把两条都钉成可执行断言，并守住一条关键语义：**没有指标就是没有行，
不补 0**（0 是合法利用率，补 0 会让"没采集到"与"确实空闲"无法区分）。
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
import sqlalchemy
from rg_contracts.collector import metrics as metric_writer
from rg_contracts.collector.providers import (
    BlukingProvider,
    SimulatedProvider,
    credential_env_names,
)
from rg_contracts.db.models import CloudAccount, Project, Resource, ResourceMetric, new_id
from rg_contracts.errors import ConfigurationError

PROBE_PROJECT = "prj_metrics_probe"
PROBE_ACCOUNT = "acc_metrics_probe"


# ---------------------------------------------------------------- 凭据引用
def _provider(ref: str | None):
    account = SimpleNamespace(
        id="acc_cred_probe",
        platform="bluking",
        credential_ref=ref,
        options={},
        endpoint="",
        region="cn-north-1",
    )
    return BlukingProvider(account)


def test_credential_env_names_prefers_ref_scope():
    """有引用作用域时只返回作用域名，且不包含任何全局名。"""
    names = credential_env_names("qingcloud", "qy-acc-01", ("QY_ACCESS_KEY_ID",))
    assert names == ["QY_ACC_01_QY_ACCESS_KEY_ID"]


def test_credential_env_names_keeps_legacy_names_without_ref():
    names = credential_env_names("qingcloud", None, ("QY_ACCESS_KEY_ID",))
    assert names == ["QY_ACCESS_KEY_ID", "QINGCLOUD_QY_ACCESS_KEY_ID"]


def test_credential_reads_ref_scoped_env(monkeypatch):
    monkeypatch.setenv("BK_PROD_01_BK_APP_CODE", "scoped-secret")
    assert _provider("bk-prod-01").credential("BK_APP_CODE") == "scoped-secret"


def test_credential_does_not_fall_back_to_global_env(monkeypatch):
    """核心断言：配了引用之后，全局密钥**不得**被当成回退。

    若允许回退，两个账号会静默共用同一份全局密钥，"按账号隔离密钥"永远不会
    被发现失效——这正是静默降级最坏的形态：功能看起来能用，隔离其实不存在。
    """
    monkeypatch.setenv("BK_APP_CODE", "global-secret")
    with pytest.raises(ConfigurationError) as err:
        _provider("bk-prod-02").credential("BK_APP_CODE")

    expected = err.value.details.get("expected") or []
    assert expected == ["BK_PROD_02_BK_APP_CODE"]
    # 报错信息只说"应该配哪个名字"，不得带出任何密钥值
    assert "global-secret" not in str(err.value)


def test_credential_without_ref_keeps_legacy_env(monkeypatch):
    """控制组：不配引用的单账号部署行为不变（全局名照旧可用）。"""
    monkeypatch.setenv("BK_APP_CODE", "legacy-secret")
    assert _provider(None).credential("BK_APP_CODE") == "legacy-secret"


def test_unusable_credential_ref_is_rejected(monkeypatch):
    """引用名必须能规范化成环境变量前缀，否则报错而不是悄悄回落全局名。"""
    monkeypatch.setenv("BK_APP_CODE", "global-secret")
    with pytest.raises(ConfigurationError):
        _provider("***").credential("BK_APP_CODE")


# ------------------------------------------------------------ 指标值清洗
def test_valid_metrics_drops_bool_and_non_finite():
    """``bool`` 与 NaN/inf 都不是测量结果，必须丢弃而不是写成 0/布尔值。"""
    clean = metric_writer.valid_metrics(
        {"cpu_utilization": 42.5, "flag": True, "nan": float("nan"), "inf": float("inf")}
    )
    assert clean == {"cpu_utilization": 42.5}


def test_simulated_provider_emits_metrics_only_where_meaningful():
    account = SimpleNamespace(
        id="acc_sim_probe",
        platform="qingcloud",
        credential_ref=None,
        options={"project_ids": ["prj_metrics_probe"], "resource_count": 25},
        endpoint="",
        region="cn-north-1",
    )
    resources = SimulatedProvider(account).fetch_resources()

    assert len(resources) == 25
    # 有指标的分片必须落在合理量程内（模拟数据是百分比）
    assert any(item.metrics for item in resources)
    for item in resources:
        for value in item.metrics.values():
            assert 0 <= value <= 100
        assert item.metric_units == {name: "%" for name in item.metrics}
    # "这一轮没采集到指标"这条分支必须真实存在，否则无法测出补 0 的回归
    assert any(not item.metrics for item in resources)


# ------------------------------------------------------- 采集写入（端到端）
@pytest.fixture()
def probe_account(session):
    """独立项目 + 独立账号，避免污染种子项目在看板/资源计数上的断言。"""
    exists = session.execute(
        sqlalchemy.select(Project.id).where(Project.id == PROBE_PROJECT)
    ).first()
    if exists is None:
        session.add(
            Project(
                id=PROBE_PROJECT,
                code="METRICS-PROBE",
                name="指标采集探针项目",
                classification="L2_INTERNAL",
                business_criticality=1,
                org_id=None,
            )
        )
        session.flush()
        session.add(
            CloudAccount(
                id=PROBE_ACCOUNT,
                platform="qingcloud",
                name="指标采集探针账号",
                endpoint="",
                region="cn-north-1",
                credential_ref="QY_METRICS_PROBE",
                enabled=True,
                options={"project_ids": [PROBE_PROJECT], "resource_count": 6},
            )
        )
        session.commit()
    return PROBE_ACCOUNT


def test_collection_writes_metric_latest_values(client, session, gov_headers, probe_account):
    first = client.post(
        "/api/v1/collection/run", json={"account_id": probe_account}, headers=gov_headers
    )
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["resources"] == 6
    assert body["metrics"] > 0, "采集结果里的指标没有被写入 resource_metric"

    resources = session.execute(
        sqlalchemy.select(Resource).where(Resource.account_id == probe_account)
    ).scalars().all()
    assert len(resources) == 6

    rows = _metric_rows(session, probe_account)
    assert rows, "resource_metric 没有落库"
    assert len({(row.resource_id, row.metric_name) for row in rows}) == len(rows), (
        "同一 (resource_id, metric_name) 出现多行，唯一约束/upsert 失效"
    )
    assert all(row.unit == "%" for row in rows)
    assert all(0 <= row.value <= 100 for row in rows)

    # 没有利用率的类型（数据库/负载均衡/对象存储/公网 IP）必须**没有行**：
    # 这是"缺失 = unknown，不是 0"在数据层面的唯一可靠表达。
    with_rows = {row.resource_id for row in rows}
    without_metrics = [r for r in resources if r.kind not in ("vm", "disk", "container")]
    assert without_metrics, "探针语料里应至少有一种不产生指标的资源类型"
    assert all(r.id not in with_rows for r in without_metrics)

    # 指标不重复存进 attributes（避免两个事实源互相矛盾）
    for resource in resources:
        assert "metrics" not in (resource.attributes or {})
        assert "metric_units" not in (resource.attributes or {})

    # 第二轮采集必须原地更新，不新增重复行
    second = client.post(
        "/api/v1/collection/run", json={"account_id": probe_account}, headers=gov_headers
    )
    assert second.status_code == 200, second.text
    assert second.json()["metrics"] == len(rows)
    assert len(_metric_rows(session, probe_account)) == len(rows)


def test_upsert_metrics_without_values_writes_nothing(session, probe_account):
    """空指标不写行、也不补 0 —— 判定层据此判 ``unknown``。"""
    resource = Resource(
        id=new_id("res"),
        platform="qingcloud",
        account_id=probe_account,
        project_id=PROBE_PROJECT,
        native_id="metrics-probe-empty",
        name="无指标资源",
        kind="database",
        classification="L2_INTERNAL",
    )
    session.add(resource)
    session.flush()

    before = session.execute(
        sqlalchemy.select(sqlalchemy.func.count()).select_from(ResourceMetric)
    ).scalar_one()
    written = metric_writer.upsert_metrics(
        session, resource_id=resource.id, metrics=None, units=None
    )
    assert written == 0
    after = session.execute(
        sqlalchemy.select(sqlalchemy.func.count()).select_from(ResourceMetric)
    ).scalar_one()
    assert after == before
    rows = session.execute(
        sqlalchemy.select(ResourceMetric).where(ResourceMetric.resource_id == resource.id)
    ).scalars().all()
    assert rows == []


def _metric_rows(session, account_id: str) -> list[ResourceMetric]:
    return list(
        session.execute(
            sqlalchemy.select(ResourceMetric)
            .join(Resource, Resource.id == ResourceMetric.resource_id)
            .where(Resource.account_id == account_id)
        ).scalars()
    )
