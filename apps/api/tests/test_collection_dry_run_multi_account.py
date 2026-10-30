"""回归（缺陷 A）：collection dry_run 必须返回全部启用账号，而非只返回第一个。

修复前 ``routes/collection.py`` 的 dry_run ``return`` 写在 for-account 循环内：
多账号场景下第 2..N 个账号被静默丢弃——调用方以为预演了全量，实际只看到一个
账号的数据。行为探针（修复前实测）：种子 4 个云账号，``{"dry_run": true}`` 不传
account_id 时返回体只含 bluking 一个账号。
"""

from __future__ import annotations

_DRY_RUN_RECORD_KEYS = {
    "account_id",
    "platform",
    "resources",
    "diffs",
    "baseline_ready",
    "summary",
}


def _enabled_accounts(client, gov_headers) -> list[dict]:
    accounts = client.get("/api/v1/collection/accounts", headers=gov_headers).json()
    enabled = [a for a in accounts if a["enabled"]]
    assert enabled, "演示种子应至少提供一个启用云账号"
    return enabled


def test_dry_run_covers_all_enabled_accounts(client, session, gov_headers):
    """核心回归：不传 account_id 的 dry_run 覆盖每一个可采集账号。"""
    enabled = _enabled_accounts(client, gov_headers)

    resp = client.post("/api/v1/collection/run", json={"dry_run": True}, headers=gov_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["dry_run"] is True
    per_account = body["per_account"]
    # 修复前循环内 return 只返回第一个账号：此处必须覆盖多个账号
    assert len(per_account) >= 2, (
        f"dry_run 只返回 {len(per_account)} 个账号（缺陷 A 复现：循环内 return 丢掉了后续账号）"
    )
    # 演示种子的四家云平台必须全部出现在预演里（账号 id 可能被其他用例扩充）
    assert {r["platform"] for r in per_account} >= {"bluking", "qingcloud", "huawei", "tencent"}
    # 预演记录只能来自启用账号集合（不得凭空造账号）
    assert {r["account_id"] for r in per_account} <= {a["id"] for a in enabled}
    # 汇总口径与逐账号记录一致（不得各算各的）
    assert body["accounts"] == len(per_account)
    assert body["resources"] == sum(r["resources"] for r in per_account)
    assert body["diffs"] == sum(r["diffs"] for r in per_account)
    assert body["baselines_ready"] == sum(1 for r in per_account if r["baseline_ready"])
    for record in per_account:
        assert set(record) == _DRY_RUN_RECORD_KEYS


def test_dry_run_single_account_unchanged(client, gov_headers):
    """控制组：指定 account_id 的 dry_run 仍只返回该账号（形状不回归）。"""
    enabled = _enabled_accounts(client, gov_headers)

    resp = client.post(
        "/api/v1/collection/run",
        json={"dry_run": True, "account_id": enabled[0]["id"]},
        headers=gov_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["accounts"] == 1
    assert body["per_account"][0]["account_id"] == enabled[0]["id"]
