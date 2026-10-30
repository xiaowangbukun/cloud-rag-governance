"""备份链路回归：加密/密钥分离、WORM 参数、分层命名、演练闸门。

这些断言对应的是「合规要求已经写进合同」的那几条，不是风格问题：

- 加密必须能被正确的私钥解开，换密钥/改一个字节都必须失败（AEAD，不留妥协空间）；
- 备份侧只应有公钥：缺失私钥时 `fetch` 必须直接失败，不能「悄悄跳过加密」；
- WORM 参数必须真的出现在 S3 请求里，且保留期与分层保留天数一致——保留期
  比生命周期长会让对象到期删不掉，桶只增不减；
- 演练目标库必须带标记且不能等于源库（防把演练灌进生产库）。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from rg_contracts.config import Settings

from rg_api import backup


def _settings(tmp_path: Path, **overrides) -> Settings:
    private_pem, public_pem = backup.generate_keypair()
    pub = tmp_path / "pub.pem"
    priv = tmp_path / "priv.pem"
    pub.write_bytes(public_pem)
    priv.write_bytes(private_pem)
    base = {
        "APP_ENV": "test",
        "BACKUP_PUBLIC_KEY_PATH": str(pub),
        "BACKUP_PRIVATE_KEY_PATH": str(priv),
        "BACKUP_WORM_MODE": "COMPLIANCE",
        "SECURITY_AUDIT_ENABLED": False,  # 纯逻辑用例不碰库
    }
    base.update(overrides)
    return Settings(**base)


# ------------------------------------------------------------------- 加密


def test_encrypt_decrypt_roundtrip(tmp_path):
    settings = _settings(tmp_path)
    plain = b"PGDMP" + b"\x00" * 1024 + b"tail"
    source = tmp_path / "pg.dump"
    source.write_bytes(plain)

    stats = backup.encrypt_file(source, tmp_path / "pg.enc", backup.load_public_key(settings.BACKUP_PUBLIC_KEY_PATH))
    assert stats["plaintext_bytes"] == len(plain)
    assert stats["ciphertext_bytes"] > len(plain), "密文必须比明文长（含 key/nonce/tag）"

    blob = (tmp_path / "pg.enc").read_bytes()
    assert blob.startswith(backup.MAGIC)
    assert plain not in blob, "明文不得出现在密文里"

    restored = backup.decrypt_file(
        tmp_path / "pg.enc", tmp_path / "pg.out", backup.load_private_key(settings.BACKUP_PRIVATE_KEY_PATH)
    )
    assert (tmp_path / "pg.out").read_bytes() == plain
    assert restored["plaintext_sha256"] == stats["plaintext_sha256"]


def test_decrypt_with_wrong_key_fails(tmp_path):
    settings = _settings(tmp_path)
    source = tmp_path / "pg.dump"
    source.write_bytes(b"payload")
    backup.encrypt_file(source, tmp_path / "pg.enc", backup.load_public_key(settings.BACKUP_PUBLIC_KEY_PATH))

    other_priv_path = tmp_path / "other.pem"
    other_priv, _ = backup.generate_keypair()
    other_priv_path.write_bytes(other_priv)

    with pytest.raises(backup.BackupError, match="解密失败"):
        backup.decrypt_file(tmp_path / "pg.enc", tmp_path / "x", backup.load_private_key(other_priv_path))


def test_tampered_ciphertext_is_rejected(tmp_path):
    settings = _settings(tmp_path)
    source = tmp_path / "pg.dump"
    source.write_bytes(b"payload-32-bytes-long-enough!!")
    backup.encrypt_file(source, tmp_path / "pg.enc", backup.load_public_key(settings.BACKUP_PUBLIC_KEY_PATH))

    blob = bytearray((tmp_path / "pg.enc").read_bytes())
    blob[-1] ^= 0x01  # 改掉 tag 的最后一个字节
    (tmp_path / "pg.enc").write_bytes(bytes(blob))

    with pytest.raises(backup.BackupError, match="解密失败"):
        backup.decrypt_file(
            tmp_path / "pg.enc",
            tmp_path / "x",
            backup.load_private_key(settings.BACKUP_PRIVATE_KEY_PATH),
        )


def test_non_backup_blob_is_rejected(tmp_path):
    settings = _settings(tmp_path)
    (tmp_path / "junk").write_bytes(b"not-a-backup-object")
    with pytest.raises(backup.BackupError, match="magic"):
        backup.decrypt_file(
            tmp_path / "junk",
            tmp_path / "x",
            backup.load_private_key(settings.BACKUP_PRIVATE_KEY_PATH),
        )


def test_missing_public_key_fails_loudly(tmp_path):
    settings = _settings(tmp_path, BACKUP_PUBLIC_KEY_PATH=str(tmp_path / "absent.pem"))
    with pytest.raises(backup.BackupError, match="公钥不可用"):
        backup.load_public_key(settings.BACKUP_PUBLIC_KEY_PATH)


# ------------------------------------------------------------- 分层与 WORM


def test_tiers_for_hourly_always_and_daily_at_configured_hour():
    assert backup.tiers_for(datetime(2026, 10, 21, 10, 5, tzinfo=timezone.utc)) == ["hourly"]
    assert backup.tiers_for(datetime(2026, 10, 21, backup.DAILY_HOUR, 5, tzinfo=timezone.utc)) == [
        "hourly",
        "daily",
    ]


def test_tiers_for_weekly_on_monday_and_monthly_on_first():
    monday = datetime(2026, 10, 5, backup.DAILY_HOUR, 5, tzinfo=timezone.utc)  # 周一、非 1 号
    assert monday.weekday() == 0 and monday.day != 1
    assert backup.tiers_for(monday) == ["hourly", "daily", "weekly"]

    first = datetime(2026, 12, 1, backup.DAILY_HOUR, 5, tzinfo=timezone.utc)  # 1 号、周二
    assert first.weekday() == 1
    assert backup.tiers_for(first) == ["hourly", "daily", "monthly"]

    both = datetime(2026, 6, 1, backup.DAILY_HOUR, 5, tzinfo=timezone.utc)  # 1 号且周一
    assert both.weekday() == 0 and both.day == 1
    assert backup.tiers_for(both) == ["hourly", "daily", "weekly", "monthly"]


def test_object_key_layout_is_prefixed_by_tier(tmp_path):
    settings = _settings(tmp_path)
    now = datetime(2026, 10, 25, 3, 5, 0, tzinfo=timezone.utc)
    key = backup.object_key(settings, "daily", now)
    assert key == "pg/daily/2026/10/25/cloud-rag-20261025T030500Z.pgc.enc"
    # 生命周期规则按 tier 前缀匹配，所以层必须出现在路径第二段
    assert key.split("/")[1] == "daily"


def test_worm_args_match_retention_days(tmp_path):
    settings = _settings(tmp_path)
    now = datetime(2026, 10, 25, 3, 5, tzinfo=timezone.utc)
    retain_until = now + timedelta(days=backup.retention_days("hourly", settings))
    args = backup.worm_extra_args(settings.BACKUP_WORM_MODE, retain_until)
    assert args["ObjectLockMode"] == "COMPLIANCE"
    assert args["ObjectLockRetainUntilDate"] == now + timedelta(days=settings.BACKUP_HOURLY_RETENTION_DAYS)

    # 留空 = 明确不开 WORM，不得凭空加上锁参数（否则普通桶直接 400）
    assert backup.worm_extra_args("", now) == {}


def test_retention_days_are_ordered_and_positive(tmp_path):
    settings = _settings(tmp_path)
    days = [backup.retention_days(tier, settings) for tier in backup.TIERS]
    assert days == sorted(days), f"分层保留期必须单调递增，实际 {days}"
    assert all(value >= 1 for value in days)


# ------------------------------------------------------------------- 上传


class _FakeS3:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def put_object(self, **kwargs):
        self.calls.append(kwargs)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


def test_upload_puts_worm_protected_objects_per_tier(tmp_path):
    settings = _settings(tmp_path)
    dump = tmp_path / "pg.dump"
    dump.write_bytes(b"PGDMP payload")
    client = _FakeS3()

    now = datetime(2026, 6, 1, backup.DAILY_HOUR, 5, tzinfo=timezone.utc)  # 四层齐发
    report = backup.upload(dump, settings, now=now, client=client)

    assert [item["tier"] for item in report["objects"]] == ["hourly", "daily", "weekly", "monthly"]
    assert len(client.calls) == 4
    for call, tier in zip(client.calls, ["hourly", "daily", "weekly", "monthly"]):
        assert call["Bucket"] == settings.MINIO_BUCKET
        assert call["Key"].split("/")[1] == tier
        assert call["ObjectLockMode"] == "COMPLIANCE"
        expected_days = backup.retention_days(tier, settings)
        assert call["ObjectLockRetainUntilDate"] == now + timedelta(days=expected_days)
        assert call["Metadata"]["worm-mode"] == "COMPLIANCE"
        assert call["Metadata"]["tier"] == tier
        # 上传的是密文，不得是明文
        assert call["Body"].startswith(backup.MAGIC)
        assert b"PGDMP payload" not in call["Body"]


def test_upload_dry_run_never_touches_network(tmp_path):
    settings = _settings(tmp_path)
    dump = tmp_path / "pg.dump"
    dump.write_bytes(b"PGDMP payload")
    client = _FakeS3()

    report = backup.upload(dump, settings, dry_run=True, client=client)
    assert client.calls == []
    assert report["dry_run"] is True
    assert report["objects"][0]["key"].startswith("pg/hourly/")


def test_upload_without_worm_mode_sends_no_lock_params(tmp_path):
    settings = _settings(tmp_path, BACKUP_WORM_MODE="")
    dump = tmp_path / "pg.dump"
    dump.write_bytes(b"PGDMP payload")
    client = _FakeS3()
    backup.upload(dump, settings, client=client)
    assert client.calls
    for call in client.calls:
        assert "ObjectLockMode" not in call


# ------------------------------------------------------------------- 演练


def test_fetch_requires_private_key(tmp_path):
    """密钥分离：备份侧没有私钥，恢复动作必须直接失败而不是跳过解密。"""
    settings = _settings(tmp_path, BACKUP_PRIVATE_KEY_PATH="")
    with pytest.raises(backup.BackupError, match="私钥"):
        backup.fetch("hourly", tmp_path / "out.dump", settings, client=_FakeS3())


def test_drill_target_must_carry_marker_and_differ_from_source(tmp_path):
    settings = _settings(tmp_path, DB_NAME="cloud_rag")
    with pytest.raises(backup.BackupError, match="必须包含"):
        backup.validate_drill_target(settings, "cloud_rag")
    backup.validate_drill_target(settings, "cloud_rag_drill")

    same = _settings(tmp_path, DB_NAME="cloud_rag_drill")
    with pytest.raises(backup.BackupError, match="不能是源库"):
        backup.validate_drill_target(same, "cloud_rag_drill")


def test_latest_object_key_picks_newest(tmp_path):
    settings = _settings(tmp_path)

    class _Lister:
        def list_objects_v2(self, **kwargs):
            assert kwargs["Prefix"] == "pg/daily/"
            return {
                "Contents": [
                    {"Key": "pg/daily/a.enc", "LastModified": datetime(2026, 10, 1, tzinfo=timezone.utc)},
                    {"Key": "pg/daily/b.enc", "LastModified": datetime(2026, 10, 3, tzinfo=timezone.utc)},
                    {"Key": "pg/daily/c.enc", "LastModified": datetime(2026, 10, 2, tzinfo=timezone.utc)},
                ]
            }

    assert backup.latest_object_key(_Lister(), "b", "daily", settings) == "pg/daily/b.enc"

    class _Empty:
        def list_objects_v2(self, **kwargs):
            return {"Contents": []}

    with pytest.raises(backup.BackupError, match="没有可用备份"):
        backup.latest_object_key(_Empty(), "b", "daily", settings)


class _VersionedLister:
    """模拟版本化桶：``ListObjectsV2`` 看不到被删除标记遮挡的对象，版本列举能看到。"""

    def __init__(self, versions: list[dict], markers: list[dict] | None = None) -> None:
        self.versions = versions
        self.markers = markers or []
        self.visible = [item for item in versions] if not self.markers else []

    def list_object_versions(self, **kwargs):
        assert kwargs["Prefix"] == "pg/daily/"
        return {"Versions": self.versions, "DeleteMarkers": self.markers, "IsTruncated": False}

    def list_objects_v2(self, **kwargs):
        return {"Contents": self.visible}


def test_latest_object_key_sees_versions_hidden_by_delete_marker(tmp_path):
    """真实 MinIO 复现的回归：加一个删除标记后 ``ListObjectsV2`` 的 KeyCount 变 0，
    但对象版本仍在（按 VersionId 可取回）。只读 V2 会把「被隐藏」报成「没有备份」，
    从而把运维引向存储故障排查，而不是「谁动了备份」。"""
    settings = _settings(tmp_path)
    client = _VersionedLister(
        versions=[
            {"Key": "pg/daily/b.enc", "LastModified": datetime(2026, 10, 3, tzinfo=timezone.utc), "VersionId": "v2"}
        ],
        markers=[{"Key": "pg/daily/b.enc", "LastModified": datetime(2026, 10, 4, tzinfo=timezone.utc)}],
    )
    # V2 确实看不见（复现现场），但版本列举能找到
    assert client.list_objects_v2(Bucket="b", Prefix="pg/daily/")["Contents"] == []
    assert backup.latest_object_key(client, "b", "daily", settings) == "pg/daily/b.enc"


def test_latest_object_key_reports_marker_as_security_event(tmp_path):
    """只剩删除标记（数据版本被彻底删除）时，报错必须说清「被遮挡」而不是「没有备份」。"""
    settings = _settings(tmp_path)
    client = _VersionedLister(
        versions=[],
        markers=[{"Key": "pg/daily/b.enc", "LastModified": datetime(2026, 10, 4, tzinfo=timezone.utc)}],
    )
    with pytest.raises(backup.BackupError, match="删除标记"):
        backup.latest_object_key(client, "b", "daily", settings)


def test_latest_object_key_falls_back_when_versions_denied(tmp_path):
    """凭证只有 s3:ListBucket（没有 ListBucketVersions）时不能直接崩：回落到 V2，
    但必须留下可搜到的告警——这条回落是「可能看不见被遮挡对象」的已知缺口。"""

    class _Denied:
        def list_object_versions(self, **kwargs):
            error = Exception("Access Denied")
            error.response = {"Error": {"Code": "AccessDenied"}, "ResponseMetadata": {"HTTPStatusCode": 403}}
            raise error

        def list_objects_v2(self, **kwargs):
            return {"Contents": [{"Key": "pg/daily/x.enc", "LastModified": datetime(2026, 10, 5, tzinfo=timezone.utc)}]}

    settings = _settings(tmp_path)
    assert backup.latest_object_key(_Denied(), "b", "daily", settings) == "pg/daily/x.enc"


def test_latest_object_key_reraises_real_storage_errors(tmp_path):
    """非权限类错误（如 500）不许被吞成「回落到 V2」——那会把故障伪装成空列表。"""

    class _Broken:
        def list_object_versions(self, **kwargs):
            error = Exception("InternalError")
            error.response = {"Error": {"Code": "InternalError"}, "ResponseMetadata": {"HTTPStatusCode": 500}}
            raise error

        def list_objects_v2(self, **kwargs):
            raise AssertionError("不应该回落到 V2")

    settings = _settings(tmp_path)
    with pytest.raises(Exception, match="InternalError"):
        backup.latest_object_key(_Broken(), "b", "daily", settings)


# ------------------------------------------------------------------- 配置


def test_backup_target_falls_back_to_minio_settings(tmp_path):
    """未单独配置备份目标时沿用 MINIO_*；显式配置时以 BACKUP_* 为准。"""
    fallback = _settings(tmp_path)
    target = backup.resolved_backup_target(fallback)
    assert target["endpoint"] == fallback.MINIO_ENDPOINT
    assert target["bucket"] == fallback.MINIO_BUCKET

    explicit = _settings(
        tmp_path,
        BACKUP_ENDPOINT="minio.backup.svc:9000",
        BACKUP_BUCKET="cloud-rag-backup",
    )
    target = backup.resolved_backup_target(explicit)
    assert target["endpoint"] == "minio.backup.svc:9000"
    assert target["bucket"] == "cloud-rag-backup"


def test_backup_secret_is_masked_by_safe_dump(tmp_path):
    """`/admin/config` 回显配置：备份凭证不得以明文出现。"""
    settings = _settings(tmp_path, BACKUP_SECRET_KEY="s3cr3t-value")
    safe = settings.model_dump_safe()
    assert safe["BACKUP_SECRET_KEY"] == "***"
    assert "s3cr3t-value" not in str(safe)


def test_manifest_retention_matches_code_defaults():
    """四层保留期在「代码默认值 / 09 ConfigMap / 10 生命周期规则」三处必须一致。

    这三处不一致时的表现很隐蔽：对象保留期比生命周期长 → 到期删不掉、桶只增不减；
    反过来则还没到保留期就被生命周期删掉，等于合规承诺（WORM 保留 N 天）失效。
    故意用字符串匹配而不是引入 YAML 依赖：断言的是「显式写死的值」，不是解析结果。
    """
    deploy = Path(__file__).resolve().parents[3] / "deploy" / "k8s"
    backup_yaml = (deploy / "09-postgres-backup.yaml").read_text(encoding="utf-8")
    minio_yaml = (deploy / "10-minio.yaml").read_text(encoding="utf-8")
    defaults = Settings(APP_ENV="test")

    assert f'BACKUP_WORM_MODE: "{defaults.BACKUP_WORM_MODE}"' in backup_yaml
    assert f'BACKUP_PREFIX: "{defaults.BACKUP_PREFIX}"' in backup_yaml
    for tier in backup.TIERS:
        days = backup.retention_days(tier, defaults)
        assert f'BACKUP_{tier.upper()}_RETENTION_DAYS: "{days}"' in backup_yaml, tier
        assert f'"pg/{tier}/:{days}"' in minio_yaml, tier
