"""PostgreSQL 备份：加密、WORM 上传、分层保留、恢复演练。

设计约束（来自合规与运维口径）：

1. **RPO 1 小时**：每小时一次全量 ``pg_dump -Fc``。库小的时候每小时全量比引入
   pgBackRest/WAL-G 更简单、恢复也更直白；等到单次 dump 超过约 5 分钟，再切增量
   （README 里写了这个阈值）。
2. **WORM**：每个对象在 S3 侧带 ``ObjectLockMode`` + ``RetainUntilDate``，
   ``COMPLIANCE`` 模式下保留期内连存储管理员也删不掉——这是防「内鬼删备份 /
   勒索软件加密备份」的唯一硬手段。保留期与生命周期到期天数**必须一致**：
   保留期比生命周期长，对象会到期删不掉、桶只增不减。
3. **密钥分离**：备份侧只挂 X25519 **公钥**；私钥单独保管、只在恢复侧挂载。
   加密在落盘前完成，因此「拿到备份桶凭证」不等于「拿到数据」。
4. **分层保留**：小时层（7 天）覆盖 RPO，日/周/月层（30/90/365 天）覆盖回溯。
   每层独立前缀，让 MinIO 生命周期规则可以按前缀分别到期。

为什么加密自己实现而不装 age/GPG：``cryptography`` 已是既有依赖，
X25519 + HKDF-SHA256 + AES-256-GCM 是标准组合，文件一位一字节都可控；
少一个离线环境要额外安装的二进制。

文件格式（``RGBAK1``）::

    magic(7) | ephemeral_pub(32) | nonce(12) | AES-256-GCM(ciphertext+tag)

用法::

    python -m rg_api.backup keygen --out-dir ./backup-keys
    python -m rg_api.backup upload --input /work/pg.dump
    python -m rg_api.backup fetch --tier daily --out /work/pg.dump
    python -m rg_api.backup drill  --tier daily --target-db rgtest_restore_drill
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from rg_contracts.audit.service import AuditService
from rg_contracts.config import Settings, get_settings
from rg_contracts.db.session import session_scope
from rg_contracts.logging_setup import get_logger

logger = get_logger(__name__)

MAGIC = b"RGBAK1\x00"
_NONCE_BYTES = 12
_PUBLIC_KEY_BYTES = 32
_HKDF_INFO = b"cloud-rag-governance/backup/v1"
#: 每日层由哪一次小时任务顺带产出：必须与 CronJob 的 schedule 对齐（见 09 清单）
DAILY_HOUR = 3
#: 分层顺序（保留期从短到长）
TIERS = ("hourly", "daily", "weekly", "monthly")


class BackupError(RuntimeError):
    """备份/恢复链路的可预期失败（配置缺失、文件损坏、目标库不合法）。"""


# --------------------------------------------------------------------- 加密


def generate_keypair() -> tuple[bytes, bytes]:
    """生成 X25519 密钥对，返回 (私钥 PEM, 公钥 PEM)。"""
    private_key = X25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def load_public_key(path: str | Path) -> X25519PublicKey:
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, ValueError) as exc:
        raise BackupError(f"备份公钥不可用：{path}（{exc}）") from exc
    if not isinstance(key, X25519PublicKey):
        raise BackupError(f"备份公钥类型不是 X25519：{path}")
    return key


def load_private_key(path: str | Path) -> X25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise BackupError(f"备份私钥不可用：{path}（{exc}）") from exc
    if not isinstance(key, X25519PrivateKey):
        raise BackupError(f"备份私钥类型不是 X25519：{path}")
    return key


def _derive_key(shared_secret: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO).derive(
        shared_secret
    )


def encrypt_bytes(plaintext: bytes, public_key: X25519PublicKey) -> bytes:
    """信封加密：每次备份都生成一次性密钥对，只有收件人私钥能解。"""
    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    key = _derive_key(ephemeral.exchange(public_key))
    nonce = os.urandom(_NONCE_BYTES)
    return MAGIC + ephemeral_public + nonce + AESGCM(key).encrypt(nonce, plaintext, MAGIC)


def decrypt_bytes(blob: bytes, private_key: X25519PrivateKey) -> bytes:
    """解密备份对象；magic / 长度 / AEAD 校验任何一项不符都直接失败。"""
    if not blob.startswith(MAGIC):
        raise BackupError("不是本系统的备份对象（magic 不匹配）")
    offset = len(MAGIC)
    ephemeral_raw = blob[offset : offset + _PUBLIC_KEY_BYTES]
    offset += _PUBLIC_KEY_BYTES
    nonce = blob[offset : offset + _NONCE_BYTES]
    offset += _NONCE_BYTES
    if len(ephemeral_raw) != _PUBLIC_KEY_BYTES or len(nonce) != _NONCE_BYTES:
        raise BackupError("备份对象被截断")
    try:
        ephemeral_public = X25519PublicKey.from_public_bytes(ephemeral_raw)
        key = _derive_key(private_key.exchange(ephemeral_public))
        return AESGCM(key).decrypt(nonce, blob[offset:], MAGIC)
    except Exception as exc:  # noqa: BLE001 - AEAD 失败统一翻译成可读错误
        raise BackupError("解密失败：密钥不匹配或文件被篡改") from exc


def encrypt_file(source: Path, target: Path, public_key: X25519PublicKey) -> dict:
    payload = source.read_bytes()
    blob = encrypt_bytes(payload, public_key)
    target.write_bytes(blob)
    return {
        "plaintext_bytes": len(payload),
        "ciphertext_bytes": len(blob),
        "plaintext_sha256": hashlib.sha256(payload).hexdigest(),
        "ciphertext_sha256": hashlib.sha256(blob).hexdigest(),
    }


def decrypt_file(source: Path, target: Path, private_key: X25519PrivateKey) -> dict:
    blob = source.read_bytes()
    payload = decrypt_bytes(blob, private_key)
    target.write_bytes(payload)
    return {
        "ciphertext_bytes": len(blob),
        "plaintext_bytes": len(payload),
        "plaintext_sha256": hashlib.sha256(payload).hexdigest(),
    }


# --------------------------------------------------------------- 分层与对象名


def tiers_for(now: datetime) -> list[str]:
    """本次任务应产出哪几层。

    小时层每次都产出（RPO 1 小时）；日层只在 ``DAILY_HOUR`` 那次顺带产出；
    周层在日层基础上要求是周一；月层要求是 1 号。CronJob 每小时触发，
    因此「顺带产出」比多挂三个 CronJob 更容易保证时间点一致性。
    """
    if now.hour != DAILY_HOUR:
        return ["hourly"]
    tiers = ["hourly", "daily"]
    if now.weekday() == 0:  # Monday
        tiers.append("weekly")
    if now.day == 1:
        tiers.append("monthly")
    return tiers


def retention_days(tier: str, settings: Settings) -> int:
    mapping = {
        "hourly": settings.BACKUP_HOURLY_RETENTION_DAYS,
        "daily": settings.BACKUP_DAILY_RETENTION_DAYS,
        "weekly": settings.BACKUP_WEEKLY_RETENTION_DAYS,
        "monthly": settings.BACKUP_MONTHLY_RETENTION_DAYS,
    }
    if tier not in mapping:
        raise BackupError(f"未知备份层：{tier}")
    return max(1, mapping[tier])


def object_key(settings: Settings, tier: str, now: datetime, suffix: str = ".pgc.enc") -> str:
    """按「前缀/层/年/月/日/时间戳」组织：生命周期规则可只匹配层前缀。"""
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    return (
        f"{settings.BACKUP_PREFIX}/{tier}/"
        f"{now.strftime('%Y')}/{now.strftime('%m')}/{now.strftime('%d')}/"
        f"cloud-rag-{stamp}{suffix}"
    )


def worm_extra_args(mode: str, retain_until: datetime) -> dict:
    """S3 PutObject/CopyObject 的 Object Lock 参数；空模式返回空 dict（明确不开 WORM）。"""
    if not mode:
        return {}
    return {
        "ObjectLockMode": mode,
        "ObjectLockRetainUntilDate": retain_until,
    }


def parse_s3_last_modified(value) -> datetime:
    """列表结果的 ``LastModified`` 统一成 UTC aware（不同实现返回类型不一致）。"""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    raise BackupError(f"无法解析对象时间戳：{value!r}")


# ------------------------------------------------------------------ S3 客户端


def resolved_backup_target(settings: Settings) -> dict:
    """解析备份目标；未填写的项回落到 ``MINIO_*``（同一套实例、可不同凭证）。"""
    return {
        "endpoint": settings.BACKUP_ENDPOINT or settings.MINIO_ENDPOINT,
        "bucket": settings.BACKUP_BUCKET or settings.MINIO_BUCKET,
        "access_key": settings.BACKUP_ACCESS_KEY or settings.MINIO_ACCESS_KEY,
        "secret_key": settings.BACKUP_SECRET_KEY or settings.MINIO_SECRET_KEY,
        "secure": settings.BACKUP_SECURE,
    }


def s3_client(settings: Settings):
    """构造 S3 客户端（延迟导入：只有备份/恢复进程需要 boto3）。"""
    import boto3
    from botocore.config import Config

    target = resolved_backup_target(settings)
    scheme = "https" if target["secure"] else "http"
    return boto3.client(
        "s3",
        endpoint_url=f"{scheme}://{target['endpoint']}",
        aws_access_key_id=target["access_key"],
        aws_secret_access_key=target["secret_key"],
        region_name="us-east-1",  # MinIO 的默认区域；显式写死避免依赖环境变量
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


# --------------------------------------------------------------------- 上传


@dataclass
class UploadResult:
    tier: str
    key: str
    plaintext_bytes: int
    ciphertext_bytes: int
    plaintext_sha256: str
    retain_until: datetime


def upload(
    input_path: Path,
    settings: Settings | None = None,
    now: datetime | None = None,
    dry_run: bool = False,
    client=None,
) -> dict:
    """加密并上传一次备份；返回可直接写审计的报告。

    ``dry_run`` 只做加密与命名，不触网——用于在没有 MinIO 的环境验证配置。
    """
    settings = settings or get_settings()
    now = now or datetime.now(timezone.utc)
    if not input_path.exists():
        raise BackupError(f"备份文件不存在：{input_path}")

    public_key = load_public_key(settings.BACKUP_PUBLIC_KEY_PATH)
    tiers = tiers_for(now)
    target = resolved_backup_target(settings)
    bucket = target["bucket"]

    results: list[UploadResult] = []
    workdir = Path(tempfile.mkdtemp(prefix="rg-backup-"))
    try:
        encrypted = workdir / "payload.enc"
        stats = encrypt_file(input_path, encrypted, public_key)
        # 小时层是必产出层；对象名带 UTC 时间戳，秒级不冲突
        primary_key = object_key(settings, "hourly", now)
        uploads = [(tier, primary_key if tier == "hourly" else object_key(settings, tier, now)) for tier in tiers]

        if not dry_run:
            client = client or s3_client(settings)
            body = encrypted.read_bytes()
            for tier, key in uploads:
                retain_until = now + timedelta(days=retention_days(tier, settings))
                extra = {
                    "ContentType": "application/octet-stream",
                    "Metadata": {
                        "tier": tier,
                        "source": "postgresql",
                        "plaintext-sha256": stats["plaintext_sha256"],
                        "worm-mode": settings.BACKUP_WORM_MODE or "none",
                    },
                    **worm_extra_args(settings.BACKUP_WORM_MODE, retain_until),
                }
                client.put_object(Bucket=bucket, Key=key, Body=body, **extra)
                results.append(
                    UploadResult(
                        tier=tier,
                        key=key,
                        plaintext_bytes=stats["plaintext_bytes"],
                        ciphertext_bytes=stats["ciphertext_bytes"],
                        plaintext_sha256=stats["plaintext_sha256"],
                        retain_until=retain_until,
                    )
                )
        else:
            results = [
                UploadResult(
                    tier=tier,
                    key=key,
                    plaintext_bytes=stats["plaintext_bytes"],
                    ciphertext_bytes=stats["ciphertext_bytes"],
                    plaintext_sha256=stats["plaintext_sha256"],
                    retain_until=now + timedelta(days=retention_days(tier, settings)),
                )
                for tier, key in uploads
            ]
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    report = {
        "dry_run": dry_run,
        "bucket": bucket,
        "endpoint": target["endpoint"],
        "worm_mode": settings.BACKUP_WORM_MODE or "none",
        "objects": [
            {
                "tier": item.tier,
                "key": item.key,
                "plaintext_bytes": item.plaintext_bytes,
                "ciphertext_bytes": item.ciphertext_bytes,
                "plaintext_sha256": item.plaintext_sha256,
                "retain_until": item.retain_until.isoformat(),
            }
            for item in results
        ],
    }
    record_audit(settings, action="backup_run", outcome="dry_run" if dry_run else "success", metadata=report)
    return report


# --------------------------------------------------------------------- 下载


def fetch(
    tier: str,
    output_path: Path,
    settings: Settings | None = None,
    object_key_override: str | None = None,
    client=None,
) -> dict:
    """取该层最新对象并解密到本地（恢复与演练共用这一条路径）。"""
    settings = settings or get_settings()
    if tier not in TIERS:
        raise BackupError(f"未知备份层：{tier}")
    if not settings.BACKUP_PRIVATE_KEY_PATH:
        raise BackupError("缺少 BACKUP_PRIVATE_KEY_PATH：恢复侧才需要私钥（密钥分离）")

    client = client or s3_client(settings)
    bucket = resolved_backup_target(settings)["bucket"]
    key = object_key_override or latest_object_key(client, bucket, tier, settings)

    private_key = load_private_key(settings.BACKUP_PRIVATE_KEY_PATH)
    workdir = Path(tempfile.mkdtemp(prefix="rg-restore-"))
    try:
        encrypted = workdir / "payload.enc"
        client.download_file(bucket, key, str(encrypted))
        stats = decrypt_file(encrypted, output_path, private_key)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    report = {"bucket": bucket, "key": key, "tier": tier, "output": str(output_path), **stats}
    record_audit(settings, action="backup_fetch", outcome="success", metadata=report)
    return report


def _is_permission_denied(exc: Exception) -> bool:
    """区分「没有版本列举权限」与真正的存储错误（后者必须原样抛出）。"""
    response = getattr(exc, "response", None) or {}
    code = str((response.get("Error") or {}).get("Code", ""))
    status = (response.get("ResponseMetadata") or {}).get("HTTPStatusCode")
    return code in {"AccessDenied", "Forbidden", "MethodNotAllowed"} or status == 403


#: 版本列举的分页上限：防御「服务端一直 IsTruncated」把恢复路径挂死
_MAX_VERSION_PAGES = 20


def _list_versions(client, bucket: str, prefix: str) -> tuple[list[dict], list[dict]] | None:
    """列出（对象版本, 删除标记）；客户端不支持或权限不足时返回 ``None``。

    为什么优先用版本列举：版本化 + WORM 桶里 ``DeleteObject`` 不带 VersionId 只会
    加一个**删除标记**，对象数据仍在，但 ``ListObjectsV2`` 看不到它（实测 MinIO：
    ``KeyCount`` 从 1 变 0，按 VersionId 仍取回完整的 22 字节）。只读 V2 的恢复路径
    因此会报「没有可用备份」，把「被隐藏」误报成「没有备份」——在合规场景里这会
    把人引向存储故障排查，而不是「谁动了备份」。
    """
    params: dict = {"Bucket": bucket, "Prefix": prefix}
    versions: list[dict] = []
    markers: list[dict] = []
    for _ in range(_MAX_VERSION_PAGES):
        try:
            response = client.list_object_versions(**params)
        except AttributeError:
            return None  # 测试替身/旧客户端没有这个方法
        except Exception as exc:  # noqa: BLE001 - 只吞权限类，其余原样抛
            if _is_permission_denied(exc):
                return None
            raise
        versions.extend(response.get("Versions") or [])
        markers.extend(response.get("DeleteMarkers") or [])
        if not response.get("IsTruncated"):
            return versions, markers
        next_key = response.get("NextKeyMarker")
        next_version = response.get("NextVersionIdMarker")
        if not next_key or not next_version:
            return versions, markers
        params["KeyMarker"] = next_key
        params["VersionIdMarker"] = next_version
    logger.warning(
        "backup_version_pages_exhausted",
        extra={"extra_fields": {"prefix": prefix, "pages": _MAX_VERSION_PAGES}},
    )
    return versions, markers


def latest_object_key(client, bucket: str, tier: str, settings: Settings) -> str:
    prefix = f"{settings.BACKUP_PREFIX}/{tier}/"

    listed = _list_versions(client, bucket, prefix)
    if listed is not None:
        versions, markers = listed
        if versions:
            if markers:
                # 数据可恢复，但「读路径看不见」本身就是需要人看的信号：
                # WORM 挡不住删除标记，只挡得住删掉数据版本。
                logger.warning(
                    "backup_objects_hidden_by_delete_marker",
                    extra={"extra_fields": {"prefix": prefix, "markers": len(markers)}},
                )
            newest = max(versions, key=lambda item: parse_s3_last_modified(item["LastModified"]))
            return newest["Key"]
        if markers:
            raise BackupError(
                f"备份对象被删除标记遮挡：s3://{bucket}/{prefix}"
                f"（{len(markers)} 个删除标记，数据版本仍在；用 list_object_versions 复核）"
                "——这是安全事件，不是存储故障"
            )
        raise BackupError(f"没有可用备份：s3://{bucket}/{prefix}")

    # 回落路径：凭证缺 s3:ListBucketVersions 或客户端不支持。此时只能看到「未被遮挡」
    # 的对象，被删除标记隐藏的备份会被误报成不存在——因此这条日志必须能被搜到。
    logger.warning(
        "backup_version_listing_unavailable",
        extra={"extra_fields": {"prefix": prefix}},
    )
    response = client.list_objects_v2(Bucket=bucket, Prefix=prefix)
    contents = response.get("Contents") or []
    if not contents:
        raise BackupError(f"没有可用备份：s3://{bucket}/{prefix}")
    newest = max(contents, key=lambda item: parse_s3_last_modified(item["LastModified"]))
    return newest["Key"]


# ------------------------------------------------------------------ 恢复演练


def validate_drill_target(settings: Settings, target_db: str) -> None:
    """演练目标库必须显式带标记、且不能是源库——防止把演练灌进生产库。"""
    marker = settings.BACKUP_DRILL_DB_MARKER
    if not marker or marker not in target_db:
        raise BackupError(f"演练目标库名必须包含 {marker!r}：{target_db}")
    if target_db == settings.DB_NAME:
        raise BackupError("演练目标库不能是源库")


def drill(
    tier: str,
    target_db: str,
    settings: Settings | None = None,
    keep_dump: Path | None = None,
) -> dict:
    """恢复演练：下载 → 解密 → 建临时库 → pg_restore → 校验 → 删库。

    校验口径是「结构完整 + 核心表非空 + pgvector 可用」，不比对行数与线上一致：
    dump 是快照，线上还在变，强行比对只会制造假失败。
    """
    settings = settings or get_settings()
    validate_drill_target(settings, target_db)
    workdir = Path(tempfile.mkdtemp(prefix="rg-drill-"))
    dump_path = keep_dump or workdir / "pg.dump"
    try:
        fetched = fetch(tier, dump_path, settings)
        _create_database(settings, target_db)
        try:
            _restore(settings, dump_path, target_db)
            checks = _verify_restored(settings, target_db)
        finally:
            _drop_database(settings, target_db)
        report = {"tier": tier, "target_db": target_db, "object_key": fetched["key"], **checks}
        record_audit(settings, action="backup_drill", outcome="success", metadata=report)
        return report
    finally:
        if keep_dump is None:
            shutil.rmtree(workdir, ignore_errors=True)


#: 演练**必须**存在的表：少一张就说明备份/恢复链路丢了结构。
#: 表名以模型元数据为准（本仓库用单数：user / project / resource …），
#: 不要凭印象写复数——写错会让「校验」误报，进而把一次成功的恢复判成失败。
_CORE_REQUIRED = (
    "user",
    "project",
    "resource",
    "knowledge_document",
    "knowledge_chunk",
    "attribution",
    "audit_log",
    "security_event",
    "snapshot",
    "snapshot_state",
    "runtime_counter",
)
#: 必须非空的核心表（种子数据保证）
_CORE_NON_EMPTY = ("user", "project", "resource")


def _admin_params(settings: Settings, dbname: str) -> dict:
    return {
        "host": settings.DB_HOST,
        "port": settings.DB_PORT,
        "user": settings.DB_USER,
        "password": settings.DB_PASSWORD,
        "dbname": dbname,
        "sslmode": settings.DB_SSLMODE or "prefer",
    }


def _create_database(settings: Settings, target_db: str) -> None:
    import psycopg

    with psycopg.connect(**_admin_params(settings, "postgres"), autocommit=True) as conn:
        exists = conn.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s", (target_db,)
        ).fetchone()
        if exists:
            raise BackupError(f"演练目标库已存在，先人工确认：{target_db}")
        conn.execute(f'CREATE DATABASE "{target_db}"')


def _drop_database(settings: Settings, target_db: str) -> None:
    import psycopg

    with psycopg.connect(**_admin_params(settings, "postgres"), autocommit=True) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{target_db}" WITH (FORCE)')


def _restore(settings: Settings, dump_path: Path, target_db: str) -> None:
    env = {**os.environ, "PGPASSWORD": settings.DB_PASSWORD}
    command = [
        settings.PG_RESTORE_BIN,
        "--no-owner",
        "--no-privileges",
        "--exit-on-error",
        f"--dbname={_dsn(settings, target_db)}",
        str(dump_path),
    ]
    result = subprocess.run(command, capture_output=True, text=True, env=env)
    if result.returncode != 0:
        raise BackupError(f"pg_restore 失败：{result.stderr.strip()[:800]}")


def _verify_restored(settings: Settings, target_db: str) -> dict:
    import psycopg
    from rg_contracts.db.models import Base

    with psycopg.connect(**_admin_params(settings, target_db)) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
            ).fetchall()
        }
        missing = [name for name in _CORE_REQUIRED if name not in tables]
        if missing:
            raise BackupError(f"恢复后缺表：{', '.join(missing)}")
        # 非核心表只报告不判失败：备份可能来自更早的版本，缺一张新表是预期内的
        missing_optional = sorted(set(Base.metadata.tables) - tables)

        extension = conn.execute(
            "SELECT extversion FROM pg_extension WHERE extname = 'vector'"
        ).fetchone()
        if extension is None:
            raise BackupError("恢复后缺少 vector 扩展（pgvector 未随库恢复）")

        counts = {}
        for name in _CORE_NON_EMPTY:
            counts[name] = int(conn.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0])
        empty = [name for name, value in counts.items() if value == 0]
        if empty:
            raise BackupError(f"恢复后核心表为空：{', '.join(empty)}")

    return {
        "vector_version": extension[0],
        "table_count": len(tables),
        "core_counts": counts,
        "missing_optional": missing_optional,
    }


def _dsn(settings: Settings, dbname: str) -> str:
    password = settings.DB_PASSWORD.replace("@", "%40") if settings.DB_PASSWORD else ""
    return (
        f"postgresql://{settings.DB_USER}:{password}"
        f"@{settings.DB_HOST}:{settings.DB_PORT}/{dbname}?sslmode={settings.DB_SSLMODE or 'prefer'}"
    )


# ----------------------------------------------------------------------- 审计


def record_audit(settings: Settings, action: str, outcome: str, metadata: dict) -> None:
    """把备份/恢复动作写进 ``audit_log``（与保留任务同一套路）。

    备份失败也要留痕——「备份连续三天没成功」恰恰是最需要被审计看见的事。
    审计写失败不得吞掉主流程结果：这里只记日志。
    """
    if not settings.SECURITY_AUDIT_ENABLED:
        return
    try:
        with session_scope() as session:
            # AuditService 的 actor 参数是用户主体；备份任务是系统动作，
            # 主体记为 None + metadata 里标注 system:backup（不伪造用户身份）。
            AuditService(session, enabled=True).record(
                action=action,
                outcome=outcome,
                metadata={"actor": "system:backup", **metadata},
            )
    except Exception:  # noqa: BLE001
        logger.warning("backup_audit_failed", extra={"extra_fields": {"action": action}})


# ------------------------------------------------------------------------- CLI


def _write_keypair(out_dir: Path) -> dict:
    private_pem, public_pem = generate_keypair()
    out_dir.mkdir(parents=True, exist_ok=True)
    private_path = out_dir / "backup-private.pem"
    public_path = out_dir / "backup-public.pem"
    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)
    try:
        os.chmod(private_path, 0o600)
    except OSError:  # Windows 无 POSIX 权限位
        pass
    fingerprint = hashlib.sha256(public_pem).hexdigest()[:16]
    return {
        "private_key": str(private_path),
        "public_key": str(public_path),
        "fingerprint": fingerprint,
        "public_key_sha256": hashlib.sha256(public_pem).hexdigest(),
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PostgreSQL 备份 / 恢复 / 演练")
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="生成 X25519 备份密钥对（公钥给备份侧，私钥离线保管）")
    keygen.add_argument("--out-dir", required=True)

    encrypt = sub.add_parser("encrypt", help="本地加密（验证公钥可用）")
    encrypt.add_argument("--input", required=True)
    encrypt.add_argument("--output", required=True)

    decrypt = sub.add_parser("decrypt", help="本地解密（验证私钥可用）")
    decrypt.add_argument("--input", required=True)
    decrypt.add_argument("--output", required=True)

    upload_cmd = sub.add_parser("upload", help="加密并上传一次备份")
    upload_cmd.add_argument("--input", required=True)
    upload_cmd.add_argument("--dry-run", action="store_true", help="只加密与命名，不触网")

    fetch_cmd = sub.add_parser("fetch", help="取某层最新备份并解密")
    fetch_cmd.add_argument("--tier", default="hourly", choices=TIERS)
    fetch_cmd.add_argument("--object-key", default=None)
    fetch_cmd.add_argument("--out", required=True)

    drill_cmd = sub.add_parser("drill", help="恢复演练：恢复到临时库并校验")
    drill_cmd.add_argument("--tier", default="daily", choices=TIERS)
    drill_cmd.add_argument("--target-db", required=True)
    drill_cmd.add_argument("--keep-dump", default=None, help="保留解密后的 dump 到该路径")

    args = parser.parse_args(list(argv) if argv is not None else None)
    settings = get_settings()

    if args.command == "keygen":
        print(json.dumps(_write_keypair(Path(args.out_dir)), ensure_ascii=False, indent=2))
        return 0

    if args.command == "encrypt":
        stats = encrypt_file(
            Path(args.input), Path(args.output), load_public_key(settings.BACKUP_PUBLIC_KEY_PATH)
        )
        print(json.dumps(stats, ensure_ascii=False, indent=2))
        return 0

    if args.command == "decrypt":
        stats = decrypt_file(
            Path(args.input), Path(args.output), load_private_key(settings.BACKUP_PRIVATE_KEY_PATH)
        )
        print(json.dumps(stats, ensure_ascii=False, indent=2))
        return 0

    if args.command == "upload":
        report = upload(Path(args.input), settings, dry_run=args.dry_run)
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    if args.command == "fetch":
        print(
            json.dumps(
                fetch(
                    args.tier,
                    Path(args.out),
                    settings,
                    object_key_override=args.object_key,
                ),
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.command == "drill":
        report = drill(
            args.tier,
            args.target_db,
            settings,
            keep_dump=Path(args.keep_dump) if args.keep_dump else None,
        )
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    parser.error("未知子命令")
    return 2


if __name__ == "__main__":  # pragma: no cover - 由 CronJob / 运维调用
    raise SystemExit(main())
