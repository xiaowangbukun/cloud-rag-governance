from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, String, TypeDecorator
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Declarative base with consistent naming for Alembic autogenerate."""

    naming_convention = {
        "ix": "ix_%(column_0_label)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s",
    }


class TimestampCodec:
    """时间戳编解码：SQLite 用文本存 ISO-8601，PostgreSQL 用原生 timestamptz。"""

    @staticmethod
    def encode(value: datetime | str | None) -> str | None:
        if value is None:
            return None
        if isinstance(value, str):
            return value
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()

    @staticmethod
    def decode(value: str | datetime | None) -> datetime | None:
        if value is None or isinstance(value, datetime):
            return value
        try:
            return datetime.fromisoformat(value)
        except (TypeError, ValueError):
            return None


def _utcnow_iso() -> str:
    return str(TimestampCodec.encode(utcnow()))


class TimestampMixin:
    """用 with_variant 区分方言，避免 SQLite 对 DateTime 的严格校验。"""

    created_at: Mapped[str] = mapped_column(
        String(32).with_variant(DateTime(timezone=True), "postgresql"),
        nullable=False,
        default=_utcnow_iso,
    )
    updated_at: Mapped[str] = mapped_column(
        String(32).with_variant(DateTime(timezone=True), "postgresql"),
        nullable=False,
        default=_utcnow_iso,
        onupdate=_utcnow_iso,
    )


def json_dumps(value: Any) -> str:
    return json.dumps(value or {}, ensure_ascii=False)


def json_loads(value: Any) -> dict:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    try:
        data = json.loads(value)
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


class JSONDictType(TypeDecorator):
    """JSON object column: JSONB on PostgreSQL, serialized text on SQLite.

    以 String 作为基类，避免 SQLite 方言自带 JSON 处理器覆盖序列化逻辑。
    """

    impl = String
    cache_ok = True

    def load_dialect_impl(self, dialect: Any) -> Any:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(String())

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        if dialect.name == "postgresql":
            # PG 的 jsonb 列必须收到 **Python 对象**，由驱动按 JSON 序列化。
            # 这里绝不能返回 ``json.dumps`` 的字符串：jsonb 会把字符串当成
            # 「JSON 字符串标量」存下去（``jsonb_typeof`` = ``'string'``），于是
            # ``metadata_json->>'actor'`` 这类 SQL 侧查询恒为 NULL —— 而 ORM 读回
            # 仍是 dict（``json_loads`` 会把字符串再解析一次），单测完全看不出来。
            # 只有真在 SQL 里按元数据过滤（备份审计、看板、导出、保留任务）才暴露。
            return value if isinstance(value, dict) else json_loads(value)
        if isinstance(value, str):
            return value
        return json_dumps(value)

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        return json_loads(value)


def JsonDict() -> Any:
    """Portable JSON object column with dict default."""
    return mapped_column(JSONDictType(), nullable=False, default=dict)


def TS(index: bool = False) -> Any:
    """Portable timestamp column: text ISO-8601 on SQLite, timestamptz on PostgreSQL."""
    variant = String(32).with_variant(DateTime(timezone=True), "postgresql")
    return mapped_column(variant, nullable=False, index=index)


def TS_NULL() -> Any:
    variant = String(32).with_variant(DateTime(timezone=True), "postgresql")
    return mapped_column(variant, nullable=True)


class StrIdMixin:
    id: Mapped[str] = mapped_column(String(64), primary_key=True)


def ts_lt(column: Any, cutoff: datetime, dialect_name: str) -> Any:
    """生成「时间戳列早于 cutoff」的方言安全条件。

    两套方言的列类型不同：PG 是 ``timestamptz``（必须绑 datetime，绑文本
    会因缺少隐式转换报 operator does not exist），SQLite 是 ISO-8601 文本
    （必须绑与写入时**同格式**的字符串，字典序才与时间序一致）。
    全代码库的时间戳都由 :class:`TimestampCodec` 编码，因此文本分支的比较
    不会因时区渲染差异失配。

    参数 ``dialect_name`` 显式传入而不是从列推断：调用方一定有会话在手，
    让方言来源唯一（``session.get_bind().dialect.name``），避免出现第二套真相。
    """
    if dialect_name == "postgresql":
        return column < cutoff
    return column < str(TimestampCodec.encode(cutoff))


def ts_gte(column: Any, cutoff: datetime, dialect_name: str) -> Any:
    """生成「时间戳列不早于 cutoff」的方言安全条件（``ts_lt`` 的正向对应）。

    不用 ``ts_lt(...).__invert__()``：那会渲染成 ``NOT (col < x)``，
    对 NULL 违背「未知即不保留」的直觉，也不利于读执行计划。
    """
    if dialect_name == "postgresql":
        return column >= cutoff
    return column >= str(TimestampCodec.encode(cutoff))
