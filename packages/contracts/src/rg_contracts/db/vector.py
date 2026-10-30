from __future__ import annotations

from typing import Any

from pgvector.sqlalchemy import Vector as PgVectorType
from sqlalchemy import JSON, TypeDecorator
from sqlalchemy.dialects.postgresql import ARRAY, REAL

EMBEDDING_DIM_HINT = 1024


class Vector(TypeDecorator):
    """Vector column: pgvector `vector` on PostgreSQL, JSON array on SQLite.

    生产使用 PostgreSQL + pgvector：列类型为 ``vector(EMBEDDING_DIM_HINT)``，
    由 pgvector 官方 SQLAlchemy 类型（``pgvector.sqlalchemy.Vector``）负责
    ``list[float]`` 与 PG ``vector`` 之间的绑定/结果转换，从而支持 ``<->`` /
    ``<=>`` 等向量算子与 HNSW 索引。

    本地 SQLite 时向量以 JSON 数组降级存储，并由 retrieval 层的 memory
    检索器完成相似度计算，保证本地环境可完整演示。

    P0-1 修复记录：旧实现 PG 分支返回 ``LargeBinary``（列建成 bytea），
    又在 ``process_bind_param`` 返回 vector 字面量字符串，导致
    (1) hnsw 索引 DDL 报 ``operator class vector_cosine_ops does not accept bytea``；
    (2) psycopg 把 str 绑进 bytea 报 ``TypeError: bytes or buffer expected``。
    现在 PG 分支直接复用 pgvector 类型，不再自行拼接字面量。
    """

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect: Any) -> Any:
        if dialect.name == "postgresql":
            # pgvector 的 UserDefinedType：DDL 编译为 VECTOR(1024)，
            # 其 bind/result 处理器完成 list[float] <-> PG vector 转换
            return dialect.type_descriptor(PgVectorType(EMBEDDING_DIM_HINT))
        return dialect.type_descriptor(JSON())

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        vector = _to_list(value)
        if dialect.name == "postgresql":
            # 交由 pgvector VECTOR 的 bind_processor 序列化为 vector 字面量，
            # 不要再自行拼字符串（旧 bug：str 绑进 bytea 直接 TypeError）
            return vector
        return vector

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, list):
            # PG 路径：pgvector 的 result_processor 已将 vector 文本解析为 list[float]
            return value
        if isinstance(value, (bytes, bytearray)):
            # 兼容历史 bytea 数据（P0-1 迁移前的存量行）
            return _from_pgvector_literal(value)
        if isinstance(value, str):
            return _from_pgvector_literal(value.encode())
        return value


def _to_list(value: Any) -> list[float]:
    if hasattr(value, "tolist"):
        return [float(x) for x in value.tolist()]  # type: ignore[union-attr]
    if isinstance(value, (bytes, bytearray)):
        return _from_pgvector_literal(value)
    if isinstance(value, str):
        return _from_pgvector_literal(value.encode())
    return [float(x) for x in value]


def _from_pgvector_literal(raw: bytes | bytearray) -> list[float]:
    text = raw.decode() if isinstance(raw, (bytes, bytearray)) else str(raw)
    text = text.strip().strip("[]")
    if not text:
        return []
    return [float(part) for part in text.split(",")]


__all__ = ["Vector", "ARRAY", "REAL", "EMBEDDING_DIM_HINT"]
