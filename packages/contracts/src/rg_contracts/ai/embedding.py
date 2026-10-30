"""Embedding service.

内置 BGE-M3：
- `http` 后端：对接内网部署的 BGE-M3 推理服务（TEI / FlagEmbedding 服务化），OpenAI 兼容可选
- `offline` 后端：确定性哈希降级向量，保证本地无模型服务时仍可完整演示链路

离线向量只用于本地演示，不具备语义召回能力；生产必须配置 http 后端。
"""

from __future__ import annotations

import hashlib
import math
from typing import Sequence

import httpx

from rg_contracts.config import EmbeddingBackend, Settings, get_settings
from rg_contracts.errors import EmbeddingError
from rg_contracts.logging_setup import get_logger

logger = get_logger(__name__)


def l2_normalize(vector: list[float]) -> list[float]:
    norm = math.sqrt(sum(x * x for x in vector)) or 1.0
    return [x / norm for x in vector]


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    if len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


class EmbeddingService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.model = self.settings.EMBEDDING_MODEL
        self.dim = self.settings.EMBEDDING_DIM

    @property
    def backend(self) -> str:
        return self.settings.EMBEDDING_BACKEND.value

    # ---------------------------------------------------------------- public
    def embed(self, text: str) -> list[float]:
        return self.embed_many([text])[0]

    def embed_many(self, texts: Sequence[str]) -> list[list[float]]:
        if not texts:
            return []
        if self.settings.EMBEDDING_BACKEND is EmbeddingBackend.HTTP:
            return self._embed_http(texts)
        return [self._embed_offline(t) for t in texts]

    # --------------------------------------------------------------- backends
    def _embed_http(self, texts: Sequence[str]) -> list[list[float]]:
        url = self.settings.EMBEDDING_HTTP_URL
        payload_options: list[dict] = [
            {"inputs": list(texts), "model": self.model},
            {"input": list(texts), "model": self.model},
        ]
        last_error: Exception | None = None
        for payload in payload_options:
            try:
                with httpx.Client(timeout=self.settings.EMBEDDING_TIMEOUT_SECONDS) as client:
                    resp = client.post(url, json=payload)
                    resp.raise_for_status()
                    data = resp.json()
                vectors = self._parse_response(data)
                if vectors and len(vectors) == len(texts):
                    return [self._fit(v) for v in vectors]
            except Exception as exc:  # noqa: BLE001 - 归一化为类型化错误
                last_error = exc
                logger.warning("embedding_http_attempt_failed", extra={"extra_fields": {"error": str(exc)}})
        raise EmbeddingError(
            "向量模型服务调用失败",
            url=url,
            model=self.model,
            error=str(last_error) if last_error else "unknown",
        )

    def _parse_response(self, data: object) -> list[list[float]]:
        """兼容 TEI([[float]]) / OpenAI({data:[{embedding}]}) / {embeddings:[...]} 三种形态。"""
        if isinstance(data, list):
            if data and isinstance(data[0], (int, float)):
                return [[float(x) for x in data]]  # type: ignore[arg-type]
            if data and isinstance(data[0], list):
                return [[float(x) for x in row] for row in data]  # type: ignore[union-attr]
        if isinstance(data, dict):
            if "data" in data and isinstance(data["data"], list):
                return [[float(x) for x in item["embedding"]] for item in data["data"]]
            if "embeddings" in data:
                return [[float(x) for x in row] for row in data["embeddings"]]
            if "embedding" in data:
                return [[float(x) for x in data["embedding"]]]
        return []

    def _fit(self, vector: list[float]) -> list[float]:
        if len(vector) == self.dim:
            return l2_normalize(vector) if self.settings.EMBEDDING_NORMALIZE else vector
        if len(vector) > self.dim:
            vector = vector[: self.dim]
        else:
            vector = list(vector) + [0.0] * (self.dim - len(vector))
        return l2_normalize(vector) if self.settings.EMBEDDING_NORMALIZE else vector

    def _embed_offline(self, text: str) -> list[float]:
        """确定性降级向量：字符 n-gram + 词级特征哈希投影，同文本恒定结果。

        用途：本地演示与单元测试。语义召回能力有限，不可替代真实模型。
        """
        vector = [0.0] * self.dim
        padded = f" {text} "

        def add(feature: str, weight: float, slots: int = 4) -> None:
            digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=16).digest()
            for i in range(slots):
                idx = int.from_bytes(digest[i * 2 : i * 2 + 2], "big") % self.dim
                sign = 1.0 if digest[i * 2 + 1] & 1 else -1.0
                vector[idx] += sign * weight

        # 字符 trigram：对中文短文本提供基础召回
        for i in range(len(padded) - 2):
            add(padded[i : i + 3], 0.4, 3)
        # 中文 bigram：显著提升同主题文本的重合度
        for i in range(len(padded) - 1):
            add(padded[i : i + 2], 1.0, 4)
        # 词级特征：中文按 2~4 字切分与非 ASCII 词，英文按空格切分
        for token in _tokens(text):
            add(f"w:{token}", 1.6, 6)

        norm = math.sqrt(sum(x * x for x in vector)) or 1.0
        return [x / norm for x in vector]


def _tokens(text: str) -> list[str]:
    """轻量分词：中文取 2~4 字滑窗，ASCII 按词切分。仅用于离线降级向量。"""
    import re

    tokens: list[str] = []
    for chunk in re.split(r"[\s，。；、（）()【】\[\]:：,.;/|-]+", text):
        if not chunk:
            continue
        if re.search(r"[\u4e00-\u9fa5]", chunk):
            for size in (2, 3, 4):
                for i in range(len(chunk) - size + 1):
                    tokens.append(chunk[i : i + size])
        else:
            lowered = chunk.lower()
            if len(lowered) >= 2:
                tokens.append(lowered)
    return tokens


_service: EmbeddingService | None = None


def get_embedding_service(settings: Settings | None = None) -> EmbeddingService:
    global _service
    if _service is None:
        _service = EmbeddingService(settings)
    return _service
