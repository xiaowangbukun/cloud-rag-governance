"""知识库摄取能力：标题感知切块与 PDF 文本抽取。

本包只负责「文本 → 切块草稿」这一纯函数环节，不做净化、不做向量化、不碰数据库，
因此可以脱离 FastAPI / SQLAlchemy 单独测试与复用（CLI、批处理脚本、离线验收）。
"""

from rg_contracts.knowledge.chunking import (
    CHUNK_MAX_CHARS,
    CHUNK_OVERLAP_CHARS,
    CHUNK_TARGET_CHARS,
    ChunkDraft,
    PageText,
    chunk_markdown,
    chunk_pdf,
)
from rg_contracts.knowledge.pdf import (
    MIN_CHARS_PER_PAGE,
    CorruptPdfError,
    EncryptedPdfError,
    PdfExtractionError,
    ScannedPdfUnsupported,
    extract_pdf_text,
    read_pdf_pages,
)

__all__ = [
    "CHUNK_MAX_CHARS",
    "CHUNK_OVERLAP_CHARS",
    "CHUNK_TARGET_CHARS",
    "MIN_CHARS_PER_PAGE",
    "ChunkDraft",
    "CorruptPdfError",
    "EncryptedPdfError",
    "PageText",
    "PdfExtractionError",
    "ScannedPdfUnsupported",
    "chunk_markdown",
    "chunk_pdf",
    "extract_pdf_text",
    "read_pdf_pages",
]
