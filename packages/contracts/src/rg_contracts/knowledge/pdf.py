"""PDF 文本抽取（P1）。

职责边界：
* 只做「PDF 字节 → 逐页文本」，不做切块（切块在 :mod:`rg_contracts.knowledge.chunking`）。
* **无文本层即报错**。扫描件（图片型 PDF）需要 OCR 引擎，超出离线 MVP 的算力预算，
  见方案 §7「明确不做」。静默返回空文本会让用户以为「文档入库成功」，
  实际上检索永远命中不到它 —— 这是最坏的一种失败，所以必须显式拒绝。
* 加密、损坏一律转成类型化异常并保留原始异常链，不吞异常：让调用方（上传接口）
  能把「密码保护」和「文件损坏」区分开，给用户不同的处置提示。
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import BinaryIO

from pypdf import PdfReader
from pypdf.errors import PyPdfError

from rg_contracts.errors import AppError
from rg_contracts.knowledge.chunking import PageText

#: 判定「有文本层」的每页最低字符数（去空白后）。
#: 一页 A4 正常排版的中文正文约 800~1500 字；20 字只是「有文字」的下限，
#: 用于挡掉「只有页眉/页码」的扫描件残页。
MIN_CHARS_PER_PAGE = 20

#: 可接受的输入类型：路径、原始字节、或已打开的可 seek 二进制流。
PdfSource = str | Path | bytes | bytearray | memoryview | BinaryIO


class PdfExtractionError(AppError):
    """PDF 抽取失败的类型化基类（映射 HTTP 422，属于「文件内容不可用」）。"""

    code = "pdf_extraction_error"
    http_status = 422
    message = "PDF 解析失败"


class ScannedPdfUnsupported(PdfExtractionError):
    """无文本层（扫描件/图片型 PDF）：本版本不支持 OCR。"""

    code = "scanned_pdf_unsupported"
    message = "该 PDF 无文本层（可能为扫描件），当前版本不支持 OCR"


class EncryptedPdfError(PdfExtractionError):
    """PDF 需要打开密码。"""

    code = "encrypted_pdf_unsupported"
    message = "该 PDF 已加密，请先去除打开密码后再上传"


class CorruptPdfError(PdfExtractionError):
    """文件损坏或不是合法 PDF。"""

    code = "corrupt_pdf"
    message = "PDF 文件损坏或格式不受支持，无法解析"


def read_pdf_pages(source: PdfSource) -> list[PageText]:
    """逐页抽取 PDF 文本，返回页码 + 文本（页序与阅读器一致，从 1 起）。

    Raises:
        ScannedPdfUnsupported: 全文没有可用文本层。
        EncryptedPdfError: 文件需要密码。
        CorruptPdfError: 文件损坏/不是 PDF/内部结构无法解析。
    """
    if isinstance(source, (str, Path)):
        with open(source, "rb") as handle:
            return _extract(handle)
    if isinstance(source, (bytes, bytearray, memoryview)):
        return _extract(io.BytesIO(bytes(source)))
    return _extract(source)


# 语义化别名：调用方读起来更贴近意图（read_pdf_pages 保留给「分页读取」语义）。
extract_pdf_text = read_pdf_pages


def _extract(stream: BinaryIO) -> list[PageText]:
    reader = _open_reader(stream)
    pages: list[PageText] = []
    for index, page in enumerate(reader.pages, start=1):
        pages.append(PageText(page_no=index, text=_page_text(page, index)))
    if not pages:
        raise CorruptPdfError("PDF 不含任何页面")
    _ensure_text_layer(pages)
    return pages


def _open_reader(stream: BinaryIO) -> PdfReader:
    """打开 PDF 并处理加密情况；所有失败都转成类型化异常。"""
    try:
        reader = PdfReader(stream)
    except PyPdfError as exc:
        raise CorruptPdfError(f"PDF 结构解析失败：{exc}") from exc
    except Exception as exc:  # noqa: BLE001 - 第三方解析器的异常类型不稳定，统一转换
        raise CorruptPdfError(f"PDF 无法读取：{exc}") from exc

    try:
        encrypted = bool(reader.is_encrypted)
    except Exception as exc:  # noqa: BLE001 - 同上
        raise CorruptPdfError(f"PDF 加密信息读取失败：{exc}") from exc

    if encrypted and not _decrypt_with_empty_password(reader):
        raise EncryptedPdfError()
    return reader


def _decrypt_with_empty_password(reader: PdfReader) -> bool:
    """尝试用空口令解密。

    「有密码但用户口令为空」的 PDF（只设了权限口令）在运维文档里非常常见，
    这类文件可以正常抽取文本；真正的打开密码才拒绝。
    """
    try:
        return bool(reader.decrypt(""))
    except Exception:  # noqa: BLE001 - 解密失败等价于「需要密码」，不区分内部原因
        return False


def _page_text(page: object, page_no: int) -> str:
    """抽取单页文本；单页解析失败视为文件损坏（不静默跳过该页）。"""
    try:
        text = page.extract_text()  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001 - 单页异常类型不稳定，统一转换
        raise CorruptPdfError(f"第 {page_no} 页文本抽取失败：{exc}") from exc
    return text or ""


def _ensure_text_layer(pages: list[PageText], min_chars_per_page: int = MIN_CHARS_PER_PAGE) -> None:
    """校验「有文本层」，否则抛 :class:`ScannedPdfUnsupported`。

    判定标准（两条任一成立即视为扫描件）：

    1. 全文去空白后的总字符数 < 页数 × 每页下限 —— 整本没有可检索文字；
    2. 每一页都没达到每页下限 —— 只有零星页眉/页码，等价于没有文本层。

    阈值按页数线性缩放而不是用绝对总量，否则「10 页只抽出 30 字」这种
    明显的抽取失败会被放过。
    """
    if not pages:
        raise ScannedPdfUnsupported()
    stripped_lengths = [len("".join(page.text.split())) for page in pages]
    total = sum(stripped_lengths)
    page_count = len(pages)
    if total < page_count * min_chars_per_page:
        raise ScannedPdfUnsupported(
            "该 PDF 无文本层（可能为扫描件），当前版本不支持 OCR"
            f"（已抽取 {total} 个有效字符 / {page_count} 页）"
        )
    if all(length < min_chars_per_page for length in stripped_lengths):
        raise ScannedPdfUnsupported(
            "该 PDF 每页均无可检索文本（可能为扫描件），当前版本不支持 OCR"
            f"（已抽取 {total} 个有效字符 / {page_count} 页）"
        )


__all__ = [
    "MIN_CHARS_PER_PAGE",
    "CorruptPdfError",
    "EncryptedPdfError",
    "PageText",
    "PdfExtractionError",
    "PdfSource",
    "ScannedPdfUnsupported",
    "extract_pdf_text",
    "read_pdf_pages",
]
