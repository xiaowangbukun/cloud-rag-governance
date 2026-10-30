"""PDF 抽取与 PDF 切块单测（P1）。"""

from __future__ import annotations

from collections.abc import Callable
from io import BytesIO

import pytest
from pypdf import PdfReader, PdfWriter

from rg_contracts.knowledge import PageText, chunk_pdf, extract_pdf_text
from rg_contracts.knowledge.pdf import (
    CorruptPdfError,
    EncryptedPdfError,
    ScannedPdfUnsupported,
)


def test_multi_page_pdf_keeps_page_numbers(
    make_pdf: Callable[[list[list[str]]], bytes],
) -> None:
    """① 正常多页 PDF：页码从 1 起且内容对得上页。"""
    raw = make_pdf(
        [
            ["Kubernetes Pod pending troubleshooting"],
            ["Nginx upstream timeout", "Check proxy_read_timeout first"],
            ["PostgreSQL point in time recovery with WAL archive"],
        ]
    )
    pages = extract_pdf_text(raw)

    assert [page.page_no for page in pages] == [1, 2, 3]
    assert "pending" in pages[0].text
    assert "proxy_read_timeout" in pages[1].text
    assert "WAL" in pages[2].text


def test_pdf_from_bytes_and_bytesio_are_equivalent(
    make_pdf: Callable[[list[list[str]]], bytes],
) -> None:
    """字节与文件流两条入口结果一致。"""
    raw = make_pdf([["dashboard cpu usage alert threshold 90 percent"]])
    from_bytes = extract_pdf_text(raw)
    from_stream = extract_pdf_text(BytesIO(raw))
    assert [page.text for page in from_bytes] == [page.text for page in from_stream]


def test_pdf_from_path(tmp_path, make_pdf: Callable[[list[list[str]]], bytes]) -> None:
    """路径入口可用（上传落盘后按路径解析的调用方式）。"""
    raw = make_pdf([["disk usage alert when filesystem is above eighty percent"]])
    path = tmp_path / "ops.pdf"
    path.write_bytes(raw)
    pages = extract_pdf_text(path)
    assert len(pages) == 1
    assert "filesystem" in pages[0].text


def test_scanned_pdf_is_rejected(make_blank_pdf: Callable[[int], bytes]) -> None:
    """② 无文本层 PDF 抛 ScannedPdfUnsupported，而不是静默返回空列表。"""
    with pytest.raises(ScannedPdfUnsupported) as excinfo:
        extract_pdf_text(make_blank_pdf(3))

    error = excinfo.value
    assert error.code == "scanned_pdf_unsupported"
    assert "OCR" in error.detail_message
    assert error.http_status == 422
    # 必须能序列化成 API 错误体
    assert error.to_dict()["code"] == "scanned_pdf_unsupported"


def test_near_empty_pdf_is_rejected(make_pdf: Callable[[list[list[str]]], bytes]) -> None:
    """只有页眉/页码的残页同样判定为扫描件（每页都不足下限）。"""
    raw = make_pdf([["1"], ["2"], ["3"]])
    with pytest.raises(ScannedPdfUnsupported):
        extract_pdf_text(raw)


def test_encrypted_pdf_is_rejected(make_pdf: Callable[[list[list[str]]], bytes]) -> None:
    """加密 PDF 转成明确错误类型，不吞异常。"""
    raw = make_pdf([["confidential runbook for database failover procedure"]])
    writer = PdfWriter()
    for page in PdfReader(BytesIO(raw)).pages:
        writer.add_page(page)
    writer.encrypt("s3cret")
    buffer = BytesIO()
    writer.write(buffer)

    with pytest.raises(EncryptedPdfError) as excinfo:
        extract_pdf_text(buffer.getvalue())
    assert excinfo.value.code == "encrypted_pdf_unsupported"


def test_corrupt_pdf_is_rejected() -> None:
    """损坏文件不能被当成「0 页正常 PDF」。"""
    with pytest.raises(CorruptPdfError):
        extract_pdf_text(b"%PDF-1.4\nthis is not a real pdf body\n")


def test_chunk_pdf_assigns_page_no_and_section_path() -> None:
    """PDF 切块：页码落到每块，页内编号型首行进 section_path。"""
    pages = [
        PageText(
            page_no=1,
            text=(
                "3.2 Database backup\n"
                "Use pg_dump -Fc to dump a single database.\n"
                "Verify the dump with pg_restore --list before archiving.\n"
            ),
        ),
        PageText(
            page_no=2,
            text=(
                "Recovery steps\n"
                "Restore with pg_restore -C -d target db.dump.\n"
                "Replay WAL segments up to the target timestamp.\n"
            ),
        ),
    ]
    chunks = chunk_pdf(pages, target_chars=60, overlap_chars=10, max_chars=200)

    assert chunks
    assert {chunk.page_no for chunk in chunks} == {1, 2}
    assert chunks[0].section_path == "3.2 Database backup"
    # 第二页首行不是编号型标题 → 不编造章节
    assert all(chunk.section_path is None for chunk in chunks if chunk.page_no == 2)


def test_chunk_pdf_never_spans_pages() -> None:
    """页是硬边界：任何块都只属于一页（跨页拼接会让 page_no 失去意义）。"""
    pages = [
        PageText(page_no=1, text="Alpha one. Beta two. Gamma three. Delta four."),
        PageText(page_no=2, text="Epsilon five. Zeta six. Eta seven. Theta eight."),
    ]
    chunks = chunk_pdf(pages, target_chars=20, overlap_chars=5, max_chars=100)

    assert len(chunks) >= 4
    for chunk in chunks:
        assert chunk.page_no in (1, 2)
        page_text = pages[chunk.page_no - 1].text
        assert chunk.text in page_text
        # 跨页块会出现别页的关键词
        other = pages[2 - chunk.page_no].text
        assert not any(word in chunk.text for word in other.split())


def test_chunk_pdf_char_offsets_are_page_local() -> None:
    """PDF 的 char_start/char_end 是页内偏移，必须能切回原文。"""
    pages = [
        PageText(page_no=1, text="Line one of page. Line two of page. Line three of page."),
        PageText(page_no=2, text="Second page content here."),
    ]
    chunks = chunk_pdf(pages, target_chars=30, overlap_chars=10, max_chars=100)
    for chunk in chunks:
        page_text = pages[chunk.page_no - 1].text
        assert page_text[chunk.char_start : chunk.char_end] == chunk.text


def test_chunk_pdf_skips_empty_pages_and_handles_empty_input() -> None:
    """空白页不产出块；全空输入返回空列表（抽取阶段已单独拒绝扫描件）。"""
    assert chunk_pdf([]) == []
    chunks = chunk_pdf(
        [
            PageText(page_no=1, text="   \n\n  "),
            PageText(page_no=2, text="Real content on page two."),
        ]
    )
    assert [chunk.page_no for chunk in chunks] == [2]


def test_chunk_pdf_long_title_is_not_treated_as_heading() -> None:
    """过长的「以数字开头」的正文行不算标题（避免日期行误判）。"""
    pages = [
        PageText(
            page_no=1,
            text=(
                "2026 10 月 18 日巡检记录显示所有节点负载正常没有异常告警需要关注的情况发生\n"
                "No action required for this shift.\n"
            ),
        )
    ]
    chunks = chunk_pdf(pages)
    assert all(chunk.section_path is None for chunk in chunks)
