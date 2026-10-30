"""契约层测试夹具：手工构造最小 PDF，避免引入 reportlab 等额外依赖。

为什么要自己拼 PDF 字节：测试「有文本层 / 无文本层」两条分支需要完全可控的
输入。用 pypdf 的 ``PdfWriter`` 只能生成空白页（无文本内容），无法构造
「有文本层」的样本；手写 PDF 对象 + xref 只需 30 行，且不依赖外部生成器。
"""

from __future__ import annotations

from collections.abc import Callable

import pytest


def _build_pdf(contents: list[bytes]) -> bytes:
    """按页内容流组装一个合法 PDF（Helvetica 字体，ASCII 文本）。"""
    page_count = len(contents)
    kids = " ".join(f"{4 + 2 * index} 0 R" for index in range(page_count))
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        f"<< /Type /Pages /Kids [{kids}] /Count {page_count} >>".encode(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    for index, content in enumerate(contents):
        content_object = 5 + 2 * index
        objects.append(
            (
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_object} 0 R >>"
            ).encode()
        )
        objects.append(
            b"<< /Length "
            + str(len(content)).encode()
            + b" >>\nstream\n"
            + content
            + b"\nendstream"
        )

    out = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_offset = len(out)
    out += b"xref\n0 " + str(len(objects) + 1).encode() + b"\n0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += b"trailer\n<< /Size " + str(len(objects) + 1).encode() + b" /Root 1 0 R >>\n"
    out += b"startxref\n" + str(xref_offset).encode() + b"\n%%EOF\n"
    return bytes(out)


def _content_stream(lines: list[str]) -> bytes:
    """把若干文本行包成 PDF 文本对象内容流（只支持 ASCII/latin-1）。"""
    body = "BT /F1 12 Tf 72 720 Td 14 TL\n"
    for line in lines:
        escaped = line.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
        body += f"({escaped}) Tj T*\n"
    body += "ET"
    return body.encode("latin-1")


@pytest.fixture
def make_pdf() -> Callable[[list[list[str]]], bytes]:
    """返回工厂：``make_pdf([["第 1 页第 1 行", "..."], [...]])`` → PDF 字节。"""

    def _make(pages: list[list[str]]) -> bytes:
        return _build_pdf([_content_stream(lines) for lines in pages])

    return _make


@pytest.fixture
def make_blank_pdf() -> Callable[[int], bytes]:
    """返回工厂：``make_blank_pdf(2)`` → 两页无文本 PDF（模拟扫描件）。"""

    def _make(page_count: int) -> bytes:
        return _build_pdf([b"q Q" for _ in range(page_count)])

    return _make
