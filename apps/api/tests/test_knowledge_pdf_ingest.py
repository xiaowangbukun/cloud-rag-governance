"""E 回归：PDF 摄取路由走**与文本摄取同一条**安全链路。

要点：
1. 路由只做「字节 → 逐页文本」与入参校验，注入检测 / 授权密级 / 净化 / 切块 /
   金丝雀 / 审计全部由 ``_ingest_document`` 完成 —— 不复制任何一份平行实现。
2. 分片带 ``page_no``，出处能指到页码（文本摄取恒为 None，两者对比可见）。
3. 越权、密级越限、非 PDF、超限、扫描件：错误码与文本摄取保持一致。

PDF 生成说明：pypdf **不是排版引擎**（没有写文字的公开 API，用它的 Writer 注入
内容流抽不出文本，探针已验证），所以这里按 PDF 规范现场拼最小字节串（每页一个
文本对象，UTF-16BE 编码），仍交给产品的 ``read_pdf_pages`` 解析 —— 与生产的解析
路径完全一致，且不依赖仓库里的外部二进制文件。
"""

from __future__ import annotations

import io

import pytest
from pypdf import PdfWriter
from rg_contracts.db.models import AuditLog, KnowledgeChunk, KnowledgeDocument
from sqlalchemy import select

PAGE_ONE = "第一章 部署流程：先核对配额与事件，再看节点资源是否充足。"
PAGE_TWO = "第二章 回滚步骤：先摘除流量入口，再回退镜像版本并核对健康检查。"


def _make_pdf(pages_text: list[str]) -> bytes:
    """按 PDF 规范拼一个最小多页文档（每页一段文本）。"""
    objects: list[bytes] = []
    page_ids: list[int] = []

    def _text_operand(text: str) -> bytes:
        payload = "﻿" + text
        return b"<" + payload.encode("utf-16-be").hex().encode("ascii") + b">"

    next_id = 4  # 1=Catalog 2=Pages 3=Font
    for text in pages_text:
        page_id = next_id
        content_id = next_id + 1
        page_ids.append(page_id)
        content = b"BT /F1 14 Tf 40 760 Td " + _text_operand(text) + b" Tj ET"
        objects.append(
            f"{page_id} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>\nendobj\n".encode()
        )
        objects.append(
            f"{content_id} 0 obj\n<< /Length {len(content)} >>\nstream\n".encode()
            + content
            + b"\nendstream\nendobj\n"
        )
        next_id += 2

    font_desc_id = next_id
    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    header = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        f"2 0 obj\n<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>\nendobj\n".encode(),
        f"3 0 obj\n<< /Type /Font /Subtype /Type0 /Encoding /Identity-H /BaseFont /STSong-Light "
        f"/DescendantFonts [{font_desc_id} 0 R] >>\nendobj\n".encode(),
    ]
    objects.append(
        f"{font_desc_id} 0 obj\n<< /Type /Font /Subtype /CIDFontType2 /BaseFont /STSong-Light "
        f"/CIDSystemInfo << /Registry (Adobe) /Ordering (GB1) /Supplement 2 >> /DW 1000 >>\nendobj\n".encode()
    )

    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = [0]
    for chunk in header + objects:
        offsets.append(out.tell())
        out.write(chunk)
    xref_pos = out.tell()
    count = len(header) + len(objects) + 1
    out.write(f"xref\n0 {count}\n".encode())
    out.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        out.write(f"{offset:010d} 00000 n \n".encode())
    out.write(
        f"trailer\n<< /Size {count} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode()
    )
    return out.getvalue()


def _blank_pdf(pages: int = 1) -> bytes:
    """无文本层的 PDF（模拟扫描件）。"""
    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=300, height=300)
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


@pytest.fixture
def upload_cleanup(session):
    created: list[str] = []
    yield created
    for document_id in created:
        for chunk in session.execute(
            select(KnowledgeChunk).where(KnowledgeChunk.document_id == document_id)
        ).scalars().all():
            session.delete(chunk)
        document = session.get(KnowledgeDocument, document_id)
        if document is not None:
            session.delete(document)
    session.commit()


def _upload(client, headers, data: bytes, filename: str = "guide.pdf", **form):
    return client.post(
        "/api/v1/knowledge/documents/pdf",
        files={"file": (filename, data, "application/pdf")},
        data=form,
        headers=headers,
    )


def test_pdf_ingest_keeps_page_numbers(client, session, admin_headers, upload_cleanup):
    """核心：PDF 分片带页码，逐页切块后 page_no 覆盖每一页。"""
    resp = _upload(client, admin_headers, _make_pdf([PAGE_ONE, PAGE_TWO]))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    upload_cleanup.append(body["id"])
    assert body["chunks"] >= 2, "多页 PDF 应切出多个分片"

    session.expire_all()
    chunks = (
        session.execute(
            select(KnowledgeChunk)
            .where(KnowledgeChunk.document_id == body["id"])
            .order_by(KnowledgeChunk.ordinal)
        )
        .scalars()
        .all()
    )
    assert {chunk.page_no for chunk in chunks} == {1, 2}, "页码未随切块写入分片"
    for chunk in chunks:
        assert chunk.page_no is not None and chunk.page_no >= 1

    document = session.get(KnowledgeDocument, body["id"])
    assert document.source_type == "pdf"
    assert document.page_count == 2
    assert document.source_path == "guide.pdf", "只存 basename，不得落完整路径"


def test_pdf_source_points_to_page_number(client, session, admin_headers, upload_cleanup):
    """出处能指到页码：检索命中的 source.page_no 有值（文本摄取恒为 None）。"""
    resp = _upload(
        client,
        admin_headers,
        _make_pdf([PAGE_ONE, PAGE_TWO]),
        project_id="prj_core_policy",
    )
    assert resp.status_code == 200, resp.text
    document_id = resp.json()["id"]
    upload_cleanup.append(document_id)

    search = client.post(
        "/api/v1/knowledge/search",
        json={"query": "部署流程 配额 事件", "project_id": "prj_core_policy", "top_k": 8},
        headers=admin_headers,
    )
    assert search.status_code == 200, search.text
    hits = [hit for hit in search.json()["hits"] if hit["source"]["document_title"]]
    assert hits, "前置：PDF 分片应被检索命中"
    assert any(hit["source"]["page_no"] is not None for hit in hits), (
        "出处指不到页码：page_no 仍为 None"
    )


def test_pdf_ingest_is_audited_like_text_path(client, session, admin_headers, upload_cleanup):
    """审计与文本摄取一致：allowed 记录带 source_type=pdf。"""
    resp = _upload(client, admin_headers, _make_pdf([PAGE_ONE]))
    assert resp.status_code == 200, resp.text
    document_id = resp.json()["id"]
    upload_cleanup.append(document_id)

    rows = session.execute(
        select(AuditLog).where(AuditLog.resource_id == document_id)
    ).scalars().all()
    allowed = [row for row in rows if row.outcome == "allowed"]
    assert allowed, "PDF 摄取未写 allowed 审计"
    metadata = allowed[-1].metadata_json or {}
    assert metadata.get("source_type") == "pdf", f"审计未标注来源类型：{metadata}"


def test_pdf_ingest_denied_when_project_out_of_scope(client, pm_headers):
    """越权拒绝：PM 上传到未授权项目 → 403，与文本摄取同一套授权判定。"""
    resp = _upload(
        client, pm_headers, _make_pdf([PAGE_ONE]), project_id="prj_claim"
    )
    assert resp.status_code == 403, resp.text
    assert resp.json()["code"] == "permission_denied"


def test_pdf_ingest_rejects_non_pdf_content_type(client, admin_headers):
    resp = client.post(
        "/api/v1/knowledge/documents/pdf",
        files={"file": ("notes.txt", b"plain text", "text/plain")},
        headers=admin_headers,
    )
    assert resp.status_code == 422, resp.text


def test_pdf_ingest_rejects_scanned_pdf(client, admin_headers):
    """无文本层（扫描件）→ 类型化错误码，不静默入库。"""
    resp = _upload(client, admin_headers, _blank_pdf(2))
    assert resp.status_code == 422, resp.text
    assert resp.json()["code"] == "scanned_pdf_unsupported"


def test_pdf_ingest_rejects_oversized_upload(client, admin_headers, monkeypatch):
    from rg_contracts.config import get_settings, reset_settings_cache

    monkeypatch.setenv("KNOWLEDGE_UPLOAD_MAX_BYTES", "10")
    reset_settings_cache()
    try:
        assert get_settings().KNOWLEDGE_UPLOAD_MAX_BYTES == 10
        resp = _upload(client, admin_headers, _make_pdf([PAGE_ONE]))
        assert resp.status_code == 422, resp.text
    finally:
        reset_settings_cache()
