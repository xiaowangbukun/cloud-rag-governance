"""P1-14 / P1-15 回归：知识文档列表与标题的出域面边界。

P1-14：``list_documents`` 曾只用用户全局 ceiling 做 SQL 过滤，
项目内 visible_ceiling 更低时越限文档会被列出（与检索路径 ceiling_for
口径不一致）；同时 ``created_at`` 用了 ``isinstance(str) else ""`` 的方言
垫片，PG 上读回 datetime 会输出空串。

P1-15：文档 title 完全绕过净化（content 走 sanitize_before_chunking），
而 title 会进文档列表、审计日志与安全事件 metadata，泄露面超出平台边界。
入库前、出库时、审计 metadata 三处都必须净化。
"""

from __future__ import annotations

import pytest
from rg_contracts.db.models import (
    KnowledgeChunk,
    KnowledgeDocument,
    ProjectMember,
    SecurityEvent,
    new_id,
)
from sqlalchemy import select

ADMIN_ID = "usr_admin"
# prj_agent 是 L2 项目；管理员全局上限 L4 → 项目内 visible_ceiling 为 L2
PROJECT_ID = "prj_agent"
RAW_PHONE = "13800138000"
RAW_EMAIL = "ops@corp.local"


@pytest.fixture
def project_ceiling_l2(session):
    """显式把 admin 在 prj_agent 内的可见上限压到 L2（全局 L4 > 项目内 L2）。"""
    member = session.execute(
        select(ProjectMember).where(
            ProjectMember.user_id == ADMIN_ID,
            ProjectMember.project_id ==PROJECT_ID,
        )
    ).scalar_one()
    original = member.visible_ceiling
    member.visible_ceiling = "L2_INTERNAL"
    session.commit()
    yield
    member = session.execute(
        select(ProjectMember).where(
            ProjectMember.user_id == ADMIN_ID,
            ProjectMember.project_id == PROJECT_ID,
        )
    ).scalar_one()
    member.visible_ceiling = original
    session.commit()


def _add_document(session, classification: str, title: str) -> KnowledgeDocument:
    document = KnowledgeDocument(
        id=new_id("kd"),
        title=title,
        doc_type="rule",
        project_id=PROJECT_ID,
        platform=None,
        classification=classification,
        content="占位内容",
        sanitized=True,
        metadata_json={},
    )
    session.add(document)
    session.commit()
    return document


@pytest.fixture
def mixed_level_documents(session):
    """prj_agent 内造 L2 与 L3 两份文档，返回各自 id。"""
    low = _add_document(session, "L2_INTERNAL", "p1-14-低密级文档")
    high = _add_document(session, "L3_CONFIDENTIAL", "p1-14-高密级文档")
    yield {"low_id": low.id, "high_id": high.id}
    for document_id in (low.id, high.id):
        session.delete(session.get(KnowledgeDocument, document_id))
    session.commit()


def _listed_ids(client, headers) -> set[str]:
    resp = client.get("/api/v1/knowledge/documents?limit=100", headers=headers)
    assert resp.status_code == 200, resp.text
    return {row["id"] for row in resp.json()}


def test_document_list_hides_entries_above_project_ceiling(
    client, admin_headers, session, mixed_level_documents, project_ceiling_l2
):
    """核心回归（P1-14）：全局 L4 但项目内上限 L2 → 项目的 L3 文档不出现。"""
    ids = _listed_ids(client, admin_headers)
    assert mixed_level_documents["high_id"] not in ids, "项目内越限的 L3 文档被列出"
    assert mixed_level_documents["low_id"] in ids, "项目内合规的 L2 文档必须可见"


def test_document_list_serializes_created_at_on_every_dialect(
    client, admin_headers, mixed_level_documents
):
    """created_at 不得为方言垫片空串（PG 上读回 datetime，旧实现输出 ""）。"""
    resp = client.get("/api/v1/knowledge/documents?limit=100", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    rows = resp.json()
    assert rows
    for row in rows:
        assert row["created_at"], f"created_at 为空串：{row}"


@pytest.fixture
def ingested_document(client, session, admin_headers):
    """经 API 写入一份标题含手机号/邮箱的文档（L4 不切片，便于清理）。"""
    payload = {
        "title": f"客户联系人 {RAW_PHONE} 与 {RAW_EMAIL} 的采购方案",
        "content": "采购流程与审批链路说明。",
        "classification": "L4_SECRET",
    }
    resp = client.post("/api/v1/knowledge/documents", json=payload, headers=admin_headers)
    assert resp.status_code == 200, resp.text
    document_id = resp.json()["id"]
    yield document_id
    for chunk in session.execute(
        select(KnowledgeChunk).where(KnowledgeChunk.document_id == document_id)
    ).scalars().all():
        session.delete(chunk)
    document = session.get(KnowledgeDocument, document_id)
    if document is not None:
        session.delete(document)
    session.commit()


def test_document_title_is_sanitized_on_ingest(client, session, admin_headers, ingested_document):
    """核心回归（P1-15）：入库存储值即为脱敏后版本。"""
    session.expire_all()
    document = session.get(KnowledgeDocument, ingested_document)
    stored = document.title
    assert RAW_PHONE not in stored, f"入库标题未脱敏：{stored}"
    assert RAW_EMAIL not in stored, f"入库标题未脱敏：{stored}"
    # 非敏感前缀保留：脱敏只替换敏感实体，不得把标题整体抹掉
    assert stored.startswith("客户联系人"), f"脱敏破坏了标题可用部分：{stored}"
    assert len(stored) > 5


def test_document_title_is_sanitized_on_read(client, admin_headers, ingested_document):
    """出库同样净化（兜住修复前已落库的历史标题）。"""
    resp = client.get("/api/v1/knowledge/documents?limit=100", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    row = next(item for item in resp.json() if item["id"] == ingested_document)
    assert RAW_PHONE not in row["title"], f"列表标题未脱敏：{row['title']}"
    assert RAW_EMAIL not in row["title"], f"列表标题未脱敏：{row['title']}"


def test_security_event_metadata_title_is_sanitized(client, session, admin_headers):
    """核心回归（P1-15）：进安全事件 metadata 的标题也必须是脱敏后版本。"""
    content = "；".join(
        [
            "y" * 250 + "项目A成本128万元",
            "z" * 250 + "项目B拓扑 10.20.30.40",
            "w" * 250 + f"项目C负责人 {RAW_EMAIL}",
        ]
    )
    resp = client.post(
        "/api/v1/knowledge/documents",
        json={
            "title": f"跨分片探测 {RAW_PHONE}",
            "content": content,
            "project_id": "prj_core_policy",
            "classification": "L2_INTERNAL",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    document_id = resp.json()["id"]

    events = session.execute(
        select(SecurityEvent).where(SecurityEvent.event_type == "jigsaw_slicing_evasion")
    ).scalars().all()
    assert events, "前置条件：跨分片重组特征应写入安全事件"
    event = events[-1]
    try:
        event_title = event.metadata_json.get("title", "")
        assert RAW_PHONE not in event_title, f"安全事件 metadata 标题未脱敏：{event_title}"
    finally:
        # 清理：文档 + 分片 + 本用例产生的安全事件
        for chunk in session.execute(
            select(KnowledgeChunk).where(KnowledgeChunk.document_id == document_id)
        ).scalars().all():
            session.delete(chunk)
        document = session.get(KnowledgeDocument, document_id)
        if document is not None:
            session.delete(document)
        for item in events:
            session.delete(item)
        session.commit()