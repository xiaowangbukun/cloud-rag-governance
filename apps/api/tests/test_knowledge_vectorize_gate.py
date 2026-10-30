"""回归：向量化闸门只认密级，不认金丝雀开关（QA 可读性审查缺陷②）。

修复前 ``routes/knowledge.py`` 把 ``SECURITY_CANARY_ENABLED`` 当向量化开关：
运维关掉金丝雀 → 所有知识文档零切片、零 embedding，接口还返回
``{"chunks": 0}`` 看似正常，检索质量静默死亡。

金丝雀在入库侧的真实职责是 ``canary.assert_clean``（disabled 时为 no-op），
与是否向量化无关；唯一合法闸门是密级（L4 原始事实禁止向量化，仅登记不切片）。
"""

from __future__ import annotations

import pytest
from rg_contracts.config import get_settings, reset_settings_cache
from rg_contracts.db.models import KnowledgeChunk, KnowledgeDocument
from sqlalchemy import select

_CONTENT = "运维排障说明：Pod 一直 Pending 时，先看事件与配额，再看节点资源是否充足。"


@pytest.fixture
def written_documents(client, session, admin_headers):
    """经 API 写文档并记录 id，用例结束后连同分片一起清理。"""
    created: list[str] = []

    def _write(classification: str, title: str) -> str:
        resp = client.post(
            "/api/v1/knowledge/documents",
            json={"title": title, "content": _CONTENT, "classification": classification},
            headers=admin_headers,
        )
        assert resp.status_code == 200, resp.text
        document_id = resp.json()["id"]
        created.append(document_id)
        return document_id

    yield _write

    for document_id in created:
        for chunk in session.execute(
            select(KnowledgeChunk).where(KnowledgeChunk.document_id == document_id)
        ).scalars().all():
            session.delete(chunk)
        document = session.get(KnowledgeDocument, document_id)
        if document is not None:
            session.delete(document)
    session.commit()


def _chunk_count(session, document_id: str) -> int:
    session.expire_all()
    return len(
        session.execute(
            select(KnowledgeChunk).where(KnowledgeChunk.document_id == document_id)
        ).scalars().all()
    )


def test_l4_document_is_not_vectorized(client, session, written_documents):
    """L4 仅登记不切片——既有行为不得因本次修复回归。"""
    document_id = written_documents("L4_SECRET", "vectorize-gate-l4")
    assert _chunk_count(session, document_id) == 0, "L4 文档产生了分片（密级闸门失效）"


def test_vectorization_survives_canary_disabled(client, session, written_documents, monkeypatch):
    """核心回归：SECURITY_CANARY_ENABLED=false 不得阻断向量化（缺陷②）。"""
    monkeypatch.setenv("SECURITY_CANARY_ENABLED", "false")
    reset_settings_cache()
    try:
        # 先证明闸门看到的确实是 disabled 状态，避免测试因设置未生效而假绿
        assert get_settings().SECURITY_CANARY_ENABLED is False, "测试设置未生效"
        document_id = written_documents("L2_INTERNAL", "vectorize-gate-canary-off")
        assert _chunk_count(session, document_id) > 0, (
            "金丝雀关闭时文档被零切片（缺陷②复现：旋钮混淆门控向量化）"
        )
    finally:
        reset_settings_cache()
