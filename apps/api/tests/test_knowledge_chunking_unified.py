"""摄取切块统一到 chunk_markdown 的回归（消灭第三套切块器）。

修复前 ``routes/knowledge.py`` 用本地 ``_split(content, size=260)``：按
``；``/``;`` 硬切，再按 260 字缓冲拼接。它有两个结构性缺陷：

* **无分号的长文档整篇塞进一个分片** —— 260 字缓冲只在遇到分号时才生效，
  通篇用 ``。`` 断句的长文档会被当成一个 2000+ 字的分片，语义被稀释，
  检索时"什么都像"。
* **块边界落在句中且无重叠** —— 按分号切完再按字数凑，边界与句末无关；
  相邻块之间也没有重叠，切断处的上下文在两块里都不完整。

``chunk_markdown``（标题感知、句末聚包、整句回退重叠）已交付但产品侧没接，
本文件把这两条行为钉住：换回旧切块器时下面的断言必须转红。
"""

from __future__ import annotations

import pytest
from rg_contracts.config import get_settings
from rg_contracts.db.models import KnowledgeChunk, KnowledgeDocument
from sqlalchemy import select

# 中文数词，避免数字被 coarse_buckets 改写（脱敏会改变文本，断言改用结构性质）
_ORDINALS = ("一", "二", "三", "四", "五", "六", "七", "八")
#: 单句模板：无分号、无数字、无敏感实体——保证净化前后文本一致
_SENTENCE = "巡检要求第%s条：每日核对资源水位与成本中心归属，异常增长需在两个工作日内给出处置结论"


def _sentence(index: int, width: int) -> str:
    """生成一条以「。」结尾、长度恰为 width 的句子（无分号）。"""
    base = _SENTENCE % _ORDINALS[index % len(_ORDINALS)]
    return (base + "补充")[:width].ljust(width, "说") + "。"


@pytest.fixture
def ingested(client, session, admin_headers):
    """经 API 写入文档并返回 (document_id, 已排序分片)；用例结束清理。"""

    def _write(content: str, title: str = "chunk-unified") -> tuple[str, list[KnowledgeChunk]]:
        resp = client.post(
            "/api/v1/knowledge/documents",
            json={"title": title, "content": content, "classification": "L2_INTERNAL"},
            headers=admin_headers,
        )
        assert resp.status_code == 200, resp.text
        document_id = resp.json()["id"]
        session.expire_all()
        chunks = (
            session.execute(
                select(KnowledgeChunk)
                .where(KnowledgeChunk.document_id == document_id)
                .order_by(KnowledgeChunk.ordinal)
            )
            .scalars()
            .all()
        )
        return document_id, list(chunks)

    created: list[str] = []

    def _write_and_track(content: str, title: str = "chunk-unified") -> tuple[str, list[KnowledgeChunk]]:
        document_id, chunks = _write(content, title)
        created.append(document_id)
        return document_id, chunks

    yield _write_and_track

    for document_id in created:
        for chunk in session.execute(
            select(KnowledgeChunk).where(KnowledgeChunk.document_id == document_id)
        ).scalars().all():
            session.delete(chunk)
        document = session.get(KnowledgeDocument, document_id)
        if document is not None:
            session.delete(document)
    session.commit()


def test_long_document_is_split_into_bounded_chunks(ingested):
    """长文档（通篇「。」断句、无分号）不得整篇塞进一个分片。

    旧 _split 只认分号：无分号时返回「整篇一个分片」；新切块器按句末聚包，
    每块不超过 CHUNK_MAX_CHARS，且首尾内容都不丢。
    """
    settings = get_settings()
    content = "".join(_sentence(index, 300) for index in range(8))
    assert "；" not in content and ";" not in content

    _document_id, chunks = ingested(content)
    assert len(chunks) >= 3, (
        f"长文档只切出 {len(chunks)} 个分片（旧切块器会把整篇塞进一块）"
    )
    assert max(len(chunk.embedding_text) for chunk in chunks) <= settings.CHUNK_MAX_CHARS, (
        "分片长度超过 CHUNK_MAX_CHARS：长文档被整篇塞进一块（语义被稀释）"
    )
    joined = "".join(chunk.embedding_text for chunk in chunks)
    # 首尾不丢：旧实现的兜底分支是 content[:260]，后半段会被静默丢弃
    assert content[:40] in joined, "文档开头内容丢失"
    assert content[-40:] in joined, "文档结尾内容被截断丢弃"


def test_adjacent_chunks_share_sentence_overlap(ingested):
    """相邻分片整句回退重叠：切断处的上下文在前后两块里都出现一次。

    旧 _split 是「按分号切完按字数凑」，没有任何重叠。
    """
    content = "".join(_sentence(index, 250) for index in range(4))
    _document_id, chunks = ingested(content)
    assert len(chunks) >= 2, f"仅切出 {len(chunks)} 个分片，无法验证重叠"

    for earlier, later in zip(chunks, chunks[1:]):
        tail = earlier.embedding_text[-30:]
        assert tail in later.embedding_text, (
            "相邻分片之间没有整句重叠：切断处的上下文在两块里都不完整"
        )


def test_markdown_headings_become_section_path(ingested):
    """Markdown 标题进入 section_path，且不作为正文混进分片文本。"""
    body = "".join(_sentence(index, 200) for index in range(3))
    content = f"# 部署\n\n## 数据库\n\n{body}\n"
    _document_id, chunks = ingested(content, title="chunk-unified-md")

    assert chunks, "标题文档未产出分片"
    # D1：章节路径的唯一真值源是 knowledge_chunk.section_path **列**
    paths = {chunk.section_path for chunk in chunks}
    assert "部署 > 数据库" in paths, f"section_path 未记录章节路径：{paths}"
    assert all("section_path" not in (chunk.metadata_json or {}) for chunk in chunks), (
        "metadata_json 仍在写 section_path：双真值源又回来了"
    )
    for chunk in chunks:
        assert "部署" not in chunk.embedding_text, "标题行被当成正文塞进了分片文本"


def test_chunk_metadata_keeps_legacy_keys(ingested):
    """字段结构不漂移：ordinal / embedding_text / display_text 与既有键位不变。"""
    _document_id, chunks = ingested(_sentence(0, 300) * 3)
    assert chunks
    for ordinal, chunk in enumerate(chunks):
        assert chunk.ordinal == ordinal
        assert chunk.embedding_text == chunk.display_text
        assert chunk.metadata_json.get("sanitized") is True
        assert "removed" in chunk.metadata_json
        assert "jigsaw_scan" in chunk.metadata_json
