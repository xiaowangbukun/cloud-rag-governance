"""切块模块单测（P1）。

覆盖方案 §3.2 的验收断言：标题层级、不跨章节、重叠正确、代码围栏、空文档、
超长单句硬切不丢内容。
"""

from __future__ import annotations

import pytest

from rg_contracts.knowledge import chunk_markdown
from rg_contracts.knowledge.chunking import CHUNK_OVERLAP_CHARS, CHUNK_TARGET_CHARS


def _join_texts(chunks: list) -> str:
    """把块文本拼回一份（用于「不丢内容」断言）。"""
    return "".join(chunk.text for chunk in chunks)


def _squeeze(text: str) -> str:
    """去掉全部空白字符，只比较语义字符。"""
    return "".join(text.split())


def test_section_path_follows_heading_hierarchy() -> None:
    """① 多级标题生成正确的 section_path，且层级回退时祖先被弹出。"""
    text = (
        "# 1 概述\n\n概述正文。\n\n"
        "## 1.1 范围\n\n范围正文。\n\n"
        "### 1.1.1 名词\n\n名词正文。\n\n"
        "## 1.2 读者\n\n读者正文。\n\n"
        "# 2 部署\n\n部署正文。\n"
    )
    chunks = chunk_markdown(text, target_chars=200, overlap_chars=0, max_chars=400)

    paths = [chunk.section_path for chunk in chunks]
    assert paths == [
        "1 概述",
        "1 概述 > 1.1 范围",
        "1 概述 > 1.1 范围 > 1.1.1 名词",
        "1 概述 > 1.2 读者",
        "2 部署",
    ]
    # 标题行本身不进块正文（否则每个块的向量都被标题词污染一遍）
    assert all(not chunk.text.startswith("#") for chunk in chunks)
    joined = _squeeze(_join_texts(chunks))
    for body in ["概述正文。", "范围正文。", "名词正文。", "读者正文。", "部署正文。"]:
        assert body in joined


def test_chunks_never_cross_sections() -> None:
    """② 不跨章节：同一切块不得同时包含两个章节的关键词。"""
    text = (
        "# 备份\n\n"
        "备份策略采用每日全量加每小时增量，备份文件写入独立磁盘并异地归档。"
        "备份校验必须逐文件比对校验和，避免静默损坏被当作可用备份。\n\n"
        "# 恢复\n\n"
        "恢复演练每季度一次，先恢复到隔离实例再切换流量。"
        "恢复后必须比对行数与关键业务时间戳，确认数据一致才放行。\n"
    )
    chunks = chunk_markdown(text, target_chars=60, overlap_chars=30, max_chars=200)

    assert len(chunks) >= 2
    for chunk in chunks:
        has_backup = "备份" in chunk.text
        has_restore = "恢复" in chunk.text
        assert not (has_backup and has_restore), chunk.text
    # 章节路径与块内关键词必须自洽
    for chunk in chunks:
        if "恢复" in chunk.text:
            assert chunk.section_path == "恢复"
        else:
            assert chunk.section_path == "备份"


def test_adjacent_chunks_overlap_without_duplicating_content() -> None:
    """③ 重叠区存在、是上一块的后缀、且覆盖总长按并集计算。"""
    sentences = [f"第{i}条：处置步骤说明第{i}项，包含命令与判定标准。" for i in range(1, 13)]
    text = "# 处置\n\n" + "".join(sentences) + "\n"
    chunks = chunk_markdown(text, target_chars=80, overlap_chars=30, max_chars=400)

    assert len(chunks) >= 3
    overlaps = 0
    for previous, current in zip(chunks, chunks[1:]):
        assert current.char_start >= previous.char_start
        if current.char_start < previous.char_end:
            overlaps += 1
            # 重叠区文本必须既是上一块的结尾，也是当前块的开头
            shared = text[current.char_start : previous.char_end]
            assert previous.text.endswith(shared)
            assert current.text.startswith(shared)
            assert len(shared) > 0
    assert overlaps >= 1, "相邻块没有产生任何重叠，CHUNK_OVERLAP_CHARS 未生效"

    # 重叠不重复计入：按块长度求和会大于并集长度，并集长度应等于原文该区间长度
    union_start = chunks[0].char_start
    union_end = chunks[-1].char_end
    union = union_end - union_start
    assert union < sum(len(chunk.text) for chunk in chunks)
    assert union <= len(text)


def test_overlap_keeps_whole_sentences() -> None:
    """重叠以整句回退实现：即使超过 overlap 预算，也不切断句子。"""
    text = (
        "# 章节\n\n"
        "第一句比较短。第二句要足够长以至于单独一句就超过重叠预算的字符数限制。"
        "第三句也足够长，用来触发下一个块。第四句收尾。\n"
    )
    chunks = chunk_markdown(text, target_chars=40, overlap_chars=5, max_chars=200)

    assert len(chunks) >= 2
    for previous, current in zip(chunks, chunks[1:]):
        if current.char_start < previous.char_end:
            shared = text[current.char_start : previous.char_end]
            assert shared.endswith("。"), shared
            # 块首必须落在句首，而不是句中标点之后
            assert current.text[0] not in "，。；、）)："


def test_code_fence_hash_is_not_heading() -> None:
    """④ 代码围栏内的 # 不产生章节（Nginx/YAML/Shell 注释都以 # 开头）。"""
    text = (
        "# 部署\n\n"
        "部署步骤见下面的配置片段。\n\n"
        "```bash\n"
        "# 这不是标题\n"
        "systemctl restart nginx\n"
        "```\n\n"
        "## 校验\n\n"
        "执行 curl 校验返回码。\n"
    )
    chunks = chunk_markdown(text, target_chars=400, overlap_chars=0, max_chars=600)

    assert [chunk.section_path for chunk in chunks] == ["部署", "部署 > 校验"]
    joined = _join_texts(chunks)
    assert "# 这不是标题" in joined
    assert all("这不是标题" not in (chunk.section_path or "") for chunk in chunks)


def test_multi_paragraph_code_fence_is_not_sentence_split() -> None:
    """带空行的代码块（nginx/yaml 常见）不得被 `;` / `.` 断句切碎。"""
    text = (
        "# 配置\n\n"
        "```nginx\n"
        "server {\n"
        "    listen 80;\n"
        "\n"
        "    location / { proxy_pass http://app_backend; }\n"
        "}\n"
        "```\n"
    )
    chunks = chunk_markdown(text, target_chars=600, overlap_chars=0, max_chars=1200)

    assert len(chunks) == 1
    assert "listen 80;" in chunks[0].text
    assert "proxy_pass" in chunks[0].text
    assert chunks[0].section_path == "配置"


def test_tilde_code_fence_is_supported() -> None:
    """~~~ 围栏同样屏蔽标题识别。"""
    text = "# 一级\n\n~~~yaml\n# 注释不是标题\nkey: value\n~~~\n\n正文结束。\n"
    chunks = chunk_markdown(text, target_chars=400, overlap_chars=0, max_chars=600)
    assert [chunk.section_path for chunk in chunks] == ["一级"]
    assert "# 注释不是标题" in _join_texts(chunks)


def test_empty_document_returns_no_chunks() -> None:
    """⑤ 空文档 / 纯空白 / 只有标题 → 空列表（不产生空块）。"""
    assert chunk_markdown("") == []
    assert chunk_markdown("   \n\n\t\n") == []
    assert chunk_markdown("# 只有标题\n\n") == []
    assert chunk_markdown("```\n# 只有代码\n```\n") != []


def test_no_chunk_is_blank_or_duplicated() -> None:
    """任何输入下都不产出空白块，也不产出完全重复的块。"""
    text = (
        "# 一\n\n" + "配置项说明。" * 40 + "\n\n# 二\n\n" + "判定标准说明。" * 40 + "\n"
    )
    chunks = chunk_markdown(text)
    assert chunks
    assert all(chunk.text.strip() for chunk in chunks)
    texts = [chunk.text for chunk in chunks]
    assert len(set(texts)) == len(texts), "出现了完全重复的块"
    assert len({chunk.ordinal for chunk in chunks}) == len(chunks)


def test_hard_split_keeps_all_content() -> None:
    """⑥ 超长单句被硬切，且拼接后覆盖原文全部有效字符。"""
    long_sentence = "啊" * 3000 + "。"
    text = "# 长句\n\n" + long_sentence + "\n"
    chunks = chunk_markdown(text, target_chars=100, overlap_chars=20, max_chars=200)

    assert len(chunks) >= 15
    assert all(len(chunk.text) <= 200 for chunk in chunks)
    assert _squeeze(_join_texts(chunks)) == _squeeze(long_sentence)
    assert all(chunk.section_path == "长句" for chunk in chunks)


def test_char_offsets_point_back_to_source() -> None:
    """char_start/char_end 必须能切回完全相同的文本。"""
    text = (
        "# 一 部署\n\n"
        "第一段包含两条要求；第二条要求涉及连接数上限。\n\n"
        "第二段补充说明，长度足够触发装包边界。\n"
    )
    chunks = chunk_markdown(text, target_chars=30, overlap_chars=0, max_chars=200)
    assert chunks
    for chunk in chunks:
        assert text[chunk.char_start : chunk.char_end] == chunk.text


def test_ordinals_are_sequential_and_pdf_fields_are_null() -> None:
    """Markdown 块不带页码，序号从 0 连续递增。"""
    text = "# 一\n\n第一段内容。\n\n第二段内容。\n"
    chunks = chunk_markdown(text, target_chars=10, overlap_chars=0, max_chars=100)
    assert [chunk.ordinal for chunk in chunks] == list(range(len(chunks)))
    assert all(chunk.page_no is None for chunk in chunks)


def test_preamble_without_heading_has_no_section_path() -> None:
    """标题之前的引言没有章节路径，不编造 section_path。"""
    text = "这是文档引言，没有标题。\n\n# 正文\n\n正文内容。\n"
    chunks = chunk_markdown(text, target_chars=50, overlap_chars=0, max_chars=200)
    assert chunks[0].section_path is None
    assert chunks[0].text.startswith("这是文档引言")
    assert chunks[-1].section_path == "正文"


def test_crlf_line_endings_are_supported() -> None:
    """CRLF（Windows 编辑的 Markdown）同样能识别标题、段落与代码围栏。"""
    text = (
        "# 一 部署\r\n"
        "\r\n"
        "第一段内容，包含两条要求。\r\n"
        "\r\n"
        "```bash\r\n"
        "# 注释不是标题\r\n"
        "systemctl restart app\r\n"
        "```\r\n"
        "\r\n"
        "## 1.1 回滚\r\n"
        "\r\n"
        "回滚见下一节。\r\n"
    )
    chunks = chunk_markdown(text, target_chars=20, overlap_chars=0, max_chars=200)

    assert [chunk.section_path for chunk in chunks] == ["一 部署", "一 部署", "一 部署 > 1.1 回滚"]
    assert all("\r" not in (chunk.section_path or "") for chunk in chunks)
    assert "# 注释不是标题" in _join_texts(chunks)
    for chunk in chunks:
        assert text[chunk.char_start : chunk.char_end] == chunk.text


def test_default_params_match_plan() -> None:
    """默认参数与方案一致：600 / 80 / 1200。"""
    assert CHUNK_TARGET_CHARS == 600
    assert CHUNK_OVERLAP_CHARS == 80


@pytest.mark.parametrize(
    ("target", "overlap", "max_chars"),
    [
        (0, 0, 100),
        (100, -1, 200),
        (100, 100, 200),
        (100, 10, 50),
        (100, 10, 0),
    ],
)
def test_invalid_params_raise(target: int, overlap: int, max_chars: int) -> None:
    """非法参数在入口暴露，而不是切出一堆畸形块。"""
    with pytest.raises(ValueError):
        chunk_markdown("正文。", target_chars=target, overlap_chars=overlap, max_chars=max_chars)
