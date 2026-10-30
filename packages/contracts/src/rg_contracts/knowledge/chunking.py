"""标题感知切块（P1）。

设计目标（见 ``docs/kb-alignment-plan.md`` §3.2）：

1. **保留结构**：Markdown 标题按层级维护标题栈，生成 ``section_path``
   （如 ``3 部署 > 3.2 数据库``）。代码围栏（``` / ~~~）内的 ``#`` 是注释
   而不是标题 —— 否则一段 Nginx/YAML 配置就能把章节树带偏。
2. **块内语义完整**：先按空行切段落，再按句末标点切句，最后贪心装包到
   ``CHUNK_TARGET_CHARS``。块边界永远落在句末，不落在句中标点之后，
   避免「半句话」进入向量库（半句的向量既检索不准，也无法被人复核）。
3. **不跨章节**：章节是语义硬边界。跨章节的块会把「部署」和「回滚」两类
   语义混进同一向量，检索时两边都不准。
4. **相邻块重叠**：``CHUNK_OVERLAP_CHARS`` 用「整句回退」实现，而不是字符截断。
   字符截断必然产生半句块首；整句回退既保住块首语义，又让被切断处的上下文
   在前后两块里都出现一次。
5. **可追溯**：每个块记录 ``char_start`` / ``char_end``（原文偏移）与
   ``page_no``（PDF），回答引用才能定位到「文档 + 章节 + 页码 + 字符区间」。

本模块是纯函数：参数全部走函数入参（不读全局 settings），便于单测覆盖边界，
也便于后续把这些参数接到配置中心而不改调用点。
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

# --------------------------------------------------------------------------- 默认参数
#: 单个块的目标字符数。600 字约等于中文 300~400 token，既够放一整段处置步骤，
#: 又不至于让 embedding 的语义被稀释（超长文本的向量倾向于「什么都像」）。
CHUNK_TARGET_CHARS = 600
#: 相邻块的重叠字符预算。80 字足够覆盖一个完整短句，避免上下文在边界处断开。
#: 注意这是**预算**不是硬上限：重叠以「整句回退」实现，最后一句若超过预算，
#: 仍然整句重复（宁可多重复一句，也不要在块首留半句）。
CHUNK_OVERLAP_CHARS = 80
#: 单个片段（一句/一段）的硬上限。超过它才允许在中途硬切；
#: 这是兜底手段而不是常规路径 —— 常规块长由 target 控制。
CHUNK_MAX_CHARS = 1200

#: Markdown ATX 标题：``#{1,6} 标题``（允许行首缩进，规范允许最多 3 个空格）。
_HEADING_RE = re.compile(r"^(#{1,6})[ \t]+(.+?)[ \t]*#*[ \t]*$")
#: 段落分隔：一个空行（允许空行里只有空白字符）。
#: ``\r?\n`` 兼容 CRLF —— Windows 上编辑的 Markdown 上传后普遍是 CRLF，
#: 若只认 ``\n``，整篇会被当成一个段落，代码块与表格的边界全部失效。
_PARAGRAPH_SEP_RE = re.compile(r"\r?\n[ \t]*\r?\n")
#: 句末标点。中文标点无条件断句；ASCII 的 ``.!?`` 只在后接空白/结尾时断句，
#: 否则 ``3.2 数据库``、``v1.2.3``、``config.yaml`` 会被切碎。
_SENTENCE_BOUNDARY_RE = re.compile(r"[。！？；]|[.!?](?=[\s\"'”’）)]|$)")
#: 断句后可能紧跟的收尾符号，应并入前一句而不是留在下一句开头。
_CLOSERS = "”’\"'）)】」』》"
#: PDF 页内编号型标题启发式：``3.2 数据库`` / ``4 备份恢复``。
_PDF_HEADING_RE = re.compile(r"^\d+(?:\.\d+)*[ \t\u3000]+\S")
#: 编号型标题的最大长度。超过这个长度更像「以数字开头的正文」（如日期行），
#: 不当标题，避免把正文首行误认成章节。
_PDF_HEADING_MAX_CHARS = 40
#: ``section_path`` 列宽 512，超出即截断（不静默丢字段，只是不再增长）。
_SECTION_PATH_MAX_CHARS = 512
#: 硬切时允许回退找空白的比例：最多回退窗口的 1/5，尽量不切在单词中间。
_HARD_SPLIT_BACKTRACK_RATIO = 5


@dataclass(slots=True)
class ChunkDraft:
    """一个待入库的切块草稿（尚未净化、尚未向量化）。

    Attributes:
        text: 块文本。Markdown 块不含标题行（标题已进 ``section_path``）；
            PDF 块含页内首行（PDF 页首行常是唯一的章节线索，保留有利于召回）。
        section_path: 章节路径，如 ``3 部署 > 3.2 数据库``；无章节结构时为 None。
        page_no: PDF 页码（从 1 起）；Markdown / 纯文本为 None。
        char_start: 原文起始偏移（Markdown 为全文偏移，PDF 为页内偏移）。
        char_end: 原文结束偏移（开区间右端，即 ``text[char_start:char_end]``）。
        ordinal: 文档内序号，从 0 起，与 ``knowledge_chunk.ordinal`` 对齐。
    """

    text: str
    section_path: str | None
    page_no: int | None
    char_start: int
    char_end: int
    ordinal: int


@dataclass(slots=True)
class PageText:
    """PDF 单页文本。

    Attributes:
        page_no: 页码，从 1 起（与 PDF 阅读器显示的页码一致）。
        text: 该页抽取出的文本，可能为空字符串（空白页）。
    """

    page_no: int
    text: str


@dataclass(slots=True)
class _Section:
    """章节：标题行之后的正文区间（标题行本身不计入正文）。"""

    section_path: str | None
    body_start: int
    body_end: int


# --------------------------------------------------------------------------- 公共入口
def chunk_markdown(
    text: str,
    *,
    target_chars: int = CHUNK_TARGET_CHARS,
    overlap_chars: int = CHUNK_OVERLAP_CHARS,
    max_chars: int = CHUNK_MAX_CHARS,
) -> list[ChunkDraft]:
    """把 Markdown 文本切成标题感知的块。

    Args:
        text: 原始 Markdown 文本（可为空）。
        target_chars: 单块目标字符数，须为正整数。
        overlap_chars: 相邻块的重叠字符预算，须为非负整数。
        max_chars: 单片段硬上限，须为正整数且不小于 ``target_chars``。

    Returns:
        按原文顺序排列的块草稿；空文档或纯空白文档返回空列表。

    Raises:
        ValueError: 参数非法（目标长度为 0、重叠大于目标等）。
    """
    _validate_params(target_chars, overlap_chars, max_chars)
    if not text or not text.strip():
        return []

    drafts: list[ChunkDraft] = []
    ordinal = 0
    for section in _split_sections(text):
        spans = _fragment_spans(text, section.body_start, section.body_end, max_chars)
        if not spans:
            continue
        for span_start, span_end in _pack_spans(
            spans, target_chars=target_chars, overlap_chars=overlap_chars
        ):
            chunk_text = text[span_start:span_end]
            if not chunk_text.strip():
                continue
            drafts.append(
                ChunkDraft(
                    text=chunk_text,
                    section_path=section.section_path,
                    page_no=None,
                    char_start=span_start,
                    char_end=span_end,
                    ordinal=ordinal,
                )
            )
            ordinal += 1
    return drafts


def chunk_pdf(
    pages: Sequence[PageText],
    *,
    target_chars: int = CHUNK_TARGET_CHARS,
    overlap_chars: int = CHUNK_OVERLAP_CHARS,
    max_chars: int = CHUNK_MAX_CHARS,
) -> list[ChunkDraft]:
    """把 PDF 逐页文本切成块，每块携带页码。

    PDF 没有可靠的标题树，所以这里退化为两条约束：

    * **页是硬边界**：绝不把两页的文字拼进同一块。跨页拼接会把页眉/页脚/
      页码混进正文，也会让 ``page_no`` 失去意义。
    * **页内首行启发式识别章节**：形如 ``3.2 数据库`` 的短行视为编号型标题，
      写入 ``section_path``；识别不到就是 None（不编造）。

    Args:
        pages: 逐页文本，``page_no`` 从 1 起。
        target_chars: 单块目标字符数。
        overlap_chars: 页内相邻块的重叠字符预算。
        max_chars: 单片段硬上限。

    Returns:
        按页序、页内顺序排列的块草稿；全空输入返回空列表。
    """
    _validate_params(target_chars, overlap_chars, max_chars)
    drafts: list[ChunkDraft] = []
    ordinal = 0
    for page in pages:
        page_text = page.text or ""
        if not page_text.strip():
            continue
        section_path = _pdf_section_path(page_text)
        spans = _fragment_spans(page_text, 0, len(page_text), max_chars)
        for span_start, span_end in _pack_spans(
            spans, target_chars=target_chars, overlap_chars=overlap_chars
        ):
            chunk_text = page_text[span_start:span_end]
            if not chunk_text.strip():
                continue
            drafts.append(
                ChunkDraft(
                    text=chunk_text,
                    section_path=section_path,
                    page_no=page.page_no,
                    char_start=span_start,
                    char_end=span_end,
                    ordinal=ordinal,
                )
            )
            ordinal += 1
    return drafts


# ------------------------------------------------------------------------ 参数校验
def _validate_params(target_chars: int, overlap_chars: int, max_chars: int) -> None:
    """校验切块参数。配置错误必须在入口暴露，不能切出一堆 0 长度块。"""
    if target_chars <= 0:
        raise ValueError(f"target_chars 必须为正整数，当前值 {target_chars}")
    if max_chars <= 0:
        raise ValueError(f"max_chars 必须为正整数，当前值 {max_chars}")
    if overlap_chars < 0:
        raise ValueError(f"overlap_chars 必须为非负整数，当前值 {overlap_chars}")
    if overlap_chars >= target_chars:
        raise ValueError(
            f"overlap_chars({overlap_chars}) 必须小于 target_chars({target_chars})，"
            "否则每块都在重复上一块，切块不前进"
        )
    if max_chars < target_chars:
        raise ValueError(
            f"max_chars({max_chars}) 不能小于 target_chars({target_chars})，"
            "否则硬切上限比目标块长还小，聚包永远达不到目标"
        )


# -------------------------------------------------------------------------- 分节
def _iter_lines(text: str) -> Iterable[tuple[int, int, str]]:
    """按行遍历，产出 ``(行起始偏移, 行结束偏移, 行文本)``。"""
    pos = 0
    length = len(text)
    while pos <= length:
        newline = text.find("\n", pos)
        if newline < 0:
            yield pos, length, text[pos:length]
            return
        yield pos, newline, text[pos:newline]
        pos = newline + 1


def _is_fence_marker(line: str) -> str | None:
    """判断是否为代码围栏标记行，返回围栏字符（````` 或 ``~``）。"""
    stripped = line.strip()
    if stripped.startswith("```"):
        return "`"
    if stripped.startswith("~~~"):
        return "~"
    return None


def _split_sections(text: str) -> list[_Section]:
    """按 Markdown 标题把文本切成章节，并生成标题栈路径。

    代码围栏内的 ``#`` 不参与标题识别（Nginx 注释、YAML 注释、Shell 注释
    都以 ``#`` 开头，误判会把章节树彻底带偏）。
    """
    sections: list[_Section] = []
    # 标题栈：(级别, 标题文本)。级别从 1 起，新标题会弹出级别 >= 自身的栈顶。
    stack: list[tuple[int, str]] = []
    current_path: str | None = None
    body_start = 0
    fence: str | None = None

    for line_start, line_end, line in _iter_lines(text):
        marker = _is_fence_marker(line)
        if fence is not None:
            # 围栏内：只有同种围栏字符能关闭它，行内内容一律视为正文。
            if marker == fence:
                fence = None
            continue
        if marker is not None:
            fence = marker
            continue

        match = _HEADING_RE.match(line.lstrip())
        if match is None:
            continue

        level = len(match.group(1))
        title = match.group(2).strip()
        if not title:
            continue
        # 关闭上一章节：正文截止到标题行之前（不含标题行自身）。
        sections.append(_Section(current_path, body_start, line_start))
        # 维护标题栈：弹出级别不低于当前标题的项，再把当前标题压栈。
        while stack and stack[-1][0] >= level:
            stack.pop()
        stack.append((level, title))
        current_path = _truncate_section_path(" > ".join(item[1] for item in stack))
        body_start = line_end + 1

    sections.append(_Section(current_path, body_start, len(text)))
    return [section for section in sections if section.body_end > section.body_start]


def _truncate_section_path(path: str) -> str:
    """按列宽截断章节路径（``section_path`` 列为 512）。"""
    if len(path) <= _SECTION_PATH_MAX_CHARS:
        return path
    return path[:_SECTION_PATH_MAX_CHARS]


def _pdf_section_path(page_text: str) -> str | None:
    """从 PDF 页首行启发式识别编号型章节标题。"""
    for line in page_text.splitlines():
        stripped = line.strip().lstrip("\u3000")
        if not stripped:
            continue
        if len(stripped) > _PDF_HEADING_MAX_CHARS:
            return None
        if _PDF_HEADING_RE.match(stripped):
            return _truncate_section_path(stripped)
        return None
    return None


# -------------------------------------------------------------------- 段落/句子切片
def _trim(text: str, start: int, end: int) -> tuple[int, int] | None:
    """去掉区间两端的空白，返回新的半开区间；全空白返回 None。"""
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    if end <= start:
        return None
    return start, end


def _scan_fence(fence: str | None, paragraph: str) -> tuple[bool, str | None]:
    """扫描段落内的围栏标记，返回 ``(本段是否属于代码块, 段落结束时的围栏状态)``。

    含围栏的段落（代码块）不参与断句：配置片段里的 ``;`` / ``.`` 断句只会
    把一段可执行配置切碎，语义反而更差。**段落起始已处于围栏内时同样算代码块**
    —— 一个带空行的 nginx/YAML 配置会跨越多个「段落」，只按围栏标记行判断会让
    围栏内部的后续段落被当成正文断句。
    """
    involved = fence is not None
    state = fence
    for line in paragraph.splitlines():
        marker = _is_fence_marker(line)
        if marker is None:
            continue
        involved = True
        if state is None:
            state = marker
        elif state == marker:
            state = None
    return involved, state


def _paragraph_spans(text: str, start: int, end: int) -> list[tuple[int, int]]:
    """按空行切段落，返回段落区间（已去掉两端空白）。"""
    spans: list[tuple[int, int]] = []
    cursor = start
    for match in _PARAGRAPH_SEP_RE.finditer(text, start, end):
        span = _trim(text, cursor, match.start())
        if span is not None:
            spans.append(span)
        cursor = match.end()
    tail = _trim(text, cursor, end)
    if tail is not None:
        spans.append(tail)
    return spans


def _sentence_spans(text: str, start: int, end: int) -> list[tuple[int, int]]:
    """按句末标点切句，返回句区间（已去掉两端空白）。"""
    spans: list[tuple[int, int]] = []
    cursor = start
    for match in _SENTENCE_BOUNDARY_RE.finditer(text, start, end):
        boundary = match.end()
        # 把紧跟的收尾引号/括号并入本句，避免下一块以标点开头。
        while boundary < end and text[boundary] in _CLOSERS:
            boundary += 1
        span = _trim(text, cursor, boundary)
        if span is not None:
            spans.append(span)
        cursor = boundary
    tail = _trim(text, cursor, end)
    if tail is not None:
        spans.append(tail)
    return spans


def _hard_split(text: str, start: int, end: int, limit: int) -> list[tuple[int, int]]:
    """把超过 ``limit`` 的单个片段硬切成多段（尽量切在空白处）。"""
    spans: list[tuple[int, int]] = []
    cursor = start
    while end - cursor > limit:
        cut = cursor + limit
        backtrack_floor = max(cursor + 1, cut - max(1, limit // _HARD_SPLIT_BACKTRACK_RATIO))
        probe = cut
        while probe > backtrack_floor and not text[probe].isspace():
            probe -= 1
        if probe > backtrack_floor:
            cut = probe
        span = _trim(text, cursor, cut)
        if span is not None:
            spans.append(span)
        cursor = cut
        while cursor < end and text[cursor].isspace():
            cursor += 1
    tail = _trim(text, cursor, end)
    if tail is not None:
        spans.append(tail)
    return spans


def _fragment_spans(
    text: str,
    start: int,
    end: int,
    max_chars: int,
) -> list[tuple[int, int]]:
    """把区间切成「可装包的最小片段」序列（段落 → 句子 → 超长硬切）。"""
    spans: list[tuple[int, int]] = []
    fence: str | None = None
    for para_start, para_end in _paragraph_spans(text, start, end):
        paragraph = text[para_start:para_end]
        involved, fence = _scan_fence(fence, paragraph)
        if involved:
            # 代码块（含带空行的多段配置）整体作为一个片段，不再断句。
            spans.append((para_start, para_end))
            continue
        for sentence_start, sentence_end in _sentence_spans(text, para_start, para_end):
            if sentence_end - sentence_start > max_chars:
                spans.extend(_hard_split(text, sentence_start, sentence_end, max_chars))
            else:
                spans.append((sentence_start, sentence_end))
    return spans


# ---------------------------------------------------------------------------- 聚包
def _pack_spans(
    spans: Sequence[tuple[int, int]],
    *,
    target_chars: int,
    overlap_chars: int,
) -> list[tuple[int, int]]:
    """贪心装包：按顺序塞片段直到超过 ``target_chars``，相邻块整句回退重叠。

    不变量：
    * 每块非空，且块序严格前进（``prev_end`` 单调递增）—— 重叠不会导致原地打转。
    * 每块至少包含一个「上一块没包含过」的片段 —— 不产出纯重复块。
    """
    total = len(spans)
    chunks: list[tuple[int, int]] = []
    index = 0
    previous_end = 0  # 上一块的片段结束下标（开区间）
    while index < total:
        chunk_start_index = index
        chunk_start, chunk_end = spans[index]
        index += 1
        while index < total:
            # 必须越过上一块的覆盖范围，保证本块有新增内容；
            # 否则「重叠片段单独成块」，内容零增量且会打断后续装包。
            if index <= previous_end or spans[index][1] - chunk_start <= target_chars:
                chunk_end = spans[index][1]
                index += 1
                continue
            break
        chunks.append((chunk_start, chunk_end))
        previous_end = index
        if index >= total:
            break
        # 整句回退：从尾部向前扩，直到重叠预算用尽。
        next_index = index
        if index - chunk_start_index >= 2:
            next_index = index - 1
            while (
                next_index - 1 > chunk_start_index
                and chunk_end - spans[next_index - 1][0] <= overlap_chars
            ):
                next_index -= 1
            index = next_index
    return chunks


__all__ = [
    "CHUNK_MAX_CHARS",
    "CHUNK_OVERLAP_CHARS",
    "CHUNK_TARGET_CHARS",
    "ChunkDraft",
    "PageText",
    "chunk_markdown",
    "chunk_pdf",
]
