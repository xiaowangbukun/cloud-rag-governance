"""BM25 关键词检索（P2）。

为什么自实现、不用 ``jieba`` / ``rank_bm25``：

* **可移植性**：交付环境是信创离线集群，装包成本高；分词器（jieba）依赖词典文件
  与运行期状态，在国产库/国产 OS 的镜像里最容易出现「开发机好用、客户现场装不上」。
  纯标准库实现可以保证「拷走源码就能跑」。
* **中文无词典分词**：中文用 **bigram**。没有词典就不会 OOV，对「数据库备份恢复」
  这类复合词，``数据/据库/备份/恢复`` 四个二元组足以命中；同时保留 **单字**，
  让「库」「盘」这类单字/短查询仍能召回（bigram 对单字查询无解）。
  代价是索引体积约翻倍、单字 IDF 偏低 —— 由 IDF 自然压制，不需要额外加权。
* **保留错误码/配置键形态**：ASCII 词按 ``[a-z0-9][a-z0-9_.-]*`` 小写化后整体保留，
  于是 ``OOMKilled`` → ``oomkilled``、``max_connections`` 原样命中。
  运维问答里「精确串」常常就是答案本身（配置项名、错误码、信号量），
  把它们切成字符 n-gram 会显著降低精确率。

安全约束（调用方责任，见方案 §4.1）：IDF 只在**传入的文档集合内**统计，
该集合必须是已按密级/项目过滤后的授权候选集。本模块不认识权限，
也绝不应当被喂入全库数据。
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Sequence

#: BM25 词频饱和参数：越大越接近「词频线性累加」。
DEFAULT_K1 = 1.5
#: BM25 文档长度归一化强度：0 = 不归一化，1 = 完全归一化。
DEFAULT_B = 0.75

#: ASCII/数字词：允许中缀 ``.`` ``_`` ``-``（配置键、错误码、版本号、域名）。
#: 首字符不允许是分隔符，避免把句末句号粘进词里。
_ASCII_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.\-]*")
#: CJK 连续片段（基本区 + 扩展 A + 兼容区）。
_CJK_RUN_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]+")


def tokenize(text: str) -> list[str]:
    """分词：ASCII 词 + 中文 bigram + 中文单字。

    Args:
        text: 任意文本（大小写不敏感）。

    Returns:
        token 列表（含重复，供词频统计）。空输入返回空列表，不抛异常。
    """
    if not text:
        return []
    lowered = text.lower()
    tokens: list[str] = []
    for match in _ASCII_TOKEN_RE.finditer(lowered):
        word = match.group(0).rstrip(".-")
        if word:
            tokens.append(word)
    for match in _CJK_RUN_RE.finditer(lowered):
        run = match.group(0)
        # 单字：短查询与单字查询的召回保底
        tokens.extend(run)
        # bigram：中文的主要语义单元
        tokens.extend(run[index : index + 2] for index in range(len(run) - 1))
    return tokens


class BM25Index:
    """在给定文档集合上构建的 BM25 索引。

    每次检索都重建索引是刻意选择：候选集上限只有 ``RAG_CANDIDATE_LIMIT``（默认 500），
    建索引是 O(候选集 token 数)，比维护一个与数据库状态同步的持久化倒排索引简单得多，
    也不会出现「索引与分片不一致」这类难查的问题。

    Attributes:
        k1: 词频饱和参数。
        b: 长度归一化强度。
    """

    def __init__(
        self,
        docs: Sequence[str],
        *,
        k1: float = DEFAULT_K1,
        b: float = DEFAULT_B,
    ) -> None:
        self.k1 = k1
        self.b = b
        self._docs: list[str] = list(docs)
        self._term_freqs: list[Counter[str]] = []
        self._lengths: list[int] = []
        document_freq: Counter[str] = Counter()
        for doc in self._docs:
            tokens = tokenize(doc)
            term_freq = Counter(tokens)
            self._term_freqs.append(term_freq)
            self._lengths.append(len(tokens))
            document_freq.update(term_freq.keys())
        self._doc_count = len(self._docs)
        self._avg_length = (
            sum(self._lengths) / self._doc_count if self._doc_count else 0.0
        )
        # Lucene 形式的 IDF：log(1 + (N - df + 0.5) / (df + 0.5))，
        # 恒为正数 —— 避免经典 BM25 里「高频词 IDF 为负 → 命中反而扣分」的坑。
        self._idf: dict[str, float] = {
            term: math.log(1.0 + (self._doc_count - freq + 0.5) / (freq + 0.5))
            for term, freq in document_freq.items()
        }

    def __len__(self) -> int:
        return self._doc_count

    def score(self, query: str) -> list[float]:
        """计算查询对每个文档的 BM25 分数（与构造时的 ``docs`` 一一对齐）。

        Args:
            query: 查询串。空串/纯空白返回全 0。

        Returns:
            与文档数等长的分数列表；无文档或空查询时全为 0，不抛异常。
        """
        if self._doc_count == 0:
            return []
        if not query or not query.strip():
            return [0.0] * self._doc_count
        # 去重保序：BM25 的查询词项按「项」累加，同一项重复出现不应重复计分。
        terms = list(dict.fromkeys(tokenize(query)))
        if not terms:
            return [0.0] * self._doc_count

        scores: list[float] = []
        for term_freq, length in zip(self._term_freqs, self._lengths):
            length_norm = length / self._avg_length if self._avg_length else 0.0
            saturation = self.k1 * (1.0 - self.b + self.b * length_norm)
            total = 0.0
            for term in terms:
                freq = term_freq.get(term, 0)
                if not freq:
                    continue
                idf = self._idf.get(term, 0.0)
                total += idf * (freq * (self.k1 + 1.0)) / (freq + saturation)
            scores.append(total)
        return scores

    def rank(self, query: str, *, limit: int | None = None) -> list[tuple[int, float]]:
        """按分数降序返回 ``(文档下标, 分数)``，便于融合层直接消费。

        分数为 0 的文档不返回（关键词路径没有命中就是没有命中，让融合层拿到
        一堆 0 分只会在归一化后摊薄真实命中的权重）。当前融合层走
        ``score()`` 取全量分数再自行归一化，``rank()`` 供需要名次的场景使用。
        """
        scores = self.score(query)
        ranked = [
            (index, value) for index, value in enumerate(scores) if value > 0.0
        ]
        ranked.sort(key=lambda item: (-item[1], item[0]))
        if limit is not None and limit >= 0:
            return ranked[:limit]
        return ranked


def bm25_scores(
    query: str,
    docs: Sequence[str],
    *,
    k1: float = DEFAULT_K1,
    b: float = DEFAULT_B,
) -> list[float]:
    """一次性打分便捷入口（内部构建临时索引）。"""
    return BM25Index(docs, k1=k1, b=b).score(query)


__all__ = [
    "DEFAULT_B",
    "DEFAULT_K1",
    "BM25Index",
    "bm25_scores",
    "tokenize",
]
