"""BM25 关键词检索单测（P2）。"""

from __future__ import annotations

from rg_contracts.ai.bm25 import BM25Index, bm25_scores, tokenize

DOCS = [
    "PostgreSQL 数据库备份恢复与 PITR：使用 pg_basebackup 做全量备份，WAL 归档实现时间点恢复。",
    "Kubernetes Pod 异常排查：Pending 多为资源不足或亲和性冲突；CrashLoopBackOff 看容器日志。",
    "Nginx 反向代理与 502 排查：调大 proxy_read_timeout，并检查 upstream 健康状态。",
    "监控告警处置：CPU 使用率持续高于 90% 需要先定位热点进程，再决定扩容或限流。",
    "安全基线：SSH 禁止 root 直接登录，开启审计日志并定期复核账号权限。",
]


def test_chinese_query_hits_backup_document_first() -> None:
    """① 「数据库 备份」应命中含「数据库备份恢复」的文档且排名第一。"""
    index = BM25Index(DOCS)
    ranked = index.rank("数据库 备份")

    assert ranked, "中文查询未命中任何文档"
    top_index, top_score = ranked[0]
    assert top_index == 0
    assert "数据库备份恢复" in DOCS[top_index]
    assert top_score > 0
    # 其他文档不应比正确答案分更高
    assert all(score < top_score for position, score in ranked[1:] if position != 0)


def test_exact_config_key_is_matched() -> None:
    """② 精确串 max_connections 命中配置文档（ASCII 词整体保留）。"""
    docs = [
        "PostgreSQL 参数调优：max_connections 与 shared_buffers 需要按内存配比设置。",
        "Nginx 与 PostgreSQL 无关的说明文档，只讨论前端静态资源缓存。",
        "重启服务的标准操作流程与回滚步骤。",
    ]
    scores = bm25_scores("max_connections", docs)

    assert scores[0] > 0
    assert scores[1] == 0
    assert scores[2] == 0
    assert scores[0] == max(scores)


def test_error_code_case_insensitive() -> None:
    """错误码大小写不敏感：OOMKilled → oomkilled。"""
    docs = [
        "Pod 状态 OOMKilled 说明容器内存超过 limit 被 kubelet 杀掉。",
        "Pod Pending 表示调度器找不到可满足资源请求的节点。",
    ]
    assert bm25_scores("oomkilled", docs)[0] > 0
    assert bm25_scores("OOMKilled", docs)[0] > 0
    assert bm25_scores("OOMKilled", docs)[1] == 0


def test_unrelated_docs_score_zero() -> None:
    """③ 完全不含查询词项的文档得 0（不靠向量相似度的「柔和」分数兜底）。"""
    docs = [
        "磁盘使用率告警：inode 耗尽会让 touch 失败，先用 df -i 确认再清理日志。",
        "Kubernetes Pod 异常排查：Pending 多为资源不足或亲和性冲突。",
        "Nginx 反向代理与 502 排查：调大 proxy_read_timeout。",
    ]
    scores = bm25_scores("磁盘 inode 耗尽", docs)

    assert scores[0] > 0
    assert scores[1] == 0
    assert scores[2] == 0


def test_common_word_scores_lower_than_specific_word() -> None:
    """泛词（排查）的 IDF 低于专有词，得分显著更低。"""
    docs = [
        "磁盘 inode 耗尽排查：先 df -i 看 inode 使用率。",
        "网络排查：先用 ping 与 mtr 定位丢包方向。",
    ]
    specific = bm25_scores("inode 耗尽", docs)
    common = bm25_scores("排查", docs)

    assert specific[0] > 0
    assert specific[1] == 0
    assert common[0] > 0 and common[1] > 0
    assert common[1] < specific[0] * 3


def test_empty_query_returns_all_zeros() -> None:
    """④ 空查询 / 纯空白查询返回全 0，不抛异常。"""
    index = BM25Index(DOCS)
    assert index.score("") == [0.0] * len(DOCS)
    assert index.score("   \n\t ") == [0.0] * len(DOCS)
    assert index.rank("") == []


def test_empty_corpus_returns_empty_scores() -> None:
    """空候选集（授权过滤后没剩下分片）返回空列表，不抛异常。"""
    index = BM25Index([])
    assert len(index) == 0
    assert index.score("数据库") == []
    assert index.rank("数据库") == []


def test_scores_align_with_docs() -> None:
    """分数列表长度与文档数严格对齐（融合层按位置取 chunk_id）。"""
    index = BM25Index(DOCS)
    scores = index.score("Pod Pending 排查")
    assert len(scores) == len(DOCS)
    assert scores[1] > 0


def test_rank_excludes_zero_scores_and_sorts() -> None:
    """rank 只返回命中项且按分数降序，便于 RRF 融合直接使用。"""
    index = BM25Index(DOCS)
    ranked = index.rank("Nginx upstream 502", limit=2)
    assert ranked
    assert ranked[0][0] == 2
    assert all(score > 0 for _, score in ranked)
    assert [score for _, score in ranked] == sorted(
        (score for _, score in ranked), reverse=True
    )
    assert len(ranked) <= 2


def test_tokenize_keeps_ascii_shapes_and_cjk_bigrams() -> None:
    """分词：ASCII 词整体保留，中文出 bigram 与单字。"""
    tokens = tokenize("OOMKilled max_connections 数据库")
    assert "oomkilled" in tokens
    assert "max_connections" in tokens
    assert "数据" in tokens and "据库" in tokens
    assert "数" in tokens  # 单字兜底，保证单字/短查询仍可召回


def test_tokenize_strips_trailing_dot() -> None:
    """句末句号不粘进 token（否则 "restart." 与 "restart" 不相等）。"""
    assert "restart" in tokenize("restart the service.")
    assert "restart." not in tokenize("restart the service.")


def test_single_char_query_still_matches() -> None:
    """单字查询靠单字索引命中（bigram 对单字无解）。"""
    assert bm25_scores("盘", ["磁盘空间不足时需要清理日志分区。"])[0] > 0


def test_term_frequency_saturation() -> None:
    """同一词重复出现带来的增益递减：100 次不应是 2 次的 50 倍。"""
    docs = ["错误码 E1001 出现。", "错误码 E1001 出现。" * 100]
    scores = bm25_scores("E1001", docs)
    assert scores[1] > scores[0]
    assert scores[1] < scores[0] * 3


def test_longer_document_is_penalized() -> None:
    """长度归一化生效：同样命中一次，长文档得分更低。"""
    short = "max_connections 需要调大。"
    long = "max_connections 需要调大。" + "无关的说明文字。" * 60
    scores = bm25_scores("max_connections", [short, long])
    assert scores[0] > scores[1] > 0
