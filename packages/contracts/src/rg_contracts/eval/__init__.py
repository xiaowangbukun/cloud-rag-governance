"""检索质量与授权泄漏评测（P0-2）。

对外只暴露稳定的四件事：题库读取、评估、基线比对、报告版本号。实现细节
（题目的数据结构、逐题结果）留在 :mod:`rg_contracts.eval.rag_baseline`。
"""

from __future__ import annotations

from rg_contracts.eval.rag_baseline import (
    DEFAULT_GOLD_SET,
    GOLD_SET_VERSION,
    MIN_CORPUS_MULTIPLE,
    REPORT_VERSION,
    GoldQuestion,
    compare,
    evaluate,
    load_gold_set,
)

__all__ = [
    "DEFAULT_GOLD_SET",
    "GOLD_SET_VERSION",
    "MIN_CORPUS_MULTIPLE",
    "REPORT_VERSION",
    "GoldQuestion",
    "compare",
    "evaluate",
    "load_gold_set",
]
