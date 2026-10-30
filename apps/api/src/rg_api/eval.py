"""检索评测命令：``python -m rg_api.eval``。

用途有三层，对应 P0-2 的验收口径：

1. **安全闸门**：任一「越权题」返回了不该返回的事实 → 退出码 2。这是把
   "检索只返回授权分片"从设计声明变成可执行断言的地方。
2. **回归基线**：``--write`` 落盘一份报告，之后 ``--compare`` 与它比对，
   召回（``recall@3/8``、``MRR@10``）或拒答率变差 → 退出码 3。
3. **决策级门禁**：``--require-decision-grade`` 时，若报告自报
   ``decision_grade.recall=false``（离线向量、语料太小、缺项目维度题）→ 退出码 4。
   默认**不**开启，因为当前环境用离线降级向量。它的意义是：等真实 embedding
   服务就位时，把这条开关一开，门禁就从"没变差"升级为"数字可信"。

环境要求：需要已建库并跑过种子（``DEMO_SEED=true`` 或
``python -m rg_api.seed``），金标准引用的文档标题来自种子的 ``KNOWLEDGE_DOCS``。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rg_contracts.config import Settings, get_settings
from rg_contracts.db.models import User
from rg_contracts.db.session import session_scope
from rg_contracts.eval import DEFAULT_GOLD_SET, compare, evaluate, load_gold_set
from sqlalchemy import select

from rg_api.routes.auth import _load_subject
from rg_api.startup import backfill_embeddings

EXIT_OK = 0
EXIT_SECURITY_FAIL = 2
EXIT_REGRESSION = 3
#: 报告自报"数字不可信"（离线向量 / 语料太小 / 缺维度题）。单列一个码，
#: 是为了让 CI 能把「不安全」和「不可信」区分开，不混成一个笼统的失败。
EXIT_NOT_DECISION_GRADE = 4


def _build_subjects(session, keys: set[str]) -> dict:
    """金标准里的 ``subject`` 是主体标识的本地部分（``viewer`` ↔ ``viewer@corp.local``）。

    为什么不按角色选人：同一角色下会有多个账号（如 ``usr_alice`` 与 ``usr_viewer``
    都是 viewer），按角色选会让基线随数据变动而漂移；按主体标识选才是稳定锚点。
    """
    subjects = {}
    for key in sorted(keys):
        user = session.execute(
            select(User).where(User.subject.like(f"{key}@%")).limit(1)
        ).scalar_one_or_none()
        if user is not None:
            subjects[key] = _load_subject(session, user)
    return subjects


def _summarise(report: dict) -> str:
    metrics = report["metrics"]
    config = report["config"]
    corpus = report["corpus"]
    lines = [
        f"hybrid={config['hybrid']} alpha={config['hybrid_alpha']} "
        f"embedding={config['embedding_backend']}({config['embedding_model']}) top_k={config['top_k']}",
        f"corpus: {corpus['documents']} 文档 / {corpus['chunks']} 分片"
        + f"（项目内 {corpus.get('project_chunks', 0)}，决策级下限 {corpus.get('min_for_decision_grade', '?')}）"
        + ("（⚠ 语料 ≤ top_k，recall 饱和）" if corpus["saturated"] else ""),
        f"questions: {metrics['questions']}"
        f"（正向 {metrics['positive_questions']} / 越权 {metrics['refusal_questions']}）",
        f"recall@3={metrics['recall_at_3']} recall@8={metrics['recall_at_8']} "
        f"mrr@10={metrics['mrr_at_10']}",
        f"unauthorized_leak_rate={metrics['unauthorized_leak_rate']} "
        f"({metrics['leaked_hits']}/{metrics['total_hits']}) "
        f"refusal_accuracy={metrics['refusal_accuracy']}",
    ]
    if not report["decision_grade"]["recall"]:
        lines.append("recall 非决策级：" + "；".join(report["decision_grade"]["reasons"]))
    slices = report.get("slices")
    if slices:
        global_slice = slices.get("global", {})
        project_slice = slices.get("project", {})
        lines.append(
            f"slices: 全局 {global_slice.get('questions', 0)} 题 "
            f"recall@8={global_slice.get('recall_at_8')} 命中率={global_slice.get('hit_rate')} | "
            f"项目内 {project_slice.get('questions', 0)} 题 "
            f"recall@8={project_slice.get('recall_at_8')} 命中率={project_slice.get('hit_rate')}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None, settings: Settings | None = None) -> int:
    parser = argparse.ArgumentParser(description="检索质量与授权泄漏评测（P0-2）")
    parser.add_argument("--gold", default=str(DEFAULT_GOLD_SET), help="金标准 JSON 路径")
    parser.add_argument("--write", help="把本次报告写入该路径（作为基线）")
    parser.add_argument("--compare", help="与该基线报告比对，变差则退出码 3")
    parser.add_argument("--hybrid", dest="hybrid", action="store_true", help="强制开启混合检索")
    parser.add_argument("--no-hybrid", dest="hybrid", action="store_false", help="强制关闭混合检索")
    parser.set_defaults(hybrid=None)
    parser.add_argument("--json", action="store_true", help="输出完整报告 JSON")
    parser.add_argument(
        "--require-decision-grade",
        dest="require_decision_grade",
        action="store_true",
        help="要求报告达到决策级（真实 embedding + 语料足够大 + 含项目维度题），否则退出码 4",
    )
    parser.add_argument(
        "--no-backfill",
        dest="backfill",
        action="store_false",
        default=True,
        help="不补算缺失的向量（默认补齐；种子分片没有向量时检索会 0 命中）",
    )
    args = parser.parse_args(argv)

    settings = settings or get_settings()
    questions = load_gold_set(args.gold)
    keys = {question.subject for question in questions}

    with session_scope() as session:
        subjects = _build_subjects(session, keys)
        missing = keys - set(subjects)
        if missing:
            print(f"缺主体（先跑种子？）：{sorted(missing)}", file=sys.stderr)
            return EXIT_SECURITY_FAIL
        # 种子里只写了 embedding_text，向量由 backfill 计算；不补的话检索命中 0 条，
        # 会得到"零泄漏 + 召回 0"的假绿，比不跑更糟。
        backfilled = backfill_embeddings(session, settings) if args.backfill else 0
        report = evaluate(session, questions, subjects, settings=settings, hybrid=args.hybrid)
    report["setup"] = {"backfilled_chunks": backfilled}

    if args.write:
        Path(args.write).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"基线已写入 {args.write}")

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(_summarise(report))
        for failure in report["failures"]:
            print(
                f"  ✗ {failure['id']} [{failure['subject']}] {failure['query']} "
                f"→ hits={failure['hits']} leaked={failure['leaked']} "
                f"forbidden_hits={failure['forbidden_hits']}"
            )

    metrics = report["metrics"]
    if metrics["leaked_hits"] > 0 or metrics["refusal_accuracy"] < 1.0:
        print(
            f"安全闸门失败：未授权命中 {metrics['leaked_hits']} 条，"
            f"拒答正确率 {metrics['refusal_accuracy']}",
            file=sys.stderr,
        )
        return EXIT_SECURITY_FAIL

    if args.compare:
        baseline = json.loads(Path(args.compare).read_text(encoding="utf-8"))
        if baseline.get("report_version") != report["report_version"]:
            print("基线报告版本不一致，无法比对（口径已变）", file=sys.stderr)
            return EXIT_REGRESSION
        diff = compare(baseline, report)
        if diff["regressions"]:
            for item in diff["regressions"]:
                print(
                    f"回归：{item['metric']} {item['baseline']} → {item['current']}", file=sys.stderr
                )
            return EXIT_REGRESSION
        print(f"与基线 {diff['baseline_generated_at']} 比对：无回归")

    # 放在最后：安全与回归先判。若两项都过了但数字不可信，说明"没变差"守住了、
    # "数据能用作决策"还没达到——这两种结论不能混成同一个退出码。
    if args.require_decision_grade and not report["decision_grade"]["recall"]:
        print(
            "未达决策级：" + "；".join(report["decision_grade"]["reasons"])
            + f"（blockers={report['decision_grade']['blockers']}）",
            file=sys.stderr,
        )
        return EXIT_NOT_DECISION_GRADE

    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover - CLI 入口
    raise SystemExit(main())
