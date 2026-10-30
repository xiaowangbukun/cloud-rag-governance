"""拼图攻击（mosaic / salami-slicing）防护测试。

覆盖三道防线：
1. 入库侧切片规避扫描（敏感值被切片切断 / 跨分片重组）
2. 检索侧跨查询累积覆盖与敏感维度共现
3. 触发后的降密级返回与静默审计记录
"""
from __future__ import annotations

from types import SimpleNamespace

from rg_contracts.config import get_settings
from rg_contracts.security.detectors import RE_CN_MOBILE
from rg_contracts.security.jigsaw import (
    JigsawGuard,
    JigsawRisk,
    detect_dimensions,
    lower_level,
    sanitize_before_chunking,
)


def _hit(chunk_id: str, text: str, project_id: str | None = None, score: float = 0.9):
    return SimpleNamespace(
        chunk_id=chunk_id,
        document_id=f"doc-{chunk_id}",
        project_id=project_id,
        platform="aliyun",
        classification="L2_INTERNAL",
        score=score,
        display_text=text,
        metadata={"sanitized": True},
    )


# ---------------------------------------------------------------- 维度识别
def test_detect_dimensions_counts_multiple_dimensions():
    text = "负责人 13800138000，邮箱 ops@corp.local，上线时间 2026-08-12，金额 128万元，IP 10.20.30.40"
    dims = detect_dimensions(text)
    assert dims.dimensions["identity"] >= 1
    assert dims.dimensions["timing"] >= 1
    assert dims.dimensions["scale"] >= 1
    assert dims.dimensions["location"] >= 1
    assert dims.count >= 4


def test_detect_dimensions_empty_text_is_clean():
    dims = detect_dimensions("治理基线符合规范，无异常")
    assert dims.count == 0


# ------------------------------------------------------- 入库侧切片规避扫描
def test_split_evasion_detected_when_sensitive_value_cut_by_chunking():
    """旧顺序「先切片后净化」会把手机号切成两段，两个分片单独看都不完整。"""
    # 258 字符前缀 + 11 位手机号：按 260 硬切时切口正好落在号码第 3 位
    content = "x" * 258 + "13800138000" + " 联系人电话"

    from rg_contracts.config import get_settings

    guard = JigsawGuard(None, get_settings())
    raw_chunks = [content[i : i + 260] for i in range(0, len(content), 260)]

    scan = guard.scan_ingest(content, raw_chunks)

    assert scan.split_evasion is True
    assert any("手机号" in v for v in scan.split_values)


def test_cross_chunk_reassembly_detected():
    """文档整体维度高于任一单分片：说明必须跨分片拼起来才构成敏感画像。"""
    from rg_contracts.config import get_settings

    guard = JigsawGuard(None, get_settings())

    content = "项目A成本128万元。" "项目B拓扑 10.20.30.40。" "项目C负责人 ops@corp.local。"
    # 每个分片只含一个维度，合起来才是完整画像
    chunks = ["项目A成本128万元。", "项目B拓扑 10.20.30.40。", "项目C负责人 ops@corp.local。"]
    scan = guard.scan_ingest(content, chunks)

    assert len(scan.doc_dimensions) >= 3
    assert scan.max_chunk_dimensions < len(scan.doc_dimensions)
    assert scan.cross_chunk_reassembly is True


def test_sanitize_before_chunking_removes_split_evasion():
    """根因修复：先净化再切片，手机号整体替换为占位符，不存在切断面。"""
    from rg_contracts.config import get_settings

    content = "x" * 258 + "13800138000" + " 联系人电话"
    sanitized, removed = sanitize_before_chunking(content)

    assert RE_CN_MOBILE.search(sanitized) is None
    # 净化后任意位置切片，都不会再出现敏感值被切断的情况
    guard = JigsawGuard(None, get_settings())
    scan = guard.scan_ingest(
        sanitized, [sanitized[i : i + 260] for i in range(0, len(sanitized), 260)]
    )
    assert scan.split_evasion is False
    assert removed  # 确实执行了净化动作


# --------------------------------------------------------- 检索侧累积评估
def _mk_guard(session, **overrides):
    from rg_contracts.config import Settings

    base = {
        "APP_ENV": "test",
        "DB_DIALECT": "sqlite",
        "AUTH_MODE": "dev",
        "SECRET_KEY": "test-secret-key",
        "SECURITY_TOKEN_SALT": "test-token-salt",
        "SECURITY_JIGSAW_ENABLED": True,
        "SECURITY_JIGSAW_MAX_UNIQUE_CHUNKS": 4,
        "SECURITY_JIGSAW_COMBO_DIMENSIONS": 3,
        "SECURITY_JIGSAW_COVERAGE_LIMIT": 0.35,
        "SECURITY_JIGSAW_MIN_VISIBLE_CHUNKS": 8,
    }
    base.update(overrides)
    settings = Settings(**base)
    return JigsawGuard(session, settings)


def test_assess_triggers_on_unique_chunk_accumulation(session):
    guard = _mk_guard(session)
    texts = [
        "治理基线检查通过，无异常变更。",
        "网络策略已收敛，白名单规则同步更新。",
        "标签规范整改完成，成本中心已补齐。",
        "快照周期调整，保留策略已复核。",
        "访问审计按月归档，日志留存合规。",
    ]
    hits = [_hit(f"kc_{i}", text, project_id="prj_x") for i, text in enumerate(texts)]

    risk = guard.assess("u-actor", "prj_x", [], "")
    assert risk.risk == "none"

    guard.record("u-actor", hits, "q1")
    risk = guard.assess("u-actor", "prj_x", [], "")
    assert risk.unique_chunks == 5
    assert risk.triggered is True
    assert risk.action == "coarsen"
    assert any("唯一分片" in r for r in risk.reasons)


def test_assess_triggers_on_dimension_cooccurrence(session):
    """跨查询维度共现：单次查询都不敏感，合起来可以拼出画像。"""
    guard = _mk_guard(session, SECURITY_JIGSAW_MAX_UNIQUE_CHUNKS=100)
    guard.record("u-actor", [_hit("kc_a", "项目负责人邮箱 ops@corp.local", project_id="prj_y")], "q1")
    guard.record("u-actor", [_hit("kc_b", "上线时间 2026-08-12 已确认", project_id="prj_y")], "q2")

    risk = guard.assess("u-actor", "prj_y", [_hit("kc_c", "月度成本 128万元", project_id="prj_y")], "q3")
    assert risk.dimension_count >= 3
    assert risk.triggered is True


def test_record_is_idempotent_per_actor_chunk(session):
    guard = _mk_guard(session)
    hits = [_hit("kc_dup", "治理基线", project_id="prj_z")]
    assert guard.record("u-actor", hits, "q") == 1
    assert guard.record("u-actor", hits, "q") == 0  # 同一 (actor, chunk) 不重复计入

    risk = guard.assess("u-actor", "prj_z", [], "")
    assert risk.unique_chunks == 1


def test_coarsen_returns_generalized_and_limited(session):
    guard = _mk_guard(session)
    hits = [
        _hit("kc_1", "负责人 13800138000 邮箱 ops@corp.local 上线时间 2026-08-12 金额 128万元", score=0.95),
        _hit("kc_2", "另一条治理规则说明", score=0.9),
        _hit("kc_3", "第三条治理规则说明", score=0.85),
    ]
    out = guard.coarsen(hits)

    assert len(out) <= 2  # 降密级后最多保留少量片段
    assert all(item["coarsened"] is True for item in out)
    joined = " ".join(item["text"] for item in out)
    assert "13800138000" not in joined
    assert "ops@corp.local" not in joined
    assert "2026-08-12" not in joined
    assert "128万元" not in joined


def test_disabled_guard_returns_no_risk(session):
    guard = _mk_guard(session, SECURITY_JIGSAW_ENABLED=False)
    risk = guard.assess("u-actor", "prj_x", [_hit("kc_1", "任意文本")], "q")
    assert isinstance(risk, JigsawRisk)
    assert risk.triggered is False
    assert risk.action == "none"


def test_lower_level_steps_down():
    assert lower_level("L4_SECRET") == "L3_CONFIDENTIAL"
    assert lower_level("L2_INTERNAL") == "L1_PUBLIC"
    assert lower_level("L1_PUBLIC") == "L1_PUBLIC"


# ------------------------------------------------------------- 集成（API）
_SEARCH_DOC_SENTENCES = [
    "资源新增需要核对成本中心标签",
    "网络策略变更需过安全评审",
    "快照保留周期不得低于三十天",
    "访问审计日志按月归档",
    "标签规范包含环境与业务线",
    "资源下线需先释放弹性IP",
    "跨账号角色信任需最小权限",
    "对象存储桶禁止公共读写",
    "数据库账号需定期轮换凭据",
    "安全组默认拒绝所有入方向流量",
]


def _padded(sentence: str) -> str:
    """填充到超过「单块目标长度」，保证每句独立成一个分片。

    阈值取自配置的 ``CHUNK_TARGET_CHARS`` 而不是写死 260：摄取已统一到
    ``chunk_markdown``，260 是旧 ``_split`` 按分号硬切后的缓冲长度，与之
    耦合会让本夹具在换切块器后失效（实测块数 10 → 9）。句子长度超过目标
    块长时聚包只能装下它自己，「每句独立成块、共 len(_SEARCH_DOC_SENTENCES)
    块」的断言语义保持不变。
    """
    return "x" * get_settings().CHUNK_TARGET_CHARS + sentence


def test_repeated_search_eventually_downgrades(client, admin_headers):
    """同一账号反复小范围检索同一项目，最终触发降密级返回。

    历史备注：P0-1（PG 向量列 bytea→vector）与 P0-3（检索账本时间窗
    比较）修复前，本用例在 PG 作业中经 ``_pg_pending`` 跳过；两项修复
    均已上线并通过 PG 实证，标记随本次 R1-R4 收尾移除，PG 恢复覆盖。
    """
    doc = {
        "title": "拼图防护测试文档",
        "content": "；".join(_padded(s) for s in _SEARCH_DOC_SENTENCES),
        "project_id": "prj_core_policy",
        "classification": "L2_INTERNAL",
    }
    r = client.post("/api/v1/knowledge/documents", json=doc, headers=admin_headers)
    assert r.status_code == 200, r.text
    assert r.json()["chunks"] == len(_SEARCH_DOC_SENTENCES)

    coarsened_seen = False
    for i in range(16):
        resp = client.post(
            "/api/v1/knowledge/search",
            json={
                "query": _SEARCH_DOC_SENTENCES[i % len(_SEARCH_DOC_SENTENCES)],
                "project_id": "prj_core_policy",
                "top_k": 6,
            },
            headers=admin_headers,
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "jigsaw" not in body["security"]  # 静默模式不回显风险
        if any(h.get("coarsened") for h in body["hits"]):
            coarsened_seen = True
            break

    assert coarsened_seen, "反复检索未触发拼图降密级返回"


def test_ingest_with_cross_chunk_reassembly_is_recorded(client, admin_headers, session):
    """文档需跨分片拼合才构成敏感画像：静默记录安全事件，且入库内容已净化。"""
    import sqlalchemy
    from rg_contracts.db.models import KnowledgeChunk, SecurityEvent

    content = "；".join(
        [
            "y" * 250 + "项目A成本128万元",
            "z" * 250 + "项目B拓扑 10.20.30.40",
            "w" * 250 + "项目C负责人 ops@corp.local",
        ]
    )
    r = client.post(
        "/api/v1/knowledge/documents",
        json={
            "title": "跨分片重组探测文档",
            "content": content,
            "project_id": "prj_core_policy",
            "classification": "L2_INTERNAL",
        },
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    doc_id = r.json()["id"]

    events = session.execute(
        sqlalchemy.select(SecurityEvent).where(
            SecurityEvent.event_type == "jigsaw_slicing_evasion"
        )
    ).scalars().all()
    assert events, "跨分片重组特征未写入安全事件"

    # 修复生效：入库分片是「先净化再切片」的产物，不含原始敏感值
    chunks = session.execute(
        sqlalchemy.select(KnowledgeChunk).where(KnowledgeChunk.document_id == doc_id)
    ).scalars().all()
    assert chunks
    joined = " ".join(c.embedding_text for c in chunks)
    assert "128万元" not in joined
    assert "10.20.30.40" not in joined
    assert "ops@corp.local" not in joined
