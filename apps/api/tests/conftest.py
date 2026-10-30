"""pytest 公共夹具：隔离环境变量 + 隔离数据库（默认 PostgreSQL）+ 演示数据。

必须在导入任何业务模块前完成环境变量设置，因此放在 conftest 顶部。

方言由环境变量 RG_TEST_DIALECT 控制：

- postgresql（默认）：**生产方言，唯一真相源**。连接外部 PG
  （DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD，均可被环境变量覆盖，
  默认指向本机 rgtest 测试库）；导入业务模块前先物理重建 schema
  （drop_all → create_all），细节见下方注释。
- sqlite：需显式 ``RG_TEST_DIALECT=sqlite`` 开启。用于无 PG 环境时的秒级
  快速回路，以及方言垫片（shim）回归——SQLite 下 JSON / 时间戳 / 向量
  走应用层编解码，这些降级路径只在该分支被覆盖。SQLite 库建在临时目录，
  无需下面两道破坏性闸门。

两个方言跑同一套全量用例，SQLite 不是废弃方言而是受控的降级路径；
但只要环境里有 PG，就应当跑默认分支。

PG 分支每次启动都会 drop 目标库全部表，因此有两道闸门（见
``_guard_destructive_reset``）：目标库被其他 pytest 占用时立即报错；
目标库名（以 ``current_database()`` 为准）不含 ``test`` 时拒绝执行，
逃生阀是 ``RG_ALLOW_DESTRUCTIVE_DB=1``。
"""
from __future__ import annotations

import os
import sys
import tempfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection, Engine

_DIALECT = os.environ.get("RG_TEST_DIALECT", "postgresql").strip().lower()

_COMMON = {
    "LOG_FORMAT": "console",
    "LOG_LEVEL": "ERROR",
    "SECRET_KEY": "test-secret-key",
    "SECURITY_TOKEN_SALT": "test-token-salt",
    "SECURITY_CANARY_ENABLED": "true",
    "SECURITY_MASK_ENTITIES": "true",
    "SECURITY_COARSE_BUCKETS": "true",
    "SECURITY_REDACT_OWNER": "true",
    "EMBEDDING_BACKEND": "offline",
    "AUTH_MODE": "dev",
    "COLLECTOR_MODE": "simulated",
    # 测试环境统一把内网推理地址钉到不可达端口（discard:9）：演示种子的
    # 模型网关默认值是集群 DNS（seed/demo.py:571），不钉住会让归因/网关测试
    # 真去拨 vllm.inference.svc.cluster.local:8000——在离线/沙箱环境里被拦截，
    # 表现为"测试跑不完"而非产品缺陷。钉死后网关测试走"不可达→失败降级"路径。
    "INTERNAL_INFERENCE_BASE_URL": "http://127.0.0.1:9",
    "MODEL_GATEWAY_ALLOW_PUBLIC": "false",
}


# 清库留痕：导入期先写一份，再用 pytest_collection_finish 补打一次到终端
# （conftest 导入期的 stderr 会被 pytest 全局 capture 吞掉，-q 下 report_header
#  也会被抑制；collection_finish 阶段的输出两者都能穿透，实测可靠）。
_RESET_TRACE: dict[str, str] = {}


def _guard_destructive_reset(engine: "Engine") -> "Connection":
    """PG 分支：在 ``drop_all`` 之前给目标库加两道闸门，并把清库动作留痕。

    ``drop_all`` 会在 conftest **导入期**无条件清空目标库的全部表，而
    ``DB_NAME`` 可能被开发机 shell 或 .env 残留成客户真实库名——那时任何一次
    pytest（包括只跑一条用例）都会在 0.5 秒内静默毁掉那个库，事后才发现。
    因此顺序固定为：拿锁 → 校验目标库 → 留痕 → 由调用方重建 schema。

    闸门一（advisory lock，按库区分）：``pg_try_advisory_lock`` 是**会话级**锁，
    连接一断即释放，所以连接必须整个 pytest 进程存活。

    **返回值必须被调用方持有到进程结束**：本函数只负责拿锁并把连接交出去，
    若调用方丢弃返回值，连接会被回收、锁会提前释放，闸门一形同虚设。
    调用点把这个连接放在模块级全局里（见下方 ``_PG_LOCK_CONN``）。

    闸门二（目标库必须是测试库）：以 ``SELECT current_database()`` 为准，
    不只信环境变量；库名大小写不敏感地包含 ``test`` 才放行。确需对非测试库
    重建时用 ``RG_ALLOW_DESTRUCTIVE_DB=1`` 显式声明，此时会额外打一条
    ``!!! DESTRUCTIVE DB GUARD DISABLED !!!`` 告警。

    注意（实测结论，勿凭直觉改）：锁的存活期 = **这条连接对象**的存活期。
    - 拿锁后立刻 commit，让会话处于 ``idle`` 而非 ``idle in transaction``：
      否则服务端设了 ``idle_in_transaction_session_timeout`` 时会在长跑中被杀，
      锁静默消失；顺带避免长事务阻塞 vacuum。
    - ``engine.dispose()`` 不会丢锁：连接处于 checked-out 状态，dispose 只关池里
      的闲置连接，这条仍开着（实测 dispose 后外部仍抢不到锁）。
    - 但一旦 ``close()`` 或被 GC 回收，会话结束 → 锁立即静默释放。
      所以调用方必须持有返回值，且绝不要 close 它。
    - 固有边界：服务端被管理员 ``pg_terminate_backend`` 或网络中断时，会话级锁
      同样静默消失，客户端无法感知。这把锁是本地开发/CI 的**防误清库护栏**，
      不是分布式互斥；长任务场景建议由 CI 侧外部探针（查 ``pg_locks``）兜底。

    Returns:
        持锁的连接（未关闭）。调用方负责保持其引用。

    Raises:
        RuntimeError: 库被其他 pytest 占用，或目标库疑似非测试库且未显式放行。
    """
    from sqlalchemy import text

    lock_conn = engine.connect()
    actual_db = lock_conn.execute(text("SELECT current_database()")).scalar_one()
    host = engine.url.host or "localhost"
    port = engine.url.port or 5432
    target = f"{host}:{port}/{actual_db}"

    if not lock_conn.execute(
        text("SELECT pg_try_advisory_lock(hashtext(:key))"), {"key": target}
    ).scalar_one():
        lock_conn.close()
        raise RuntimeError(
            f"PostgreSQL 库 {target} 正被另一个 pytest 进程占用（那个进程会重建 "
            "schema）。请换一个库名（DB_NAME=...）或等它结束后再跑；不要指向他人"
            "正在使用的库。"
        )

    allow = os.environ.get("RG_ALLOW_DESTRUCTIVE_DB", "").strip() == "1"
    name_ok = "test" in actual_db.lower()
    if not name_ok and not allow:
        lock_conn.close()
        raise RuntimeError(
            f"拒绝重建疑似非测试库 {target}：conftest 会在导入期 drop_all 该库全部表。"
            "请改用名称含 test 的测试库（如 rgtest / rgtest_seed）；若确知后果仍要执行，"
            "显式设置 RG_ALLOW_DESTRUCTIVE_DB=1。"
        )

    # 关键：拿锁后立刻结束事务，让连接处于 idle 而不是 idle in transaction。
    # pg_advisory_lock 是**会话级**锁，不受 commit 影响（这正是它区别于
    # pg_advisory_xact_lock 的地方），但悬着的事务有两个真实危害：
    # ① 服务端若设了 idle_in_transaction_session_timeout，长跑中会话会被 kill，
    #    锁随之静默释放 —— 闸门失效却不报错；
    # ② 长事务快照会阻塞 vacuum，测试库长跑时白白拖累服务端。
    lock_conn.commit()

    # 留痕：清库动作在日志里可追溯（只打连接坐标，不打口令）。
    _RESET_TRACE["target"] = target
    _RESET_TRACE["user"] = engine.url.username or ""
    # 逃生阀真的放行了「名称不含 test」的库时必须醒目告警：否则事后排查无法
    # 区分「库名本来就含 test」与「防护被人为关掉」。
    if allow and not name_ok:
        _RESET_TRACE["guard_disabled"] = target
        print(
            f"!!! DESTRUCTIVE DB GUARD DISABLED !!! 目标库 {target} 已被显式放行，"
            "drop_all + create_all 即将执行 —— 这不是名称含 test 的库，请确认后果自负",
            file=sys.stderr,
            flush=True,
        )
    print(
        f"[pytest] destructive schema reset: host={host} port={port} dbname={actual_db} "
        f"user={engine.url.username} -> drop_all + create_all",
        file=sys.stderr,
        flush=True,
    )
    # 把持锁连接交还给调用方：锁的存活期 = 这个连接的存活期
    return lock_conn


if _DIALECT == "postgresql":
    # 默认连接本机测试库（CI 由 postgres service 容器注入同名环境变量）。
    # DB_NAME 为空时 libpq 会回落到操作系统用户名，静默连到一个未知库，
    # 表现是「建表建到别处 / 权限报错」这类难排查的故障，因此 fail-fast。
    _db_name = os.environ.get("DB_NAME", "rgtest").strip()
    if not _db_name:
        raise RuntimeError(
            "DB_NAME 为空，拒绝启动测试：无法确定要连接哪个 PostgreSQL 测试库。"
            "请显式设置 DB_NAME（如 DB_NAME=rgtest），"
            "或在无 PG 环境下用 RG_TEST_DIALECT=sqlite 走 SQLite 快速回路。"
        )
    os.environ.update(
        {
            "APP_ENV": "test",
            "DB_DIALECT": "postgresql",
            "DB_HOST": os.environ.get("DB_HOST", "127.0.0.1"),
            "DB_PORT": os.environ.get("DB_PORT", "5432"),
            "DB_NAME": _db_name,
            "DB_USER": os.environ.get("DB_USER", "rgtest"),
            "DB_PASSWORD": os.environ.get("DB_PASSWORD", "rgtest"),
            "DEMO_SEED": "true",
            **_COMMON,
        }
    )

    # PG 是默认方言，schema 必须在导入任何业务模块之前重建：rg_api.main 的
    # 模块级 `app = create_app()` 在**导入期**就会跑 bootstrap + 灌种子，
    # 那时看到的就是库里的既有状态，三个坑都会炸掉整个套件（pytest 收集期
    # ImportError，而不是某条用例失败）：
    # ① 数据漂移——所有 seed 函数都是 skip-if-exists 幂等语义（demo.py 的
    #    seed_all / seed_knowledge / seed_model_gateway / seed_attribution_samples），
    #    上一轮测试 mutate 的残留会让种子整体跳过（演示用户缺失）；
    # ② 半种子状态——上一轮若在 seed_all 之前就中断（项目已写入、账号未写入），
    #    seed_all 会因「项目已存在」整体跳过而不补 cloud_account，随后
    #    seed_demo_facts 插入资源触发 FK 违例；
    # ③ 结构漂移——并行开发给模型加列后，create_all 能跟上，存量库不会。
    # 因此这里 drop_all + create_all（含 pgvector 扩展；HNSW 索引随表删除，
    # 由随后的 bootstrap 重建），让每次 pytest 进程都从确定的空库起步。
    # drop_all 之前先过 _guard_destructive_reset 两道闸门（占用锁 + 目标库校验）。
    import rg_contracts.db.models  # noqa: F401,E402  (register models on Base.metadata)
    from rg_contracts.db.base import Base  # noqa: E402
    from rg_contracts.db.session import ensure_schema, get_engine  # noqa: E402

    _engine = get_engine()
    # 模块级全局持有锁连接（事实：这是 _guard_destructive_reset 的返回值，一个
    # 未关闭的 sqlalchemy Connection）。pg_try_advisory_lock 是会话级锁，
    # 只有这个引用活到进程结束，锁才覆盖整个 pytest 生命周期；一旦被 GC/close
    # 锁就会提前释放，第二个 pytest 进程便能进来再清一次库。
    _PG_LOCK_CONN = _guard_destructive_reset(_engine)  # noqa: F841  (keep-alive)
    Base.metadata.drop_all(_engine)
    ensure_schema(_engine)
else:
    _tmp = tempfile.mkdtemp(prefix="rg_test_")
    os.environ.update(
        {
            "APP_ENV": "test",
            "DB_DIALECT": "sqlite",
            "SQLITE_PATH": os.path.join(_tmp, "test.db").replace("\\", "/"),
            "DEMO_SEED": "true",
            **_COMMON,
        }
    )

# 根目录 .env 不应影响测试
os.environ.pop("PYTHONPATH", None)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from rg_contracts.db.session import get_session_factory  # noqa: E402
from rg_contracts.security.policy import Subject  # noqa: E402

from rg_api.main import create_app  # noqa: E402


def is_pg() -> bool:
    """当前测试是否跑在 PostgreSQL 方言上。"""
    return _DIALECT == "postgresql"


def pytest_collection_finish(session) -> None:
    """把本进程重建过的目标库打进终端输出。

    为什么不在导入期直接 print：conftest 导入期的 stderr 会被 pytest 全局
    capture 吞掉（成功运行时完全看不到），而 ``-q`` 又会抑制 report_header。
    collection_finish 阶段的输出两条都能穿透，保证「谁把哪个库清了」在 CI 日志
    里可追溯。SQLite 分支不重建 schema，不打这条。
    """
    if not _RESET_TRACE:
        return
    if _RESET_TRACE.get("guard_disabled"):
        print(
            "!!! DESTRUCTIVE DB GUARD DISABLED !!! 目标库 "
            f"{_RESET_TRACE['guard_disabled']} 已被 RG_ALLOW_DESTRUCTIVE_DB=1 显式放行，"
            "drop_all + create_all 已执行 —— 这不是名称含 test 的库，请确认后果自负",
            file=sys.stderr,
            flush=True,
        )
    print(
        f"[pytest] destructive schema reset done: {session.config.rootpath} "
        f"-> postgresql://{_RESET_TRACE.get('user')}@{_RESET_TRACE.get('target')}"
        f" (drop_all + create_all at conftest import)",
        file=sys.stderr,
        flush=True,
    )


@pytest.fixture(scope="session")
def app():
    return create_app()


@pytest.fixture(scope="session")
def client(app):
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture
def session():
    factory = get_session_factory()
    with factory() as s:
        yield s


def login(client: TestClient, username: str, password: str) -> dict[str, str]:
    resp = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def gov_headers(client):
    return login(client, "governance@corp.local", "Gov@2026")


@pytest.fixture(scope="session")
def admin_headers(client):
    return login(client, "admin@corp.local", "Admin@2026")


@pytest.fixture(scope="session")
def pm_headers(client):
    return login(client, "pm@corp.local", "Pm@2026")


@pytest.fixture(scope="session")
def viewer_headers(client):
    return login(client, "viewer@corp.local", "View@2026")


def make_subject(role: str, ceiling: str, project_ids=(), **kwargs) -> Subject:
    return Subject(
        user_id=kwargs.get("user_id", "u-test"),
        subject=kwargs.get("subject", f"{role}@corp.local"),
        display_name=kwargs.get("display_name", "测试用户"),
        role=role,
        org_id="org-001",
        classification_ceiling=ceiling,
        project_ids=frozenset(project_ids),
        visible_ceilings=kwargs.get("visible_ceilings", {}),
    )
