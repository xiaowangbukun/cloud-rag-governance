from __future__ import annotations

import json
import secrets
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[4]
_ENV_FILE = REPO_ROOT / ".env"

# 生产环境 SECRET_KEY 弱值黑名单（比较时已 strip + lower）
_WEAK_SECRET_KEYS = frozenset(
    {
        "",
        "change_me",
        "changeme",
        "replace_via_external_secret",
        "secret",
        "test",
        "dev",
        "password",
        "admin",
    }
)
# HMAC-SHA256 密钥最低长度（RFC 7518 建议 ≥32 字节）
_MIN_SECRET_KEY_LENGTH = 32


def _default_secret() -> str:
    """Generated at import time; production must provide an explicit value."""
    return secrets.token_urlsafe(32)


class DbDialect(str, Enum):
    POSTGRES = "postgresql"
    SQLITE = "sqlite"


class AuthMode(str, Enum):
    OIDC = "oidc"
    DEV = "dev"


class EmbeddingBackend(str, Enum):
    HTTP = "http"
    OFFLINE = "offline"


class DirectoryMode(str, Enum):
    STATIC = "static"
    HTTP = "http"
    LDAP = "ldap"


class RetrievalBackend(str, Enum):
    AUTO = "auto"
    PGVECTOR = "pgvector"
    MEMORY = "memory"


class Settings(BaseSettings):
    """Central configuration. Validated once at startup (fail fast)."""

    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE),
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        extra="ignore",
        case_sensitive=False,
    )

    APP_ENV: Literal["local", "test", "prod"] = "local"
    APP_NAME: str = "cloud-rag-governance"
    API_PREFIX: str = "/api/v1"
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    LOG_FORMAT: Literal["json", "console"] = "console"
    SECRET_KEY: str = Field(default_factory=_default_secret)

    # ---------------------------------------------------------------- database
    DB_DIALECT: DbDialect = DbDialect.SQLITE
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_NAME: str = "cloud_rag"
    DB_USER: str = "cloud_rag"
    DB_PASSWORD: str = "cloud_rag"
    DB_SSLMODE: str = ""  # 空 = 按 APP_ENV 推导（见 _resolve_env_defaults）
    SQLITE_PATH: str = "var/cloud_rag.db"
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_ECHO: bool = False
    # 行级安全（RLS）第二道防线：仅 PostgreSQL 生效，SQLite 无等价物。
    # 默认开启——它只在应用层漏写条件时才起作用，正常路径零行为变化。
    # 唯一的前置条件是连接角色不能是 SUPERUSER / BYPASSRLS（启动时会探测并告警）。
    DB_RLS_ENABLED: bool = True
    # 启动时是否由本进程执行 schema 初始化（建表/补列/策略/向量索引）。
    # 默认开启是为了本地开发与测试「一条命令起服务」；**生产必须关闭**，因为
    # 运行角色（rg_app）按最小权限只拿 DML、没有 DDL 权限：开着会让启动直接
    # 因权限不足失败。生产由 ``python -m rg_contracts.db.migrate`` 的部署 Job
    # 以属主身份完成初始化，应用侧改为只校验 schema 是否就绪（缺表即 fail-fast）。
    DB_MIGRATE_ON_STARTUP: bool = True

    # ------------------------------------------------------------------- redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_ENABLED: bool = False

    # --------------------------------------------------------------- object sto
    MINIO_ENDPOINT: str = "localhost:9000"
    MINIO_ACCESS_KEY: str = "minioadmin"
    MINIO_SECRET_KEY: str = "minioadmin"
    MINIO_BUCKET: str = "cloud-rag-evidence"
    MINIO_SECURE: bool = False

    # -------------------------------------------------------------------- auth
    AUTH_MODE: AuthMode = AuthMode.DEV
    OIDC_ISSUER: str = ""
    OIDC_CLIENT_ID: str = ""
    OIDC_CLIENT_SECRET: str = ""
    OIDC_REDIRECT_URI: str = "http://localhost:5173/auth/callback"
    OIDC_SCOPES: str = "openid profile email groups"
    OIDC_JWKS_URL: str = ""
    OIDC_AUTHORIZE_URL: str = ""
    OIDC_TOKEN_URL: str = ""
    OIDC_USERINFO_URL: str = ""
    OIDC_ROLES_CLAIM: str = "roles"
    OIDC_GROUPS_CLAIM: str = "groups"
    OIDC_ORG_CLAIM: str = "org_id"
    OIDC_TIMEOUT_SECONDS: int = 10
    JWT_ACCESS_TTL_MINUTES: int = 60
    JWT_REFRESH_TTL_MINUTES: int = 720
    DEV_LOGIN_ENABLED: bool = True
    # 刷新 Cookie 的 Secure 属性。默认 True（仅 HTTPS 发送）。
    # 纯 HTTP 部署（非 localhost）时浏览器会直接丢弃 Secure Cookie，表现为
    # 「登录成功但一刷新就掉线」且没有任何错误提示；需要明文 HTTP 的环境
    # 必须**显式**关掉它，让这个降级动作留在配置里可审计。prod 强制为 True。
    AUTH_COOKIE_SECURE: bool = True

    # --------------------------------------------------------------- directory
    DIRECTORY_MODE: DirectoryMode = DirectoryMode.STATIC
    DIRECTORY_HTTP_URL: str = ""
    DIRECTORY_HTTP_TOKEN: str = ""
    DIRECTORY_LDAP_URL: str = ""
    DIRECTORY_LDAP_BASE_DN: str = ""
    DIRECTORY_LDAP_BIND_DN: str = ""
    DIRECTORY_LDAP_BIND_PASSWORD: str = ""
    DIRECTORY_TIMEOUT_SECONDS: int = 10
    DIRECTORY_STATIC_FILE: str = "config/directory.json"

    # --------------------------------------------------------- embedding / rag
    EMBEDDING_BACKEND: EmbeddingBackend = EmbeddingBackend.OFFLINE
    EMBEDDING_MODEL: str = "BAAI/bge-m3"
    EMBEDDING_HTTP_URL: str = "http://localhost:8081/embed"
    EMBEDDING_TIMEOUT_SECONDS: int = 30
    EMBEDDING_DIM: int = 1024
    EMBEDDING_NORMALIZE: bool = True
    EMBEDDING_INSTRUCTION: str = "为语义检索生成向量表示"
    RETRIEVAL_BACKEND: RetrievalBackend = RetrievalBackend.AUTO
    RAG_TOP_K: int = 8
    RAG_MIN_SCORE: float = 0.05
    RAG_MAX_CHUNKS_PER_PROJECT: int = 2

    # ---- 知识库摄取与切块（P1：标题感知切块 / PDF 摄取）
    # 单个分片目标字符数；重叠按整句回退，保证块首落在句首
    CHUNK_TARGET_CHARS: int = 600
    CHUNK_OVERLAP_CHARS: int = 80
    # 单句超长时才硬切的上限，避免产生超长分片撑爆上下文
    CHUNK_MAX_CHARS: int = 1200
    # 扫描件判定：全文去空白后平均每页少于此字符数即视为无文本层
    PDF_MIN_CHARS_PER_PAGE: int = 20
    # 上传体积上限（默认 20MiB），超出直接 413，不进解析器
    KNOWLEDGE_UPLOAD_MAX_BYTES: int = 20 * 1024 * 1024

    # ---- 混合检索（P2：BM25 + 向量，线性 alpha 融合）
    # 授权候选集上限：先按密级/项目过滤出候选，再在其内做向量与关键词排序。
    # 它是候选集规模的**硬上限**（不是预取量）：语料超过它时只取前 N 个候选，
    # 超出的分片本次不参与排序。
    RAG_CANDIDATE_LIMIT: int = 500
    # 融合开关。**默认关闭是有意为之，不是忘开**：
    # ① 真实 embedding（BGE-M3）下没有 recall 对照数据，无法证明收益；
    # ② 内置的离线降级向量区分度极低（实测任意两文本余弦 0.06~0.18），
    #    「两边跑全绿」不能作为翻转默认的证据——它只说明测试不依赖排序；
    # ③ 融合会改变召回排序，安全治理类产品改召回行为必须有测量支撑。
    # 现在有了测量工具：`python -m rg_api.eval`（40 题金标准，输出 recall@3/8、
    # MRR、未授权泄漏率、拒答率，可与 docs/eval-baseline.json 比对）。但它**还没
    # 拿到决策级数据**：种子语料只有 6 个分片（≤ top_k=8，recall@8 必然饱和），
    # 且运行的是离线降级向量。因此这里仍默认关闭——工具就位 ≠ 证据就位。
    # 在真实语料 + 真实 embedding 后端上重跑并留存基线后再翻转（一行配置）。
    # 关闭时打分与融合前逐位一致（纯向量余弦），零行为变化。
    RAG_HYBRID_ENABLED: bool = False
    # 融合权重：final = alpha * vector_norm + (1 - alpha) * bm25_norm，
    # 两侧都归一化到 [0,1] 后线性加权。0.6 的依据：向量仍是主判据（余弦的
    # 绝对值带「相似度」语义），BM25 作为补召回通道；alpha=0.6 时「纯向量
    # 高分命中」(余弦 0.7 → 0.42) 仍高于「纯关键词命中」(0.4)，关键词噪声
    # 不会整体压过语义命中。
    RAG_HYBRID_ALPHA: float = 0.6
    # 说明：原方案（docs/kb-alignment-plan.md §4.2）预留的 RRF 配置
    # （RAG_HYBRID_VECTOR_WEIGHT / RAG_HYBRID_BM25_WEIGHT / RAG_RRF_K）与
    # 外部重排开关（RAG_RERANK_ENABLED）已删除——无任何代码消费，且实现的
    # 是线性加权而非 RRF。需要 RRF 时按方案文档重新引入，不要凭空加回空键。

    # ----------------------------------------------------------------- security
    SECURITY_MAX_SPAN_DAYS: int = 31
    SECURITY_QUERY_BUDGET_PER_HOUR: int = 60
    SECURITY_EXPORT_LIMIT: int = 500
    SECURITY_CANARY_ENABLED: bool = True
    SECURITY_MASK_ENTITIES: bool = True
    SECURITY_COARSE_BUCKETS: bool = True
    SECURITY_REDACT_OWNER: bool = True
    SECURITY_BLOCK_ON_CANARY: bool = True
    SECURITY_TOKEN_SALT: str = Field(default_factory=lambda: secrets.token_urlsafe(16))
    SECURITY_AUDIT_ENABLED: bool = True

    # ------------------------------------------------- jigsaw (mosaic) 拼图防护
    SECURITY_JIGSAW_ENABLED: bool = True
    # 同一主体的检索累积窗口（分钟）
    SECURITY_JIGSAW_WINDOW_MINUTES: int = 60
    # 窗口内同一项目可见唯一分片数上限
    SECURITY_JIGSAW_MAX_UNIQUE_CHUNKS: int = 10
    # 窗口内同一项目可见分片覆盖率上限（0-1）
    SECURITY_JIGSAW_COVERAGE_LIMIT: float = 0.35
    # 覆盖率判定的最小可见分片数：小知识库上覆盖率天然偏高，低于该值不启用覆盖率判定
    SECURITY_JIGSAW_MIN_VISIBLE_CHUNKS: int = 8
    # 跨查询敏感维度共现数达到该值即判定「可重组出高密级画像」
    SECURITY_JIGSAW_COMBO_DIMENSIONS: int = 3
    # 命中后的处置：coarsen=降密级返回 / deny=拒绝 / none=仅记录
    SECURITY_JIGSAW_ACTION: Literal["coarsen", "deny", "none"] = "coarsen"
    # 静默模式：风险只在审计留痕，响应体不回显风险细节
    SECURITY_JIGSAW_SILENT: bool = True
    # 降密级返回时最多保留的片段数
    SECURITY_JIGSAW_COARSEN_TOP_K: int = 2
    SECURITY_JIGSAW_RETENTION_DAYS: int = 7

    # -------------------------------------------------------------- model gateway
    MODEL_GATEWAY_TIMEOUT_SECONDS: int = 120
    MODEL_GATEWAY_MAX_TOKENS: int = 2048
    MODEL_GATEWAY_TEMPERATURE: float = 0.1
    MODEL_GATEWAY_ALLOW_PUBLIC: bool = False
    MODEL_ALLOWED_HOSTS: str = ""
    INTERNAL_INFERENCE_BASE_URL: str = ""
    INTERNAL_INFERENCE_API_KEY: str = ""
    INTERNAL_INFERENCE_MODEL: str = "deepseek-r1-distill-qwen-14b-int4"
    PUBLIC_API_KEY: str = ""

    # ------------------------------------------------------------------ collector
    COLLECTOR_MODE: Literal["api", "simulated"] = "simulated"
    COLLECTOR_TIMEOUT_SECONDS: int = 30
    COLLECTOR_PAGE_SIZE: int = 100
    COLLECTOR_MAX_RETRIES: int = 3
    COLLECTOR_ALLOW_INSECURE_TLS: bool = False

    # --------------------------------------------------------------- governance
    # D1 利用率/浪费判定阈值（百分比）：``allocated_gpus > 0`` 且
    # ``gpu_utilization`` 低于该值 → 产出一条 ``UTILIZATION_WASTE`` 治理项。
    # 阈值只能是默认值的显式覆盖，不做"按平台差异化"——那会让同一条规则在不同
    # 平台给出不同结论，回归时无法解释。
    GOVERNANCE_GPU_IDLE_UTIL_THRESHOLD: float = 10.0

    # ------------------------------------------------------------------ platform
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:8080"
    TRUSTED_HOSTS: str = "localhost,127.0.0.1"
    RATE_LIMIT_PER_MINUTE: int = 120
    DEMO_SEED: bool = True
    DEMO_SEED_FORCE: bool = False

    # ------------------------------------------------------------------ retention
    # 目标保留期（``rg_api.retention`` 定时任务消费）。
    # 审计与安全事件**只统计超期行数、不删除**：取证场景下通常「只能归档不能删」，
    # 口径未定前删证据比留证据危险得多，因此这里的天数只用于报告规模。
    RETENTION_AUDIT_DAYS: int = 180
    RETENTION_SECURITY_EVENT_DAYS: int = 365
    # 快照明细保留月数；更早的月份只保留「每月最后一份成功快照」的明细
    # （否则 resource_diff 无法重放「当时有哪些资源」）
    RETENTION_SNAPSHOT_DETAIL_MONTHS: int = 12
    # 运行期滑动窗口计数（预算 / 登录锁定）的残留行保留小时数
    RETENTION_RUNTIME_STATE_HOURS: int = 24

    # -------------------------------------------------------------------- metrics
    # ``GET /metrics`` 是否对外开放（进程内计数，按副本抓取后由 Prometheus 聚合）。
    # 只应经集群内网访问：Ingress 不路由它，默认拒绝入站的 NetworkPolicy 也已覆盖。
    METRICS_ENABLED: bool = True

    # --------------------------------------------------------------------- backup
    # 备份目标：默认复用 MINIO_*，可用独立凭证（合规要求备份凭证与库凭证分离）。
    BACKUP_ENDPOINT: str = ""  # 空 = MINIO_ENDPOINT
    BACKUP_BUCKET: str = ""  # 空 = MINIO_BUCKET
    BACKUP_ACCESS_KEY: str = ""  # 空 = MINIO_ACCESS_KEY
    BACKUP_SECRET_KEY: str = ""  # 空 = MINIO_SECRET_KEY
    BACKUP_SECURE: bool = True  # S3 走 TLS（MinIO 未启用 TLS 时显式关掉）
    BACKUP_PREFIX: str = "pg"
    # WORM：对象保留模式。COMPLIANCE=保留期内连管理员也删不掉（合规要求用这个）；
    # GOVERNANCE=有 BypassGovernanceRetention 权限者可提前解除（运维兜底）。
    # 留空表示不开 WORM——但取证场景下不建议。
    BACKUP_WORM_MODE: Literal["", "COMPLIANCE", "GOVERNANCE"] = "COMPLIANCE"
    # 分层保留：小时层覆盖 RPO 1 小时，日/周/月层覆盖回溯需求。
    # 对象级 Retain-Until 与此处天数一致（WORM 保留期必须 ≤ 生命周期到期时间，
    # 否则对象会「到期却删不掉」，桶只增不减）。
    BACKUP_HOURLY_RETENTION_DAYS: int = 7
    BACKUP_DAILY_RETENTION_DAYS: int = 30
    BACKUP_WEEKLY_RETENTION_DAYS: int = 90
    BACKUP_MONTHLY_RETENTION_DAYS: int = 365
    # 加密（密钥分离）：备份侧只挂**公钥**，私钥只在恢复侧/离线保管。
    BACKUP_PUBLIC_KEY_PATH: str = "/etc/backup/pubkey.pem"
    BACKUP_PRIVATE_KEY_PATH: str = ""
    # 恢复所需二进制（容器内由 pgvector:pg16 提供；宿主可指向本地客户端）。
    # 不设 PG_DUMP_BIN：dump 由 09 的 initContainer 直接执行，Python 侧只消费 restore。
    PG_RESTORE_BIN: str = "pg_restore"
    # 恢复演练目标库名必须包含该词（防止把演练数据灌进生产库）
    BACKUP_DRILL_DB_MARKER: str = "drill"

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.CORS_ORIGINS.split(",") if item.strip()]

    @property
    def trusted_host_list(self) -> list[str]:
        """Host 白名单（供 TrustedHostMiddleware 使用）。

        非 prod 额外放行 ``testserver``（TestClient 的默认 Host）与 ``test``，
        让测试与本地脚本能直接打应用；prod 严格只认 TRUSTED_HOSTS，
        不额外放行任何主机。
        """
        hosts = [item.strip() for item in self.TRUSTED_HOSTS.split(",") if item.strip()]
        if not self.is_prod:
            for extra in ("testserver", "test"):
                if extra not in hosts:
                    hosts.append(extra)
        return hosts

    @property
    def allowed_model_hosts(self) -> list[str]:
        return [item.strip() for item in self.MODEL_ALLOWED_HOSTS.split(",") if item.strip()]

    @property
    def sqlite_abs_path(self) -> Path:
        path = Path(self.SQLITE_PATH)
        return path if path.is_absolute() else REPO_ROOT / path

    @property
    def database_url(self) -> str:
        if self.DB_DIALECT is DbDialect.SQLITE:
            return f"sqlite:///{self.sqlite_abs_path.as_posix()}"
        password = self.DB_PASSWORD.replace("@", "%40") if self.DB_PASSWORD else ""
        return (
            f"postgresql+psycopg://{self.DB_USER}:{password}"
            f"@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}?sslmode={self.DB_SSLMODE}"
        )

    @property
    def is_prod(self) -> bool:
        return self.APP_ENV == "prod"

    @model_validator(mode="after")
    def _resolve_env_defaults(self) -> "Settings":
        """把「随 APP_ENV 变化」的默认值放到实例化时计算。

        旧写法 ``DB_SSLMODE: str = "require" if APP_ENV == "prod" else "prefer"``
        在**类定义时**求值：那时读到的是类属性默认值 ``APP_ENV="local"``，
        与环境变量无关 —— 生产环境永远拿到 ``prefer``，TLS 建连静默降级。
        同理，宽松默认值不能在类体里依赖其它字段。
        """
        if not self.DB_SSLMODE:
            self.DB_SSLMODE = "require" if self.is_prod else "prefer"
        return self

    @model_validator(mode="after")
    def _validate_production(self) -> "Settings":
        if self.is_prod:
            if not self.OIDC_ISSUER and self.AUTH_MODE is AuthMode.OIDC:
                raise ValueError("OIDC_ISSUER is required when AUTH_MODE=oidc in prod")
            if self.DB_DIALECT is DbDialect.SQLITE:
                raise ValueError("SQLite is not allowed in prod; set DB_DIALECT=postgresql")
            if self.DEV_LOGIN_ENABLED:
                raise ValueError("DEV_LOGIN_ENABLED must be false in prod")
            if self.SECRET_KEY == "":
                raise ValueError("SECRET_KEY is required in prod")
            # 弱密钥防护（P0-7）：SECRET_KEY 直接决定 JWT 签名，
            # 占位符/常见弱值/过短值一律视为可伪造，生产必须拒绝启动。
            weak = self.SECRET_KEY.strip().lower()
            if (
                weak in _WEAK_SECRET_KEYS
                or len(self.SECRET_KEY) < _MIN_SECRET_KEY_LENGTH
            ):
                raise ValueError(
                    "SECRET_KEY is weak or placeholder-like in prod; "
                    "provide a random key of at least "
                    f"{_MIN_SECRET_KEY_LENGTH} characters via ExternalSecret/KMS"
                )
            if self.DEMO_SEED:
                raise ValueError("DEMO_SEED must be false in prod")
            if self.AUTH_MODE is AuthMode.DEV:
                raise ValueError("AUTH_MODE=dev is not allowed in prod; use oidc")
            if not self.AUTH_COOKIE_SECURE:
                raise ValueError("AUTH_COOKIE_SECURE must be true in prod (HTTPS only)")
            # TLS 不得降级：prefer/allow/disable 会让密码与查询走明文（中间人可读）。
            if self.DB_SSLMODE in {"disable", "allow", "prefer"}:
                raise ValueError(
                    f"DB_SSLMODE={self.DB_SSLMODE} is not allowed in prod; use require/verify-*"
                )
            # SECURITY_TOKEN_SALT 参与所有主体令牌/归因指纹的派生：多副本必须一致，
            # 缺失时旧实现回退到「每个进程随机生成」，多副本之间互不认账。
            if "SECURITY_TOKEN_SALT" not in self.model_fields_set:
                raise ValueError(
                    "SECURITY_TOKEN_SALT must be provided explicitly in prod "
                    "(same value across replicas, via ExternalSecret/KMS)"
                )
            # 占位符/过短的 salt 与缺省等价：攻击者可离线猜出主体令牌派生
            salt = self.SECURITY_TOKEN_SALT.strip().lower()
            if salt in _WEAK_SECRET_KEYS or len(self.SECURITY_TOKEN_SALT) < _MIN_SECRET_KEY_LENGTH:
                raise ValueError(
                    "SECURITY_TOKEN_SALT is weak or placeholder-like in prod; "
                    "provide a random value of at least "
                    f"{_MIN_SECRET_KEY_LENGTH} characters"
                )
        if self.AUTH_MODE is AuthMode.OIDC and not (self.OIDC_JWKS_URL or self.OIDC_ISSUER):
            raise ValueError("OIDC_JWKS_URL or OIDC_ISSUER is required when AUTH_MODE=oidc")
        return self

    def model_dump_safe(self) -> dict[str, Any]:
        """Config snapshot with secrets removed - safe for API responses and logs."""
        secret_keys = {
            "SECRET_KEY",
            "DB_PASSWORD",
            "OIDC_CLIENT_SECRET",
            "MINIO_SECRET_KEY",
            "BACKUP_SECRET_KEY",
            "DIRECTORY_HTTP_TOKEN",
            "DIRECTORY_LDAP_BIND_PASSWORD",
            "INTERNAL_INFERENCE_API_KEY",
            "PUBLIC_API_KEY",
            "SECURITY_TOKEN_SALT",
        }
        data = self.model_dump()
        return {k: ("***" if k in secret_keys else v) for k, v in data.items()}


@lru_cache
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()


def load_json_config(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    if not file_path.is_absolute():
        file_path = REPO_ROOT / file_path
    if not file_path.exists():
        return {}
    with file_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)
