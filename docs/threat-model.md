# 威胁模型与防护对照

面向内部威胁与供应链威胁建模（STRIDE 简化版），逐条给出本项目的缓解措施与验证方式。

## 资产与信任边界

| 资产 | 敏感度 | 说明 |
|---|---|---|
| 多云资源事实（规格、成本、状态） | L2–L3 | 可进入向量库的**脱敏后**语义 |
| 项目真实名称 / 负责人姓名 | L3 | 不得进入向量库与模型上下文 |
| 进度排期、里程碑、合同金额 | L4 | 不得进入向量库与模型上下文 |
| 云账号凭证、模型 API Key | 密钥 | 只保存环境变量引用名 |
| 审计日志与安全事件 | L3 | 只追加，不提供更新/删除接口 |

信任边界：**浏览器 / API 服务 / 向量库 / 模型服务 / 云 API / 公司身份目录**。跨边界一律重新校验。

## 威胁与缓解

| # | 威胁 | 缓解措施 | 代码位置 / 验证 |
|---|---|---|---|
| T1 | 越权读取他人项目资源 | 查询必须带 `project_id`；角色只决定能力，项目范围与密级下推 SQL | `security/policy.py`、`services/access.py`；`test_api.py::test_pm_cannot_read_other_project_resources` |
| T2 | 低密级用户读取高密级数据 | 密级上限取「用户上限 ∩ 项目成员上限」；行级 `.in_(levels_at_or_below(ceiling))` | `test_governance_cannot_read_l4_secret_project` |
| T3 | 通过列表接口枚举全量项目 | 项目列表按授权过滤；枚举意图识别直接拒绝 | `detect_enumeration_intent`；`test_enumeration_intent_blocked` |
| T4 | 多次窄查询拼出全貌 | 时间跨度上限 + 每小时查询预算 + 单项目召回上限 | `check_time_span`、`security/budget.py` |
| T5 | 敏感原文进入向量库 | 写入即净化；L4 禁止向量化 | `routes/knowledge.py`；`test_security.py` |
| T6 | 提示词注入（文档/查询/差异字段） | 入库拦截 + 出网前二次检测 | `detect_injection`；`test_prompt_injection_neutralized` |
| T7 | 模型输出回泄敏感信息 | 输出 DLP + 金丝雀扫描，命中即拦 | `security/dlp.py`、`security/canary.py` |
| T8 | 数据经外部模型出网 | 主机白名单（`MODEL_GATEWAY_ALLOW_PUBLIC`），**保存配置阶段即拒绝** | `routes/admin.py::_assert_endpoint_allowed`；`test_public_model_host_is_rejected` |
| T9 | 密钥泄露（配置/日志/响应） | 密钥只存引用名 + 掩码；`model_dump_safe()` 脱敏；响应不含密钥字段 | `config.py::model_dump_safe`；`test_admin_config_hides_secrets` |
| T10 | 先召回后过滤导致的旁路 | 检索先做授权预过滤，再排序 | `ai/retrieval.py`；`test_controlled_search_returns_only_authorized_chunks` |
| T11 | 批量导出带走数据 | 导出行数 + 频次双重限制；导出不含负责人与内部备注 | `check_export`；`routes/governance.py::export_diffs` |
| T12 | 身份伪造 / 令牌篡改 | JWT 签名校验；OIDC 走 JWKS 验签 + issuer/audience/exp | `auth/oidc.py`、`auth/sessions.py` |
| T13 | 组织归属被篡改导致越权 | 组织信息来自目录服务，落地为 `ProjectMember.visible_ceiling`，不信任客户端传入 | `seed/demo.py`、`auth` 目录接口 |
| T14 | 抵赖（操作不可追溯） | 所有访问/检索/调用/判定落审计，拒绝额外产生安全事件 | `audit/service.py`；`test_governance_resolve_writes_audit` |
| T15 | 容器内提权 / 横向移动 | 非 root、只读根文件系统、丢弃全部 Capabilities、默认拒绝入站 NetworkPolicy | `apps/api/Dockerfile`、`deploy/k8s/06-networkpolicy.yaml` |
| T16 | XSS / 点击劫持 | CSP + X-Frame-Options + nosniff + Referrer-Policy | `apps/web/nginx.conf`、`errors.py` |
| T17 | 模型不可用导致治理中断 | 降级为规则归因，链路不中断并在响应标注 `evidence_level=rule` | `ai/gateway.py::_rule_based_result` |
| T18 | 新接口漏写 `WHERE` 导致越权（应用层过滤单点失效） | PostgreSQL RLS：八张受保护表（`resource`/`resource_diff`/`snapshot_state`/`knowledge_document`/`knowledge_chunk`/`attribution`/`resource_metric`/`gpu_node`）`ENABLE + FORCE`，作用域走 `app.rls_*` 会话变量；未设上下文即 0 行；请求会话初始作用域为「无授权」 | `db/rls.py`；`test_rls.py::test_leaky_query_without_where_is_contained`、`test_request_session_without_auth_is_denied` |
| T19 | 检索静默降级（该看到的看不到，且无人发现） | 40 题金标准 + CI `eval-gate`：泄漏率与拒答率硬门禁、召回对照基线；报告自报 `decision_grade` | `eval/rag_baseline.py`、`rg_api.eval`；`test_rag_eval.py`、`test_retrieval_level_filter.py` |

## 明确的非目标

- 不防御已完全控制服务器的攻击者（需依赖主机与镜像安全基线）
- 不承诺离线降级向量的语义质量（仅保证链路连通）
- 不替代公司统一身份系统，只做对接与落地
