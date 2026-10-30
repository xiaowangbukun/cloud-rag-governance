# 行级安全（RLS）：第二道防线

## 为什么要有第二道防线

本项目的授权边界原本只表达一次：应用层把 `project_id` 与 `classification` 拼进
`WHERE`（`ai/retrieval.py` 的授权预过滤、`routes/*` 的 `scoped_project_ids`）。
这种方法在「每条查询都写对」时是够的，代价是**漏一个条件就等于越权**：

- 新增一个列表接口，忘了带 `project_id` → 直接返回他人数据；
- 写一句 `select count(*)`，只加了密级没加项目 → 数量本身泄露项目规模；
- 这两种漏法都不会报错、不会进异常日志，代码评审也很难发现——漏的是条件，
  不是分支。

RLS 把同一条边界再写一次在数据库里。即使应用层漏写，数据库也只返回授权范围内的
行。**它是加法，不是替换**：应用层过滤继续保留，两道防线同时存在。

## 语义：作用域如何进入数据库

每个请求解析出 `Subject` 后，`current_subject` 调用 `scope_session_for_subject`
把作用域写进当前事务的会话变量（`set_config(..., is_local=true)`，事务结束自动
失效，下一次事务由 `after_begin` 重新写入）：

| GUC | 含义 | 取值来源 |
|---|---|---|
| `app.rls_mode` | `system` = 显式系统通道；其它值 = 用户作用域 | 服务端，不接受客户端 |
| `app.rls_projects` | 可见项目 ID，逗号分隔 | `Subject.project_ids` |
| `app.rls_unrestricted` | `on` 时放开项目维度（密级仍受限） | 角色能力表 |
| `app.rls_levels` | `{项目: 密级序号, "*": 用户上限序号}`，JSON | `Subject.ceiling_for` |
| `app.rls_anchor_ids` | 已授权锚点 ID（`resource.id`），逗号分隔 | `services/objects.py` 从已过滤的 `resource` 查询结果授予 |

策略表达式（`db/rls.py::_policy_expression`）形如：

```text
mode = 'system'
OR (  (unrestricted = 'on' OR project_id = ANY(projects))
      AND (级别(classification) <= COALESCE(levels[project_id], levels['*'])) )
```

属性/指标分表没有项目列与密级列，走另一种形态（`RlsTable(anchor_only=True)`）：

```text
mode = 'system' OR resource_id = ANY(string_to_array(NULLIF(anchor_ids, ''), ','))
```

三条口径必须与代码保持一致，改动时一起改：

1. **全局知识**（`knowledge_document` / `knowledge_chunk` 上 `project_id IS NULL`）
   对所有人可见，密级按「用户总体上限」判定。这也是没有项目授权的只读岗唯一
   能看到的内容。
2. **项目内知识**按「用户上限 ∩ 项目上限」判定，`ceiling_for` 对未知项目回落
   用户总体上限。
3. **脏密级按 L4 处理**：`ceiling` 非空但不合法（拼写错误、尾随空格）一律取
   最高级别，不能因为拼错而降密；`ceiling` 为空则给 `-1`（一行都读不到），
   因为"没拿到上限"意味着没有授权信息，而不是"无上限"。

## 受保护对象

`resource`、`resource_diff`、`snapshot_state`、`knowledge_document`、
`knowledge_chunk`、`attribution`、`resource_metric`、`gpu_node`。每张表固定三步：
`ENABLE` + `FORCE` + 重建策略（`ensure_schema` 里调用，幂等）。

- `FORCE` 很关键：测试库与单机部署里应用用户常常就是建表用户，只 `ENABLE`
  的话策略对属主形同虚设。
- **本批不含** `audit_log` / `security_event`：读取侧已按项目过滤，写入路径多数
  来自系统通道，强行加策略的风险（审计漏写 = 抵赖）大于收益。这条是明确的
  待办，不是遗漏。
- `resource_metric` / `gpu_node` 用**锚点集合**判定，而不是给它们冗余
  `project_id` / `classification`（分表的设计约束明令禁止冗余，否则密级会被
  不一致地写两份）。锚点集合只能来自 `resource` 查询结果：`services/objects.py`
  先按「项目 + 密级上限」查锚点，再调 `rls.scope_anchor_ids` 把集合授予本事务，
  最后才读属性表。所以「漏写 `WHERE`」仍然只会查不到——策略表达式依旧不含
  子查询，既有不变量 `test_policy_expression_has_no_subquery` 未放宽。
- **写入侧同理**：采集在写 `resource_metric` / `gpu_node` 之前先把自己刚落库的
  锚点授予本事务（`routes/collection.py`），顺序反过来在运行角色下会被
  `WITH CHECK` 拒绝。

残留风险（明确写在这里）：锚点集合是「受信任的输入」——只有服务端代码能授予，
数据库无法自己判断某个 `resource_id` 是否本该可见。真正把范围收紧的是
`resource` 上的策略与应用层条件；直接拿到属主凭据的进程本来就能看全量。

## 部署前置条件（不做则第二道防线无效）

**连接角色不能是超级用户，也不能带 `BYPASSRLS`。** 这两种角色会绕过所有策略。

这里有一个容易被忽略的约束：**`ensure_schema` 里的建表、补列、`ENABLE ROW LEVEL
SECURITY`、建向量索引全是 DDL**，而运行角色按最小权限只拿 DML。所以「把
`DB_USER` 直接改成 `rg_app`」会让应用启动直接失败——必须先完成初始化与运行角色
的**身份拆分**。

部署形态（`deploy/k8s/12-schema-job.yaml`）：

| 身份 | 角色 | 权限 | 用途 |
|---|---|---|---|
| 属主 | `governance`（`POSTGRES_USER`） | DDL + DML，超级用户 | schema-init Job、备份 `09`、演练 `11` |
| 运行 | `rg_app` | 只 `SELECT/INSERT/UPDATE/DELETE` | 业务 api（`04-api.yaml` 覆盖 `DB_USER`/`DB_PASSWORD`） |

三步落地：

1. 在 `api-secrets` 注入真实的 `DB_APP_PASSWORD`（占位符会让 api 连接失败，
   这是故意的：不允许"忘记注入"静默上线）；
2. `kubectl apply -f deploy/k8s/12-schema-job.yaml` 并等待 Job 完成——它的
   init 容器以属主身份执行 `python -m rg_contracts.db.migrate`（建表 + 策略 +
   HNSW 索引），主容器用 psql 建 `rg_app` 并授权（只 DML，另 `REVOKE CREATE`）；
3. 部署 api（`DB_MIGRATE_ON_STARTUP=false` + 运行角色），确认日志出现
   `schema_verified` 与 `rls_enforced`。

为什么应用要关掉 `DB_MIGRATE_ON_STARTUP`：开着它会执行 DDL，运行角色权限不足
必然失败。关掉后启动只做 `verify_schema`——缺任何一张 ORM 表就 fail-fast，
并在异常里列出表名与修复命令，避免把「Job 没跑」伪装成运行时 500。
Job 漏建策略时，自检会额外打印 `rls_policies_missing`（策略数为 0）。

本地/CI 不受影响：`DB_MIGRATE_ON_STARTUP` 默认 `true`，一条命令即可起服务。

## 运维口径

- **迁移/种子/保留/备份** 走 `session_scope()`，默认 `system` 通道；直接用
  `engine.begin()` 的连接也由引擎级监听设为 `system`。这两条路径必须看全，
  否则迁移会静默更新 0 行。**注意这也意味着：任何拿到属主凭据的进程都能看到
  全量**，所以运行角色与属主凭据必须分开保管（`04-api.yaml` 用
  `DB_APP_PASSWORD`，运维 Job 用 `DB_PASSWORD`）。
- **HTTP 请求** 走 `db_session()`，它先把作用域登记为 `REQUEST_SCOPE`
  （什么都没有），认证成功后才升级为真实作用域。于是「新接口忘了依赖认证」
  会得到空结果，而不是系统通道的全量——这是最容易被悄悄绕开的一条路。
- **降级开关**：`DB_RLS_ENABLED=false` 可整体关闭，只建议在排障时临时使用；
  关闭后应用层过滤仍然是唯一防线（与改造前一致）。
- **SQLite** 没有 RLS 等价物，`DB_RLS_ENABLED` 对它无效，相关测试自动 skip。

## 怎么验证它真的在拦

`apps/api/tests/test_rls.py` 里 27 条用例（写入侧按表参数化，共 28 次执行），其中最关键的五条：

| 用例 | 断言 |
|---|---|
| `test_scope_without_authorization_sees_nothing` | 会话设了作用域但没有密级上限 → 每张受保护表返回 0 行（不是全量） |
| `test_leaky_query_without_where_is_contained` | 不带任何 `WHERE` 的全表查询 = 显式授权过滤的结果 |
| `test_request_session_without_auth_is_denied` | 请求会话漏认证 → 受保护表读不到 |
| `test_attribute_tables_are_contained_by_the_anchor_guc` | 未授予锚点时 `resource_metric` / `gpu_node` 为 0 行；只授予一条也只看到那一条 |
| `test_app_role_cannot_run_ddl` | 运行角色执行 `CREATE TABLE` 被拒（能改表就能自己 `DROP POLICY`） |

写入侧另有一条 `test_attribute_write_requires_the_same_anchor_grant`，对 `resource_metric` 与
`gpu_node` **各跑一遍**：向未授予的锚点写入会被 `WITH CHECK` 拒绝（报 `row-level security`），
授予后才写得进去，且写完能用同一锚点读回。对应的真实权限是运行角色的 `INSERT/UPDATE/DELETE`，
测试里也只给这两张表 DML 权限（其它受保护表仍只给 `SELECT`）。

这些用例会临时建一个 `NOSUPERUSER NOBYPASSRLS` 角色并 `SET ROLE` 过去执行——
用超级用户连接**测不出真假**（策略会被绕过），这点值得写进任何后续 RLS 测试。

授权脚本本身也在本机用 `psql` 实跑过（`psql -v role=… -f 10-app-role.sql`）：
建角色/授权/重复执行均成功，随后以该角色连接确认 `SELECT` 可用、
`CREATE TABLE` 报 `permission denied for schema public`、无作用域时 `resource`
返回 0 行而属主同表为 96 行。该脚本尚未在真实集群上执行过。
