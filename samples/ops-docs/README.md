# 运维示例语料（自撰，非客户数据）

本目录是知识库检索验收用的**领域示例语料**，全部为项目自撰，用于验证
「文档 → 切块 → 混合检索 → 带出处回答」这条主链路的效果。**不含任何客户数据、
真实主机名、真实内网地址或真实凭证**（出现的 IP 均为 `10.0.0.0/8` 文档示例地址）。

| 文件 | 主题 | 主要章节 |
|---|---|---|
| `k8s-pod-anomaly.md` | Kubernetes Pod 异常排查 | Pending / CrashLoopBackOff / OOMKilled / ImagePullBackOff |
| `nginx-502-504.md` | Nginx 反向代理与网关错误 | 502 / 504 / 499、upstream keepalive、限流 |
| `postgresql-backup-pitr.md` | PostgreSQL 备份恢复 | pg_dump / pg_basebackup / WAL 归档 / PITR |
| `monitoring-alert-handling.md` | 监控告警处置 | CPU / 内存 / 磁盘与 inode / 连接数 |
| `network-troubleshooting.md` | 网络排查 | DNS / MTU / 丢包 / tcpdump |
| `security-baseline.md` | 安全基线 | SSH / 防火墙 / 账号提权 / 审计留存 |

## 用途

1. **切块质量抽查**：每篇都有多级标题、代码块与表格，用于验证
   `section_path` 生成正确、块不跨章节、代码围栏内的 `#` 不被当作标题。
2. **检索命中率验收（P4）**：以「问题 → 期望命中的 `section_path`」构造问答集，
   指标为 `recall@5 ≥ 0.8` 与引用章节正确率 ≥ 0.8。
3. **出处展示**：每条语料都有明确章节，回答可以带「文档名 + 章节」引用。

## 典型问答对（节选，完整问答集见 P4 验收清单）

| 问题 | 期望命中的章节 |
|---|---|
| Pod 一直 Pending 怎么排查 | `k8s-pod-anomaly.md` → `3 Pending 排查` |
| 容器退出码 137 是什么意思 | `k8s-pod-anomaly.md` → `4.2 退出码语义` |
| Nginx 502 报 connection reset by peer | `nginx-502-504.md` → `4.2 处置步骤` |
| 反向代理如何配置 keepalive 复用连接 | `nginx-502-504.md` → `2 最小可用反向代理配置` |
| PostgreSQL 如何恢复到指定时间点 | `postgresql-backup-pitr.md` → `5 PITR 恢复流程` |
| 归档失败会有什么后果 | `postgresql-backup-pitr.md` → `4.1 开启归档` |
| 磁盘还有空间但写入报 No space left | `monitoring-alert-handling.md` → `5 磁盘空间与 inode 告警` |
| 数据库连接数告警怎么处置 | `monitoring-alert-handling.md` → `6.1 数据库连接数` |
| 小包通大包不通是什么原因 | `network-troubleshooting.md` → `4 MTU 与分片` |
| 公钥配好了但还是登不上 | `security-baseline.md` → `2.3 密钥管理` |

## 许可

与项目一致，Apache License 2.0，见根目录 `LICENSE`。
