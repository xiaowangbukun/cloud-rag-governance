# 监控告警处置手册（CPU / 内存 / 磁盘 / 连接数）

## 1 适用范围

覆盖基础设施层四类最高频告警的判定标准、分级、处置动作与恢复确认：
CPU 使用率、内存使用率、磁盘空间与 inode、连接数（数据库连接 / TCP 连接 / Nginx 连接）。
不覆盖：应用层错误率告警、业务指标告警、中间件集群状态告警（另有专项手册）。

统一原则：**先止血、再定位、后根治**。告警处置的第一步永远是「确认影响面」，
而不是直接登录机器 `top`。影响面未确认前不要重启服务 —— 重启会让现场消失，
而多数告警是周期性的，现场消失意味着下一轮还要重来。

## 2 告警分级与响应时限

| 级别 | 判定 | 响应时限 | 通知 |
|---|---|---|---|
| P1 | 核心业务不可用，或资源使用率 > 98% 持续 5 分钟 | 5 分钟 | 电话 + 群 + 值班主管 |
| P2 | 关键功能降级，或使用率 > 90% 持续 15 分钟 | 15 分钟 | 群 + 工单 |
| P3 | 单实例异常但已冗余，或趋势性增长 | 1 小时 | 工单 |
| P4 | 容量预警（预计 7 天内触顶） | 次工作日 | 工单 |

分级不看单一指标数值，而看「是否影响可用性 + 是否有冗余」。单实例 CPU 100% 但
负载均衡已摘除该节点时是 P3；集群整体 CPU 70% 但 P99 延迟翻倍时是 P2。

## 3 CPU 使用率告警

### 3.1 判定标准

- 采集：`node_exporter` 的 `1 - avg(rate(node_cpu_seconds_total{mode="idle"}[5m]))`。
- 告警阈值：5 分钟均值 > 85% 持续 10 分钟（P2）；> 95% 持续 5 分钟（P1）。
- **必须同时看 load average**：`node_load1` 与核数比较。4 核机器 `load1 > 8` 说明排队严重，
  而 CPU 使用率可能只有 60%（大量 IO 等待）。

### 3.2 处置步骤

```bash
# 1. 影响面：是否已影响请求
curl -s -o /dev/null -w "code=%{http_code} time=%{time_total}\n" http://127.0.0.1:8080/healthz

# 2. 谁在吃 CPU（按进程）
top -b -n1 -o %CPU | head -20
pidstat -u 1 5 | sort -k8 -nr | head -10

# 3. 是用户态还是内核态
mpstat -P ALL 1 3        # %usr 高 = 应用计算；%sys 高 = 系统调用/软中断
vmstat 1 5               # r 列（运行队列）持续 > 核数说明排队

# 4. 若是软中断（si 高）
cat /proc/softirqs | head -20
# 网络软中断不均衡时，检查网卡多队列与 RPS
ethtool -l eth0
```

判定分流：

- `%usr` 高 → 应用计算密集（死循环、正则回溯、序列化大对象、GC 频繁）。
  JVM 用 `jstack` 抓两次对比，看是否同一批线程栈卡在同一方法。
- `%sys` 高 → 频繁系统调用或上下文切换，`pidstat -w 1 5` 看 `cswch/s`。
- `%si` 高 → 网络中断压力，多为小包风暴或网卡中断绑核不当。
- `%iowait` 高 → 其实是 IO 瓶颈，转第 5 节磁盘部分。

### 3.3 止血动作

1. 有冗余时先摘流量：`nginx -s reload` 前把该节点从 upstream 注释或标记 `down`。
2. 单进程失控时 `kill -TERM <pid>`（先 TERM 后 KILL，给优雅退出机会），并记录 PID 与栈。
3. 不得在未定位的情况下直接扩容 —— 扩容会掩盖死循环类问题，且成本不可控。

## 4 内存使用率告警

### 4.1 判定标准

- 使用率按 `(MemTotal - MemAvailable) / MemTotal` 计算，**不要用 `MemFree`**
  （Linux 会用空闲内存做 page cache，`MemFree` 低是正常现象）。
- 阈值：> 90% 持续 10 分钟（P2）；> 95% 且开始出现 OOM 记录（P1）。
- swap 使用率 > 20% 单独告警：swap 换入换出会让延迟成倍上升。

### 4.2 处置步骤

```bash
free -m
# 要看真实占用：available 列，而不是 free 列
cat /proc/meminfo | grep -E "MemTotal|MemAvailable|Cached|SwapUsed"

# 进程级
ps -eo pid,rss,comm --sort=-rss | head -15
smem -t -k -s rss | head -20        # 按 PSS 更准确（共享内存只算一次）

# 是否有 OOM 记录
dmesg -T | grep -i "out of memory" | tail -20

# slab 是否异常增长（内核对象泄漏）
slabtop -o -s c | head -15
```

判定分流：

- 单进程 RSS 持续增长且不回落 → 内存泄漏，抓堆快照（JVM `jcmd GC.heap_dump`；
  Go `GODEBUG=gctrace=1` 观察堆增长曲线）。
- `Cached` 很大但 `MemAvailable` 充足 → 不是问题，page cache 会被自动回收。
- `slab` 异常 → 内核态泄漏（常见于频繁 `open` 未 `close` 导致的 dentry 膨胀）。
- swap 使用量增长而物理内存充足 → `vm.swappiness` 过高，建议调到 10 以下。

### 4.3 止血动作

1. P1 且有 OOM 风险时，先重启异常单实例（有冗余前提下），保留 core dump：
   `sysctl -w kernel.core_pattern=/var/crash/core.%e.%p`。
2. 容器环境优先调 `limits.memory` 而不是宿主机 swap（Kubernetes 默认禁用 swap）。
3. 内存泄漏未修复前，配置定时重启属于**临时手段**，必须登记技术债与修复排期。

## 5 磁盘空间与 inode 告警

### 5.1 判定标准

- 空间：任一分区使用率 > 85% 告警（P3），> 92% 升级 P2，> 97% 升级 P1。
- inode：使用率 > 85% 告警。**inode 耗尽的表现是「磁盘还有空间但写不进去」**，
  报错为 `No space left on device`，极易误判。

### 5.2 处置步骤

```bash
df -h                    # 空间
df -i                    # inode —— 必须两条一起看
du -x -h --max-depth=2 / | sort -h | tail -20

# 找大文件（排除挂载点）
find / -xdev -type f -size +1G -exec ls -lh {} \; 2>/dev/null | head -20

# 找「已删除但仍被进程占用」的文件 —— 空间不释放的头号原因
lsof +L1 2>/dev/null | awk '{print $1,$2,$7,$9}' | sort -k3 -nr | head -20
```

`lsof +L1` 命中说明有进程持有已 unlink 的文件句柄（典型：日志轮转后应用未重新打开文件）。
处置：`kill -HUP <pid>` 让其重开日志，或重启该进程。

### 5.3 清理优先级

1. `journalctl --vacuum-size=500M` / `journalctl --vacuum-time=7d`（系统日志）；
2. 应用日志按保留策略删除（先压缩再删，`gzip` 后通常只剩 10%）；
3. `/tmp` 下超过 7 天的文件（注意先确认无进程占用）；
4. 包缓存：`yum clean all` / `apt-get clean`；
5. **不要**删除 `$PGDATA/pg_wal`（数据库 WAL，删了会丢数据）、
   不要删除 `/var/lib/docker` 或 `/var/lib/containerd` 下的文件（会破坏运行中的容器）。

容量趋势：若使用率在 7 天内从 70% 涨到 85%，必须提容量工单，清理只是延后故障。

## 6 连接数告警

### 6.1 数据库连接数（PostgreSQL 为例）

```sql
-- 当前连接数与上限
SELECT count(*) AS used,
       (SELECT setting::int FROM pg_settings WHERE name='max_connections') AS max_conn
FROM pg_stat_activity;

-- 按状态与来源分组，定位是连接泄漏还是长事务占用
SELECT state, usename, client_addr, count(*)
FROM pg_stat_activity
GROUP BY 1,2,3 ORDER BY 4 DESC;

-- 长事务（idle in transaction 是连接池泄漏的典型信号）
SELECT pid, now()-xact_start AS dur, state, query
FROM pg_stat_activity
WHERE state LIKE 'idle in transaction%'
ORDER BY dur DESC LIMIT 10;
```

判定标准：`used / max_connections > 80%` 告警（P2），> 90% 且出现
`FATAL: sorry, too many clients already`（P1）。

处置：

1. `idle in transaction` 超过 5 分钟的连接先 `pg_terminate_backend(pid)`，
   并追查应用是否漏了 `commit`。
2. 应用侧连接池（HikariCP / Druid）`maximumPoolSize` 之和不得超过
   `max_connections - 预留（10 个给运维与复制）`。多实例部署时尤其容易超：
   4 实例 × 每实例 50 = 200，而 `max_connections=100`。
3. 引入 PgBouncer（`pool_mode=transaction`）可把上千前端连接压到几十个后端连接，
   但**事务级池化不支持 prepared statement 与 session 级设置**，需应用侧配合。
4. 调整 `max_connections` 需重启，且每连接约 10MB 私有内存，不是无限可调。

### 6.2 TCP 连接数

```bash
ss -s                                     # 汇总
ss -tan | awk '{print $1}' | sort | uniq -c    # 按状态分布
ss -tan state time-wait | wc -l
cat /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max
```

- `TIME_WAIT` 大量堆积（> 20000）通常是短连接过多，检查是否漏配 keepalive。
- `nf_conntrack_count` 接近 `max` 会出现 `nf_conntrack: table full, dropping packet`，
  表现为随机丢包与新建连接失败。处置：调大 `nf_conntrack_max` 并缩短
  `nf_conntrack_tcp_timeout_established`（默认 5 天过长）。

### 6.3 Nginx 连接数

```bash
curl -s http://127.0.0.1/nginx_status    # 需先开启 stub_status
# Active connections / accepts / handled / requests / Reading / Writing / Waiting
```

`Writing` 数持续高位 = 上游慢导致 Nginx 缓冲/回传慢；`Waiting` 高是 keepalive 空闲连接，正常。
`worker_connections` 上限约为 `worker_processes × worker_connections`，同时受
`worker_rlimit_nofile` 限制（必须 >= `worker_connections × 2`）。

## 7 恢复确认与复盘

告警关闭不等于问题解决，必须完成三步确认：

1. **指标回落并稳定 15 分钟**（不是瞬时回落）；
2. **业务指标恢复**：错误率、P99 延迟回到告警前基线；
3. **根因记录**：工单里写清「触发条件 / 定位证据（命令输出）/ 处置动作 / 防复发项」。
   只有「重启后恢复」的工单视为未闭环。

P1/P2 告警在 48 小时内输出复盘，必须包含：时间线（精确到分钟）、影响范围（用户数/订单数）、
直接原因与根本原因（5 Why）、改进项与责任人。

## 8 交接条件

- 需要变更实例规格或扩容（涉及采购/预算）；
- 需要修改 `max_connections`、`vm.swappiness`、`nf_conntrack_max` 等需重启或影响全局的内核/数据库参数；
- 同一告警 24 小时内重复触发 3 次以上，视为未闭环，需转架构评审。
