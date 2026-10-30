# PostgreSQL 备份恢复与 PITR 操作手册

## 1 适用范围

面向 PostgreSQL 12+（含 openGauss/KingbaseES 兼容模式下的差异说明），覆盖逻辑备份
（`pg_dump`/`pg_dumpall`）、物理备份（`pg_basebackup`）、WAL 归档与时间点恢复（PITR）、
以及备份有效性验证。**不覆盖**：流复制切换（主备 switchover）、逻辑复制订阅冲突处理。

核心结论先行：

- 日常全量用 `pg_basebackup -Fp -Xs`（物理），跨版本迁移与单表恢复用 `pg_dump -Fc`（逻辑）。
- **没有 WAL 归档就没有 PITR**，`archive_mode=on` 是前提而不是可选项。
- 备份不做恢复演练 = 没有备份。每季度必须做一次恢复到隔离实例。

## 2 备份策略基线

| 类型 | 频率 | 保留 | 工具 | 恢复粒度 |
|---|---|---|---|---|
| 物理全量 | 每日 02:00 | 14 天 | `pg_basebackup` | 整实例 |
| WAL 归档 | 连续 | 14 天 | `archive_command` | 秒级时间点 |
| 逻辑全量 | 每周日 03:00 | 8 周 | `pg_dump -Fc` | 单库/单表 |
| 对象定义 | 每次变更 | 版本库 | `pg_dump -s` | DDL 审计 |

RPO 目标 5 分钟（靠 WAL 归档节奏，`archive_timeout=300`），RTO 目标 30 分钟
（物理全量 + WAL 回放到目标时间 + 切换连接串）。

## 3 逻辑备份

### 3.1 pg_dump 自定义格式（推荐）

```bash
export PGPASSWORD="$(cat /etc/pgbackup/pgpass)"   # 或用 ~/.pgpass 权限 600
pg_dump -h 127.0.0.1 -p 5432 -U backup -d appdb \
        -Fc -Z6 \
        --no-owner --no-privileges \
        -f /backup/logical/appdb_$(date +%Y%m%d_%H%M).dump
```

参数说明：

- `-Fc`：自定义格式，支持并行恢复（`pg_restore -j`）与选择性恢复（`-t`/`-n`）。
  **不要用 `-Fp` 明文 SQL 作为主备份**，它无法并行恢复，也无法只恢复一张表。
- `-Z6`：压缩级别 6，压缩率与 CPU 开销的平衡点；`-Z9` 在小库上收益不足。
- `--no-owner --no-privileges`：恢复到不同环境的必备项，否则会因角色不存在而报错。

### 3.2 校验（备份完立刻做）

```bash
# 1. 文件完整性：能列出目录即说明头部结构完好
pg_restore --list /backup/logical/appdb_20261018_0200.dump > /tmp/toc.txt
echo "对象数: $(grep -c ';' /tmp/toc.txt)"

# 2. 记录校验和，便于发现静默损坏
sha256sum /backup/logical/appdb_20261018_0200.dump >> /backup/logical/SHA256SUMS

# 3. 定期抽查：恢复到临时库验证行数
createdb -h 127.0.0.1 -U postgres appdb_verify
pg_restore -h 127.0.0.1 -U postgres -d appdb_verify -j 4 --clean --if-exists \
           /backup/logical/appdb_20261018_0200.dump
psql -d appdb_verify -c "\dt+" | head -20
```

## 4 物理备份 + WAL 归档

### 4.1 开启归档（需要重启）

`postgresql.conf`：

```ini
wal_level = replica                 # 至少 replica；逻辑解码需 logical
archive_mode = on
archive_command = 'test ! -f /backup/wal/%f && cp %p /backup/wal/%f'
archive_timeout = 300               # 5 分钟强制切换，保证 RPO
max_wal_senders = 10
wal_keep_size = 2GB                 # 12+ 用 wal_keep_size，11 及以下用 wal_keep_segments
```

`archive_mode` 修改需要**重启**（`reload` 不生效）；`archive_command` 只需 `reload`。

验证归档是否真的在工作：

```sql
-- 归档失败会一直重试，pg_stat_archiver 的 failed_count 会持续增长
SELECT archived_count, failed_count, last_archived_wal, last_failed_wal
FROM pg_stat_archiver;
```

若 `failed_count > 0`，立刻看日志 `grep -i "archive command failed" $PGDATA/log/*.log`。
**归档卡住会导致 `pg_wal` 目录无限增长直到磁盘满库**，这是最常见的生产事故之一。

### 4.2 执行物理全量

```bash
pg_basebackup -h 127.0.0.1 -p 5432 -U replicator \
              -D /backup/base/base_$(date +%Y%m%d) \
              -Fp -Xs -P -R -c fast
```

- `-Fp`：plain 格式（目录），可直接被 `pg_ctl start` 使用，恢复最快。
- `-Xs`：并行流式传 WAL，备份期间产生的 WAL 一并带走，**恢复起点不需要额外补 WAL**。
- `-R`：自动写 `standby.signal` 与 `primary_conninfo`。用于 PITR 时要**手动删除** `standby.signal`，
  否则实例会以从库身份启动并等待主库。
- `-c fast`：立即 checkpoint，缩短备份时间。

## 5 PITR 恢复流程

### 5.1 恢复到目标时间点

场景：`2026-10-18 10:32` 发生误删表操作，需恢复到 `10:31:30`。

```bash
# 1. 停库，保留故障实例现场（改名而不是删除）
pg_ctl -D /var/lib/pgsql/data stop -m fast
mv /var/lib/pgsql/data /var/lib/pgsql/data.broken_$(date +%s)

# 2. 用最近一次全量恢复出数据目录（含备份期间的 WAL）
cp -a /backup/base/base_20261018 /var/lib/pgsql/data
chown -R postgres:postgres /var/lib/pgsql/data
rm -f /var/lib/pgsql/data/standby.signal        # 关键：不然会等主库

# 3. 补齐备份之后的 WAL
cp /backup/wal/0000000100000000000000* /var/lib/pgsql/data/pg_wal/

# 4. 写恢复目标
cat >> /var/lib/pgsql/data/postgresql.auto.conf <<'EOF'
restore_command = 'cp /backup/wal/%f %p'
recovery_target_time = '2026-10-18 10:31:30+08'
recovery_target_action = 'promote'
EOF

touch /var/lib/pgsql/data/recovery.signal        # 12+ 需要该文件触发恢复

# 5. 启动并观察日志
pg_ctl -D /var/lib/pgsql/data start
tail -f /var/lib/pgsql/data/log/postgresql-*.log | grep -i "recovery"
```

### 5.2 判定恢复成功

日志出现以下三行即成功：

```
redo done at ...
restored log file "..." from archive
database system is ready to accept connections
```

`recovery_target_action = 'promote'` 会在到达目标点后自动接受写入（12+）。
在 11 及以下版本，PITR 完成后实例是只读的，必须 `SELECT pg_wal_replay_resume();`。

### 5.3 目标点选错的处置

`recovery_target_time` 设晚了（把误操作也回放了）：停库、改
`recovery_target_time` 为更早时间、删除 `pg_wal` 里已应用的段并重新从全量开始。
**不要在同一个数据目录上反复重试**，每次重试都从全量 + 归档重放，成本高且容易混乱。
建议先在临时目录验证时间点，再动生产目录。

## 6 常见故障

### 6.1 恢复时报 "could not locate required checkpoint record"

原因：`pg_wal` 里缺少备份起点的 WAL 段 —— 备份时用了 `-Xf`（备份结束后再取 WAL）且归档有缺口。

处置：确认 `/backup/wal` 里是否存在 `backup_label` 中记录的 `START WAL LOCATION` 段。
若确实缺失，只能退回到上一个可用的全量备份，接受 RPO 损失。

### 6.2 归档目录满了

```bash
# 先确认 pg_wal 是否在膨胀（正常应为 1~2GB）
du -sh $PGDATA/pg_wal

# 清理策略：只删除已完成归档且早于保留期的 WAL
find /backup/wal -type f -name "00000001*" -mtime +14 -delete
```

必须在 `pg_stat_archiver.last_archived_wal` 之后才能删除，删掉未归档的段会让 PITR 断链。

### 6.3 逻辑恢复报 role does not exist

```bash
pg_restore -d appdb --no-owner --no-privileges -j 4 backup.dump
# 或先建角色
psql -c "CREATE ROLE app_rw LOGIN;" 
```

`--no-owner` 之后对象的 owner 变成执行恢复的用户，恢复后需按需 `ALTER ... OWNER TO`。

## 7 备份有效性验收清单

每个季度按下面清单打勾，任何一项不通过都视为备份不可用：

1. `pg_stat_archiver.failed_count` 在最近 24 小时内无增长；
2. 最近一次物理全量的 `backup_label` 存在且时间符合计划；
3. 逻辑备份 `pg_restore --list` 能输出 TOC，对象数与上一周期偏差小于 5%；
4. 在隔离实例完成一次「全量 + WAL 回放到指定时间」的恢复，`SELECT count(*)` 与源库抽样一致；
5. 记录恢复耗时，若超过 RTO（30 分钟）需评估增量方案或提升磁盘 IOPS。

## 8 安全与合规

- 备份文件含全量业务数据，**密级与生产库一致**，必须加密存储：
  `gpg --encrypt --recipient backup@corp` 或使用带服务端加密的对象存储。
- 备份账号最小权限：`pg_dump` 需要 `SELECT` 与 `USAGE`，`pg_basebackup` 需要 `REPLICATION`；
  禁止用 `postgres` 超级用户跑定时备份。
- 备份目录与数据目录必须**不同物理磁盘**，否则磁盘故障会同时丢失数据与备份。
- 跨区域异地保留一份，保留周期按合规要求（本项目默认 14 天本地 + 90 天异地）。

## 9 交接条件

- 需要变更 `wal_level` / `archive_mode`（需重启，涉及变更窗口）；
- 恢复演练发现 RTO 不达标，需要引入增量备份或提升存储性能；
- 归档出现不可修复的缺口（缺少 WAL 段），需要评估数据丢失范围并上报。
