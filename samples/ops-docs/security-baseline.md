# 安全基线配置手册（SSH / 防火墙 / 账号与审计）

## 1 适用范围

面向前述运维知识库的 Linux 服务器（RHEL/openEuler 8/9、Kylin V10、Ubuntu 22.04）
安全加固基线，覆盖四块：SSH 访问控制、主机防火墙、账号与提权管理、审计与日志留存。

目标等级：等保 2.0 三级「安全计算环境」要求的最小集。**本基线不替代**正式的
等保测评与漏洞扫描，只作为日常开服与巡检的执行标准。

执行原则：

- 变更前必须确认已有**带外通道**（控制台/VNC）可用，否则 SSH 配置错误会导致机器失联。
- 每次变更只改一类，改完立刻验证，不在一次登录里改 SSH 又改防火墙。
- 所有变更通过配置管理下发，禁止直接在机器上手改后不落库。

## 2 SSH 加固

### 2.1 基线配置

`/etc/ssh/sshd_config.d/00-baseline.conf`（OpenSSH 8+ 支持 include 目录）：

```ini
Port 22
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
UsePAM yes
Banner /etc/ssh/banner
# 仅允许指定用户与来源网段
AllowUsers opsadmin deploy@10.0.0.0/8 audit
```

关键项说明：

- `PasswordAuthentication no`：必须**先完成密钥登录验证**再关闭密码，顺序反了就是失联。
- `MaxAuthTries 3`：配合 `fail2ban` 或 `sshd` 自带限速，减少暴力破解成功率。
- `AllowUsers` 支持 `user@cidr`，比 `DenyUsers` 白名单更安全（默认拒绝）。
- `ClientAliveInterval 300` + `ClientAliveCountMax 2`：10 分钟无响应断开，
  清理僵死会话，也降低会话被劫持的窗口。

### 2.2 变更与验证流程

```bash
# 1. 备份
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F)

# 2. 语法校验（必须在 reload 前做）
sshd -t

# 3. 平滑重载（不断开现有会话，保留回滚通道）
systemctl reload sshd

# 4. 另开一个新终端验证密钥登录，成功前不要退出当前会话

# 5. 验证失败时回滚
cp /etc/ssh/sshd_config.bak.$(date +%F) /etc/ssh/sshd_config && systemctl reload sshd
```

### 2.3 密钥管理

```bash
# 客户端生成 ed25519 密钥（比 RSA 2048 更短更安全）
ssh-keygen -t ed25519 -a 100 -C "ops@corp-2026" -f ~/.ssh/id_ed25519

# 服务端权限要求：目录 700，文件 600，属主必须是本人
chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys
chown -R "$USER:$USER" ~/.ssh

# 复核服务端权限（权限过宽会导致公钥认证被拒绝且日志只报 Authentication failed）
ls -ld ~ ~/.ssh ~/.ssh/authorized_keys
```

`StrictModes yes`（默认）会拒绝权限过宽的 `authorized_keys`，这是「公钥明明配上却登不上」
的最常见原因。排查时看 `/var/log/secure`：

```bash
grep -i "Authentication refused: bad ownership" /var/log/secure | tail
```

### 2.4 暴力破解防护

```bash
# 统计失败来源
grep "Failed password" /var/log/secure | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head

# fail2ban 策略（/etc/fail2ban/jail.d/sshd.conf）
# [sshd]
# enabled = true
# maxretry = 5
# findtime = 600
# bantime  = 3600

fail2ban-client status sshd
```

内网环境也应开启：横向移动的第一跳往往就是被窃密钥的机器。

## 3 主机防火墙

### 3.1 firewalld 基线（RHEL/openEuler/Kylin）

```bash
# 默认拒绝入站，只放通必要端口
firewall-cmd --permanent --set-default-zone=public
firewall-cmd --permanent --zone=public --remove-service=dhcpv6-client
firewall-cmd --permanent --zone=public --add-service=ssh
firewall-cmd --permanent --zone=public --add-port=8080/tcp

# 仅允许管理网段访问 SSH（更细的收敛）
firewall-cmd --permanent --zone=public --remove-service=ssh
firewall-cmd --permanent --zone=public \
  --add-rich-rule='rule family="ipv4" source address="10.0.0.0/8" service name="ssh" accept'

firewall-cmd --reload
firewall-cmd --list-all
```

要点：

- `--permanent` 与运行时是两套规则，**必须 `--reload`** 才生效；只加 `--permanent` 会「看起来配了但没生效」。
- 变更前先放通 SSH 再改其他规则，顺序错会把自己关在门外。
- 富规则（rich rule）比单纯 open port 更符合最小权限，可限定 source 与目标端口组合。

### 3.2 nftables 基线（Ubuntu 22.04 / 新版发行版）

```bash
# /etc/nftables.conf
# table inet filter {
#   chain input {
#     type filter hook input priority 0; policy drop;
#     ct state established,related accept
#     iif lo accept
#     ip protocol icmp accept
#     ip6 nexthdr icmpv6 accept
#     tcp dport 22 ip saddr 10.0.0.0/8 accept
#     tcp dport { 80, 443, 8080 } accept
#     counter comment "drop others"
#   }
# }
nft -f /etc/nftables.conf
nft list ruleset
```

`ct state established,related accept` 必须在 drop 策略之前，否则所有回包被丢弃。

### 3.3 验证

```bash
# 从其他机器验证（不要只在本机测）
nc -zv <host> 22
nc -zv <host> 8080
# 确认被拒端口确实被拒
nc -zv -w2 <host> 3306    # 期望 Connection refused / timed out

# 看规则命中计数，确认流量真的走了预期规则
nft list ruleset -a | grep counter
firewall-cmd --list-all --zone=public
```

## 4 账号与提权

### 4.1 账号基线

```bash
# 检查空口令账号（必须为空）
awk -F: '($2==""){print $1}' /etc/shadow

# 检查 UID 0 的非 root 账号（必须为空）
awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd

# 检查可登录 shell 的系统账号（应为 /sbin/nologin 或 /bin/false）
awk -F: '($7!="/sbin/nologin" && $7!="/bin/false" && $3<1000){print $1,$3,$7}' /etc/passwd

# 锁定长期未使用的账号
lastlog -b 90
usermod -L <user>
```

口令策略 `/etc/security/pwquality.conf`：

```ini
minlen = 12
minclass = 3
maxrepeat = 3
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
```

`/etc/login.defs` 配合：`PASS_MAX_DAYS 90`、`PASS_WARN_AGE 7`。
注意 `pwquality` 只对新设置的口令生效，存量账号需强制改期。

### 4.2 sudo 最小权限

```bash
# 只授予必要命令，且用绝对路径（避免 PATH 劫持）
# /etc/sudoers.d/ops
# Cmnd_Alias SVC = /bin/systemctl restart nginx, /bin/systemctl status nginx
# opsadmin ALL=(root) NOPASSWD: SVC
visudo -cf /etc/sudoers.d/ops       # 语法校验，必须有 -c
```

禁止项：

- `ALL=(ALL) NOPASSWD: ALL`（等价于 root，且无审计价值）；
- 授予 `vim`/`less`/`find` 等可逃逸的命令（`sudo vim` 等于 `sudo su`）；
- 把用户加入 `wheel` 组了事。

### 4.3 会话与提权审计

```bash
# 记录所有 sudo 命令（默认已记录到 /var/log/secure，需确认）
grep -i sudo /var/log/secure | tail -20
# 用 sudo 日志独立文件更清晰
# /etc/sudoers: Defaults logfile=/var/log/sudo.log, log_input, log_output
```

`log_input` / `log_output` 会录制会话的输入输出到 `/var/log/sudo-io`，
是事后取证的关键，但会产生额外磁盘开销，按需开启并纳入容量监控。

## 5 审计与日志留存

### 5.1 auditd 基线

```bash
# 关键文件变更监控
cat > /etc/audit/rules.d/99-baseline.rules <<'EOF'
## 身份与提权
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /etc/sudoers.d/ -p wa -k privilege
## SSH 配置
-w /etc/ssh/sshd_config -p wa -k sshd
## 审计自身防篡改
-w /etc/audit/ -p wa -k auditconfig
## 提权执行
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -k rootcmd
EOF

augenrules --load
auditctl -l | wc -l        # 确认规则条数
```

查询：

```bash
ausearch -k identity -ts today | tail -40
ausearch -k rootcmd -ts recent | aureport -x --summary
```

### 5.2 登录审计

```bash
last -n 20                 # 成功登录
lastb -n 20                # 失败登录（需 /var/log/btmp 存在且权限 600）
who -a                     # 当前会话
grep -c "Accepted publickey" /var/log/secure   # 密钥登录次数
```

### 5.3 日志留存要求

- 本地保留 ≥ 180 天（等保三级要求 6 个月），通过 `logrotate` 控制：
  `/etc/logrotate.d/syslog` 中 `rotate 26` + `weekly`，并开启 `compress`；
- 远程集中收集（rsyslog/syslog-ng 转发到日志服务器），**防止本机被入侵后日志被删**；
- 审计日志与业务日志分离存储，`auditd` 日志建议设置 `max_log_file_action = keep_logs`
  而不是 `rotate`（避免攻击者触发轮转覆盖证据）。

## 6 开服前检查清单

| # | 检查项 | 通过标准 |
|---|---|---|
| 1 | 是否仍允许 root 直接 SSH | `PermitRootLogin no` |
| 2 | 是否仍允许密码登录 | `PasswordAuthentication no` |
| 3 | 是否存在空口令账号 | 无输出 |
| 4 | 是否存在 UID 0 的非 root 账号 | 无输出 |
| 5 | 防火墙默认策略 | 入站 default drop / 仅放通白名单 |
| 6 | 高危端口是否暴露 | 3306/6379/9200/27017 不对 0.0.0.0 开放 |
| 7 | sudo 是否最小权限 | 无 `NOPASSWD: ALL` |
| 8 | auditd 是否运行 | `systemctl is-active auditd` = active |
| 9 | 日志是否外发 | 日志服务器能查到该主机近 1 小时日志 |
| 10 | 口令有效期策略 | `chage -l <user>` 显示最长 90 天 |

## 7 常见误区

- **只改配置不验证**：`sshd -t` 通过 ≠ 能登录，必须新开终端实测。
- **以为防火墙改了**：`firewall-cmd` 不加 `--permanent` 重启后失效，加了不 `--reload` 当前不生效。
- **密钥登录失败先怀疑 sshd**：90% 是 `~/.ssh` 或 `authorized_keys` 权限过宽。
- **关闭 SELinux 图省事**：应改为 `permissive` 观察 AVC 日志后再定策略，
  `disabled` 会让后续开启成本极高。
- **审计只看 auditd**：命令历史（`~/.bash_history`）、sudo 日志、SSH 登录日志要一起看，
  单一日志源容易漏。

## 8 交接条件

- 需要变更 SSH 端口或关闭密码登录 → 必须走变更流程并在带外通道可用时执行；
- 需要调整防火墙策略开放新端口 → 转网络组审批，附业务方申请单；
- 发现失陷迹象（异常登录、异常提权、可疑进程）→ 立即隔离主机、保全镜像与日志，
  按安全事件流程上报，**不要先清理现场**。
