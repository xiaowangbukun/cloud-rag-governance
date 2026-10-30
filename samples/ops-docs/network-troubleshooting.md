# 网络故障排查手册（DNS / MTU / 丢包 / tcpdump）

## 1 适用范围

覆盖内网环境的四类网络故障：DNS 解析异常、MTU 不匹配导致的大包丢失、
链路丢包与延迟抖动、以及用 `tcpdump` 做证据留存。适用 Linux 7/8 系发行版
（含 openEuler、Kylin、UOS），命令以 `iproute2` 为准，`net-tools`（`ifconfig`/`route`）已废弃。

排查顺序固定为 **分层自下而上**：物理/链路 → IP → 端口 → 应用。
跳层排查（例如先怀疑应用配置）会把时间浪费在错误的方向上。

## 2 分层速查

```bash
ip -br link                 # 链路层：接口是否 UP
ip -br addr                 # IP 层：地址与掩码
ip route get 10.0.2.20      # 路由选择：走哪个网关与出口
ss -lntup                   # 传输层：端口监听
ping -c4 10.0.2.20          # 三层连通性
nc -zv 10.0.2.20 5432       # 四层端口连通性
curl -sv --max-time 5 http://10.0.2.20:8080/healthz   # 七层
```

一次典型的「服务不可达」按上面顺序执行，通常 3 个命令内就能定位到层。

## 3 DNS 排查

### 3.1 判定标准

- 现象：`ping: unknown host`、`Name or service not known`、Java 报
  `java.net.UnknownHostException`、Go 报 `lookup xxx: no such host`。
- 但用 IP 直连正常 → 确认是解析问题而不是连通性问题。

### 3.2 处置步骤

```bash
# 1. 看实际使用的解析配置
cat /etc/resolv.conf
resolvectl status 2>/dev/null || systemd-resolve --status 2>/dev/null

# 2. 分别测「系统解析器」与「直连 DNS 服务器」
getent hosts app.example.internal
dig @10.0.0.2 app.example.internal +short
nslookup app.example.internal 10.0.0.2

# 3. 看解析耗时（超时会长在 5s/10s 这种整数上，说明 packets dropped）
time getent hosts app.example.internal

# 4. 抓 DNS 报文，确认请求有没有发出、有没有回应
tcpdump -i any -nn -vv 'udp port 53' -c 20
```

常见根因与处置：

- `/etc/resolv.conf` 被 NetworkManager 反复覆盖 → 在
  `/etc/NetworkManager/dispatcher.d/` 或 `nmcli con mod <con> ipv4.dns` 中固化。
- 配了两个 DNS，第一个不可达 → glibc 默认每次查询先等第一个超时（默认 5s，
  `options timeout:1 attempts:2` 可缩短）。**这是「首次访问慢、后面正常」的头号原因**。
- `/etc/nsswitch.conf` 中 `hosts` 顺序含 `dns` 之外的源（如 `nis`）且不可达 → 拖慢解析。
- 内网域名多了 search domain 拼接（`app` → `app.example.internal.example.internal`）→
  检查 `search` 与 `ndots:5` 设置，短域名多时建议 `options ndots:2`。
- 容器环境：排查 `/etc/resolv.conf` 是否为 `127.0.0.53`（systemd-resolved），
  容器内无该服务导致全部解析失败 → 改用宿主机真实 DNS 或 `dnsPolicy: Default`。

### 3.3 验证

```bash
# 连续 20 次解析，统计失败与耗时
for i in $(seq 20); do /usr/bin/time -f "%e" getent hosts app.example.internal >/dev/null; done 2>&1 | sort -n | tail -3
```

P99 应小于 50ms。若出现 5s 级耗时，按上面「第一个 DNS 不可达」处理。

## 4 MTU 与分片

### 4.1 判定标准

典型症状：**小包通、大包不通**。

- `ping -s 1400` 通，`ping -s 1500` 不通；
- SSH 能登录但 `scp`/`git clone` 卡住；
- TLS 握手失败（ClientHello 较大）或握手成功后第一个大数据包卡死；
- 走 VPN / 隧道 / VXLAN 的链路必然涉及额外封装开销。

### 4.2 探测路径 MTU

```bash
# Linux：-M do 禁止分片，-s 指定负载大小（不含 28 字节 IP+ICMP 头）
ping -c2 -M do -s 1472 10.0.2.20     # 1472+28 = 1500，通说明 MTU 1500
ping -c2 -M do -s 1400 10.0.2.20     # 若 1472 不通而 1400 通，MTU 在 1400~1500 之间
ping -c2 -M do -s 1372 10.0.2.20     # 1372+28 = 1400（VXLAN 常见值）
```

二分法收敛：从 1472 往下试，找到最大的通值 + 28 就是路径 MTU。

### 4.3 处置

```bash
# 临时调整接口 MTU
ip link set dev eth0 mtu 1400

# 永久化（各发行版路径不同）
# RHEL/openEuler: /etc/sysconfig/network-scripts/ifcfg-eth0 加 MTU=1400
# nmcli: nmcli con mod <con> 802-3-ethernet.mtu 1400 && nmcli con up <con>
```

注意：

- 容器网络（Calico VXLAN / Flannel VXLAN）会在宿主机 MTU 基础上减 50，
  Pod 内 MTU 常见为 1450；**应用若硬编码 1500 会出问题**。
- `net.ipv4.tcp_mtu_probing=1` 可让内核在检测到黑洞时自动降 MSS，
  是兜底手段，但不能替代正确的 MTU 配置。
- ICMP 被防火墙拦截时 `ping -M do` 会误报不通，此时用
  `tracepath` 或 `tcpdump` 观察实际分片行为。

## 5 丢包与延迟抖动

### 5.1 判定标准

```bash
# 连续 100 包统计丢包与抖动
ping -c 100 -i 0.2 -q 10.0.2.20

# 逐跳定位（mtr 比 traceroute 更适合看持续性丢包）
mtr -rw -c 50 10.0.2.20

# 网卡层错误计数
ip -s link show eth0
ethtool -S eth0 | grep -E "err|drop|miss|discard"
```

- 丢包率 > 0.1% 即需关注；> 1% 属于故障。
- `mtr` 关键判读：**中间跳丢包但末端不丢**通常是对该跳 ICMP 限速，可忽略；
  **从某一跳开始持续丢到末端**，说明问题在该跳之后。
- `ip -s link` 的 `errors`/`dropped` 增长 → 链路层或驱动问题（网线、光模块、双工不匹配）。
- `ethtool -S` 的 `rx_missed_errors` 增长 → 收包队列满，需调 `ring buffer`
  （`ethtool -G eth0 rx 4096`）或增加 RSS 队列。

### 5.2 常见根因

| 现象 | 根因 | 处置 |
|---|---|---|
| 周期性丢包（固定秒级间隔） | 对端 GC 停顿 / 定时任务抢占 | 看对端监控与日志 |
| 单向丢包 | 路由不对称、策略路由错配 | `ip route get`，核对双向路由 |
| 高负载时丢包 | 软中断单核打满 | 检查 `/proc/interrupts`，配 RPS/多队列 |
| 跨机房丢包 | 专线拥塞或 MTU | `mtr` 定位到设备，提工单 |
| 容器内丢包 | conntrack 表满、veth 队列满 | 看 `nf_conntrack_count` 与 `tc -s qdisc` |

### 5.3 应用侧确认

网络指标正常但业务报超时，需区分「网络丢包」与「应用处理慢」：

```bash
# 看 TCP 重传（重传率高说明确实在丢包）
ss -ti | grep -o "retrans:[0-9/]*" | head
nstat -az | grep -E "TcpRetransSegs|TcpExtTCPLostRetransmit"

# 看连接建立耗时
curl -o /dev/null -s -w "dns=%{time_namelookup} conn=%{time_connect} tls=%{time_appconnect} total=%{time_total}\n" https://app.example.internal
```

`conn` 耗时长而 `dns` 正常 → 建连阶段问题（SYN 丢包/backlog 满）；
`tls` 耗时长 → 握手阶段大包问题（回看 MTU）；`total - tls` 大 → 应用处理慢。

## 6 tcpdump 使用要点

### 6.1 抓包前先确认三件事

1. **抓哪个接口**：`ip -br addr` 确认，容器环境注意 `any` 会看到重复包（veth + 宿主接口）。
2. **过滤条件要窄**：不加过滤会瞬间打满磁盘并拖慢内核。
3. **文件要落盘而不是只打屏**：`-w` 写 pcap，事后用 Wireshark 分析，
   屏幕输出会因 `-A` 丢失大量细节。

### 6.2 常用命令

```bash
# 抓某主机某端口的完整会话（含内容），限制 200 个包
tcpdump -i any -nn -s0 -A 'host 10.0.2.20 and tcp port 8080' -c 200

# 只抓 TCP 握手与挥手（定位建连失败/半开连接）
tcpdump -i any -nn 'host 10.0.2.20 and tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0' -c 100

# 抓包落盘并按大小滚动（生产环境必备，避免打满磁盘）
tcpdump -i any -nn -s0 -w /tmp/cap.pcap -C 100 -W 5 'host 10.0.2.20'

# 统计某端口的重传与 RST
tcpdump -i any -nn -r /tmp/cap.pcap 'tcp[tcpflags] & tcp-rst != 0' | wc -l
```

### 6.3 判读要点

- `Flags [S]` 之后没有 `[S.]` → SYN 到达但回包没回来（对端未监听/被防火墙丢弃/回程路由错）。
- 出现 `[R]` → 对端主动重置，看是端口未监听（RST 紧跟 SYN）还是应用主动关闭。
- `[.]` 后长时间无数据 → 对端应用未处理，回看应用侧线程栈。
- `length 0` 的纯 ACK 大量重复 → 对端未收到数据或窗口为 0，检查 `ss -ti` 的 `rwnd`。
- `DF` 标志 + `frag needed` → MTU 问题，转第 4 节。

### 6.4 抓包的性能与合规提醒

- `-s0` 抓全包在高流量接口上会产生可观 CPU 开销，故障机器上建议先
  `-c` 限制包数、或加大 `-B` 缓冲（`-B 4096` 单位 KB）。
- pcap 可能包含凭证与业务数据，**按敏感数据处理**：抓完立刻转存到受控目录、
  限期删除，禁止直接贴到工单或聊天工具。

## 7 结果记录模板

```text
时间：2026-10-18 14:02 ~ 14:20
现象：订单服务调用支付网关偶发超时，成功率 92%
分层结论：
  链路  eth0 UP，ip -s link 无 errors 增长
  IP    10.0.2.20 ping 100 包丢 3%
  端口  nc -zv 10.0.2.20 8443 通
  七层  TLS 握手 1.8s（正常 80ms）
证据：tcpdump 显示 ClientHello（约 1400 字节）发出后无响应，重传 3 次
根因：VPN 隧道 MTU 1400，客户端仍按 1500 发送大包，PMTUD 被 ICMP 拦截
处置：客户端网卡 MTU 调为 1400，TLS 握手恢复 80ms
防复发：VPN 下发 MTU 配置，客户端镜像默认 1400
```

## 8 交接条件

- 需要变更网络设备（防火墙策略、路由、VPN MTU）→ 转网络组，附 `mtr` 与 `tcpdump` 证据；
- 怀疑专线质量 → 提工单并附 24 小时 `mtr` 汇总；
- 需要在生产长时间抓包 → 必须先申请，明确过滤条件、时长与落盘大小上限。
