# Kubernetes Pod 异常排查手册

## 1 适用范围

本手册覆盖生产集群中 Pod 无法正常运行的四类高频故障：`Pending`、`CrashLoopBackOff`、
`OOMKilled` 与 `ImagePullBackOff`。适用于 Kubernetes 1.24 及以上、容器运行时为 containerd
的集群；Docker 作为运行时（1.24 之前）同样适用，仅日志路径不同。

不覆盖：节点级故障（kubelet 不健康、磁盘打满）、网络插件自身故障、控制面 etcd 性能问题，
这些请转《节点与网络排查手册》。

排查原则：**先看状态与事件，再看日志，最后才改配置**。跳过前两步直接调参，通常会把
「资源不足」误判成「应用 bug」，导致扩容掩盖真实原因。

## 2 三步定位法

### 2.1 第一步：确定 Pod 当前状态与所在阶段

```bash
kubectl -n <ns> get pod <pod> -o wide
kubectl -n <ns> get pod <pod> -o jsonpath='{.status.phase}{"\n"}{.status.reason}{"\n"}'
```

判定要点：

- `STATUS=Pending` → 未调度成功，看第 3 节。
- `STATUS=Running` 但 `READY=0/1` → 容器起来了但 readinessProbe 未通过，看 2.3 的探针部分。
- `STATUS=CrashLoopBackOff` → 已调度且启动过，进程反复退出，看第 4 节。
- `STATUS=ImagePullBackOff` / `ErrImagePull` → 镜像拉取失败，看第 6 节。

### 2.2 第二步：读事件（Events）

```bash
kubectl -n <ns> describe pod <pod> | sed -n '/Events:/,$p'
kubectl -n <ns> get events --field-selector involvedObject.name=<pod> \
  --sort-by=.lastTimestamp | tail -20
```

事件保留时间默认 1 小时（`--event-ttl`），**故障超过 1 小时后事件已过期**，
此时只能用 `lastState` 与节点日志回溯：

```bash
kubectl -n <ns> get pod <pod> -o jsonpath='{.status.containerStatuses[*].lastState}' | jq
```

### 2.3 第三步：读日志与退出码

```bash
# 当前容器的日志
kubectl -n <ns> logs <pod> -c <container> --tail=200

# 上一次崩溃（重启前）的日志 —— CrashLoopBackOff 必看
kubectl -n <ns> logs <pod> -c <container> --previous --tail=200

# 退出码与原因
kubectl -n <ns> get pod <pod> \
  -o jsonpath='{range .status.containerStatuses[*]}{.name}{" exit="}{.lastState.terminated.exitCode}{" reason="}{.lastState.terminated.reason}{"\n"}{end}'
```

`--previous` 是最容易被忽略的一步：容器重启后 `logs` 拿到的是**新进程**的输出，
往往是空的或用例启动阶段的几行，真正的 panic 堆栈在上一轮。

## 3 Pending 排查

### 3.1 判定标准

`Pending` 且事件中出现以下任一关键字，即确认是调度失败而非启动失败：

- `0/N nodes are available: N Insufficient cpu/memory`
- `node(s) had untolerated taint`
- `node(s) didn't match Pod's node affinity/selector`
- `persistentvolumeclaim "xxx" not found` / `waiting for first consumer to be created`
- `exceeded quota`

### 3.2 原因与处置对照

| 事件关键字 | 根因 | 处置 |
|---|---|---|
| `Insufficient cpu/memory` | 节点可分配资源不足 | 降 request、扩容节点池、或清理已完成 Pod |
| `untolerated taint` | 节点有污点，Pod 无对应 toleration | 加 toleration，或换节点池 |
| `didn't match node affinity` | nodeSelector/affinity 写错 | 核对标签 `kubectl get node --show-labels` |
| `pod has unbound immediate PVC` | StorageClass 为 WaitForFirstConsumer 但无可用 PV | 检查 SC 与 PV 容量 |
| `exceeded quota` | 命名空间 ResourceQuota 用满 | 提配额或清理无用工作负载 |

### 3.3 常用处置命令

```bash
# 看节点可分配与已分配资源
kubectl describe node <node> | sed -n '/Allocated resources/,/Events/p'

# 看命名空间配额使用
kubectl -n <ns> describe resourcequota

# 看节点污点
kubectl get node <node> -o jsonpath='{.spec.taints}'

# 看 PVC 是否绑定
kubectl -n <ns> get pvc
```

注意：`kubectl describe node` 的 `Allocated resources` 只统计 **request**，不统计实际用量。
若 Pod 未设置 request，调度器会把它们当作 0，于是出现「节点 CPU 已经 95% 但还能调度新 Pod」
的情况 —— 这类集群必须先补齐 request 再谈扩容。

## 4 CrashLoopBackOff 排查

### 4.1 判定标准

容器反复退出并被 kubelet 重启，重启间隔按指数退避增长：10s → 20s → 40s → … → 最大 300s（5 分钟）。
状态列显示 `CrashLoopBackOff`，`RESTARTS` 持续增长。

### 4.2 退出码语义

| 退出码 | 含义 | 常见原因 |
|---|---|---|
| `0` | 正常退出 | 容器主进程是短任务，缺 `command` 常驻逻辑 |
| `1` | 应用错误 | 配置缺失、依赖不可达、端口占用、panic |
| `137` | 128+9，被 SIGKILL | OOMKilled、livenessProbe 失败被杀、`kubectl delete` 超期 |
| `139` | 128+11，段错误 | 二进制不兼容、glibc 版本不匹配 |
| `143` | 128+15，SIGTERM | 优雅退出流程中被终止，通常是滚动更新正常现象 |
| `255` | 应用自定义 | 启动脚本 `exit -1` 或参数校验失败 |

### 4.3 处置顺序

1. **看 `--previous` 日志的最后 30 行**，定位是配置错误（`configmap not found`、
   `connection refused`）还是代码异常（panic、OOM、断言失败）。
2. **确认退出码**。137 且 `reason=OOMKilled` → 转第 5 节；137 但 `reason=Error` →
   检查 livenessProbe 是否过严。
3. **确认命令与入口**。`kubectl get pod <pod> -o jsonpath='{.spec.containers[0].command}'`，
   若镜像 ENTRYPOINT 是前台进程而 command 覆盖成了 `bash -c "xxx"`，进程退出后容器即结束。
4. **确认依赖可达**。在集群内起临时 Pod 验证 DNS 与端口连通：

```bash
kubectl -n <ns> run tmp-shell --rm -it --image=busybox:1.36 --restart=Never -- sh
# 容器内：
nslookup <service>.<ns>.svc.cluster.local
wget -qO- --timeout=3 http://<service>:<port>/healthz
```

探针过严的典型特征：`livenessProbe.initialDelaySeconds` 小于应用冷启动时间，
日志里能看到应用刚完成初始化就被 SIGTERM。此时应先调 `initialDelaySeconds` 与
`failureThreshold`，而不是加 `restartPolicy: Never` 掩盖问题。

## 5 OOMKilled 排查

### 5.1 判定标准

```bash
kubectl -n <ns> get pod <pod> \
  -o jsonpath='{.status.containerStatuses[0].lastState.terminated.reason}'
# 输出 OOMKilled 即确认
```

同时核实内核日志，区分「容器 cgroup 超限」与「节点整体内存不足」：

```bash
# 节点上执行
dmesg -T | grep -i -E "out of memory|oom-kill" | tail -20
journalctl -k --since "1 hour ago" | grep -i oom | tail -20
```

- 出现 `Memory cgroup out of memory: Killed process <pid> (java)` → 容器超 `limits.memory`。
- 出现 `Out of memory: Killed process <pid>` 且无 cgroup 前缀 → **节点内存耗尽**，
  kubelet 按 QoS 驱逐，`BestEffort` 最先死。

### 5.2 内存参数关系

- `requests.memory`：调度依据，也决定 QoS 等级（requests=limits 为 Guaranteed）。
- `limits.memory`：cgroup 硬上限，超过即 OOMKilled，**没有缓冲区**。
- JVM 类应用必须同时设置 `-XX:MaxRAMPercentage=75`（或 `-Xmx`），
  让堆上限低于 `limits.memory`，否则堆外内存（元空间、直接内存、线程栈）会把容器顶爆。
- Go 应用注意 `GOMEMLIMIT`（1.19+），否则 GC 目标是进程启动时的内存快照，容易滞后。

经验配比：`limits.memory` 应为应用稳定期 RSS 峰值的 1.3~1.5 倍；
`requests.memory` 取稳定期 RSS 的 1.0~1.1 倍。

### 5.3 处置步骤

1. 采集基线：`kubectl top pod <pod> --containers`，连续观察 10 分钟看峰值。
2. 若是启动即 OOM（几秒内），先临时把 `limits.memory` 翻倍，确认是否只是启动期需要更多内存。
3. 若是运行数小时后 OOM，检查是否内存泄漏：

```bash
# JVM：看老年代增长
kubectl -n <ns> exec <pod> -- jcmd 1 GC.heap_info
# 通用：看 cgroup 内存用量
kubectl -n <ns> exec <pod> -- cat /sys/fs/cgroup/memory.current 2>/dev/null \
  || kubectl -n <ns> exec <pod> -- cat /sys/fs/cgroup/memory/memory.usage_in_bytes
```

4. 同步评估节点侧：`kubectl describe node <node> | grep -A5 "Allocated resources"`，
   节点内存分配率超过 85% 时应先扩容，单靠调 Pod limit 会把风险转移到节点。

## 6 ImagePullBackOff 排查

### 6.1 判定标准

事件中出现 `Failed to pull image` + `unauthorized` / `manifest unknown` / `no such host` / `x509`。

### 6.2 处置

```bash
# 确认镜像地址与 tag 真实存在
crictl pull <registry>/<repo>:<tag>

# 确认 imagePullSecrets 是否存在且绑定正确
kubectl -n <ns> get secret | grep regcred
kubectl -n <ns> get pod <pod> -o jsonpath='{.spec.imagePullSecrets}'
```

- `unauthorized`：secret 过期或与 registry 不匹配，重新 `kubectl create secret docker-registry`。
- `no such host`：节点 DNS 或内网 registry 域名解析失败，在节点上 `nslookup <registry>` 验证。
- `x509: certificate signed by unknown authority`：内网 registry 使用自签证书，需把 CA 放到
  节点 `/etc/containerd/certs.d/<registry>/ca.crt` 并重启 containerd。

## 7 命令速查

```bash
kubectl -n <ns> get pod -o wide                              # 状态与节点
kubectl -n <ns> describe pod <pod>                           # 事件
kubectl -n <ns> logs <pod> --previous --tail=100             # 上次崩溃日志
kubectl -n <ns> get pod <pod> -o yaml                        # 完整定义
kubectl -n <ns> top pod --containers                         # 实时资源
kubectl get events -A --sort-by=.lastTimestamp | tail -30    # 全局事件
kubectl -n <ns> exec -it <pod> -- sh                         # 进容器
```

## 8 交接与升级条件

出现以下任一情况，转二线并保留现场（先 `kubectl get pod -o yaml > /tmp/<pod>.yaml`）：

- 同一 Deployment 的多副本在不同节点同时 OOMKilled；
- 事件为空但状态持续 Pending 超过 15 分钟；
- 节点 NotReady 或 kubelet 日志出现 `PLEG is not healthy`；
- 需要修改集群级配置（kubelet 参数、RuntimeClass、CNI 配置）。
