# 固定内核资源合同 v1

本计划冻结 14 个场景，各执行一次。输入、判据、工作量在运行前归档；保留原始失败。
不通过修改预算、延长时限、重试直到通过来替代失败。修订实现或夹具后，产生新候选、
新构建及新证据目录，历史证据仍保留。当前开发树的工具单元测试不代表实际合同通过。

## 场景与预算

默认实际 cgroup：`memory.max=1073741824`、`memory.swap.max=0`、
`cpu.max=200000 100000`、`cpu.max.burst=0`、`pids.max=256`、
`memory.oom.group=1`。进程 `oom_score_adj=0`，调度策略为 `SCHED_OTHER`，
没有生效的 BPF scheduler。systemd 固定 `CPUSchedulingPolicy=other`、
`LimitRTPRIO=0`、`RestrictRealtime=yes`、`NoNewPrivileges=yes`、空 capability 集合、
`ProtectControlGroups=yes`。每个 unit 的运行上限是 45 秒。

配置声明同样的上限；临时存储声明为 96 MiB / 6144 inode。cache、`/tmp`、
`/var/tmp` 分别是 64 MiB / 4096、16 MiB / 1024、16 MiB / 1024 的私有 tmpfs。
`SQLITE_TMPDIR`、`TMPDIR` 都固定 `/tmp`，工作目录是 cache。所有原生 fallback
（含 `/usr/tmp` 和 cwd）都被观察；同一设备的别名只计算一次且几何必须一致。
`/usr/tmp` 可以不存在，也可以是这三个挂载之一的别名，不能引入第四个未限制设备。

| 场景 | 相对于默认值的唯一资源变体 | 原始结果要求 |
| --- | --- | --- |
| valid | 无 | 正式 `scapd --check-config` 退出 0，唯一配置验证事件 |
| memory-unlimited | 实际 `memory.max=max` | 正式进程退出 1，唯一 `RESOURCE_ENVELOPE` 错误 |
| memory-over-budget | 配置内存声明减 1 byte | 同上 |
| swap-over-budget | 实际 swap 上限 1 MiB | 同上 |
| cpu-over-budget | 配置 CPU 声明 1999 ms/s | 同上 |
| tasks-over-budget | 配置 tasks 声明 255 | 同上 |
| storage-over-budget | 配置 tmpfs 总字节声明减 1 | 同上 |
| inodes-over-budget | 配置 tmpfs 总 inode 声明减 1 | 同上 |
| unbounded-fallback | 不挂载 `/var/tmp` 私有 tmpfs，观察到实际非 tmpfs fallback | 同上 |
| oom-not-grouped | `OOMPolicy=continue`，实际 `memory.oom.group=0` | 同上 |
| memory-pressure | 实际内存上限 64 MiB | 独立压力进程最多申请并逐页触碰 128 MiB；原 systemd `Result=oom-kill`、`CLD_KILLED` / SIGKILL |
| cpu-pressure | 实际 `cpu.max=20000 100000` | 1.2 秒有界忙循环；原 `cpu.stat` 的 throttle 次数及时间增长；退出 0 |
| tasks-pressure | 实际 `pids.max=16` | 最多尝试 32 个 owned sleep；EAGAIN、`pids.events.max` 增长；15 个子进程全部真实 wait，计数恢复 1 |
| storage-pressure | 无 | 超容量 `posix_fallocate` 返回 ENOSPC；删除后容量/inode 恢复；再分配、释放 1 MiB，容量再次恢复；退出 0 |

前 10 个场景执行正式 release 二进制，绝不创建 S3 client、领取 worker 或启动监听器。
后 4 个场景只证明真实内核执行了指定限制；它们不执行 SQL、不代表数据库恢复验证。
任务压力在全部 owned child 真正 wait 后，最多观察 5 秒等待内核任务记账恢复；不再
产生新子进程，也不重新执行压力。所有 unit 的 45 秒总运行上限仍保持不变。
`memory.max` 限制 cgroup 的内存记账，并有内核回收/OOM 语义；它不是任意采样时刻
进程 RSS 的精确硬阈值。CPU quota 是 CFS 周期预算，不是延迟 SLO。

## 来源、进程与退出证据

正式构建使用既有 `object-service/build.py`，原 Cargo stdout/stderr、源码 tar、
源码清单、二进制和 native archive 收据归档到 `build/`。oracle 单独调用
`object-network/audit_build.py::receipt(profile="service")` 完整核对；不信任 runner
的构建摘要，也不允许无二进制/native bytes 的部分审计冒充通过。源码 commit 必须一致。

本目录的全部 10 个文件及三个复用构建工具另有完整清单、源 tar 和 SHA-256，运行
前后校验。它们不加入既有产品构建输入枚举，因为它们既不链接进 `scapd`，也不改变
SDK/生产代码；独立源码归档绑定实际实验。oracle 同时核对当前夹具和归档原字节。

每个 unit 有随机、不复用的名字。systemd 的实际 `ExecStart` 是固定 Python
解释器（`-I -B`）、冻结的 `launch.py` 和确切的最终 argv。observer 先保存原始
`/proc`、真实 cgroup 控制文件、挂载几何、mountinfo、mount namespace、调度策略、
OOM 分数，以及目标可执行文件 hash，然后用 `execv` 在同一 PID 执行正式程序或
压力助手。systemd 原始 ExecMainPID、原 ExecStart 的 PID/argv/退出、单调时钟寿命
与 observer 互相绑定。observer 不修改限制、不替代产品准入。

runner 对自己启动的命令保留 argv、owned Popen PID、开始/真实 wait 时刻、退出码
和原 stdout/stderr；超时杀死并 wait 自己拥有的进程组。unit 结束使用实际
`ExecMainCode` / `ExecMainStatus` / `Result`，不读取自报 shell 式退出摘要。
原 stdout/stderr 不是“寻找某条 PASS 文本”：成功、拒绝及压力事件都有完整输出判据。

每例都显式 stop，并保留 `is-active` 的原 bytes 与真实退出码。成功 transient unit
在 stop 后可能卸载，`systemctl show` 的 not-found 不视为孤儿。此时仍要求
`is-active` 非活动证据，以及原 cgroup 路径已消失，或同一设备/inode 下 `cgroup.procs`
为空且 `cgroup.events populated=0`。两种证据缺一不可。临时凭据在证据目录之外创建，
原目录 0700、文件 0600，结束后销毁；任何 token 都不归档。

## 判定与反例

独立 oracle 重算 14 组固定 config、请求属性和真实 systemd/内核属性，核对源码与
正式构建、执行目标、原退出、全部压力判据和生命周期。runner 的 `status`、派生
exit/stop 摘要没有判定权。缺少环境或场景为 `NOT_RUN` / 失败，不补造 PASS。

`controls.py` 固定 24 个负控、2 个正控。负控会修改原字节并更新外层 hash，要求
命中指定语义规则，覆盖丢失案例、错误声明/实际限制、CPU burst、实时/BPF 旁路、
OOM 免疫、成员漂移、fallback 丢失/别名容量冲突、错误目标、错误原退出、CPU 未节流、
未回收子进程、空间未归还、活动 unit/残留 cgroup、归档源及构建二进制错配。
正控验证无权威摘要不起作用，以及 transient unit 卸载路径可正确通过。
控制复制使用硬链接且每次替换 inode；最后重新审计原 evidence，禁止修改基线。

## 信任与不覆盖范围

证据以受信 CI 宿主机、systemd/kernel 和冻结的采集工具为边界，hash 不是宿主机签名
或抗恶意管理员证明。部署器必须在生命周期内维持 cgroup membership、限制、挂载、
调度类、OOM 调整、临时路径和无 BPF scheduler；不得混入 OOM 免疫、实时/其它旁路
进程。单次启动验证不能约束拥有宿主机管理权限的后续操作。

本合同不声称 AWS Standard 资格、SQL 吞吐/延迟 SLO、租户之间的内核硬隔离、持续
过载下的业务公平性、完整 daemon OOM 后恢复或宿主机故障恢复。那些结论必须分别
来自对应的真实服务/持久性合同。所有原始失败保留。

内核及 systemd 语义参考：[cgroup v2 官方文档](https://docs.kernel.org/admin-guide/cgroup-v2.html)、
[systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)、
[systemd D-Bus 属性](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html)。
