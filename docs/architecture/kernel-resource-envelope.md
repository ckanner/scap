# 内核资源边界与启动准入

本切片在既有请求、结果、恢复和队列预算之外增加可选的 `resource_envelope`。
Linux 部署器先建立有界 cgroup v2 和私有临时文件系统；`scapd` 在读取凭据、永久
占用 worker 身份及开始服务前检查实际内核配置。直接使用 Rust assembly 的调用方
也会在占用身份前重复检查。服务自身不修改宿主资源配置、不移动进程。

## 合同

```json
{
  "resource_envelope": {
    "version": 1,
    "memory_bytes": 1073741824,
    "swap_bytes": 0,
    "cpu_millis_per_second": 2000,
    "tasks": 256,
    "temporary_bytes": 100663296,
    "temporary_inodes": 6144
  }
}
```

这是一份小型验收配置示例，不能覆盖默认 10 GiB 数据库的完整镜像空间。生产配置
需计入写 actor、读池镜像、并行恢复、WAL、临时排序、对象缓冲和结果的峰值需求。
CPU 的 2000 表示带宽配额/周期的比值最多为 2，不保证任意滑动时间窗内的瞬时
用量、两核吞吐或延迟。合同要求 `cpu.max.burst=0`，仅支持普通 fair-class 调度。[1]

| 检查 | 拒绝条件 |
| --- | --- |
| `/proc/self/cgroup` | 非唯一 v2 路径、路径逃逸、前后成员关系改变 |
| 当前 cgroup | 打开的目录不是 cgroup2、非 domain、`cgroup.procs` 不含本进程 |
| `memory.max` / `memory.swap.max` | `max`、非法值，或超过声明上限 |
| `pids.max` | 无限、零或超过声明上限；tasks 包含线程 |
| `cpu.max` | 无限、非法周期或配额，或配额/周期超过声明值 |
| CPU 调度与突发 | `cpu.max.burst` 非零、调用线程不是普通 `SCHED_OTHER`，或存在未禁用的 BPF `sched_ext` |
| `memory.oom.group` / 自身 `oom_score_adj` | 必须启用整组 OOM 策略，自身不得设为 OOM 免疫的 -1000 |
| 缓存与所有 native 临时目录候选 | 非有限 tmpfs、不可读、同设备容量前后不同，或去重后的总容量/总 inode 数超过声明 |

临时目录名单由固定 native 适配器统一提供，包括 `SQLITE_TMPDIR`、`TMPDIR`、
`/var/tmp`、`/usr/tmp`、`/tmp` 和工作目录。不存在的 fallback 可以跳过；权限错误
不能当作不存在。多个 bind 路径按实际设备去重，多个 tmpfs 的容量相加。普通本地
ext4/XFS 仍能使用原有逻辑预算路径；本切片未实现它们的项目配额认证，因此启用
此合同后会拒绝这些未认证的临时文件系统。tmpfs 的 `size` 与 inode 上限由内核
执行；其内存也受 cgroup memory 控制器约束。[1][2]

`memory.max` 是 cgroup 内存控制机制，覆盖范围比单进程 RSS 更广，内核也允许某些
情况下短暂超过阈值。本合同不声称每一瞬间 RSS 都不超过给定数字。[1]

## 生命周期与失败

缺少该字段保持既有行为，同时不声称启用了内核资源隔离。配置错误返回 `CONFIG`，
读取或验证实际内核边界失败返回 `RESOURCE_ENVELOPE`。失败发生在永久 worker
claim 和监听之前；已配置的内核检查不可因平台不支持而降级跳过。

管理员可以运行 `scapd --check-config /path/config.json`。它执行真实配置、文件系统、
内核边界和凭据解析校验，输出 `configuration_validated` 与是否启用此合同；不建立
S3 客户端、不 claim worker、不打开 HTTP 监听。它不认证 S3 权限或端点可用性。

OOM、ENOSPC 或任务额度耗尽仍按现有失败合同处理。进程死亡后，客户端保留原请求
身份并查询 S3 中的原结果，不能盲目重放 SQL。内核资源限制不会把未发布事务变成
成功，也不会把本地文件变成持久权威。跨租户的逻辑额度和公平性仍由调度器负责；
共享一个 cgroup 的进程共同消耗该组额度，不能把组上限解释为每租户硬隔离。

部署器必须控制进程生命周期中的 cgroup、挂载、环境、工作目录与目录命名空间，
并禁止业务进程重新挂载、修改 cgroup 或提权。全部缓存和临时候选的祖先目录、
symlink 及目标必须保持解析不变；不能让不受信主体把缺失 fallback 变成可写目录。
proc/sysfs/cgroup 视图由可信部署器提供，本检查不是对恶意伪造挂载命名空间的认证。
这些要求与现有 native 本地文件系统准入的信任边界一致。
启动检查不防御拥有宿主权限的操作者在运行中放宽资源限制。
内核不会因整组 OOM 杀死 `oom_score_adj=-1000` 的任务，因此部署器也不得向该组
加入免疫的邻居进程，或在准入后把 worker 改成免疫。生产进程应撤销修改挂载和
cgroup 的权限，保持 `OOMScoreAdjust=0` 与 `NoNewPrivileges=yes`。[1]

`cpu.max` 不约束实时调度类；BPF 调度器也可能接管普通任务但不执行该带宽限制。
因此准入检查当前调用线程的 `/proc/thread-self/stat` 调度策略，以及存在时的
`/sys/kernel/sched_ext/state`。部署器必须保证组内全部任务与后续线程保持普通调度，
运行期间不加载 BPF 调度器。可配置 `CPUSchedulingPolicy=other`、`LimitRTPRIO=0`
和 `RestrictRealtime=yes`；直接嵌入 Rust assembly 的宿主也必须遵守这些前提。[1][6]

## 部署与验收

systemd 可使用 `MemoryMax`、`MemorySwapMax`、`CPUQuota`、`TasksMax`、`OOMPolicy=kill`
以及 `TemporaryFileSystem` 建立这些条件；`OOMPolicy=kill` 对应 `memory.oom.group=1`。
`PrivateTmp=yes` 本身不保证磁盘容量有限，必须明确有限挂载；工作目录和全部
SQLite fallback 也应指向这些挂载。[3][4][5]

固定实际合同在 [kernel-envelope](../../experiments/kernel-envelope/README.md)：
真实 systemd/cgroup/tmpfs 的配置正例与定向拒绝，另用有界压力进程观察 OOM、CPU
throttle、pids 拒绝及 ENOSPC/释放。压力进程验证内核执行，不替代 SCAP 的 SQL/S3
故障恢复合同；组合 CI 同时保留原完整恢复合同。本地执行环境没有可用 cgroup2 时
记 `NOT_RUN`，由具备真实内核能力的固定 CI 作业执行，不能用模拟文件给出通过。

## 官方依据

1. [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
2. [Linux tmpfs](https://docs.kernel.org/filesystems/tmpfs.html)
3. [systemd resource control](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html)
4. [systemd OOMPolicy](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html#OOMPolicy=)
5. [systemd TemporaryFileSystem](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#TemporaryFileSystem=)
6. [Linux extensible scheduler](https://docs.kernel.org/scheduler/sched-ext.html)
