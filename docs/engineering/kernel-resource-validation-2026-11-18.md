# 内核资源合同：2026-11-18 首轮实际验证

**固定候选的 14 个实际场景、独立 oracle、24 个负控和 2 个正控全部通过。**
这份结果来自专用 GitHub `ubuntu-24.04` runner 的真实 systemd/cgroup v2/tmpfs。
本地合成工具单元未计入实际通过数，也没有用模拟内核文件补齐场景。
完整机器记录见 [kernel-resource-validation-2026-11-18.json](kernel-resource-validation-2026-11-18.json)。

## 精确来源

| 项目 | 值 |
| --- | --- |
| PR | [#66](https://github.com/ckanner/scap/pull/66) 首轮候选 |
| PR head | `a2cc536770d7fc2e1b155d439616e29d25ad724a` |
| head 完整树 | `a1cc6966e11918aee9a51b498e3ebf20b49528ca` |
| CI 实际 checkout / build commit | `b1fd8ff64b8f159f8dea7aed883f6831c725df61`，该候选的 PR merge ref |
| 工作流 / job | [44258165625 / 134644762946](https://github.com/ckanner/scap/actions/runs/44258165625/job/134644762946) |
| 原始 artifact | [14407665312 · next-kernel-envelope-evidence](https://github.com/ckanner/scap/actions/runs/44258165625/artifacts/14407665312) |
| 原 ZIP | 35,402,649 bytes，6,810 个条目，包含原基线和全部控制副本 |
| 操作系统 | Ubuntu 24.04.5；Linux `7.0.0-1017-azure`，x86_64 |
| systemd | `255 (255.4-1ubuntu8.18)` |
| Rust / Node | Rust 1.90.0；Node 22.16.0 |

原 ZIP SHA-256：

```text
04a79fa1e1d9ef9df489259dbab45dff6fafde2f1b03c78040bf154b7f25dd76
```

CI 正式 release `scapd` SHA-256：

```text
40afacb26c85aae968ce10c17b233f13f6254bdc7e7f56e62f14f5a07d566c80
```

CI 中独立构建审计的范围为 `full`：正式二进制、native archive、原 Cargo 输出和
完整源码清单均在原 runner 核验。取回 ZIP 后再次核对了 **309 个构建输入、13 个
夹具输入与冻结 head 一致**，以及 **238 个案例原文件的 hash**；独立重读源码 tar、
manifest 和 Cargo 事件。取回环境没有原 runner 的全部 executable/native 路径，
因此离线重审仅称归档源码、Cargo 与原案例字节核验，不冒充第二次完整运行。

本报告仅限定上述候选。随后 GC 单元 region 补测、独立实验 lockfile 修正及其他
候选变动，均不能继承“最终 head 已通过”的表述；最终 PR head 仍须运行自己的 CI。

## 实际结果

默认 unit 使用 1 GiB 内存、零 swap、`cpu.max=200000 100000`、零 CPU burst、
256 tasks；三个私有 tmpfs 合计 96 MiB / 6,144 inode。`oom_score_adj=0`、
`SCHED_OTHER`、无生效 BPF scheduler，且采用受限权限和只读 cgroup 配置。
各变体及固定命令见[冻结计划](../../experiments/kernel-envelope/PLAN.md)。

| 原场景 | 原进程结果 | 判定 |
| --- | --- | --- |
| valid | 正式 `scapd --check-config` 退出 0；唯一配置验证事件 | 通过 |
| memory-unlimited | `RESOURCE_ENVELOPE`；退出 1 | 通过 |
| memory-over-budget | `RESOURCE_ENVELOPE`；退出 1 | 通过 |
| swap-over-budget | `RESOURCE_ENVELOPE`；退出 1 | 通过 |
| cpu-over-budget | `RESOURCE_ENVELOPE`；退出 1 | 通过 |
| tasks-over-budget | `RESOURCE_ENVELOPE`；退出 1 | 通过 |
| storage-over-budget | `RESOURCE_ENVELOPE`；退出 1 | 通过 |
| inodes-over-budget | `RESOURCE_ENVELOPE`；退出 1 | 通过 |
| unbounded-fallback | `RESOURCE_ENVELOPE`；退出 1 | 通过 |
| oom-not-grouped | `RESOURCE_ENVELOPE`；退出 1 | 通过 |
| memory-pressure | 原 `ExecMainCode=2` / `ExecMainStatus=9`，systemd `Result=oom-kill` | 通过 |
| cpu-pressure | 原 CPU throttle 计数及时间增长；退出 0 | 通过 |
| tasks-pressure | EAGAIN 和内核计数增长；owned child 全部 wait；退出 0 | 通过 |
| storage-pressure | ENOSPC、释放、再分配及再次释放；退出 0 | 通过 |

压力读数来自原 stdout 和内核观察：

| 压力 | 实测 |
| --- | --- |
| 内存 | `memory.max=67,108,864` bytes、`memory.oom.group=1`；有界逐页触碰最终触发真实 OOM kill |
| CPU | 原 1.200145689 秒工作窗口内，`nr_throttled` 增加 12，`throttled_usec` 增加 960,805 |
| tasks | 15 个子进程全部实际 wait，退出值均为 `-15`；`pids.current` 从 16 恢复至 1 |
| tmpfs | ENOSPC 后和再写入/释放 1 MiB 后，都恢复至 16,384 个空闲 block、4,095 个空闲 inode；owned 文件不存在 |
| 清理 | 14 个 stop 命令均成功；4 个 unit 为 `inactive`，10 个保留为 `failed`，全部非活动；14 个原 cgroup 路径均已消失 |

14 个场景的 runner 总观察时间约 3.9914 秒。这是固定有界故障合同的运行时间，
不是持续业务稳定性或延迟 SLO 样本。`MemoryPeak` 原值被保留，但不参与 RSS 上限判定。

## 证据链与控制

实际属性不是 runner 自报配置：同 PID observer 保存原 `/proc`、cgroup 控制文件、
挂载几何与 namespace、目标二进制 hash，随后 `execv` 正式进程。原 systemd 的
ExecStart、ExecMainPID、退出和时间与这些观察绑定。所有 native fallback 都核对，
同一设备的别名容量只计一次，声明配置与实际限制分别验证。

独立 oracle 从原字节重算结果；runner 的 `status` 或派生退出摘要不具判定权。
24 个负控修改原字节并修复外层 hash，全部命中指定语义规则，覆盖错误配置/限制、
CPU burst、实时/BPF 旁路、OOM 免疫、cgroup 成员漂移、fallback/别名容量、执行目标、
错误退出、压力未生效、资源未释放、原源码与构建错配。2 个正控验证摘要不影响权威
判定，以及 transient unit 卸载路径合法。每个命中的规则均在机器记录中列明。

## 结论的边界

这份证据闭合了**冻结配置下的启动资源准入与四种内核限制行为**。它不执行 SQL/S3
工作负载，不证明 daemon 被 OOM 杀死后的数据库恢复、租户之间的内核硬隔离、真实
AWS Standard 或生产 SLO。`memory.max` 是 cgroup 记账、回收和 OOM 机制，不是
任意时刻单个进程 RSS 的精确上限；CPU quota 是周期预算，不是响应时间保证。

部署器仍须在生命周期内保持 cgroup membership、上限、挂载、目录解析、调度类和
OOM 调整稳定，不加入免疫/实时旁路进程，不启用 BPF scheduler。源码 hash 和原观察
不能替代对宿主机管理员及采集环境的信任。相关生产边界见
[内核资源设计](../architecture/kernel-resource-envelope.md)。
