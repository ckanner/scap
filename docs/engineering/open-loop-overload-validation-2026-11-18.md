# 开环过载与 SQL batch：2026-11-18 首轮验证记录

**首轮 CI 的正式构建、固定实际工作负载、独立 oracle、完整控制脚本和证据上传均已
成功。原 ZIP 因超过连接器 512 MiB 下载上限，尚未独立取回。** 因此本报告明确记录
CI 门禁通过和交付缺口；TPS、延迟分位数、具体状态分布、资源峰值等原始读数仍待取回，
没有从运行时间、测试代码或其他实验推算填充。

机器记录见 [open-loop-overload-validation-2026-11-18.json](open-loop-overload-validation-2026-11-18.json)。
相关[内核合同报告](kernel-resource-validation-2026-11-18.md)的较小 artifact 已完整取回，
其独立复核不受这个大 ZIP 的下载限制影响。

## 精确候选和已取得的证据

| 项目 | 值 |
| --- | --- |
| PR | [#66](https://github.com/ckanner/scap/pull/66) 首轮候选 |
| PR head | `a2cc536770d7fc2e1b155d439616e29d25ad724a` |
| head 完整树 | `a1cc6966e11918aee9a51b498e3ebf20b49528ca` |
| CI 实际 checkout | `b1fd8ff64b8f159f8dea7aed883f6831c725df61`，该候选的 PR merge ref |
| 工作流 / job | [44258165625 / 134644763034](https://github.com/ckanner/scap/actions/runs/44258165625/job/134644763034) |
| 原始 artifact | [14408010850 · next-object-overload-evidence](https://github.com/ckanner/scap/actions/runs/44258165625/artifacts/14408010850) |
| job 结论 | `completed / success` |
| 原 ZIP 大小 | 1,044,566,776 bytes |
| 上传日志中的文件数 | 250,770 |
| 已取得的原 job log | 45,903 bytes；具体 SHA-256 见下 |

原 job log SHA-256：

```text
e23c648c159a0682ae2f96940decc174bcaace2d4ec41e97992fb42ec1e59a8b
```

GitHub 元数据和原上传日志报告的 ZIP SHA-256：

```text
b3865e8a275fb3f87faa2cb29098fccbb60ba14a464d0047ae3cc8c19f988895
```

这个 ZIP hash 尚未通过本地 ZIP 字节重新计算。原日志中的 release 构建事件报告
`status=passed`，`scapd` SHA-256 为：

```text
40afacb26c85aae968ce10c17b233f13f6254bdc7e7f56e62f14f5a07d566c80
```

记录只适用于上述候选。之后的 GC 单元补测、独立实验 lockfile 修正及新的交付包装，
应绑定各自的新 CI，不能被这份首轮结果提前认定通过。

## 原日志与 CI 状态实际证明了什么

| 步骤 | 已观察结果 |
| --- | --- |
| Build and bind the complete current service and SDK | `success`；原 release hash 如上 |
| Observe the complete fixed actual contract | `success`；runner 的原摘要为 `OBSERVED_NOT_AUDITED` |
| Independently audit original bytes and all negative controls | `success`；固定 oracle 和 controls 两个命令都完成 |
| Retain original successes and failures without claiming production SLO | `success`；原 artifact 已完成上传 |

runner 的原摘要时间是 `2026-11-18T07:26:00.2066810Z`，其中
`private_removed=true`、`cleanup_errors=[]`、`aws_standard=NOT_RUN`、
`production_slo_passed=false`。runner 自身没有声称已经审计。

独立步骤采用失败即退出的 shell，依次执行固定 `oracle.py` 和 `controls.py`。
两个 JSON 输出分别重定向至 artifact 中的 `oracle.json`、`controls.json`，没有
打印在 job log 中。冻结的 controls 实现要求 **18 个负控、1 个正控和最终原件重审**
均成功才正常完成。因此 CI 进程门禁通过可以确认，但尚不能写成“原 controls JSON
已取回逐项核对”或“全部原字节已在本地再次审计”。

## 冻结的工作量和合同

以下是[固定计划](../../experiments/object-overload/PLAN.md)及
[输入规格](../../experiments/object-overload/spec.py)中的声明，不充当尚未取回的性能读数。

| 项目 | 冻结值 |
| --- | --- |
| 拓扑 | 4 库、2 租户、1 个正式 worker；`admission.read_pool=null` |
| 完整 HTTP 分母 | 4,340 次 POST；其中 1,036 个原 execute 身份 |
| 热点开环写 | 32 次/秒，共 960 次 |
| 另一租户强读 | 4 次/秒，共 120 次 |
| control | 2 次/秒，共 60 次 |
| 开环窗口 | 30 秒；共 1,140 个预定到达，固定 6 个 5 秒进展窗口 |
| 到达偏移上限 | 1,000 ms；不能通过移动计划时间掩盖迟到 |
| 单语句组 | 64 个独立事务，写 64 行 |
| 显式 SQL batch 组 | 8 个事务，每个 8 条语句，同样写 64 行 |
| SQL 重试 | 原 SQL 只发送一次；不因 UNKNOWN、拒绝或传输结果不明而重放 |

独立 oracle 检查完整计划与原 HTTP 分母、各窗口内的实际进展、服务 BACKPRESSURE、
原请求身份的 lookup/cancel/lookup 收敛、原随机结果与最终完整行、HEAD 发布前完整
不可变依赖回读，以及 owned 进程/资源与私有目录回收。18 个负控覆盖丢失到达、
移动时间表、删除慢请求、伪造成功、窗后进展、请求/结果身份变更、S3 发布与回读
错序、worker 条件创建、二进制/进程身份、采样丢失和回收缺失等。

同样 64 行可以用于比较逻辑工作量，但 8 个 batch 事务不能计成 64 个独立事务；
报告应同时给出事务/s 和逻辑操作/s。固定先 single 后 batch 的一次对照不构成稳定
提速比例或统计置信区间。本次 read pool 明确关闭，不用这组结果推断并行读池效果。

## 尚未取回的读数

下列字段在机器报告中保持未取得状态：

- 各原状态的次数、成功事务数及实际 committed/cancelled 分布。
- 各阶段事务/s、逻辑操作/s、调用延迟及从预定到达计算的延迟分位数。
- S3 请求数、方法分布、原请求/响应字节，以及发布依赖数量。
- 原 proc 采样的 RSS/HWM、FD、线程、cache/backend 空间峰值与 wait4 读数。
- 原 fixture/source archive、全部 HTTP/S3 原字节及每个 controls JSON 的本地重审。

这些缺口是原件取回受阻，不能通过另跑短 TPS 样本或删除控制副本来填补，也不能
借此宣称历史 GET-elision 候选约 24% 回退已归因或解决。

## 交付包装修复

下载连接器的原错误是：

```text
InvalidInputException: Artifact exceeds max size of 536870912 bytes: 1044566776 bytes.
```

完整目录包含 `build/`、`run/`、顶层汇总，以及 `controls/` 下的 `summary_changed/`
正控和 18 个负控完整副本。控制复制使用硬链接，变异时替换 inode；普通 ZIP 上传
把同一原字节重复保存。原 artifact 保留，没有为了取回而重跑旧工作负载。

后续候选已准备将**整个 evidence 目录打包为保留硬链接的 `tar.gz`**，记录包的
SHA-256，再以 `compression-level=0` 上传 tar 和校验文件。所有原件、路径、控制副本
及门槛保持；新包装尚未在本报告所述 CI 中上传或验证，必须等待下一轮实际交付。
若还需分片，每个分片都应是单独可下载的 artifact，并记录各片及完整包的 hash。

## 范围

本合同面向本地认证 S3 兼容端点和完整观察代理；它不提供 AWS Standard 资格、
无代理吞吐/延迟 SLO、无限持续运行或任意负载下的公平性保证。RSS 采样不是硬上限，
SQL batch 也不改变单库串行 writer 的协议。最终资格还需要当前候选的完整 CI 和
可取回的原证据；本报告不会将首轮 job 成功扩展成这些额外结论。
