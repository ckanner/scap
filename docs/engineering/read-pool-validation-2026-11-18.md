# 同库强读池：2026-11-18 本地实际验收

**结果：固定同库读池合同通过，21 个 SDK 命令、27 次 HTTP POST，以及 19 个定向负控和
1 个原始正控全部通过。** 这里认证的是正式 release `scapd`、原 Node SDK、native
SQLite 与本地 SeaweedFS 的一次完整执行；AWS S3 Standard、生产吞吐和延迟 SLO 均为
`NOT_RUN`。本页不认证组合候选的全仓覆盖门禁或远端 CI。

执行候选为 [`a2cc536770d7fc2e1b155d439616e29d25ad724a`](https://github.com/ckanner/scap/commit/a2cc536770d7fc2e1b155d439616e29d25ad724a)，
属于 [PR #66](https://github.com/ckanner/scap/pull/66) 的开发工作。
协议见[同库强读池设计](../../crates/scap-service/docs/read-pool.md)，固定场景见
[read-pool 实验](../../experiments/read-pool/README.md)，完整计数、原始证据 SHA-256
和分类见[机器记录](../evidence/read-pool-local-2026-11-18.json)。

## 1. 精确源码、构建与证据范围

| 标识 | 实际值 |
| --- | --- |
| 执行与构建源码提交 | `a2cc536770d7fc2e1b155d439616e29d25ad724a` |
| 全部 tracked 源码清单 | 864 个文件，包含夹具及其复用 helper |
| 正式 release 构建输入 | 309 个文件，5,114,837 字节 |
| 构建过程 | Rust 1.90.0、`--release --locked`；原 Cargo exit 0、最终 `build-finished.success=true` |
| SDK 运行时与后端 | Node v22.16.0、固定 SeaweedFS 4.51 |
| 二进制与 native archive | 独立 auditor 实际取回字节并核验；无缺失 artifact |
| 运行证据标识 | `next-read-pool-first` |

运行前后 `source.json` 与 `source-after.json` 完全相同。`source.tar` 保存全部
864 个跟踪文件；正式构建另存原 Cargo 输出、构建清单和 `build-source.tar`。
夹具没有扩大既有 builder 的输入规则，而是把自身与全部 helper 的源码另外闭合。
独立 oracle 验证两份源码范围一致交叠、实际配置与调用二进制，以及原始 Cargo 和
native link 证据，得到 `verification_scope=full`。本页和机器记录在执行后新增，
不属于上述 864 个冻结文件。

| 原始证据或 artifact | SHA-256 |
| --- | --- |
| `scapd` | `8d99dd7380aa1aa34270edf34748e16025fc06a6144b9b870ede398ee78ad47b` |
| `liblibsql.a` | `ab0981f53ac70eeafa604624f6ee4fdff0754f8b9195c713be35e138a85ba3f5` |
| 原 `next-combined-release-second-build/build.json` | `16cfbae97cfee89163cea62ae82f0eefdadbb2694dfabaf86451960b48ff06b5` |
| 归档后的 `build/build-receipt.json` | `bb8abe8cbef84fcd5b045b94cf3f56e7b5ec77dad500c0d6100d8ea95e8e9eea` |
| `source.json` 与 `source-after.json` | `de7a72dd0e1e2c6d38d3b1b01e1fd2e884cd83c7da55e7fef04386f0696b4c68` |
| `source.tar` | `48680472c5c4fc03be703f07c79c518e3c817db28da9a48209d64437f42ccac9` |
| 原始 `result.json` | `72627a3ea7b89894c7d622095c39e5e39151efc8b4644bc0134145231721de04` |

原 build receipt 与归档 receipt 的 hash 不同，因为后者增加归档文件的绑定信息；
二者绑定同一 release executable 和原构建过程。机器记录中的本机路径只用于检索
原始证据，不是永久下载地址。摘要不能替代原始账本、构建输出和源码归档；这些原始
文件、运行配置、凭据与数据库均未作为本次文档提交内容。

## 2. 配置与实际结果

读池显式配置为 `workers=3`、`active_per_tenant=2`、`active_per_database=2`。
另有 2 个 writer actor 槽位、1 个 control worker；每个 worker 的操作后缓存预算为
8,192 页，恢复并行度为 4。两个租户分别使用同编号数据库，主库固定三行整数和
非确定的 `random()` 原始写结果。本次配置未启用 `resource_envelope`。

| 实际观察 | 数量或结果 |
| --- | ---: |
| SDK 命令 / 原始 HTTP POST | 21 / 27 |
| 成功 Query | 9 |
| 全部实际签名 S3 请求 | 183 |
| 业务 S3 请求 / 永久 worker claim 请求 | 181 / 2 |
| accepted object versions / 条件 PUT 响应 | 34 / 34 |
| exact GET body/ETag 对 | 146 |
| 线性化因果约束 | 178 |
| 明确在转发前 blackhole 的 GET | 1 |
| 原始非确定结果 / 原身份 lookup | 4 / 3 |
| 结束前观察到的私有 SQLite 镜像 | 5，device/inode 与 worker 目录无别名 |
| 正常服务退出、SDK 退出与缓存清理 | 通过 |
| 4 个 owned 后端子进程回收 | 通过，原 `wait4` 证据完整 |

HTTP 与 S3 原始请求、响应、完整字节及 ETag 均被保存和校验。并发场景有 33 个 S3
请求落入多个合法 HTTP 调用区间；oracle 校验相容的原始区间和对象版本约束，没有
把它们冒称为逐项唯一的 HTTP 归因。代理退出时的 HTTP/S3 高水位计数与原始账本
分母一致，未通过省略尾部交换来闭合证据。

## 3. 并发、刷新与失败合同

| 场景 | 判据与实际结果 |
| --- | --- |
| 同库并行读 | 两个 Query 都在释放任意 gate 前进入不同的真实 HEAD GET；原单 actor 无法满足这个区间条件。 |
| writer/control 与租户公平性 | 两条读被停驻期间，另一租户 Query、主库写和 control status 全部完成；第三个同租户请求已送到服务，在额度释放后完成。 |
| 同一 reader 的 stale refresh | 先以另一租户两个真实 GET 停驻两个 reader，剩余唯一 reader 完成 warm、主库提交第三行后再 Query。恰好三次 HEAD GET 分别对应 stale 检查、重新恢复和新鲜 Query 检查，结果包含三行。 |
| 强读依赖不可用 | 原 HEAD GET 在转发前 blackhole，返回 UNKNOWN；本阶段仅一次 HEAD GET、无对象写和 SDK 重试。 |
| Query 只读边界 | Query 中的 INSERT 返回 ENGINE；该阶段没有对象 PUT，最终库中不存在被拒绝的第 99 行。 |
| 权限撤销 | 独立 reader 的 READ 被撤销后，新 Query 返回 DENIED；权限修改与请求仍使用原始认证身份。 |
| 原结果与请求身份 | 主库三个非确定写事务按原 request identity lookup，原 receipt 和结果字节完全相同；固定命令集合、保存的身份、scope 与实际 wire 请求逐项绑定。 |
| 私有资源与退出 | 五个镜像不复用 inode 或 worker 目录；正常 SIGINT 后服务退出，全部缓存清空。SDK 和四个后端子进程也有 owned 身份与回收记录。 |

每条 Query 仍依赖新的授权 HEAD；此实验没有增加缓存授权租约。允许的 stale 重建
严格发生在用户 SQL 之前，最多一次；它不改变 writer 的原 HEAD CAS、原请求 UNKNOWN
处理或 durable-before-ACK 顺序。运行中的完整私有镜像、GC 和 owner 交接的协议边界
见[设计](../../crates/scap-service/docs/read-pool.md)；本固定实际合同没有额外执行
并发 GC 或 owner 交接。

## 4. 负控的准确范围

19 个负控都是对本次已验证证据的定向修改，不能算成 19 次新的故障执行。

- **8 个完整原始证据负控**：修改配置计划、删除原 HTTP 响应、重复 SDK POST、修改
  响应字节、替换 S3 签名身份、替换原 lookup 结果、制造私有镜像 inode 别名、伪造
  正常退出状态。每项都由完整 raw verifier 在指定判断处拒绝。
- **11 个区间投影负控**：将同库读改成串行、用无关 GET 代替、把一次 GET 计成两条
  reader、分别阻止另一租户/writer/control 进展、绕过活跃额度；让 warm、write 或
  refresh 中任一项逃出唯一剩余 reader 的区间；以冷 reader 的单次 GET 代替 stale
  镜像重建。它们明确标为 `interval_projection`，只认证因果判断边界，不认证新的
  S3 执行或完整 raw-history 变体。

负控前后都复核原始正例相同，1 个原始正控通过。oracle 的 12 个单元测试另外检查
了这些区间边界和 SDK 十进制字符串时钟格式；它们不计入 Rust 单元覆盖，也不替代
真实执行。[固定 oracle 与负控入口](../../experiments/read-pool/README.md)

## 5. 覆盖历史与保留问题

独立开发分支曾运行 fresh unit-only LLVM：898 个 Rust 单元通过，76 个生产文件的
行、函数、region、branch 均精确 100%。该记录只属于当时的独立分支，不能套用到
含资源边界和 fleet 改动的组合候选。

随后组合覆盖发现 scheduler 的真实 `Readers::pop` 单态存在不稳定的测试路径：
初始两条 Query 是否同时排队依赖线程调度，导致 `if !database.empty()` 的 true
分支和剩余队列重排有时未覆盖。第一次组合报告保留为失败：1 行、3 regions 和
1 分支缺失。测试修正提交 `8946ec6` 先固定停驻两个实际 worker，再排入两条同库
请求，依次释放并断言排队数从 2 到 1 到 0；生产代码与门禁阈值均未改动。
修正后的定向 nightly 单元通过，并已包含在本次实际执行候选中。

本实际执行开始时，组合 full unit 的 911 个测试通过，但 strict gate 仍有另一处
GC region 缺口需要处理。因此 **911 个测试通过不等于组合四维覆盖通过**。本页的
组合覆盖状态为 `NOT_CERTIFIED_BY_THIS_REPORT`，最终结果必须由对应组合报告给出；
实际 HTTP/S3/native profile 没有并入任何 Rust unit profile。

本次 `next-read-pool-first` 实际执行与负控没有失败。更早开发阶段的编译 ENOSPC、
测试类型错误、daemon 测试预期字段错误、首轮覆盖缺口及上述组合调度覆盖失败，
仍属于保留的开发记录；它们没有被计入这里的一次实际通过。SeaweedFS 版本检查
打印过环境 netlink 权限告警，随后后端 readiness、真实签名请求及全部 oracle
正常完成；本报告不把该告警解释成额外的产品故障注入。

## 6. 时间、能力边界与复核入口

原始单机 monotonic 事件差值为：`probe_started → probe_stopped` 917,144,722 ns，
`service_started → service_stopped` 1,071,391,852 ns。这些是指定父进程观察事件之间
的差值，不是完整启动耗时、SQL 延迟样本或吞吐基准；后端 provisioning 与部分
启动观察开销不在这些区间内。没有预热/稳态负载分布、统计样本或生产资源组合，
因此不能据此推导 TPS、p99、成本、RSS 硬上限或 SLO。

本切片提供同库有界并行强读，保持单 writer actor 和完整私有镜像。它没有实现
group commit、lazy VFS、共享 WAL reader 或新的 MVCC 引擎。AWS S3 Standard、目标
IAM、生产吞吐/容量/成本及内核资源隔离验收均不在本次实际通过范围。

冻结候选与原构建 artifact 仍可获取时，运行和复核入口为：

```sh
python3 experiments/read-pool/run.py \
  --binary /path/to/scapd \
  --build-record /path/to/build.json \
  --weed /path/to/weed \
  --node /path/to/node \
  --evidence /path/to/new-evidence-directory
python3 experiments/read-pool/oracle.py /path/to/original-evidence-directory
python3 experiments/read-pool/controls.py /path/to/original-evidence-directory
```

运行器要求新证据目录，禁止带覆盖 instrumentation；它在原始实际结束后执行完整
oracle 与 19 个负控。独立复核还检查本机源文件和原 executable/native archive，
源树变化或 artifact 缺失时不能把当前目录当作原冻结候选重新宣称 full 通过。
