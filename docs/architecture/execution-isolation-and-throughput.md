# 活跃数据库执行隔离与吞吐边界

本轮审查基于 [PR #68](https://github.com/ckanner/scap/pull/68) 合入后的 `3be8be7`：
每库一个 writer actor，可显式启用独立强读池；不同数据库的 actor 可以并行。
已经合入[独立事务 group commit](independent-group-commit.md)，默认关闭，组合已入队
的连续请求并保留逐事务语义。单库 SQL 仍串行；没有 lazy VFS 或并行 writer。

#66 的冻结组合 stable/nightly 各 911 项单位、77 个 Rust 生产文件逐文件四维精确
覆盖，以及最终 PR/主线各 24 个 CI job 已通过。读池、动态 fleet、内核资源准入和
固定开环过载有各自实际合同；这不是 AWS 或生产性能认证。来源、原始失败和测量
口径见[并发与资源交付记录](../engineering/sqlite-s3-scale-validation-2026-11-18.md)。
下文旧 actor 切片与早期组合的测试数量、覆盖缺口及吞吐数据只描述当时的冻结来源。

## 问题与决定

原调度器把所有数据请求及 `Open` / `Activate` 按 HEAD 哈希到固定 data lane。一个 lane 的同步恢复最长可以占用 recovery deadline；同 lane 中另一库即使已有热 Session，也不能执行。独立 HTTP recovery intake 与恢复 semaphore 只限制数量，不能解除这个排队阻塞。

当前采用有界的活跃数据库 actor。一个 actor 是一个专用线程及一个数据库的 Engine；该线程创建、使用、关闭本地 SQLite Session，冷恢复后继续直接使用同一 Session。控制请求继续进入独立的固定 control worker pool。另设一个固定 reaper 线程回收退出线程，请求路径不调用 `join`。这些线程不迁移 `!Send` Session，不共享 SQLite 活动文件，不改变对象权威或 WAL gate。

启用 `admission.read_pool` 后，只有 `query` 进入固定 query worker pool，每个 reader
持有独立的完整私有镜像。每次强读重新读取 HEAD、检查当前权限和数据根；SQL 前的
stale-cache 检查允许沿原 deadline 重建一次，第二次变化直接返回错误。已经开始的
SQL 和失败写请求不重放。详见[读池合同](../../crates/scap-service/docs/read-pool.md)。

## 必须保持的不变量

1. Registry key 是完整 HEAD key，刻意不包含 incarnation / generation；同一 HEAD 在本进程中最多有一个尚未退出的 data actor。启用读池后，并行 query worker 不属于 writer actor registry，也不能执行写请求。Engine 内仍用完整 scope 隔离镜像身份。
2. `Starting` 在启动线程前占用全局及租户 actor 槽位。并发首请求只追加到同一 actor。线程启动、工厂初始化、执行、原生连接关闭及 `join` 均不持 registry 锁。
3. actor 只有在没有在途操作、没有排队请求且 idle deadline 到达时才进入 `Draining`。`is_finished()` 只证明线程主函数返回，线程局部析构仍可能运行，因此不能把它当作允许请求线程同步 join 的证明。固定 reaper 在锁内取走 Draining handle，锁外 `join`，真正返回后才移除预留；请求提交不等待这一过程。新请求不能在旧连接或线程仍存活时复用槽位；handle 已被回收者取走时也必须保留预留。
4. 活跃 actor 数及每租户 actor 数有显式硬上限，`Starting` / `Running` / `Draining` 都计入，不能靠初始化或退出阶段绕过。容量满时新库返回 `BACKPRESSURE`，已有热 actor 仍能接收其预算内的工作。不存在一请求一线程或无界启动等待队列。
5. 全局、租户及 HEAD 排队预算统一计算 actor、读池和 control 队列中的 data / recovery / control。普通单请求出队或丢弃时归还；组提交的选中前缀在实际工作结束之前继续保留原计费，未开始后缀原序回队且不重新加额度。真正的 control 请求享有预留空间，冷恢复不能消耗它。在途操作仍受 actor 数、control worker 数，以及读池全局 worker 数和 tenant/database 活跃额度约束。
6. 同库优先恢复/管理任务最多连续执行三个后让普通 SQL 获得一次机会；control pool 在租户及库之间轮转。这个调度是非抢占的；正在执行的单库 SQL 仍可占用自己的 actor 到原始 deadline。
7. 关闭、启动失败、工厂失败及 panic 都关闭相应队列并返回稳定错误。当前请求由 worker owner 持有，执行期间只借用 Job；panic 时 worker/native/cache 全部析构后，才归还 intake/output，再释放 reader 活跃计数或组 Batch 额度。HTTP 断线不改变实际工作生命周期。已经失去响应的在途操作不自动重放。全局关闭先封闭 admission，再在锁外等待线程退出。
8. 恢复并发继续由同一全局 semaphore 限制，包含读池镜像重建，获取失败返回 `RECOVERY_BUSY`。调度器本身不探测故障或自动接管，不刷新候选 ETag、修改请求身份或重放 SQL；独立 controller 只能通过既定 owner-plan 协议推进。
9. actor/read/control 与 catalogue 提交均在各自调度锁内检查原 deadline，先拒绝过期请求，再改变预算或创建 actor。有效提交排队后才超时仍按原出队规则丢弃；本次 lookup/cancel 超时不能推断旧 SQL 结果。
10. 读队列按租户和库轮转，跳过已达到活跃额度的库／租户。活跃读额度在客户端断线或期限经过后仍由执行任务持有；panic 时先销毁 worker/native/cache，再释放该活跃额度。关闭排空读队列并等待正在执行的 reader 真正退出。

## 显式配置

数据库 admission 用 `active_database_actors`、`active_database_actors_per_tenant`、`actor_idle_timeout_ms` 取代含混的固定 data `workers`，队列总上限改为 `queued_total`。`control_workers` 保持独立池语义。严格解析拒绝旧字段，不悄悄改变旧配置含义。

缓存只允许一个完整 scope 的 Session 留在一个 actor 或 reader 中，均使用
`pages_per_actor`；控制 worker 不恢复 SQLite 镜像。在这些数据库调度 worker 中，
操作后常驻 Session 数最多为 `active_database_actors + read_pool.workers`，省略
读池时第二项为零。该数不包含独立 restore 任务的临时镜像。page 预算是操作完成后
的缓存淘汰阈值，不是恢复过程的磁盘预留或进程 RSS 硬限制。启用
[resource_envelope](kernel-resource-envelope.md) 可另外校验部署器配置的实际
cgroup/tmpfs 边界，但不把共享进程边界变成每租户硬隔离。

actor 总数、control worker 数、query worker 数加固定 **1** 个 reaper 最多 256，
每租户 actor 上限不得超过全局 actor 上限。读池的 `active_per_database` 不大于
`active_per_tenant`，后者不大于 `workers`，三个值都必须非零。启动 reaper 失败时
整个调度器启动失败并关闭已启动的 control/query workers。慢 native / TLS 清理可能
延迟旧槽位回收，已有热 actor 与 control 的提交路径不等待该清理；容量满仍返回
`BACKPRESSURE`。新库容量失败可在某 actor 空闲退出后重新提交原请求，但客户端必须
继续遵守 UNKNOWN 的 lookup / cancel 合同，不能据限流或连接关闭推断旧 SQL 未提交。

**256 只限制这组数据库调度线程，并非整个进程线程数。** 可选目录 pool 有独立最多 32 workers；当前 HTTP Tokio runtime 有 2 个 worker，S3 I/O runtime 有 1 个 worker；运行时与依赖内部辅助线程另计。空闲 actor 的连接与线程回收都不依赖新请求。单 reaper 被某次析构阻塞时，后续已退出但未 join 的 actor 也继续保留额度；此时可用容量减少并触发限流，不无界增加线程，也不让 HTTP 提交线程等待 join。

## 当前验收与历史开发矩阵

当前读池合同验证同库读真正重叠、读写／控制独立进展、活跃额度与公平跳过、启动失败、
panic 清理、shutdown join、fresh HEAD、一次 stale 重建和错误不重试；原生
HTTP/SDK/签名 S3 的来源与独立负控见
[read-pool 实验](../../experiments/read-pool/README.md)和本页开头的 #66 交付记录。

本文件最初开发时的 scoped 单元记录保留如下。后续 #31/#32 的组合 workspace、真实 HTTP/S3 与冷热隔离验收已完成并合入，最新冻结身份和失败修正过程见[验收记录](../engineering/catalogue-actors-validation.md)。下方最初阶段的 NOT_RUN 不是该后续候选的状态，后续新增目录/恢复/索引仍须按自己的输入单独验证。

最初 actor 开发候选的 Rust 1.90 服务 unit **70/70**、workspace 严格 clippy 和 fresh nightly unit 已运行。来自完整 workspace unit-only profile 的 12 个 `scap-service` 生产文件行/函数/region/branch 计数均覆盖全部实际分母；`catalogue.rs`、`lib.rs`、`main.rs` 没有可测 branch region，明确为 0/0，不把它们宣称为测得的 100% 分支覆盖。主要改动文件的精确计数如下。

| 文件 | 行 | 函数 | region | branch |
| --- | --- | --- | --- | --- |
| `scheduler.rs` | 451/451 | 47/47 | 740/740 | 104/104 |
| `config.rs` | 118/118 | 16/16 | 151/151 | 50/50 |
| `daemon.rs` | 129/129 | 20/20 | 198/198 | 2/2 |

这是当时的 **service scoped** 结果。该隔离副本的 catalogue recovery 基线仍有覆盖缺口，当时整体 workspace gate 尚未通过，真实 HTTP/S3/进程隔离与 AWS 为 **NOT_RUN**；后续真实本地验收已由本节首段链接记录，AWS 与新组合仍分别验收，不回写历史 verdict。服务实验配置已同步到显式 actor 字段，Python 服务 harness unit 41 项通过，但该 unit 不替代真实网络实验。

以下历史 actor 场景由 unit 门控实际 `Scheduler::submit` / 正式 Engine 路径验证；
其中同库串行查询指未启用读池的路径：

- 门控真实调度调用：A 的恢复被阻塞，已经热的 B 仍完成查询；同 HEAD 的下一调用保持串行。
- actor 全局/租户配额、全局/租户/库队列额度、控制预留均独立触顶；容量满不阻塞已有热 actor 或 control。
- 并发首次访问只创建一个线程；idle eviction 与 submit 竞争没有双 actor；`Draining` 的连接未 drop 或线程局部析构尚未完成时槽位不复用；TLS 清理暂停后第一个 Status 提交本身也必须完成，不能把 join 工作推给碰巧到达的请求。
- 工厂/线程创建失败、panic、过期、调用方放弃、关闭、poisoned mutex 不泄漏额度或重放调用。
- 原生 Engine 激活后保留 Session，查询不再次全量下载；创建、使用及关闭都留在同线程。
- Rust 1.90 编译、严格 clippy、unit suite、nightly 每生产文件精确行/函数/region/branch 覆盖单独运行；HTTP/S3/进程实验单独验收。

## 仍然存在的吞吐与规模边界

actor 隔离消除固定哈希 lane 上的跨库恢复阻塞，读池允许同库查询并行，但每个库的
writer 仍串行，活跃库数受 actor 线程上限约束。未启用读池时，query 也继续走单 actor。
下一阶段若要大量热库共享少量线程，应把恢复拆成可跨线程的已验证私有 image 与
本线程 native open，并设计 continuation、完成事件预留、原始 deadline、fresh HEAD
校验和所有权交接；只搬下载、仍在热线程执行完整 integrity check 不能获得完整隔离。

热强读每次仍做 exact HEAD GET 与权限/数据根校验，再在本地查询。冷恢复仍顺序下载
整个不可变树、校验历史结果并做 native integrity check。读池追随新的数据根时也可能
需要完整重建，不能把固定 reader 数直接换算成吞吐倍数。写提交按 128 KiB chunk /
256 路数据树做 COW，并非每次全库上传；然而新对象依赖逐个 PUT + exact GET、分段
请求索引路径更新、HEAD CAS、native publication 和同步 checkpoint 都位于提交路径。
本轮可选 group commit 摊薄多个独立事务的 HEAD 检查/发布及最终 checkpoint，逐成员
真实 COMMIT 仍保留 FULL 同步；没有 lazy VFS、新 MVCC 引擎或 S3 Express 专用适配器。
已有 SQL batch 是一个事务内的多条语句，不能用逻辑行数/秒冒充独立事务/秒，也不能
借 Turso 其他架构/硬件基准宣称 SCAP TPS。

数据 actor、读池和 control pool 仍共享对象客户端、网络、磁盘、CPU 和 HTTP runtime。
HTTP JSON 解码仍在 runtime 内同步执行，缓存页预算没有入场磁盘预留；HEAD6/7 的显式
回收已经实现，默认仍未授予 GC 删除权限。固定开环过载和可选内核资源合同已交付，
长期存储增长、真实 AWS 成本和生产 SLO 仍需独立测量。`BACKPRESSURE` 与
`RECOVERY_BUSY` 是可观察的资源限制，不能宣传成无限扩展。

主线 HEAD7 和 #59 早期组合的单库 C1/C4 写 5.149/2.822 次每秒、四库 C4 写
7.206 次每秒，仍只属于[历史组合验收](../engineering/sqlite-s3-integration-validation.md)
的本地样本。#66 的单条事务与 SQL batch、30 秒开环过载数字使用本页开头的独立新
记录；不同源码、事务定义或后端的样本不拼成一个性能结论。

## SQLite、NFS 与原生依赖

本地镜像由 `ImageBuilder` 创建为私有目录和独占文件，config / Engine / builder 在打开的目录句柄上验证 Linux 文件系统 allowlist。native 打开前还检查全部已存在的 Unix 临时目录候选，配置最先拒绝宿主全局临时目录覆盖。S3 通过 immutable objects 与 HEAD 条件更新提供数据库权威，不挂载成 SQLite 的共享 `.db` / WAL。环境须从首次 SQLite 初始化前保持不变；overlay 底层、默认 VFS 和不可变挂载命名空间仍是部署信任边界，见[执行存储说明](../operations/sqlite-storage-safety.md)。

固定 libSQL commit `d8bc862d20bedc72945a1da27c8b7045414c0261` 的默认 bundled 头文件报告 SQLite **3.47.0**，不能把 Cargo package `0.10.0` 当成 SQLite 版本。SQLite 官方记录了并发 writer / checkpointer 的 WAL-reset 缺陷；当前私有单连接、禁自动 checkpoint、同线程 `TRUNCATE` 不提供该并发拓扑。将来增加共享本地连接或外部 checkpointer 前，必须确认 upstream 修复或适配回补并做原生回归；本批 actor 隔离不会解除这个约束。

官方资料：

- [SQLite 网络文件系统说明](https://www.sqlite.org/useovernet.html)
- [SQLite WAL 与 WAL-reset 说明](https://www.sqlite.org/wal.html)
- [固定 libSQL bundled SQLite 头文件](https://github.com/tursodatabase/libsql/blob/d8bc862d20bedc72945a1da27c8b7045414c0261/libsql-ffi/bundled/src/sqlite3.h)
- [SQLite checkpoint 修复源码](https://github.com/sqlite/sqlite/commit/fe57e14b49f9189b56da8233ab3415ce5ff6b1ff)
- [Turso Cloud diskless 架构](https://turso.tech/blog/turso-cloud-goes-diskless)
- [Turso 平台与开源边界](https://turso.tech/blog/upcoming-changes-to-the-turso-platform-and-roadmap)
- [S3 conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)
- [Rust JoinHandle 的退出与 join 语义](https://doc.rust-lang.org/std/thread/struct.JoinHandle.html)
