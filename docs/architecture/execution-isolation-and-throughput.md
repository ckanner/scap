# 活跃数据库执行隔离与吞吐边界

## 问题与决定

原调度器把所有数据请求及 `Open` / `Activate` 按 HEAD 哈希到固定 data lane。一个 lane 的同步恢复最长可以占用 recovery deadline；同 lane 中另一库即使已有热 Session，也不能执行。独立 HTTP recovery intake 与恢复 semaphore 只限制数量，不能解除这个排队阻塞。

本批采用有界的活跃数据库 actor。一个 actor 是一个专用线程及一个数据库的 Engine；该线程创建、使用、关闭本地 SQLite Session，冷恢复后继续直接使用同一 Session。控制请求继续进入独立的固定 control worker pool。另设一个固定 reaper 线程回收退出线程，请求路径不调用 `join`。本批不把 `!Send` Session 放进可迁移任务，不增加共享 SQLite 文件连接，不改变对象权威或 WAL gate。

## 必须保持的不变量

1. Registry key 是完整 HEAD key，刻意不包含 incarnation / generation；同一 HEAD 在本进程中最多有一个尚未退出的 data actor。Engine 内仍用完整 scope 隔离镜像身份。
2. `Starting` 在启动线程前占用全局及租户 actor 槽位。并发首请求只追加到同一 actor。线程启动、工厂初始化、执行、原生连接关闭及 `join` 均不持 registry 锁。
3. actor 只有在没有在途操作、没有排队请求且 idle deadline 到达时才进入 `Draining`。`is_finished()` 只证明线程主函数返回，线程局部析构仍可能运行，因此不能把它当作允许请求线程同步 join 的证明。固定 reaper 在锁内取走 Draining handle，锁外 `join`，真正返回后才移除预留；请求提交不等待这一过程。新请求不能在旧连接或线程仍存活时复用槽位；handle 已被回收者取走时也必须保留预留。
4. 活跃 actor 数及每租户 actor 数有显式硬上限，`Starting` / `Running` / `Draining` 都计入，不能靠初始化或退出阶段绕过。容量满时新库返回 `BACKPRESSURE`，已有热 actor 仍能接收其预算内的工作。不存在一请求一线程或无界启动等待队列。
5. 全局、租户及 HEAD 排队预算统一计算 data / recovery / control，出队或丢弃立即归还。真正的 control 请求享有预留空间；冷恢复不能消耗这部分预留。计数不包含当前已执行操作；在途操作另受 actor 数和 control worker 数约束。
6. 同库优先恢复/管理任务最多连续执行三个后让普通 SQL 获得一次机会；control pool 在租户及库之间轮转。这个调度是非抢占的；正在执行的单库 SQL 仍可占用自己的 actor 到原始 deadline。
7. 关闭、启动失败、工厂失败及 panic 都关闭相应队列并返回稳定错误。已经失去响应的在途操作不自动重放。全局关闭先封闭 admission，再在锁外等待线程退出。
8. 恢复并发继续由同一全局 semaphore 限制，获取失败返回 `RECOVERY_BUSY`。没有后台自动接管、刷新候选 ETag、修改请求身份或 SQL 重放。

## 显式配置

数据库 admission 用 `active_database_actors`、`active_database_actors_per_tenant`、`actor_idle_timeout_ms` 取代含混的固定 data `workers`，队列总上限改为 `queued_total`。`control_workers` 保持独立池语义。严格解析拒绝旧字段，不悄悄改变旧配置含义。

缓存只允许一个完整 scope 的 Session 留在一个 actor 中，配置为 `pages_per_actor`；控制 worker 不恢复 SQLite 镜像。总常驻 Session 数最多等于 `active_database_actors`。现有 page 预算仍是操作完成后的缓存淘汰阈值，不是恢复过程的磁盘预留或进程 RSS 硬限制；改变这一点需要另一个资源预留协议。

actor 总数、control worker 数加固定 **1** 个 reaper 最多 256，每租户 actor 上限不得超过全局 actor 上限。启动 reaper 失败时整个调度器启动失败并关闭已启动 control workers。慢 native / TLS 清理可能延迟旧槽位回收，已有热 actor 与 control 的提交路径不等待该清理；容量满仍返回 `BACKPRESSURE`。新库容量失败可在某 actor 空闲退出后重新提交原请求，但客户端必须继续遵守 UNKNOWN 的 lookup / cancel 合同，不能据限流或连接关闭推断旧 SQL 未提交。

**256 只限制这组数据库调度线程，并非整个进程线程数。** 可选目录 pool 有独立最多 32 workers；当前 HTTP Tokio runtime 有 2 个 worker，S3 I/O runtime 有 1 个 worker；运行时与依赖内部辅助线程另计。空闲 actor 的连接与线程回收都不依赖新请求。单 reaper 被某次析构阻塞时，后续已退出但未 join 的 actor 也继续保留额度；此时可用容量减少并触发限流，不无界增加线程，也不让 HTTP 提交线程等待 join。

## 当前验收与历史开发矩阵

本文件最初开发时的 scoped 单元记录保留如下。后续 #31/#32 的组合 workspace、真实 HTTP/S3 与冷热隔离验收已完成并合入，最新冻结身份和失败修正过程见[验收记录](../engineering/catalogue-actors-validation.md)。下方最初阶段的 NOT_RUN 不是该后续候选的状态，后续新增目录/恢复/索引仍须按自己的输入单独验证。

本候选的 Rust 1.90 服务 unit **70/70**、workspace 严格 clippy 和 fresh nightly unit 已运行。来自完整 workspace unit-only profile 的 12 个 `scap-service` 生产文件行/函数/region/branch 计数均覆盖全部实际分母；`catalogue.rs`、`lib.rs`、`main.rs` 没有可测 branch region，明确为 0/0，不把它们宣称为测得的 100% 分支覆盖。主要改动文件的精确计数如下。

| 文件 | 行 | 函数 | region | branch |
| --- | --- | --- | --- | --- |
| `scheduler.rs` | 451/451 | 47/47 | 740/740 | 104/104 |
| `config.rs` | 118/118 | 16/16 | 151/151 | 50/50 |
| `daemon.rs` | 129/129 | 20/20 | 198/198 | 2/2 |

这是 **service scoped** 结果。隔离副本的 catalogue recovery 基线仍有覆盖缺口，整体 workspace gate 尚未通过，不把本批结果冒充其他批次验收。真实 HTTP/S3/进程隔离实验与 AWS 云端容量/SLO 为 **NOT_RUN**；必须在合并最终 core 候选后分别执行。服务实验配置已同步到显式 actor 字段，Python 服务 harness unit 41 项通过，但该 unit 不替代真实网络实验。

以下场景由 unit 门控实际 `Scheduler::submit` / 正式 Engine 路径验证：

- 门控真实调度调用：A 的恢复被阻塞，已经热的 B 仍完成查询；同 HEAD 的下一调用保持串行。
- actor 全局/租户配额、全局/租户/库队列额度、控制预留均独立触顶；容量满不阻塞已有热 actor 或 control。
- 并发首次访问只创建一个线程；idle eviction 与 submit 竞争没有双 actor；`Draining` 的连接未 drop 或线程局部析构尚未完成时槽位不复用；TLS 清理暂停后第一个 Status 提交本身也必须完成，不能把 join 工作推给碰巧到达的请求。
- 工厂/线程创建失败、panic、过期、调用方放弃、关闭、poisoned mutex 不泄漏额度或重放调用。
- 原生 Engine 激活后保留 Session，查询不再次全量下载；创建、使用及关闭都留在同线程。
- Rust 1.90 编译、严格 clippy、unit suite、nightly 每生产文件精确行/函数/region/branch 覆盖单独运行；HTTP/S3/进程实验单独验收。

## 仍然存在的吞吐与规模边界

此改动消除固定哈希 lane 上的跨库恢复阻塞，但每个库的 SQL 仍串行，且活跃库数受线程上限约束。它不是十万热库的调度终点。下一阶段若要大量热库共享少量线程，应把恢复拆成可跨线程的已验证私有 image 与本线程 native open，并设计 continuation、完成事件预留、原始 deadline、fresh HEAD 校验和所有权交接；只搬下载、仍在热线程执行完整 integrity check 不能获得完整隔离。

热强读每次仍做 exact HEAD GET 与权限/数据根校验，再在本地查询。冷恢复仍顺序下载整个不可变树、校验历史结果并做 native integrity check。写提交按 128 KiB chunk / 256 路数据树做 COW，并非每次全库上传；然而新对象依赖逐个 PUT + exact GET、分段请求索引路径更新、HEAD CAS、native publication 和同步 checkpoint 都位于提交路径。没有 group commit、同库并发 reader pool、MVCC 或 S3 Express 专用适配器，不能借 Turso 公布的其他架构/硬件基准宣称本项目 TPS。

数据 actor、control pool 仍共享对象客户端、网络、磁盘、CPU 和 HTTP runtime。HTTP JSON 解码仍在 runtime 内同步执行，缓存页预算没有入场磁盘预留，GC 仍关闭；这些边界必须在容量/延迟实验中独立测量。`BACKPRESSURE` 与 `RECOVERY_BUSY` 是可观察的资源限制，不能宣传成无限扩展。

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
