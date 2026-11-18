# SQLite on S3：2026-11-17 代码审查、修复与剩余交付

本次从远端 `main=fab8ca0`、PR #59 `9674bb1`、PR #60 `b25b785` 开始核对。
当前路线保持 **S3 为唯一持久权威，SQLite 使用私有本地执行镜像**，不回到旧 Raft/RocksDB
原型，也不把活动 `.db`、WAL 或 SHM 放到跨主机共享文件卷。

## 1. 当前状态

| 代码 | 已提交/已实现的内容 | 仍然存在的边界 |
| --- | --- | --- |
| main `fab8ca0` | 对象原生提交、原结果查证、HTTP/Node 接入、按库 actor、代际复制/GC、永久删除 seal | 尚未包含 #59 的 owner/controller/S1 集成 |
| [PR #59](https://github.com/ckanner/scap/pull/59) | 集成 #56/#57/#58；本轮 `b4c5236` 在持有调度锁后拒绝已经过期的请求 | 既有 7 个生产文件的分支测量缺口仍阻止严格门禁通过 |
| [PR #60](https://github.com/ckanner/scap/pull/60) | `9b5e9ae` 减少 Manifest 校验证明的临时分配，保留完整绑定 | 原两组四库写吞吐约 24% 回退仍未定位；不能宣称已完成整体提速 |
| [PR #61](https://github.com/ckanner/scap/pull/61) | `841da9c` 在服务启动前永久登记显式 worker ID，拒绝重复与不确定启动；同一后端、服务装配入口统一校验 | 自动编号分配、首次升级的历史身份迁移和 AWS IAM 验收仍是独立事项 |

#56/#57/#58 的产品组合由 #59 承载；#41/#43/#49 是仍打开的模型/验证工作，不能将
这些 PR 的存在或各自的测试数相加作为产品完成率。三条当前产品 PR 均保留 Draft。

## 2. 网络文件系统风险如何处理

SQLite 官方明确要求共享 WAL 的进程位于同一主机，原因包含 WAL-index 的共享内存
要求；网络文件系统的锁和同步语义也可能不满足 SQLite 的假设。SQLite 支持同机
多进程/连接，单库同一时刻一个写事务，不等于整个服务只能运行一个进程。
不能把所有 NFS 实现都描述成必然立刻损坏，也不能把一次试运行成功当作跨主机 WAL
已经得到支持。来源：[SQLite WAL](https://sqlite.org/wal.html)、
[网络存储说明](https://sqlite.org/useovernet.html)、
[损坏原因](https://sqlite.org/howtocorrupt.html)。

SCAP 的数据路径如下，安全性来自组合协议：

1. 每个执行实例用新建私有目录和本地 SQLite 文件。当前服务在 Linux 用目录描述符的
   `fstatfs` 做文件系统白名单准入；拒绝 NFS/EFS、FUSE 和未知类型。overlay 只在
   受信本地 backing 和稳定挂载命名空间前提下允许；分类测试不认证真实网络挂载。
2. 固定 libSQL 的 `WrapWal::insert_frames` 挂点在原生发布之前捕获变化页及原始结果；
   不可变对象条件创建并完整回读验证。这不是普通提交后的 WAL 通知，直接换成普通
   SQLite driver 不能自动保留此确认协议。
3. 数据根、请求结果、身份、权限及 owner 等状态通过同一份 HEAD 的原 ETag 条件发布排序。
4. 只有依赖与 HEAD 已持久化、native publication 完成后返回普通成功。
5. 接管推进同一 HEAD 的 owner epoch；旧候选不能换 ETag 后继续覆盖。响应丢失保留
   UNKNOWN，后续只查证或取消原请求，不自动重新执行 SQL。

HEAD 已接受而本地 native publication 失败时，以 `COMMITTED_BUT_UNAVAILABLE`
及可用的 receipt 单独表达，不能把本地错误解释成远端回滚；
客户端没有确定结果时仍按原身份查证，不重放 SQL。热缓存的新强读也要 exact GET
最新 HEAD、检查当前权限并固定数据根；S3 不可得时读写都失败关闭，不降级成陈旧成功。

S3 的单 key 原子性和条件写是底层能力；跨对象提交、旧写者隔离、查证和 GC 闭包由
SCAP 实现。它没有跨 key 的通用事务。来源：[S3 一致性模型](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html#ConsistencyModel)、
[条件写](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)。

因此，本方案规避跨主机共享活动 WAL 的架构风险；本地设备/VFS 错误、错误的 native
计算、特权进程改变挂载、对象被管理员删除等不由“用了 S3”自动解决。详见
[安全与吞吐设计](../architecture/sqlite-s3-safety-and-throughput.md)和
[执行存储要求](../operations/sqlite-storage-safety.md)。

## 3. 本轮修复及行为

### 3.1 过期请求不再占用 actor 和队列

旧代码在等待调度锁期间可能用完原 deadline，仍然创建数据库 actor、运行 factory
并占据活跃库额度，直到执行前才返回 DEADLINE。目录队列也会接受已经失效的工作。

`b4c5236` 在锁内、预算变更和 actor 创建前检查同一个 deadline。拒绝后归还本次
intake/output 持有物；原本有效、排队后才超时的请求仍按原协议丢弃。Lookup/Cancel
本次过期并不判定旧 SQL 的结果，不触发重放。

四个回归场景覆盖直接过期、等待锁超时、目录额度以及编码结果/输入额度释放。
新测试在原生产实现上的两个直接过期场景均失败，修复后的调度集合 24/24 通过。

### 3.2 校验证明减少分配，完整 HEAD 绑定保留

`9b5e9ae` 将进程内完整 HEAD 指纹保留为 32 字节 SHA-256；不再转换成临时十六进制
String。Manifest 证明借用原数据根，未变化的输出使用借用，变化的输出继续拥有新根。
对象格式和持久化哈希不变；backend、handle lineage、Scope、原 deadline、完整 HEAD、
ETag、配额、健康检查及原条件 CAS 不变。证明仍只能在原提交中消费一次。

完整正文等价测试包括正常/最大权限列表、快照、转义文字以及权限、owner、结果窗口
和 auth epoch 的变化。独立 release 微型分析比较 JSON 缓冲加十六进制、二进制摘要
和直接流入 SHA-256 三种方式。流式方式在大 HEAD 上没有优势，因此没有引入该候选。
独立 target 的九轮中位数：745 字节 HEAD 从 938 ns 到 893 ns；58,975 字节 HEAD
从 61,056 ns 到 61,048 ns，后一差异基本为零。全部样本保留；微型分析只说明该辅助
函数的墙钟时间，不证明每事务 CPU、服务 TPS 或 RSS 改善。详见
[性能报告](https://github.com/ckanner/scap/blob/0fb883dfeab281def53b4b086485111999b1280a/docs/engineering/manifest-proof-profile-2026-11-17.md)。

### 3.3 服务启动时拒绝重复 worker ID

#61 用普通数据库 authority 的同一个对象后端，对固定 bucket 级 key
`scap-worker/v1/instances/{worker_instance}` 只做一次条件创建及 exact GET。既有相同
正文也不能当作幂等成功；两个进程竞争相同 ID 只有一次可以获得启动资格。

配置/能力校验在占用之前完成，服务 worker/listener 在占用成功之后才创建。丢失 ACK、
损坏回读或截止时间耗尽均拒绝启动。正常退出、崩溃或后续启动失败都不释放编号。
marker 不授予任一数据库 owner 权限，接管仍走原 HEAD/owner-plan 协议。

这是显式编号的防重用保护；编号仍需由部署层提供，不能称为自动分配器。marker
必须排除于 GC/生命周期删除；旧版本没有历史登记，首次升级必须处理旧进程和已用
编号，不能通过扫描当前 HEAD 推导完整历史。设计/IAM/升级说明见
[独立 PR 的设计](https://github.com/ckanner/scap/blob/fix/durable-worker-instance-20261117/docs/architecture/worker-instance-claim.md)。

## 4. 吞吐、进程和规模：已解决与未解决

| 问题 | 当前处理 | 尚未解决的部分 |
| --- | --- | --- |
| 多实例共享 WAL | 私有本地执行文件，跨节点使用对象协议 | 挂载稳定性及受信宿主仍需保证 |
| 旧 owner 迟到发布 | 同一 HEAD 上的 epoch、完整原条件与请求身份 | 正式部署故障域/AWS 验证 |
| 重启后误用同一 worker ID | #61 永久占用并拒绝重复 | 自动发号、旧版本迁移与 IAM 实测 |
| 多库相互阻塞 | 有界按库 actor，独立控制/恢复准入 | 全机 CPU/网络/内存/磁盘仍共享 |
| 已过期工作浪费容量 | #59 入队前锁内拒绝，无新 actor | 执行中的工作仍占自己的 actor；deadline/取消通过协作式 interrupt 生效 |
| 单库热点写入 | 同库串行、短事务、一次事务内多条 SQL | 没有同库 MVCC、独立事务 group commit；加 Pod 不会提高该库写吞吐 |
| S3 提交成本 | 128 KiB 增量块/COW 树，#60 省去一次重复 Manifest GET | 多次串行对象往返、native checkpoint；端到端回退尚待定位 |
| 冷库唤醒 | 流式完整恢复，空闲 actor 回收 | 仍读取完整数据库及结果闭包；没有 lazy VFS |
| 快照/长期存储 | retained roots、代际 COPY/GC、Deleted seal | S2 新 Scope 恢复、任意时间 PITR、长期成本与持续压力 |

当前重点服务大量独立租户/Agent 数据库。单库高写入热点需要单独的引擎与提交策略，
不能把多库扩展等同于单库多写者。现有 Node SDK 提供远程 SQL/原请求身份，不能
宣称是任意同步 SQLite driver 的零改动替代品。

## 5. Turso 对照与采用顺序

| 层次 | 已核实能力 | SCAP 的决定 |
| --- | --- | --- |
| libSQL 开源 | SQLite 分支、远程访问/副本，仍有单写者模型 | 维持当前 native publication hooks，不借用新引擎的并发宣传 |
| Turso Rust 引擎 | MVCC、BEGIN CONCURRENT、group commit；0.8 有明确并发写实现 | 真正解除同库限制需要独立引擎适配和冲突语义设计 |
| Turso Cloud | 本地缓存、S3/S3 Express、分段/按需加载、远端持久化后确认 | 借鉴持久化边界、分段、懒恢复和合批；当前 Cloud 多租户服务端不是全部开源 |

来源：[libSQL 官方 README](https://github.com/tursodatabase/libsql)、
[Turso 0.8](https://turso.tech/blog/turso-0.8.0)、
[Cloud 持久化](https://turso.tech/blog/how-does-the-turso-cloud-keep-your-data-durable-and-safe)、
[服务端开源边界](https://turso.tech/blog/upcoming-changes-to-the-turso-platform-and-roadmap)。
Turso 的公开延迟/TPS 不作为 SCAP 的测量。S3 Express One Zone 的单 AZ 故障域也不能
用周期 checkpoint 包装成跨 AZ 同步 RPO=0。

工程顺序保持：先闭合当前正确性与验证；定位实际对象/actor/native 等待；在保持确认
边界的条件下优化请求/缓冲；再分别设计 lazy VFS、group commit、读池或新 MVCC 内核。
当前固定 libSQL 的 WAL-reset 问题由私有单连接、同步 checkpoint 的拓扑排除触发；
这不是原生内核已修补。引入同文件读池/后台 checkpoint 前必须完成
[native 补丁与回归门禁](../architecture/sqlite-wal-reset-assessment.md)。

## 6. 本轮验证及合入边界

调度修复 `b4c5236`：独立 stable 和 fresh nightly 各 787 项通过；严格 Clippy、格式、
仓库检查通过。新 unit-only 报告中 `scheduler.rs` 为行 560/560、函数 55/55、region
863/863、branch 112/112；`catalogue_scheduler.rs` 为 225/225、32/32、312/312、34/34。
全项目 67 个生产文件已发出计数全部命中，但原有 7 个文件仍是 branch 0/0，严格
检查器退出 1。没有改变门槛、排除生产文件或把 region 当作 branch。

首轮 stable 使用了被不同 worktree 复用的构建目录，四个新回归失败。原控制二进制
的 DWARF 编译目录可确认来自只带新测试的旧实现；该结果保留，不作为候选证明。
之后用全新独占 target 重建，787 项全部通过。后续各候选、单位、覆盖和 release
分别使用独占构建目录，不能只依赖 Cargo 的相对依赖路径区分 worktree。

性能修复 `9b5e9ae` 的隔离 stable workspace 为 792 项通过、零失败/忽略，严格 Clippy
通过。它与 #59 的调度结果不是同一份组合，不能相加。

#61 `841da9c` 的 tree `0047a419d3f09b76d9da8ab82425ffb2a6cf5981` 与实际测试的本地
`2c0d18f` 完全一致。独立 stable/nightly 各 797 项通过、零失败/忽略；严格 Clippy、
格式检查通过。新 `instance.rs` 的行／函数／region／branch 为 40/40、4/4、64/64、
10/10，`daemon.rs` 为 257/257、28/28、373/373、38/38，`auth.rs` 为 79/79、13/13、
111/111、30/30；整仓仍只被原有七个零分支分母阻断。

实际 `scapd` 与 pinned SeaweedFS 完成 10 个启动场景：新身份、运行中/正常退出后/
SIGKILL 后重复、全新替代、两个进程竞争、成功 PUT 丢回执且不 GET、未知身份再次
启动、损坏回读、不可达端点；另完成 8 个 bounded TCP 场景及 5 个 oracle 自测/反例。
这些是真实本地进程与兼容端点结果，不是 AWS IAM 认证。全部历史 native/network
合同没有在此候选上重跑，不借先前 #59 的 1 GiB/owner/S1 结果认证新源码。
验证记录见[#61 实际验收](https://github.com/ckanner/scap/blob/1b667078b7f66145a4967054cb4526abb3ec2b7e/docs/engineering/worker-instance-validation-2026-11-17.md)；本轮调度证据见
[机器记录](../evidence/sqlite-s3-review-local-2026-11-17.json)。

真实 NFS/EFS/FUSE 挂载、AWS Standard、IAM、长期持续过载、生产 SLO 均未运行。远端 Actions 的失败与
本地结果分别报告；不能把本地通过改称远端 CI 通过。按 `AGENTS.md` 的现行要求，
完整必要验证未满足时可提交草稿，但不合并，因此本次更新没有合入 main。

## 7. 剩余交付

1. 解决完整源码决策的覆盖测量缺口；无源码分支入口与编译器未插桩的决策分别处理，
   不能凭空添加假分支或把 0/0 当作通过。新候选的运行合同按变更影响范围完成。
2. 按既有 S2 协议实现恢复到全新 Scope：固定意图、跨 Scope 重封装、native 校验、
   源权限完成屏障、取消和 CompletionRecord、HTTP/SDK；不继承旧 owner/ACL/请求空间。
3. 对 #60 继续实际服务的 CPU/等待定位，随后做持续开环负载、租户公平性、唤醒风暴
   与资源总账。重复小样本 TPS 或一次 helper 微型分析不能替代原因定位。
4. 完成动态 fleet、自动实例编号、硬 RSS/磁盘隔离、长期 GC/保留成本。
5. 在明确的真实目标 S3、权限和故障域上完成条件写、故障恢复、容量及预先定义的 SLO。

保留的详细设计见[交付计划](sqlite-s3-delivery-plan.md)、[路线图](roadmap.md)、
[S2 恢复设计](../architecture/retained-snapshot-restore.md)。这些未完成项不会因本轮
修复已提交而自动变成完成；当前可核实的是对象原生基础及本轮具体安全/资源改进。
