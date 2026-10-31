# G0 持久存储、快照与恢复边界

初始日期：2026-10-29；非空业务 genesis 更新：2026-10-31。实现与验证范围见 [G0 证据](g0-evidence.md)；决策见 [ADR-0008](../adr/0008-bounded-durable-store-g0.md)与 [ADR-0010](../adr/0010-cell-acceptance-and-raft-safety.md)。本模块是有界存储策略，尚未组成可部署的数据库服务。

## 1. 代码职责

正式 `crates/scap-raft-store` 负责格式、身份、顺序与恢复规则，并实现固定版本的 `raft::Storage`。它通过 `AtomicBackend` 调用最终 I/O；不包含网络服务或自动选主循环，也不返回 SQL Accepted 回执。

独立 `experiments/raft-store` 保存第一步的真实 RawNode/RocksDB 退出边界实验，其中 driver、连接与合成应用仍是测试资产。后续正式 `scap-raft-driver` / `scap-raft-rocks` 已分别实现可复用顺序和 native I/O，新的三进程实验直接依赖正式模块；接口和范围见 [串行 driver 合同](serial-driver.md)。研究夹具不成为运行时依赖。

| 边界 | 正式模块负责 | 端口或调用方负责 |
| --- | --- | --- |
| 磁盘镜像 | 编码、版本、完整性和结构校验、资源上限 | 原子读取与同步替换、独占访问、真实设备错误 |
| 初始化/恢复 | 身份绑定，存在与不存在的区别，全部恢复不变量 | 合法新组的外部授权、节点身份分配、目录生命周期 |
| Raft 日志 | 连续性、已提交前缀保护、合法后缀替换、查询边界 | RawNode 产生合法 Ready，串行驱动和消息发送时机 |
| 业务应用 | 精确日志范围与位置绑定，app/ConfState/applied 原子保存 | 确定性执行、owner/auth/dedup、数据库与请求语义 |
| checkpoint | 保存持久应用视图和 boundary term 后压缩 | 完整业务状态与数据引用闭包、外部对象保留 |

## 2. I/O 端口与失败语义

一个 backend 属于一个独占的 store 实例。端口明确区分空存储、已有镜像和无法识别的残留；不能把“没有找到预期 key”自动解释成安全的空新库。多个进程同时修改同一后端不属于允许的执行方式。

`load(max_image_bytes)` 将已验证的镜像限额交给后端；后端在复制为 owned image 前拒绝超限值。该限制不等于约束 RocksDB 自身所有 native 缓存分配。`replace_sync` 成功表示完整镜像已在后端的原子同步边界保存。返回错误可能发生在写入前，也可能发生在写入已经完成之后，因此错误不等于回滚。实现先校验并准备候选状态，只有同步成功后才发布内存视图；失败时停止当前实例，下一步通过重新打开和校验磁盘确定恢复状态。

输入或恢复不变量错误不能靠 `max(commit, applied)`、清空目录、静默重置投票或重新创建配置来修复。`Storage` 的 Compacted、Unavailable 等正常范围结果与存储损坏是不同语义。

## 3. 初始化与恢复

`create_new` 要求真正的空后端；`open_existing` 要求已有合法镜像。genesis 的 index/term 为 1，HardState.term/commit 和 applied 同为 1，配置与空应用状态在同一次原子写中保存。该 checkpoint 是新组的明确初始状态，不代表已经提交了客户事务。

需要非空业务状态时使用 `create_new_with_application`：先于 backend I/O 和候选复制检查应用字节上限，再把相同 application bytes 同时保存为当前应用与 genesis snapshot data。所有 founding replicas 的业务 genesis 与配置须一致；单元验证完整原子恢复、超限不接触后端，以及同步报错可能发生在写前或写后的 UNKNOWN 边界。原 `create_new` 委托该入口传入空 bytes，磁盘格式仍为 v1。

恢复至少校验：

- 格式与完整性、预期 cell/实例/node 身份、资源上限；
- checkpoint 及完整 ConfState；
- `snapshot_index <= durable_applied <= durable_commit <= last_index`；
- checkpoint 后日志连续，条目身份及 term 与 HardState 一致；
- 保存的应用状态和已应用位置作为同一视图恢复。

传给 `Config.applied` 的值只能来自已校验的持久 applied。启动不自动应用未提交后缀；对应记录等待后续合法共识对齐。

## 4. 写入与应用

`persist_ready` 验证 entries、HardState 和可选 snapshot，统一保存对应可恢复状态。已提交记录受到保护，合法的未提交后缀可以被替换。相同 term 内已经作出的非零投票不能更换或清零；term 和 commit 不回退。

RawNode 的 `advance_append` 可能生成新的 LightReady commit 和已提交条目。driver 必须保留最初 Ready 的 committed entries，处理两批条目，并通过 `apply_committed` 保存准确的日志应用范围、完整新应用状态与 ConfState。此路径只推进 commit，保留当前 term/vote。

应用输入必须对应已持久日志的连续位置；没有新 applied 位置时，不能借 apply 接口任意改变业务视图。返回成功后，driver 才能调用 `advance_apply_to`。配置在内存中发生变化而持久保存失败时，同样停止节点并从磁盘恢复。

这些步骤不替代 [完整 Ready 次序](raft-rs-integration.md)。网络发送入队、`propose` 返回和单副本持久应用都不是 SQL ACK。

## 5. 快照与压缩

接收的 snapshot 连同业务数据、完整 joint ConfState、snapshot 位置、applied、合法 HardState/commit 和新日志边界原子发布。拒绝回退已提交或已应用的视图；不能只保存 snapshot 文件就提前报告完成。

Store 只校验 opaque application 的外层完整性与原子位置，业务 codec 仍须校验自己的不变量。`scap_cell::CellState::decode_bound` 将应用内 cell 身份、term/index、限额与同一 Store 持久视图匹配；snapshot-only 路径不调用 `Application::apply`，恢复后的业务读取不能跳过这项检查。

`checkpoint_and_compact` 从已持久应用的位置形成 checkpoint，并保留匹配需要的 boundary term。后续 `Storage::snapshot(request_index, to)` 只返回实际发布的 checkpoint；请求的最低位置更高时返回暂不可用，不能从 commit 构造尚不存在的业务快照。

真实 RawNode 可能在日志已经匹配 snapshot index/term 时只快进 commit。验证安装路径的测试必须使其产生真正的 snapshot Ready，不能把快进路径算作原子安装证据。

## 6. 限额与布局代价

G0 镜像包含 `SCAPRAFT` magic、u32 格式版本 1、cluster/cell/实例/node 身份、applied、HardState、完整 ConfState、已发布 snapshot、application 和连续 entries。定长整数及长度前缀使用大端编码，Raft 消息采用固定 protobuf-codec。尾部 SHA-256 覆盖前面的完整镜像，通过固定 `sha2 0.10.9` 实现；它用于完整性检查，不是 MAC、对端认证或防止整份旧镜像回滚的机制。

资源预算分别限制整个镜像、单条记录、日志条目数量和应用数据，正式 API 要求显式传入，未设置生产默认。真实契约夹具采用 8 MiB image、1 MiB entry、4096 entries、1 MiB application；这些是 G0 测试参数，不修改现有 64 KiB 小事务性能负载定义。

该布局每次保存可能复制和序列化整个有界状态，保留了明显的写放大成本。它用于先证明原子恢复，不作为大量活跃库或长期日志的容量结论。增量布局、外部 snapshot 文件与日志回收均须保留同样的恢复不变量，并提供新的格式/升级与崩溃证据。

checkpoint 不保证缩小镜像：当前 application 会复制进 snapshot，而当前 application 和尚未压缩的日志仍要保留。因此，即使各字段分别没有超限，checkpoint 后的完整镜像也可能超过总预算。实现必须在写后端前拒绝，保留原有磁盘镜像并停止当前实例；不能把 checkpoint 当成必定成功的容量救援操作。单元测试分别验证 persist、apply 和 checkpoint 的总预算失败路径。格式的固定开销为 120 字节，此外还要计入各 protobuf 字段、应用数据以及每条 entry 的长度前缀和内容。

## 7. 测试与证据分类

生产单元测试使用可控 AtomicBackend，验证真实生产函数的合法/非法输入、状态变化、查询和错误后的停止行为。它们独立采集 lines/functions/regions/branches，全部要求 100%。

真实契约测试采用固定 raft-rs 与 RocksDB，单独验证 Ready/LightReady、投票、应用、快照、未提交后缀和进程退出后的重开。执行结果、依赖版本、同步选项和确切故障点以 [实验 README](../../experiments/raft-store/README.md)记录为准，不进入单元覆盖率分子。

`experiments/raft-store` 与 `experiments/raft-cluster` 继续使用合成应用，单独验证持久/共识契约。后续正式 [cell 业务状态机](cell-state-machine.md)及独立 [SQLite/cell 实验](../../experiments/sqlite-cell/README.md)增加有界业务接受与真实页面证据。进程退出不是断电；单节点或本机消息交换不是三 AZ 可用性证据。RPO、RTO 和端到端延迟继续按 [性能合同](performance-slo.md)测量。

## 源码依据

- [固定 raft-rs Storage 与 MemStorage](https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/storage.rs)：查询语义、内存实现的 snapshot 假设与 commit_to 行为。
- [固定 RawNode](https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/raw_node.rs)：Ready、LightReady 与显式应用推进。
- [RocksDB 0.24.0 WriteOptions](https://github.com/rust-rocksdb/rust-rocksdb/blob/v0.24.0/src/db_options.rs)：sync 与 WAL 选项；真实 fixture 固定依赖，不推广为其他 binding 的自动保证。
- [sha2 0.10.9](https://docs.rs/sha2/0.10.9/sha2/)：标准 SHA-256 实现。
