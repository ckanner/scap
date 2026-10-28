# Raft 库选型：TiKV raft-rs 与 OpenRaft

查询日期：2026-10-28。状态：源码与官方资料审查；**设计首选调整为 `tikv/raft-rs`，SCAP 尚未集成或验证其持久化适配**。决策见 [ADR-0006](../adr/0006-raft-rs-consensus-library.md)，具体门禁见 [集成契约](../engineering/raft-rs-integration.md)。

## 1. 结论及选择依据

SCAP 优先采用 TiKV 使用的 **[raft-rs][raft-repo]** 共识核心，Rust crate 名为 `raft`。OpenRaft 保留为替代候选，首期只实现一套 adapter。

选择的主要依据是 raft-rs 在 TiKV 数据复制路径中的长期使用、可以追溯到正式 TiKV 发布的具体源码，以及适合逐事件验证的 `RawNode` 接口。TiKV 官方[实现说明][tikv-blog]记录了从 etcd Go 实现发展 Rust 共识模块、在 TiKV 中使用并独立成库的过程。这是重要的采用证据，不是对 SCAP 新实现的持久化、SQLite 发布或恢复逻辑的证明。

此前选择 OpenRaft 的理由是减少初期集成工作：它提供异步运行框架、存储与网络 traits，以及较高层的写入、读屏障、快照和成员管理接口。这个理由仍然成立，但原方案没有充分比较 TiKV 的生产使用背景。对于本项目，优先级调整为：**共识核心的数据库使用经验、持久性契约清晰度、故障可验证性，随后才是接入代码量**。这是一项工程判断，未对两库进行性能或缺陷率排名。

## 2. 名称与层次不能混用

| 名称 | 负责什么 | 与 SCAP 的关系 |
| --- | --- | --- |
| Raft | 选举、日志复制、提交与成员变更的共识协议 | 采用现有实现，不自行重写算法 |
| TiDB | 分布式 SQL 的计算与 SQL 层，使用 TiKV 等组件 | 不引入整套 TiDB SQL 层 |
| TiKV | 分布式事务 KV 数据库 | 参考成熟实现，不因复用其库而声称具备整个 TiKV 的能力 |
| `tikv/raft-rs` / crate `raft` | 共识核心；应用驱动 `RawNode` 并处理输出 | 首选共识库候选 |
| TiKV `raftstore` | 围绕共识核心组织日志、apply、快照、通信及多个 Group 的调度 | 阅读并借鉴；不是随 `raft` crate 自动获得的服务 |
| `tikv/raft-engine` | 面向多个 Raft Group 的嵌入式本地日志引擎 | 后续存储比较项；不是另一套共识算法 |

依据：[TiDB 官方架构][tidb-architecture]、[raft-rs README][raft-readme]、[TiKV raftstore 源码][tikv-peer]、[Raft Engine README][raft-engine]。raft-rs 官方明确只提供 Consensus Module，Log、State Machine 和 Transport 仍由使用者实现。

## 3. 具体比较

| 维度 | raft-rs | OpenRaft | 对 SCAP 的影响 |
| --- | --- | --- | --- |
| 可核实采用 | TiKV 数据复制；本次核到正式 LTS 锁文件 | 官方列明 Databend meta-service 等采用 | 数据复制的直接经验使 raft-rs 更贴近本项目 |
| 抽象层次 | 显式 `tick / step / propose / Ready`，运行时由应用驱动 | 异步 Raft runtime 与高层 API，网络和存储仍需实现 | raft-rs 增加 driver 工作量，控制边界也更明确 |
| 持久化 | `HardState`、entries、snapshot 和 Ready 完成顺序由应用保证 | `save_vote`、`append` / `LogFlushed` 等契约由应用保证 | 两者都不能把内存 store 当生产底座 |
| 强读 | Safe ReadIndex 返回读取水位，应用等待 apply | 0.9.25 的 `ensure_linearizable()` 封装 quorum 与 apply 等待 | 两者都不能替远程 SQLite worker 固定精确 SQL 快照 |
| 成员变更 | learner、`ConfChangeV2`、joint consensus | learner、成员变更与快照相关 API | 成员身份、恢复和运维编排仍属 SCAP |
| 多个 Group | 多个 `RawNode`；TiKV raftstore 实现上层调度 | 可运行多个实例；当前主线另有多组示例 | 均不自动提供 SCAP 的配额、公平调度和跨 cell 迁移 |
| 测试资产 | RawNode、重启、读、成员变更、异步持久化等上游测试 | storage suite；主线另有模拟与故障测试 | 必须补 SCAP 真实 I/O 与 SQLite 集成证据 |
| 许可 | Apache-2.0 | MIT OR Apache-2.0 | 实现时还须核对具体传递依赖与 notices |

接口依据：[锁定 raft-rs RawNode][raft-raw]、[Storage][raft-storage]、[读取源码][raft-read]、[OpenRaft 0.9.25 存储接口][openraft-store]、[0.9.25 Raft API][openraft-api]。上表的适配成本与项目适合度是本项目判断，不是上游性能承诺。

### 3.1 对 OpenRaft 的公平评价

[当前官方 README][openraft-readme]将 0.9.25 列为 0.9 维护线版本，0.10.0-alpha.37 为开发线。它有真实项目采用，并非只能演示的库。但主线功能、测试和 API 不能自动归给 0.9.25：例如 0.9.25 使用 `LogFlushed` 与无参数 `ensure_linearizable()`；0.9 发布说明明确没有 Pre-Vote，开发线才加入相关功能。

[0.9.25 发布说明][openraft-release]记录已修复的 quorum 计算安全问题和快照安装后的成员配置分歧，并建议 0.9.x 用户升级。应将这些回归场景纳入版本审查，不能把已修复缺陷写成当前版本仍然存在的问题，也不能据此推断 raft-rs 没有缺陷。SCAP 不使用上游微基准、星数或单元覆盖率推导自身的可靠性与吞吐。

## 4. 版本来源：从正式 TiKV 发布追溯，不跟随浮动 master

本次核查得到以下不同层次的版本信息：

| 对象 | 核实结果 | 用途 |
| --- | --- | --- |
| raft-rs GitHub 发布 | `v0.7.0`，2023-03-07 | 说明发布包版本，不代表包含后续全部修复 |
| TiKV 正式发布 | `v8.5.8`，2026-08-27 | 本次 G0 源码候选的来源 |
| 对应 TiKV commit | `a1fdd6a59bb9c8a282c15677e1894501a52425cf` | 固定核查 `Cargo.toml` 与 `Cargo.lock` |
| 该 lock 的 `raft` / `raft-proto` | `ad13f3d90780f53aea2488c6a4b76c0d334bf136` | SCAP 的待验证源码候选 |

来源：[raft-rs release][raft-release]、[TiKV release][tikv-release]、[固定 Cargo.toml][tikv-cargo]、[固定 Cargo.lock][tikv-lock]。TiKV 声明的 crate 版本号仍为 0.7.0，同时通过 Git patch 和锁文件选择后续源码。因此，直接添加 crates.io 的 `raft = "0.7"` **不等于**复用该 TiKV 发布所用源码。老的 crate 发布日期也不能单独证明项目停止维护。

后续实现需使用完整 `rev` 固定候选源码，提交实际生成的 Cargo.lock，核验 `raft-proto`、codec、Rust 工具链、编译特性及许可证，再跑本项目门禁。TiKV 的锁文件只证明其依赖选择；我们的 Tonic、存储和运行时组合仍需独立验证。本轮不修改 Cargo 依赖，不声明该候选已经通过 SCAP 测试。

## 5. SCAP 应如何采用

### 5.1 维持共享 cell

一个 cell 仍是三个跨 AZ voter 的复制组，承载多个数据库。选择 raft-rs 不改变数据库身份、单 writer、CP 行为、完整物理事务复制、异步 S3 归档或冷库规则。不能因为 TiKV 有多个 Region，就为每个长期闲置的 Agent 建立常驻三副本 Group。

### 5.2 将 Raft 集成限制在 adapter

`scap-core` 保持依赖自己的 `ConsensusPort` 和 `VisibilityPort`。`RawNode`、`Ready`、`HardState` 等具体类型属于 Raft adapter；数据库 epoch、dedup、权限和提交接受规则属于 SCAP 的确定性状态机。首版采用单 cell 有序驱动与同步持久化，先明确 `advance_append` 和持久 apply 的边界，再考虑流水线和跨组批量刷盘。

这能降低代码耦合，**不表示两个 Raft 实现可以混合组成同一个集群、共享磁盘格式或在线热切换**。未来更换共识实现必须单独设计完整迁移协议。当前没有实际 Raft 集群或已发布日志格式，因此本轮只是设计修订。

### 5.3 保留 RocksDB 为初始持久后端候选

当前 TiKV 的[官方配置][tikv-config]默认启用 Raft Engine 存储 Raft 日志。SCAP 保留 RocksDB 是控制自身恢复边界的工程选择，并非照搬 TiKV 当前默认日志配置。

Raft Engine 值得在日志吞吐、写放大或多组密度成为实测瓶颈时比较。首版暂不同时引入第二个日志引擎：先用有界的 RocksDB 实例与同步 WriteBatch 建立可验证的日志 / HardState / 状态机恢复协议。若日志和业务状态分置两个引擎，跨引擎恢复边界要单独证明；“TiKV 这样用”不能代替证明。

这是控制首版实现复杂度的决定，不宣称 RocksDB 的日志性能优于 Raft Engine。后端最终选择仍由正确性、写放大、尾延迟和恢复测量决定。

### 5.4 性能与覆盖率承诺保持

[既定性能目标](../engineering/performance-slo.md)不因换库自动实现。Raft leader 故障、SQL writer 故障和整个 AZ 故障仍是三种不同的恢复路径；选举时间不能代替完整 RTO。必须记录调度、AZ RTT、fsync、apply、owner fencing、追赶和 SQL 快照激活。

所有第一方 driver、配置、store、transport、恢复与错误处理继续满足 [100% 单元覆盖率合同](../engineering/testability-and-coverage.md)。未经修改的上游库独立归类，真实多节点、断电与网络分区验证单独报告，不能混入单元 profile 提高覆盖率。

## 6. 继续采用与重新评审条件

只有通过 [raft-rs 专项集成门禁](../engineering/raft-rs-integration.md)、现有 G0/G1 和性能测量，才形成可发布能力。若外围 driver 和恢复适配的复杂度不可控，或测量表明需要更完整的现成底座，应重新比较 OpenRaft、dqlite 等方案，不自改 Raft 算法来绕过上游约束，也不降低 durable quorum 合同。

[raft-repo]: https://github.com/tikv/raft-rs
[raft-readme]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/README.md
[raft-raw]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/raw_node.rs
[raft-storage]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/storage.rs
[raft-read]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/read_only.rs
[raft-release]: https://github.com/tikv/raft-rs/releases/tag/v0.7.0
[raft-engine]: https://github.com/tikv/raft-engine
[tikv-blog]: https://tikv.org/blog/implement-raft-in-rust/
[tidb-architecture]: https://docs.pingcap.com/tidb/stable/tidb-architecture/
[tikv-release]: https://github.com/tikv/tikv/releases/tag/v8.5.8
[tikv-cargo]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/Cargo.toml
[tikv-lock]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/Cargo.lock
[tikv-peer]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/components/raftstore/src/store/peer.rs
[tikv-config]: https://docs.pingcap.com/tidb/stable/tikv-configuration-file/#raft-engine
[openraft-readme]: https://github.com/databendlabs/openraft
[openraft-store]: https://github.com/databendlabs/openraft/blob/v0.9.25/openraft/src/storage/v2.rs
[openraft-api]: https://docs.rs/openraft/0.9.25/openraft/raft/struct.Raft.html
[openraft-release]: https://github.com/databendlabs/openraft/releases/tag/v0.9.25
