# 架构决策记录

ADR 记录背景、选择、代价和重新评审条件。当前记录为设计基线；其中需要 PoC 的组件不能因为 ADR 已写下就视为已实现。

| 编号 | 决策 | 状态 |
| --- | --- | --- |
| [0001](0001-sqlite-scope-and-client.md) | SQLite 优先，SDK 服务化入口 | 设计基线 |
| [0002](0002-shared-quorum-cells.md) | 共享同步复制 cell 与 CP 行为 | 设计基线；持久化适配待验证 |
| [0003](0003-object-storage-and-cold-lifecycle.md) | 异步归档、明确发布、可验证回收 | 设计基线；恢复链待验证 |
| [0004](0004-engine-and-implementation-boundary.md) | libSQL / Rust 技术方向及自研边界 | 候选；G0 通过后锁定 |
| [0005](0005-measurable-performance-and-unit-coverage.md) | 明确性能目标、恢复分级与 100% 单元覆盖率 | 工程约束已接受；集群性能待测 |
| [0006](0006-raft-rs-consensus-library.md) | 共识核心优先验证 TiKV raft-rs | 替代 0002/0004 中 OpenRaft 优先候选；G0/G1 待验 |
| [0007](0007-tikv-stack-and-rpc-boundaries.md) | 参考 TiKV 技术栈，明确运行、RPC 与 sqld 依赖边界 | 技术方向确定；编码/传输已有有限实验，生产集成待 G0/G1 |
| [0008](0008-bounded-durable-store-g0.md) | 有界持久镜像与真实 RawNode/RocksDB 恢复验证 | G0 存储策略；生产布局与完整 cell 待验 |
| [0009](0009-serial-driver-and-native-backend.md) | 正式串行 driver、native 后端与三进程故障验证 | 正式模块与有限进程证据；完整业务/RPC/SQL 接合待验 |
| [0010](0010-cell-acceptance-and-raft-safety.md) | 有界 cell 业务接受、非空 genesis、PreVote / Safe ReadIndex 与 SQLite 接合 | 正式接受子集与受限故障证据；完整生命周期、SDK 和生产接管待验 |
| [0011](0011-bounded-native-sqlite-adapter.md) | 正式 SQL 类型/结果、提交前 native gate、无变化事务与完整逻辑镜像恢复 | 有界正式 adapter；完整服务、SDK、自动接管与性能待验 |
| [0012](0012-bounded-raft-network-runtime.md) | 正式 wire、mTLS transport、固定成员运行时、物理配额与真实网络故障合同 | 正式模块与八项三进程契约；完整 SQL/SDK/S3 接合及生产性能待验 |
| [0013](0013-tracked-sqlite-network-commit.md) | 逐请求持久裁决、可信 SQLite 网络 gate 和明确 owner 恢复入口 | 有界正式组合；外部 SDK、自动接管调度、S3 与性能待验 |
| [0014](0014-sqlite-service-and-cold-lifecycle.md) | 正式三节点 SQL/SDK 服务、自动 owner 恢复、独立强读和有界 S3 冷生命周期 | 有界可运行实现与真实故障证据；生产容量、动态控制面、GC/PITR/DR 与 SLO 待验 |
| [0015](0015-incremental-blocks-and-isolated-execution.md) | 增量 native 块布局、按库执行隔离、逐次重新授权的 peer 连接复用 | 实现与独立验证；逻辑分段、生产规模和 SLO 继续保留门禁 |
| [0016](0016-durable-membership-replacement.md) | learner 追赶、持久联合配置、受控副本替换与独立管理入口 | 已实现；完整本地单元和真实四进程门禁通过，生产规模仍未验收 |
| [0017](0017-bounded-physical-history.md) | 物理基线与有限尾部、保留原结果、确定的旧格式升级与通信世代隔离 | 已实现并通过完整本地门禁；生产规模/SLO 未验收 |
| [0018](0018-request-retention-windows.md) | 有序请求窗口、旧请求永久拒绝与结果回收 | 提案，待实施；当前请求/行政记录上限不变 |
| [0019](0019-explicit-request-result-retirement.md) | 显式结果确认、请求世代屏障与有序退休 | 已实现并通过完整本地门禁；承接并修订 ADR-0018 提案，生产规模/SLO 未验收 |

新增 ADR 使用下一个编号，保留被替代记录并注明替代关系。用户或维护者改变范围时记录原因，不通过删除旧决策隐藏取舍。
