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

新增 ADR 使用下一个编号，保留被替代记录并注明替代关系。用户或维护者改变范围时记录原因，不通过删除旧决策隐藏取舍。
