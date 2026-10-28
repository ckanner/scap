# ADR-0006：优先验证 TiKV raft-rs 共识核心

- 日期：2026-10-28
- 状态：设计首选已调整；候选源码与集成仍待 G0/G1 验证
- 替代范围：ADR-0002、ADR-0004 中的 OpenRaft 优先候选；共享 cell、CP 与 durable ACK 合同保持

## 背景

用户要求优先评估 TiKV 长期使用的 Raft 库。原方案选择 OpenRaft，主要考虑异步框架与高层接口带来的集成便利，但没有充分比较 TiKV 数据复制的实际使用背景。当前仓库尚无 OpenRaft 依赖、生产 Raft adapter 或已部署的 Raft 日志格式，可以在正式集成前修订选型。

## 决策

1. 共识核心首选 `tikv/raft-rs`，crate 名为 `raft`。OpenRaft 保留为对照，不并行维护两个生产实现。
2. 以 TiKV v8.5.8 正式发布的 Cargo.lock 为源码来源，G0 候选为 `ad13f3d90780f53aea2488c6a4b76c0d334bf136`。这是待测试候选，不是已经加入 Cargo.lock 或通过验证的生产依赖。
3. 每个共享 cell 仍采用三个跨 AZ voter，多个数据库共享一个 Group。SCAP 自行实现日志持久化、网络、driver、状态机、快照、成员运维和恢复。
4. 首版采用单 cell 串行 Ready、同步持久完成、`advance_append`、显式持久 apply 与 `advance_apply_to`。先不启用异步 Ready / 跨 cell group commit。
5. 强读使用 Safe ReadIndex，匹配请求身份、等待 apply，再绑定数据库与实际 SQLite 快照。`pre_vote`、`check_quorum` 只辅助共识运行，不能替代 owner fencing。
6. 核心领域接口不暴露具体 Raft 类型。日志位置以 SCAP 定义的 cell 身份加 term/index 表达，磁盘与网络格式独立版本化。

## 取舍

优先利用 TiKV 数据复制路径的共识经验，同时承担更多 runtime 驱动和持久化次序实现。TiKV 的可靠性不能直接转移给 SCAP；OpenRaft 仍有真实采用和更高层的接口，并非不适合生产。

RocksDB 保留为初始持久后端候选。Raft Engine 是独立的日志引擎，待有实际瓶颈后再评估；引入它需要重新证明跨引擎状态与恢复边界。不同共识实现不能因抽象接口一致而混群或热切换。

## 验收与后续

具体要求以 [集成契约](../engineering/raft-rs-integration.md) 和 [一致性协议](../architecture/consistency.md) 为准：真实 durable quorum、commit/applied 恢复、Ready/LightReady 消费、snapshot、成员变更、分区、UNKNOWN 与 SQL 发布缺一不可。所有第一方实现维持 100% 单元覆盖率；多节点故障测试单独执行。

既定 RTO、延迟、RPO 和容量仍为待测目标。本轮只调整研究和设计合同，不新增可用性或性能实测结论。如果 G0/G1 不能证明正确性或工程成本不成立，重新评审底座，不降低 ACK 或分区合同。

事实证据与精确版本来源见 [选型比较](../research/raft-library-selection.md)。
