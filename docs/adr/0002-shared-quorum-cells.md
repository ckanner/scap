# ADR-0002：共享同步复制 cell 与网络分区策略

- 日期：2026-10-27
- 状态：设计基线；实现通过 G0/G1 后才形成可承诺能力

## 背景

大量小库不适合每库常驻独立三节点集群。异步上传 S3 无法独自保证活跃节点与磁盘同时丢失时保留全部 ACK。需要明确提交和 owner 的共同权威。

## 决策

采用多个共享 storage cell。每个 cell 初始为三个跨可用区 voter 的 Raft 组，复制完整物理事务和控制记录；多个数据库共享一个 cell。OpenRaft 作为共识候选，持久化适配和数据库状态机由本项目实现。

同一状态机裁决 incarnation、placement、owner epoch、前序提交位置和幂等结果。只有 durable quorum 加应用层接受才构成写成功。网络分区时无 quorum 的一侧拒绝新强读写。

etcd 保存目录与调度意图，不能独立授予可绕过 cell 的写权。租约超时只用于触发调度，不证明旧写者失效。

## 代价

跨 AZ 同步增加提交延迟；少数派不可写；共享组有热点和故障影响范围。需要有界事务、公平队列、独立资源池及可证明的跨 cell 迁移。

每库计算可休眠，但共享 quorum 仍要运行。RocksDB 写放大、快照与对象存储请求是实际成本，须测量。

## 替代方案

- **dqlite** 已有基于 SQLite 页面和 Raft 的复制设计，是降低复制自研风险的重要对照。若采用它，需要重评 Node 接入、存算分离和冷库生命周期集成，而不能直接假设与现有 libSQL 服务可互换。[官方复制设计](https://canonical.com/dqlite/docs/explanation/replication)
- **纯异步备份** 易于集成，但不满足本设计的 ACK 保留合同。
- **同步对象存储提交** 是另一条可研究路线，仍需完整的写权、原子发布和故障协议；本期不同时研发两种提交权威。
- **成熟的同步持久存储承载 SQLite 文件** 可转移部分复制工作，但须独立证明 fsync、独占写权与故障域保证；普通共享网络文件不能自动满足 WAL 的要求。

## 重新评审条件

若 G0 无法可靠接入引擎提交点，或共享 cell 自研和维护成本不成立，则重评底座。不能通过允许本地提交或缩小测试故障面继续宣称严格 HA。

参考：[一致性协议](../architecture/consistency.md)、[OpenRaft 存储接口](https://docs.rs/openraft/latest/openraft/storage/trait.RaftLogStorage.html)。
