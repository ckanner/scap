# ADR-0009：正式串行 driver、原生后端与三进程验证

- 日期：2026-10-29
- 状态：实现决策；实际测试结果以 [G0 执行证据](../engineering/g0-evidence.md)为准
- 关联：[ADR-0008](0008-bounded-durable-store-g0.md)、[Raft 接合契约](../engineering/raft-rs-integration.md)

## 背景

有界持久 Store 已提供版本化状态与恢复不变量，前一轮实验以测试夹具装配 RawNode 和 RocksDB。下一步需要把可复用的运行顺序和 native I/O 纳入正式源码，并用三个独立进程验证多数派、分区与重启行为。第一方实现继续受精确 100% 单元覆盖率门禁约束。

## 决策

1. 新增正式 `scap-raft-driver`，直接使用固定 raft-rs 的 RawNode 和正式 Store；不再实现一份简化共识算法。一个 driver 串行处理逻辑 tick、消息和提案，按既定 Ready / LightReady / 持久 apply 顺序推进。
2. 注入的应用接口只从旧应用字节和有序条目计算候选新状态，不在此接口发布 SQL 页面或执行外部副作用。driver 保存应用、完整配置与 applied 后才交出完成结果；错误，或穿过 driver 调用链后由外层捕获的 panic，使当前实例停止。
3. 为输入、输出、待处理读和每次 drain 的工作量设置明确预算。准入前的拒绝与处理开始后的失败分别表达；一旦发生持久化或状态变化，失败不能被解释为确定未提交。
4. 读 context 由 driver 生成并绑定 cell、节点、启动身份与递增序号。匹配本次待处理请求且 durable applied 达到 ReadIndex 后才能交出 Raft 应用屏障。它还不是 SQL 快照、权限或 owner 的完整读授权。
5. 新增正式 `scap-raft-rocks`，兑现 AtomicBackend。创建使用独占目录预留，打开已有目录禁止自动创建新数据库，WAL、同步写、paranoid checks 和 `AbsoluteConsistency` WAL 恢复模式由模块固定，不能通过调用方选项关闭。失败保留现场，不自动删除残留或修复旧状态。
6. `experiments/raft-cluster` 使用三个真实进程、各自真实 RocksDB 目录和上述正式模块。测试父进程以有界 IPC 帧路由 Raft 消息并注入隔离、丢弃与退出；这验证受控消息分区，尚不验证生产 RPC、mTLS、真实链路断连或跨 AZ。

## 单元与真实依赖的边界

driver 的单元测试只验证一个正式模块的输入、顺序、预算、应用与停止行为。未修改的 Raft 内核作为确定性依赖，存储、应用、逻辑时间和输出交付受控；不把三个节点的协议历史放进单元 profile。

native 后端的策略使用窄 I/O 边界枚举错误。薄 native 委托使用上游 memory Env 验证单个 adapter 的参数与返回行为，数据文件放在受控内存环境中；默认入口的目录准入行为仍须实际覆盖。memory Env 不提供磁盘同步证据，也不能用于证明进程重启后的持久性。

真实磁盘、RawNode/RocksDB 接合、子进程退出和多节点故障继续在独立测试层执行。不得把旧集成测试改名并入 unit，也不得排除正式适配器或改变覆盖阈值。

## 代价与后续边界

driver 是同步、单 cell 的运行组件，需要由有序阻塞执行路径调用；它不是共享 Tokio 网络 runtime 的调度方案。多 cell 公平性、控制流量预留、慢盘隔离和取消策略仍需相应实现及负载验证。

本轮沿用 ADR-0008 的完整有界镜像。RocksDB 正式装配和真实 quorum 行为不消除其写放大、checkpoint 容量和大快照限制；增量布局需要独立格式与恢复证据。

固定 native 的默认 WAL 恢复模式允许在发现损坏时恢复到较早的一致位置。对 Raft，这可能返回一份 checksum 正确但缺少已持久 term/vote/commit 的旧镜像。因此本模块选择严格恢复并拒绝损坏，交给有依据的健康副本重建流程处理。代价是崩溃留下的损坏尾部也可能使本地打开失败；不得临时切换到宽松恢复来恢复服务。自动重建流程及物理掉电故障仍需后续实现与验证。

三进程合成应用验证不能替代完整业务状态机、SQL 原子发布、SDK UNKNOWN 语义、认证、S3 生命周期或端到端 RTO。即便局部测试通过，G0/G1 的其他门禁仍保持原状态。

## 上游依据

- [固定 RawNode](https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/raw_node.rs)：串行 Ready、显式应用与 Safe ReadIndex 接合。
- [固定 Config](https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/config.rs)：选举、复制和未提交/待应用大小选项。
- [RocksDB binding 0.24.0 Env](https://github.com/rust-rocksdb/rust-rocksdb/blob/v0.24.0/src/env.rs)：memory Env 将文件数据保存在内存，其他任务仍委托底层环境。
- [native RocksDB 打开路径](https://github.com/facebook/rocksdb/blob/410c5623195ecbe4699b9b5a5f622c7325cec6fe/db/db_impl/db_impl_open.cc)：目录创建与已有数据库检查的实际顺序。
- [native WAL 恢复模式与默认值](https://github.com/facebook/rocksdb/blob/410c5623195ecbe4699b9b5a5f622c7325cec6fe/include/rocksdb/options.h)：严格拒绝损坏与按时间点恢复的语义差异。
