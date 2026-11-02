# 文档地图

阅读顺序：需求 → 架构 → 一致性 → 存储生命周期 → API → 故障矩阵 → 验证与实施。

## 架构

- [requirements.md](architecture/requirements.md)：范围、假设、故障合同和术语。
- [overview.md](architecture/overview.md)：组件、部署、流量、扩容及隔离单元。
- [consistency.md](architecture/consistency.md)：权威状态、提交、读、分区、幂等和恢复协议。
- [storage-lifecycle.md](architecture/storage-lifecycle.md)：对象布局、快照、归档、GC 和冷库。
- [api-contracts.md](architecture/api-contracts.md)：SDK、事务、错误、管理接口与兼容性。
- [tenancy-security.md](architecture/tenancy-security.md)：权限、资源、安全边界与密钥。
- [technology-stack.md](architecture/technology-stack.md)：语言、组件、工程模块与集成门槛。

## 运行与实施

- [failure-matrix.md](operations/failure-matrix.md)：故障和分区行为。
- [runbooks.md](operations/runbooks.md)：操作程序与恢复保护条件。
- [validation.md](engineering/validation.md)：验证模型、故障注入和上线门禁。
- [roadmap.md](engineering/roadmap.md)：逐阶段交付和拒绝降级的条件。
- [capacity-cost.md](engineering/capacity-cost.md)：成本模型与测量计划。
- [performance-slo.md](engineering/performance-slo.md)：明确的延迟、恢复、冷启动和可用性目标及测量口径。
- [testability-and-coverage.md](engineering/testability-and-coverage.md)：100% 单元覆盖率分母、松耦合架构与设计原则。
- [g0-evidence.md](engineering/g0-evidence.md)：已运行的原型、测试结果及尚未证明的边界。
- [raft-rs-integration.md](engineering/raft-rs-integration.md)：Ready 持久完成、应用与快照恢复的集成合同和专项门禁。
- [runtime-and-rpc.md](engineering/runtime-and-rpc.md)：平台执行、RPC、健康检查和 sqld 依赖设计；peer 网络的当前实现见下一项。
- [raft-network-runtime.md](engineering/raft-network-runtime.md)：正式 wire/mTLS/runtime、固定成员与撤销复核、RAII 配额、Safe ReadIndex、停止和真实网络证据边界。
- [durable-store.md](engineering/durable-store.md)：正式持久存储策略、磁盘格式、失败后停止、应用与 checkpoint，以及真实契约测试边界。
- [serial-driver.md](engineering/serial-driver.md)：正式单 cell driver、强类型读票据、取消容量、native 后端和错误完成边界。
- [raft-safety.md](engineering/raft-safety.md)：PreVote、check_quorum、Safe ReadIndex、分区与快照的实际实现边界。
- [cell-state-machine.md](engineering/cell-state-machine.md)：有界业务状态机的身份、owner/auth、事务接受、去重和取消规则。
- [sqlite-engine.md](engineering/sqlite-engine.md)：正式引擎提交、完整结果、前置去重、无变化事务与全量物理恢复边界。
- [repository-layout.md](engineering/repository-layout.md)：当前和规划中的目录结构。

## 决策与证据

- [ADR 索引](adr/README.md)。
- [ADR-0007](adr/0007-tikv-stack-and-rpc-boundaries.md)：参考 TiKV 技术栈，明确采用方向与运行/RPC 边界。
- [ADR-0012](adr/0012-bounded-raft-network-runtime.md)：正式单 cell 网络运行时、逐次 mTLS、有限资源与回执语义。
- [开源组件调查](research/components.md)。
- [Raft 库选型](research/raft-library-selection.md)：TiKV raft-rs 与 OpenRaft 的比较、准确版本来源和采用边界。
- [TiKV Rust 技术栈审计](research/tikv-rust-stack.md)：固定发布源码、实际调用路径与锁文件；区分直接候选、借鉴设计和暂不引入。
- [机器可读的设计清单](../contracts/design-contract.json)。
- [机器可读的技术决策](../contracts/technology-decisions.json)：技术方向、未采用项和不变量；不是服务配置或依赖锁文件。
- [覆盖率策略](../contracts/coverage-policy.json) 与 [性能目标清单](../contracts/performance-targets.json)。
- [Raft RPC 真实实验](../experiments/raft-rpc/README.md)：8 项真实 loopback 编码/传输测试已通过；不包含 RawNode、持久化、quorum 或 HA 验证。
- [Raft/RocksDB 恢复实验](../experiments/raft-store/README.md)：真实 RawNode、同步存储与进程恢复，测试结果和限制单独记录。
- [三进程故障实验](../experiments/raft-cluster/README.md)：正式 driver/backend 的多数派、少数派、整组重启和快照追赶；受控 IPC 故障模型。
- [SQLite/cell 接合实验](../experiments/sqlite-cell/README.md)：真实提交前 gate、业务裁决、原生页面发布与保留物理事务恢复；不属于生产 SDK/服务。

- [正式 SQLite adapter 实验](../experiments/sqlite-engine/README.md)：正式模块与真实 cell 的提交、分区、幂等、快照和进程退出恢复合同。
- [真实 mTLS 网络实验](../experiments/raft-network/README.md)：八项正式网络/runtime 三进程合同；含分区、重启、snapshot、pin 撤销与非持久回执，不执行 SQLite SQL。

## 文档解释规则

1. 文档中的“必须”是设计不变量，不能因演示成功而降低。
2. “目标”表示尚需验证，不能改写为性能或可靠性实测结果。
3. 一致性细节以 `architecture/consistency.md` 为准；故障操作必须遵守该协议。
4. 官方组件行为、项目设计选择、待验证集成能力必须分别标识。
5. 修改协议时，同时检查 API、故障矩阵、验证计划和相关 ADR。
6. 实验锁定的依赖与结果只适用于所测范围；平台与 sqld 的 fork、模块提取或独立进程边界仍须通过 G0 验证。

最新实现：[SQLite 网络提交与恢复](engineering/sqlite-network.md)，以及对应的 [ADR-0013](adr/0013-tracked-sqlite-network-commit.md)。
