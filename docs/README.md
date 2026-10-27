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
- [repository-layout.md](engineering/repository-layout.md)：当前和规划中的目录结构。

## 决策与证据

- [ADR 索引](adr/README.md)。
- [开源组件调查](research/components.md)。
- [机器可读的设计清单](../contracts/design-contract.json)。

## 文档解释规则

1. 文档中的“必须”是设计不变量，不能因演示成功而降低。
2. “目标”表示尚需验证，不能改写为性能或可靠性实测结果。
3. 一致性细节以 `architecture/consistency.md` 为准；故障操作必须遵守该协议。
4. 官方组件行为、项目设计选择、待验证集成能力必须分别标识。
5. 修改协议时，同时检查 API、故障矩阵、验证计划和相关 ADR。
