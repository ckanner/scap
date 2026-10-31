# ADR-0010：有界业务状态机与 Raft 选举、读的专项验证

- 日期：2026-10-31
- 状态：实现决策；实际结果以 [G0 执行证据](../engineering/g0-evidence.md)为准
- 关联：[ADR-0009](0009-serial-driver-and-native-backend.md)、[一致性合同](../architecture/consistency.md)

## 背景

正式 driver、Store 和 native 后端已经能够运行真实 Raft，但上一阶段的多副本应用是合成计数器。Raft 提交不能直接作为 SQL 业务接受；owner、权限、事务前序和去重必须进入同一个确定性状态机。用户同时要求明确分区、两阶段选举、快照与读的实际实现程度。

## 决策

1. 新增正式 `scap-cell`，实现有界数据库元数据、Claim/Activate owner、AuthFence、物理事务接受、请求去重与持久取消 fence；不访问外部服务、不重放 SQL、不在 apply 中发布页面。
2. 复用 core 的不可变提交票据；业务意图 fingerprint 与物理 payload digest 分离，原结果、原 receipt、原准入身份和接受位置一起保留。业务拒绝正常推进应用位置，坏编码和恢复不变量失败仍使 driver 停止。
3. 应用内保存明确位置和复制限额，使用版本化严格 codec 与 `decode_bound` 对齐外层持久 Store。新增非空 genesis 初始化接口，同时保存 application 与 snapshot，保留已有 Store v1 格式。
4. 首版完整保留事务、管理操作和取消 fence；总状态预留拒绝结果空间。容量满时拒绝新增工作，不实施未经证明的回收或去重过期。
5. 沿用 `pre_vote=true`、`check_quorum=true`、Safe ReadIndex。补真实 tick 选举、孤立 follower term 稳定、单向分区与迟到读 ACK 合同；不引入未经时钟假设验证的 LeaseBased。
6. 新 leader 未有当前 term 提交时，driver 显式返回非致命 `ReadNotReady`，不创建被上游丢弃的 ReadIndex 请求票据。当前 term 提交推进后再准入新读。
7. 用独立真实 SQLite/cell 实验验证受限 virtual WAL gate 与 durable quorum、业务结果、native publish、进程退出恢复的组合。研究 helper 不作为产品依赖，也不进入第一方单元覆盖 profile。

## 取舍与限制

预投票改善孤立节点恢复时的选举稳定性，不替代 quorum、持久投票或日志匹配。显式 leadership transfer 仍保留上游特殊选举路径；check_quorum 的退位窗口不能作为读请求授权。

Safe ReadIndex 避免引入租约读所需的额外时钟漂移/暂停证明，但增加 quorum 往返；它还需要业务授权与精确 SQLite snapshot 接合。租约读在满足假设时也可以线性一致，本轮不实现该路径。

业务模块是 G0 子集：bootstrap 管理员轮换、真实凭证认证、完整 lifecycle、迁移和对象引用尚未实现。物理 bytes 的摘要与保留不等于已经验证 SQLite 格式或基线，完整镜像也不满足规模化布局要求。内部结果查询与恢复 API 不能直接成为无保护的外部接口。

本轮不把受控 tick/IPC 实验称为生产自动接管，也不从实验耗时推导 RTO。原有性能、RPO 和覆盖率合同保持不变。

## 依据与验收

- [业务状态机合同](../engineering/cell-state-machine.md)：接口、身份、授权、恢复和容量。
- [Raft 安全与实现边界](../engineering/raft-safety.md)：PreVote、check_quorum、ReadIndex、快照及固定上游源码依据。
- [三进程实验](../../experiments/raft-cluster/README.md)与 [SQLite/cell 实验](../../experiments/sqlite-cell/README.md)：真实依赖的独立合同。
- [覆盖率规范](../engineering/testability-and-coverage.md)：所有新增正式源码仍要求精确 100% 单元覆盖，不能用集成测试补分母。
