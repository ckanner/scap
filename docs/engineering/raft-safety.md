# Raft 状态机、分区、选举与读的实现边界

内核核查日期：2026-10-31；正式网络接合进展更新：2026-11-01。本文以固定 raft-rs `ad13f3d90780f53aea2488c6a4b76c0d334bf136` 和正式 `scap-raft-driver` 为依据。当前 [单 cell 网络运行时](raft-network-runtime.md)已接上正式 mTLS peer transport。实际用例与计数见 [G0 执行证据](g0-evidence.md)；本页不将配置存在或有限故障历史通过视为完整 HA 已交付。

## 1. 两层状态机

| 层 | 实现职责 | 当前接合范围 |
| --- | --- | --- |
| Raft 协议状态机 | follower / pre-candidate / candidate / leader、term/vote、日志匹配、quorum、提交和配置转换 | 复用固定 `raft-rs`，由正式 driver、Store 与 RocksDB 后端兑现持久化顺序 |
| SCAP 数据库状态机 | 数据库身份、owner、权限版本、事务前序、幂等与取消、物理事务保留 | 正式 `scap-cell` 的有界 G0 子集已接真实 peer 网络；native SQLite 另有独立 adapter 证据，完整 SQL 网络组合、生命周期和 SDK 仍有门禁 |

Raft 条目提交只表示它进入了有序历史。携带过期 owner 或权限版本的事务，仍可成为已提交条目，但业务应用必须返回拒绝，且不得发布 SQLite 页面。协议内核、业务接受和 SQL 可见性是三个需要实际接合的边界。

## 2. 预投票与正式选举

driver 强制设置 `pre_vote = true`。正常选举超时先进入 `PreCandidate`：发送面向下一 term 的预投票请求，但不递增自己的当前 term，也不记录正式 vote。只有达到所需多数支持，才进入正式 `Candidate`，增加 term、投票并按持久化规则发送相应消息。正式选举获得多数后成为 leader。[固定 tick/campaign 与投票实现][raft-source]

这通常称为 PreVote 加正式投票两阶段选举，与事务两阶段提交不同。它主要避免孤立节点持续增加 term，恢复连接后干扰原本健康的多数派。它不能让一个少数派安全写入，也不替代日志新旧比较、单 term 单票、持久化或 quorum 规则。

需要保留一个上游语义例外：显式 leadership transfer 使用专门的 `CAMPAIGN_TRANSFER` 路径，可跳过预投票；不能把“正常超时选举启用 PreVote”写成所有选举路径都无条件执行两轮。[固定 hup/transfer 实现][raft-source]

[受控消息三进程契约](../../experiments/raft-cluster/README.md)记录真实 PreVote/Vote 消息与持久 term/vote；以显式逻辑 tick 触发正常选举，并检查预投票未通过前持久状态不变。该测试不使用墙钟来推导生产选举或接管时长。

后续 [真实网络契约](../../experiments/raft-network/README.md)由正式 runtime 按单调时钟自动 tick，通过 mTLS 完成实际选举与 leader 故障恢复。逐条释放投票前的持久 term/vote 对照仍属于前一套受控消息证据，不能把网络套件的选举成功描述成又一次精确消息调度验证。本阶段 wire 拒绝 TransferLeader，尚无生产领导权转移管理 API；上游 transfer 路径的语义例外仍须保留。

## 3. 分区与 check_quorum

driver 强制设置 `check_quorum = true`。leader 在检测窗口内失去活动多数后退回 follower。检测存在时间窗口，因此一个孤立旧 leader 暂时仍自认为 leader 是正常情况；安全性不能只依赖它最终退位。[固定 leader quorum 检查][raft-source]

| 分区情况 | 要求 |
| --- | --- |
| 1 对 2，仍有合法多数 | 多数派可以选主、持久提交；少数派新提案不能形成提交，新强读不能完成 |
| 不存在有效多数 | 停止新的提交与强读完成；不得改为本地成功、缩小配置或强制选主 |
| 单向断连 / 延迟消息 | 按真实往返与请求 context 判断 quorum；旧心跳 ACK 不能授权后来的新读 |
| 恢复连接 | 由 Raft 日志规则对齐未提交后缀；不能把 UNKNOWN 一概解释为已回滚 |

已有分区前固定的 SQL 读快照，是否可以继续读取，属于 [SQL 读协议](../architecture/consistency.md)的单独边界。当前 driver 只交付 Raft 读屏障，不自动维护 SQL 快照。

## 4. Safe ReadIndex 与租约读

首版强制 `ReadOnlyOption::Safe`，不会因调用方配置 `LeaseBased` 而切换默认安全策略。固定上游实现首先要求 leader 已有当前 term 的提交，然后对实际请求携带的唯一 context 发起 heartbeat quorum 确认，最后产生对应 ReadState。[读模式定义][read-only] [实际 ReadIndex/heartbeat 路径][raft-source]

driver 的完整边界是：

1. 本次请求必须在 leader 上准入，且此前 Ready / 待交出的读结果已处理。
2. 当前 term 尚无提交时返回非致命 `ReadNotReady`，不分配读票据，不占 pending 容量。
3. 票据绑定 boot 与不复用的 sequence；wire context 还绑定 cell/节点身份。
4. 只匹配本次仍有效请求的 ReadState，等待 durable applied 至少达到该 index 后交出屏障。
5. 应用调用方在同一持久业务视图上校验数据库身份、owner、当前权限和目标 revision；真正固定相应 SQLite 快照仍由引擎接合负责。

第二步修复了固定上游的一项接口细节：新 leader 未提交当前 term 条目时，原始 MsgReadIndex 会被丢弃并返回成功状态，之后不会自动补发该读结果。准入层明确返回 `ReadNotReady`，让调用方在 quorum 推进后重新发起；不能留下一个看似已受理却没有完成路径的票据。[固定 MsgReadIndex 分支][raft-source]

取消外层读不会立即移除 Raft 内部待确认上下文，因此两个集合分别受容量约束。已取消、旧 boot 或不匹配的 context 不会完成新请求。

租约读在满足时钟漂移、暂停等必要假设时也可以线性一致；不能把它直接称为最终一致。固定上游明确指出，无界回拨或暂停会破坏租约安全。本项目当前没有提供这组部署与时钟证明，因此不启用 LeaseBased。`check_quorum` 是领导权检测机制，不能单独作为每次读请求的授权。[读模式安全说明][read-only]

## 5. 快照、日志压缩与恢复

Store 的快照包含应用 bytes、完整 ConfState、index/term；安装与应用位置、提交水位和日志边界按同一原子镜像发布。保留完整 joint configuration，不能仅恢复 voters 列表。压缩保留 boundary term，不能在可恢复快照形成前删除必要日志。

这是底层 Store 格式与恢复能力的要求，不表示当前网络运行时接受动态成员。正式 runtime 启动只允许与 policy 精确一致的固定 voters，wire 也拒绝配置变更 entry 及携带 learner/joint/auto-leave 或不同成员集的 snapshot；不能用修改本地配置代替有序成员管理。

driver 处理 snapshot-only Ready 时直接安装完整 application，不再逐条调用业务 apply。因此 `scap-cell` 读取必须执行 `decode_bound`，把应用内的 cell 身份和 term/index 与外层 Store 的同一持久视图匹配，避免以较新的 applied 掩盖较旧的业务数据。

受控消息三进程实验已经提供真实 MsgSnapshot 失败反馈、重试、安装和再次重启的独立合同。后续真实网络实验补充了落后副本通过正式 mTLS 路径安装 snapshot、再 SIGKILL/重开仍保留快照的证据。底层 driver 的已提交配置应用与持久化存在，但正式网络入口限定固定成员；生产成员管理 API、learner 调度、大快照分片和自动坏副本重建尚未完成。

Raft snapshot 不能直接等同于单个 SQLite 文件或 S3 备份。业务状态机快照需保留其元数据、事务、幂等和取消 fence；引擎格式、数据库基线、对象引用与回收还须满足各自的恢复合同。

## 6. 已证明与仍待验收

2026-10-31 阶段的证据覆盖固定内核的驱动顺序、投票与提交持久化、受控分区、请求绑定读、快照和重启，以及业务状态机的有界规则。其 IPC 故障模型没有验证真实 RPC/mTLS，这一历史范围保持不变。

2026-11-01 后续八项真实网络契约已使用正式 wire/transport/runtime、三进程 RocksDB 和有方向的 TCP 故障代理，补充双向黑洞与单向分区、实际连接恢复、进程重启、snapshot、mTLS/node/cell 授权、旧连接与旧队列 pin 撤销、非持久 Received 等证据。普通 RPC 返回不能授权新的强读；所有成功读都检查当前 boot 的票据与 durable applied 屏障。单向分区用例验证新读不成功，没有逐条记录分区后的每个正向 RPC receipt；旧 ACK 捕获重放仍由受控消息套件验证。

网络实验使用正式 cell 的合成物理 payload，没有执行 SQLite SQL。完整 SQL 网络组合、writer 自动故障检测/接管、多 cell 负载调度、跨 AZ 与掉电故障、S3 生命周期，以及端到端延迟/RTO 仍未由这些用例证明。详细当前边界见 [ADR-0012](../adr/0012-bounded-raft-network-runtime.md)。

不把单个选举算法、100% 单元覆盖率或数个故障历史概括为完整分布式系统证明。完整出口仍按 [raft-rs 集成门禁](raft-rs-integration.md)、[验证计划](validation.md)与[性能合同](performance-slo.md)执行。

[raft-source]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/raft.rs
[read-only]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/read_only.rs
