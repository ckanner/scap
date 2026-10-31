# Raft 状态机、分区、选举与读的实现边界

核查日期：2026-10-31。本文以固定 raft-rs `ad13f3d90780f53aea2488c6a4b76c0d334bf136` 和正式 `scap-raft-driver` 为依据。实际用例与计数见 [G0 执行证据](g0-evidence.md)；本页不将配置存在视为完整 HA 已交付。

## 1. 两层状态机

| 层 | 实现职责 | 当前接合范围 |
| --- | --- | --- |
| Raft 协议状态机 | follower / pre-candidate / candidate / leader、term/vote、日志匹配、quorum、提交和配置转换 | 复用固定 `raft-rs`，由正式 driver、Store 与 RocksDB 后端兑现持久化顺序 |
| SCAP 数据库状态机 | 数据库身份、owner、权限版本、事务前序、幂等与取消、物理事务保留 | 正式 `scap-cell` 的有界 G0 子集；完整引擎、生命周期、生产传输和 SDK 接合仍有门禁 |

Raft 条目提交只表示它进入了有序历史。携带过期 owner 或权限版本的事务，仍可成为已提交条目，但业务应用必须返回拒绝，且不得发布 SQLite 页面。协议内核、业务接受和 SQL 可见性是三个需要实际接合的边界。

## 2. 预投票与正式选举

driver 强制设置 `pre_vote = true`。正常选举超时先进入 `PreCandidate`：发送面向下一 term 的预投票请求，但不递增自己的当前 term，也不记录正式 vote。只有达到所需多数支持，才进入正式 `Candidate`，增加 term、投票并按持久化规则发送相应消息。正式选举获得多数后成为 leader。[固定 tick/campaign 与投票实现][raft-source]

这通常称为 PreVote 加正式投票两阶段选举，与事务两阶段提交不同。它主要避免孤立节点持续增加 term，恢复连接后干扰原本健康的多数派。它不能让一个少数派安全写入，也不替代日志新旧比较、单 term 单票、持久化或 quorum 规则。

需要保留一个上游语义例外：显式 leadership transfer 使用专门的 `CAMPAIGN_TRANSFER` 路径，可跳过预投票；不能把“正常超时选举启用 PreVote”写成所有选举路径都无条件执行两轮。[固定 hup/transfer 实现][raft-source]

三进程契约记录真实 PreVote/Vote 消息与持久 term/vote；以显式逻辑 tick 触发正常选举，并检查预投票未通过前持久状态不变。该测试不使用墙钟来推导生产选举或接管时长。

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
5. 在同一持久业务视图上校验数据库身份、owner、当前权限和目标 revision；真正固定相应 SQLite 快照仍由引擎接合负责。

第二步修复了固定上游的一项接口细节：新 leader 未提交当前 term 条目时，原始 MsgReadIndex 会被丢弃并返回成功状态，之后不会自动补发该读结果。准入层明确返回 `ReadNotReady`，让调用方在 quorum 推进后重新发起；不能留下一个看似已受理却没有完成路径的票据。[固定 MsgReadIndex 分支][raft-source]

取消外层读不会立即移除 Raft 内部待确认上下文，因此两个集合分别受容量约束。已取消、旧 boot 或不匹配的 context 不会完成新请求。

租约读在满足时钟漂移、暂停等必要假设时也可以线性一致；不能把它直接称为最终一致。固定上游明确指出，无界回拨或暂停会破坏租约安全。本项目当前没有提供这组部署与时钟证明，因此不启用 LeaseBased。`check_quorum` 是领导权检测机制，不能单独作为每次读请求的授权。[读模式安全说明][read-only]

## 5. 快照、日志压缩与恢复

Store 的快照包含应用 bytes、完整 ConfState、index/term；安装与应用位置、提交水位和日志边界按同一原子镜像发布。保留完整 joint configuration，不能仅恢复 voters 列表。压缩保留 boundary term，不能在可恢复快照形成前删除必要日志。

driver 处理 snapshot-only Ready 时直接安装完整 application，不再逐条调用业务 apply。因此 `scap-cell` 读取必须执行 `decode_bound`，把应用内的 cell 身份和 term/index 与外层 Store 的同一持久视图匹配，避免以较新的 applied 掩盖较旧的业务数据。

三进程实验已经提供真实 MsgSnapshot 失败反馈、重试、安装和再次重启的独立合同。成员变更的已提交配置应用与持久化已有实现，但生产成员管理 API、learner 调度、大快照传输和自动坏副本重建尚未完成。

Raft snapshot 不能直接等同于单个 SQLite 文件或 S3 备份。业务状态机快照需保留其元数据、事务、幂等和取消 fence；引擎格式、数据库基线、对象引用与回收还须满足各自的恢复合同。

## 6. 已证明与仍待验收

当前证据覆盖固定内核的驱动顺序、投票与提交持久化、受控分区、请求绑定读、快照和重启，以及新增业务状态机的有界规则。正常选举测试使用真实 tick 和消息，但没有提供生产 failure detector、负载下调度、RPC/mTLS 或端到端自动接管时间。

不把单个选举算法、100% 单元覆盖率或数个故障历史概括为完整分布式系统证明。完整出口仍按 [raft-rs 集成门禁](raft-rs-integration.md)、[验证计划](validation.md)与[性能合同](performance-slo.md)执行。

[raft-source]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/raft.rs
[read-only]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/read_only.rs
