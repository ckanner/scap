# ADR-0014：有界 SQLite 服务与可验证冷生命周期

日期：2026-11-02（UTC）。状态：有界正式实现，发布门禁以 [G0 执行记录](../engineering/g0-evidence.md)和[真实服务实验](../../experiments/service-network/README.md)的实际证据为准。本记录扩展 ADR-0010、0011、0012、0013，保留 durable quorum、单 owner、物理复制、CP 和未知业务写不自动重放的合同。

## 背景

正式 native SQLite gate、tracked proposal 和 mTLS cell 已具备独立接口，但还需要面向应用的入口、自动 owner 恢复、鉴权与进程监督。长尾库的物理历史若永久留在热 cell 镜像中，计算停止后仍不能降低这部分驻留；仅增加异步 PUT 也不能证明可以安全卸载。

直接把 SQLite 文件放到普通 S3 key，或依赖文件目录标签自动重开，会绕过 owner 世代、当前权限和最新确认历史。归档若同步运行在唯一 SQL 执行线程上，S3 超时还会拖住其他热库。必须同时定义权威转换、完整验证、后台资源预算和恢复竞态。

## 决策

1. 提供正式 `scap-server` daemon：固定三 voter、单 cell、静态配置；每个进程私有 RocksDB 与证书。明确分离 Initialize 和 OpenExisting，打开失败不创建空库。SQL 对象只在一个专用线程构造、使用和销毁；Raft 由独立 owner 线程推进。
2. 提供 `scap-service` 的有界、自包含 Hrana HTTP v2 子集和本地 TypeScript SDK。固定真实 `@libsql/client`，保留常用 execute/batch 输入结果形式；SCAP `query` 显式走强读。凭据由静态摘要表映射不可变数据库和 principal，随后在 cell 中重新检查当前权限与 auth epoch。公网 TLS 由显式配置的代理终止，peer 始终采用 mTLS 与 scope/leaf pin。
3. SDK 的请求身份与 deadline 在任何探测前固定。仅明确、尚未提案的 NOT_LEADER 可以在原预算内换配置节点；网络中断、超时或结果不明停止自动业务写。Lookup 未找到保留 Unknown，ResolveOrCancel 用有序 fence 取得可解释终态。原 SQL 结果仅在完整确认后交付。
4. leader/term 改变时退休本地 writers。当前 leader 用正式 ClaimOwner、精确物理恢复、新目录构建和 ActivateOwner 接管。周期维护逐库推进，休眠库保持休眠。正常选举启用 PreVote/check_quorum，读采用 Safe ReadIndex，未引入租约读。
5. 强读在新的 ReadIndex 上绑定权限、owner 和完整物理 head，通过只读 SQLite 事务返回结果；不登记 accepted-write 结果，不推进 revision。当前保留完整历史核验成本，后续优化不得削弱屏障或镜像绑定。
6. `scap-cell` 增加 `SuspendDb`、`PublishArchive`、`PruneArchive`、`HydrateArchive`。Suspend 撤销 owner；Publish 绑定原 owner、当前 head、前序引用与完整对象证明；Prune 只卸载被当前发布根覆盖的物理字节；Hydrate 只补回与保留 receipt/result/fingerprint/hash 完全一致的字节，不替换权限或请求元数据。
7. `scap-archive` 使用显式 S3 凭据、不可变内容寻址 key、签名条件 PUT、有界 HEAD/GET、长度及 SHA-256 校验。对象完整可读后才能在原 cell 发布引用。未发布对象不参与恢复，禁止通过 bucket 列表或旧缓存目录推导数据库状态。
8. server 的归档线程受 supervisor 管理，任务/结果各 8 槽，每库一个 pending，重试表受配置库数约束；任务不携带对象正文。所有 I/O 保留原 deadline，失败至少到该 deadline 加 5 秒前不重新排队。原 DatabaseView 经 bound Controller 接口和最终 expected_owner 校验贯穿对象 I/O，不能为旧任务偷偷更新 owner 或 head。
9. 若后台 Prune 恰好发生在前景读取非冷 view 与 ClaimOwner 之间，只对确定 `Rejected(Cold)` 允许一次新视图、hydrate 和恢复。SQL 尚未执行、原 deadline 不变，第二次拒绝立即结束；Unknown 不进入该刷新。
10. 单库归档不授权截共享日志。成功 Prune 通知请求正式全 cell checkpoint；每个 voter 同时保留有界周期检查。快照和原有 Store 协议共同保护完整应用状态、membership 与 applied position。
11. 新 state/command/outcome 写入 v2，支持绑定相同身份和限额的合法 v1 热状态与旧命令/结果。原管理 intent 不含 envelope version，旧操作 ID 升级后仍匹配原 receipt。新生命周期不能放入 v1 envelope；不支持旧二进制原地降级或混合版本协商。
12. 当前永久保留全部对象与请求结果/取消记录。暂不实现对象 GC、自动删除、S3-only 多数副本灾难恢复或动态搬迁；不会通过回收唯一恢复根获得表面容量收益。

## 替代方案与取舍

- **直接把异步备份作为 HA 切换点**：不能证明覆盖最后一次 durable ACK，也不能解决旧 owner 与当前权限；不采用。
- **把 S3 I/O 放在 SQL maintenance 中串行等待**：逻辑简单但故障时影响所有热库；改为有界后台归档。冷请求前景 hydrate 仍占一个 SQL actor，按库分片执行器留到后续。
- **一次支持完整 Hrana、所有 ORM 与本地同步驱动**：协议和事务边界未经验证；本阶段只开放固定 SDK 实际使用的自包含子集，其他程序在执行 SQL 前拒绝。
- **每库独立三节点共识组**：不适合本轮长尾成本目标；共享 cell 提供同步持久性，数据库身份和 owner 在 cell 内有序隔离。当前仍缺少更强的租户计算资源隔离与多 cell 调度。
- **立即实现增量对象、日志布局和安全 GC**：范围会引入新的恢复根、pin、覆盖及删除协议；当前选择完整有界历史、永久对象保留和明确容量拒绝，先验证完整闭环。

## 边界与后果

首个 profile 为静态三个 voter、最多 32 个库、单库 64×4096-byte 逻辑页、每库 128 条请求记录、cell 4096 条管理记录；cell state 8 MiB、command 4 MiB。完整 Store 镜像同步替换、完整历史恢复和强读校验均有写放大或 CPU 成本。后台对象 I/O 已分离，但一个前景 cold hydrate 仍可能推迟同 SQL actor 的其他库。

容量拒绝不会淘汰原结果或取消 fence。已冷库的恢复也可能因 cell 总容量不足被拒绝；本轮尚无恢复容量预留。对象永久保留意味着未发布对象和历史版本会持续占用存储。

没有 quorum、存储损坏、对象缺失或当前权限无法验证时保持拒绝。单节点重新选主和从当前权威历史恢复不等于多数副本永久丢失后的 DR。Ready 是路由提示，Raft 接受和 SQLite 发布仍是写成功的必要条件。

当前不把 100 ms tick、2 秒维护 deadline、5 秒关闭等待或小规模故障实验结果当成生产 RTO/SLO。性能规范中的 1 GiB、跨 AZ、R1/R2 与长期可用性有独立容量和验证门禁。

## 验证与后续变更

第一方 Rust 生产代码必须通过单元 line/function/region/branch 精确 100% 门禁，Node SDK 独立检查 V8 对应计数。线程、时钟、网络、对象、native 构造及错误路径通过窄端口验证；正式算法不能只存在于测试或实验。

独立的 [service-network](../../experiments/service-network/README.md) 运行三个真实 daemon、固定 SDK、mTLS 和透明故障代理；[archive-s3](../../experiments/archive-s3/README.md)单独检查真实兼容端点条件写与重启；它们的 profile 不补单元覆盖率。完整配置与启动命令见[工程说明](../engineering/sqlite-service.md)。

扩大容量、改变保留期、删除对象、增加动态成员/多 cell、按库并发执行、租约读、增量持久布局或改变 SDK 的 UNKNOWN 重试规则，都需要重新评审本记录的恢复根、身份、顺序和资源合同。


2026-11-05 后续协议变更：第 9 项的调用内部 Cold 刷新在 [ADR-0020](0020-bounded-administrative-control.md) 中由固定控制身份替代。v5 管理交错拒绝原恢复任务，本次调用不刷新序号；后续独立任务可重新捕获状态。本文其余阶段性结果仍按原执行记录保留。
