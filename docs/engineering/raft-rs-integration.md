# raft-rs 集成与验收契约

初始日期：2026-10-28；G0 存储与 driver 推进：2026-10-29；业务接受、选举与读合同更新：2026-10-31。状态：完整接合门禁；有界 Store、正式串行 driver/native 后端与真实依赖实验已按 [ADR-0008](../adr/0008-bounded-durable-store-g0.md) / [ADR-0009](../adr/0009-serial-driver-and-native-backend.md)进入实现，[ADR-0010](../adr/0010-cell-acceptance-and-raft-safety.md)继续加入有界 cell 和受限 SQLite 接合，精确结果见 [G0 记录](g0-evidence.md)。三进程证据采用受控 IPC 消息故障；**不能据此宣布生产传输、通用 SQL 服务或完整 HA 验收完成**。共识库选型见 [ADR-0006](../adr/0006-raft-rs-consensus-library.md)。

## 1. 范围与源码基线

初始候选为 `tikv/raft-rs` commit `ad13f3d90780f53aea2488c6a4b76c0d334bf136`，来自 TiKV v8.5.8 的锁文件。源码、版本与采用证据见 [选型调查](../research/raft-library-selection.md)。实现提交必须加入实际锁文件与可复现构建，不能直接使用浮动 `master`。

本文件约定 **单 cell 单串行 driver、同步有序持久 Ready、显式 apply**。这是减少第一版证明义务的选择，不意味着 Tokio 线程必须执行阻塞 fsync。网络和磁盘工作通过受控执行器完成，结果回到所属 cell；不同 cell 的调度和限额分开。

`RawNode` 是共识状态对象，不负责帮 SCAP 创建持久日志、业务状态或网络服务。[上游 README][readme]和 [Storage trait][storage]明确这些边界。SQL worker、S3 和 etcd 均不能绕过此 adapter 形成第二个提交权威。

## 2. 责任与窄接口

以下是模块责任，不是要求立即创建空 crate 或通用插件框架：

| 责任 | 输入 / 输出 | 主要不变量 |
| --- | --- | --- |
| Raft driver | 提案、消息、tick、完成事件 → Ready 工作与完成结果 | 一个 cell 的 RawNode 串行驱动；不能提前确认磁盘或 apply |
| 持久 store | 日志、HardState、snapshot 元数据、有序状态批次 | WAL 开启，真实 sync，恢复状态一致，错误使副本停止 |
| transport | 带 cell/node 身份的消息和 snapshot 流 | mTLS、版本、限额、deadline 与背压；拒绝错组、旧世代和无权对端 |
| cell 状态机 | 已提交记录 → Accepted / Rejected / AlreadyCommitted | fencing、授权、前序、dedup 与数据引用确定性裁决 |
| read barrier | 唯一请求 context、ReadState、持久 applied | 完成当前请求的 Safe ReadIndex 后才能产生对应屏障 |
| recovery | 经校验的本地状态或完整 snapshot | 不应用未提交后缀，不丢弃必要世代、权限与取消记录 |

领域层继续使用 `ConsensusPort`，SQLite 使用 `VisibilityPort`。`RawNode`、`Ready`、`eraftpb` 等类型留在 adapter。业务返回的 `Accepted` 必须是本次新接受；去重命中返回原始结果，不能授权发布新暂存页。

## 3. 日志位置与启动身份

SCAP 使用版本化的位置描述：

```text
CellLogPosition {
  cell_id,
  cell_incarnation,
  term,
  index
}
```

只在同一 cell 实例内比较有效的日志水位；索引表示组内顺序，term 用于确认该位置的日志身份，不能跨组排序，也不能用对 term/index 的任意字典序替代协议校验。数据库的 `revision/db_seq`、worker 的 `owner_epoch` 都独立于此位置。

首版明确初始化 cluster identity、合法成员、node identity 和初始配置。已存在数据目录禁止作为空新组初始化。节点替换不得复用仍可能在线的旧节点身份；迁移、区域恢复和数据库重建必须维护各自 incarnation 边界。

## 4. 同步 Ready 的处理顺序

以锁定 [RawNode 源码][raw]为准。下面是协议步骤，不能直接作为省略错误处理的可运行示例。

1. driver 有序消费 `tick / step / propose / read_index` 输入。发现 `has_ready()` 后取得 `Ready`，保存其编号、messages、read_states 和待应用条目。在该 Ready 被按约定推进前，不调用会修改 RawNode 状态的 `step / propose / campaign` 等操作。
2. 若有 snapshot，可先暂存、校验并同步其不可变数据；随后将 active generation、snapshot 位置、业务/ConfState/applied、匹配的合法 `HardState {term, vote, commit}` 与日志边界作为同一个可恢复安装事务发布。不能先发布 snapshot/applied 再补写 commit。entries 与其他 HardState 更新按序持久保存；日志替换、截断、投票和 commit 更新不得被独立后台任务重排。首版对这些持久状态更新采取同步完成边界；`Ready::must_sync()` 为 false 的优化不在首版开启。
3. 普通 `Ready::messages()` 可以按上游契约提前发送；**`Ready::persisted_messages()` 必须等待该 Ready 所需持久状态真实完成**。SCAP 初始实现可以保守延后普通消息，但必须单独计量额外延迟，不把所有消息都需刷盘表述成上游要求。
4. 持久成功后调用 `advance_append(ready)`，取得 `LightReady`。它会报告新的 commit index、committed entries 和 messages；必须完整消费。保存最初 Ready 的 committed entries，并与 LightReady 的条目按日志顺序处理，不能漏掉任一批。
5. 只对库报告的已提交条目进行业务 apply。**持久 commit 必须先于或与该批持久 applied 同时完成**；随后原子持久化业务变化、去重结果、权限、成员配置和真实 applied 位置。使用同一 RocksDB 实例中的同步 WriteBatch 时可将相应 commit 更新与业务 apply 合并；不得覆盖更高的 term/vote，且必须校验连续性和完整日志范围。
6. 持久应用完成后调用 `advance_apply_to(durable_applied)`。所有正常、空条目、被拒绝事务、去重命中和成员变更都正确推进 applied。snapshot-only Ready 即使没有 committed entries，也须把完整持久安装后的应用位置正确推进给 RawNode。任何同步错误都停止相关副本的后续处理；不得推进应用位置、返回业务成功或将失败转为重试成功。
7. 在正确处理本批 messages、读请求状态与完成响应后继续下一轮。提交结果由 `request_id` 等完整身份匹配；`propose()` 成功只表示进入提案路径。只有 durable quorum、业务接受和 worker 的原子 SQL 发布全部成立，客户端才能得到成功。

对原始 `Ready` 的 apply，首版使用上述 `advance_append` 与显式 `advance_apply_to`，避免误用 `advance()` 隐含“该批已经应用”的语义。上游 `advance()` 本身有效，但必须满足其完整处理前提，不能为了缩短代码提前调用。

### 4.1 commit 与 applied 的磁盘关系

[上游集成说明][lib]明确：条目已持久且 committed，不代表 commit index 已经在应用前持久化。若重启时 durable applied 高于 durable commit，可能导致恢复失败，甚至被错误的补救逻辑掩盖数据问题。

SCAP 因而要求在每个可恢复状态上满足：`snapshot_index <= durable_applied <= durable_commit <= recoverable_last_index`，其中最后一项由已安装 snapshot 与连续日志尾部共同定义。这里的 commit 只由库的合法提交进度产生，不能从已接收日志尾部猜测。

`LightReady::commit_index()` 的上游最小要求不强制单独持久该值，但 SCAP 的持久状态机策略要求它不落后于将要持久的 applied。把 commit 与 applied 原子保存或先保存 commit 是本项目选择。启动时禁止直接用 `max(commit, applied)` 修补不一致并继续服务；必须校验并走明确的失败/恢复路径。

### 4.2 首版关闭的优化

不使用 `advance_append_async()`，不让一个 cell 存在多批未完成的 Ready 持久写，不跨 cell 合并 fsync。在后续启用这些优化前，必须单独证明有序完成前缀：`on_persist_ready(n)` 隐含所有较小编号已经持久；完成 n+1 不能替代尚未完成的 n。迟到、重复或来自旧进程的完成事件不得推进新实例。

允许同一个 Ready 或一次受限提案批处理包含多条日志；必须限制总字节、等待时间和单租户份额。任何批处理都不改变单个事务的 durable ACK 条件。

## 5. RocksDB 与线程执行

正式有界后端已使用固定 RocksDB，实际范围见 [driver/native 合同](serial-driver.md)。初版保持 WAL 开启，并明确使用 sync 完成。一个原子 WriteBatch 只能覆盖同一实例内的数据；跨实例、外部 snapshot 文件或 S3 对象需要额外发布与恢复协议。不得把 write 返回、队列入队、页缓存更新或普通 flush 等同于所需持久完成。

G0 采用 [有界完整镜像](durable-store.md)，先验证可恢复原子边界，再通过正式 driver/native 后端连接真实三进程。写放大、镜像大小和各实验的应用边界均明确记录；有界 cell 接受子集已另行实现，可扩展布局、大快照、完整生命周期和生产调度仍需后续实现与同等级测试。native 后端对 WAL 损坏采用严格拒绝，不以较早的一致镜像自动回退 term/vote/commit。

大 snapshot 先写临时版本、校验并完成文件/目录持久化，再原子发布 active generation、snapshot 位置、业务状态引用、ConfState、applied、合法 HardState/commit 与日志边界。若物理布局不能用一个 WriteBatch 发布，必须另行证明安装事务的恢复协议后才能实现。安装发布前不得 advance_append、发送依赖该安装的 persisted_messages 或开放新视图读取；文件持久不等于安装完成。发生任何错误时不能出现“新的 applied 指向旧的业务状态”，也不能恢复一半新配置一半旧日志。

fsync、压缩和快照不阻塞共享网络 runtime。每 cell 的有界状态机调度与存储任务保持顺序；多个 cell 间需要公平配额与控制消息预留。首版一个 cell 在磁盘等待期间可以暂停其 RawNode 驱动，但不能因此占住整个进程的执行线程。磁盘过慢导致的选举与尾延迟必须计入性能结果。

## 6. 读、选举和 SQL writer 切换

正式 driver 强制 `pre_vote = true`、`check_quorum = true`、`ReadOnlyOption::Safe`。2026-10-31 的真实三进程合同覆盖 tick 触发预投票/正式投票、孤立 follower 不膨胀持久 term、单向分区中的旧读 ACK 隔离和新 leader 的 `ReadNotReady`。范围与上游 transfer 例外见 [Raft 安全边界](raft-safety.md)。tick、heartbeat/election tick、实际调度迟滞和背压阈值必须进入构建/实验配置记录；此处不把某个 election timeout 当作 RTO 保证。

强读顺序：

1. 为已经到达的实际请求生成唯一 context，关联 cell 实例、请求身份、主体与过期控制；调用 `read_index(context)`。当前 term 尚无已提交条目时，正式 driver 返回非致命 `ReadNotReady`，不分配票据，待 quorum 推进后重新准入。
2. 从后续 Ready 取得匹配的 `ReadState {index, request_ctx}`。错误、超时、重复、旧世代或不匹配结果不能完成当前请求。
3. 等待该 cell 的持久状态机应用至少到该 index，从同一状态机视图取得数据库身份、owner、权限与提交头。
4. 遵守 [一致性协议](../architecture/consistency.md)的 snapshot-start gate，使独立 worker 固定恰好对应 revision 的 SQLite 快照，然后开始读取。

[Safe 与 LeaseBased][read]的区别必须保持。首版不采用基于时钟租约的读优化；check_quorum 不是读取授权，Raft term 不是数据库 owner epoch。Raft leader 切换与 SQL worker 切换分别处理；后者还需 ClaimOwner、追赶、ActivateOwner 和路由收敛。

既有 R0/R1/R2、leader-only 和单 AZ 的 [性能目标](performance-slo.md)保持不变。恢复计时仍从实际故障到稳定服务窗口起点，包含网络、排队、选举、owner fence、文件恢复与读写成功；不能只报告首次选出 leader 的时间。

## 7. 成员变更、快照与重启

成员配置通过 `ConfChangeV2` 的已提交条目推进，调用 `apply_conf_change` 并持久保存完整 `ConfState`、配置变更应用位置和必要的恢复元数据。joint 状态的进入/退出与 learner 晋升按锁定版本处理；不能只保存一个当前 voter 数组。若内存配置已修改而持久写失败，停止节点并从合法持久状态恢复，不能继续使用未持久的配置服务。

cell snapshot 包含完整 Raft 位置与 `ConfState`，以及数据库 heads、incarnation、placement、owner、auth、dedup、取消 tombstone、migration seal、archive/GC 引用和必要数据。安装遵守第 4–5 节的原子发布，完整旧视图或完整新视图均须满足 commit/applied 关系；不能因只完成文件传输就报告数据库可服务。snapshot 消息的成功/失败反馈使用上游约定，随后仍验证正常复制和应用收敛。

日志压缩仅在 cell snapshot 可恢复且所有数据/引用受保护后执行；单库已上传 S3 不足以清除共享日志。细节遵守 [存储生命周期](../architecture/storage-lifecycle.md)。

重启先校验身份、snapshot、HardState、ConfState、日志范围与状态机真实 applied。`Config.applied` 从经过验证的持久状态恢复，不能设为日志末尾、旧进程内存水位或尚未持久的完成值。只应用被共识判定为 committed 的记录；未提交后缀等待合法对齐。任何新强读仍走读屏障，进程启动不等于恢复完成。

## 8. 单元设计与真实集成验证

采用高内聚的 driver、store、transport、apply/recovery 边界，注入逻辑时间、完成事件、存储故障和消息次序。测试同一生产逻辑，不另写一份简化 Raft 算法去代替真实 `RawNode`。核心业务状态机不读取本地墙钟、网络或可变化的外部权限状态。

未经修改的 raft-rs 属第三方；第一方 driver、配置、序列化封装、持久化次序、错误转换、恢复和自维护 patch 全部进入 [100% 单元覆盖率](testability-and-coverage.md)。模拟持久层必须遵守真实端口语义；真实磁盘、进程和网络验证独立归类。覆盖率全绿不能证明下面的故障合同已经成立。

| 门禁 | 故障或输入 | 必须观察到的结果 |
| --- | --- | --- |
| R-01 | term/vote 写入前后崩溃、短写、fsync 失败 | 不错误投票，不提前发送依赖持久化的响应 |
| R-02 | Ready 完成迟到、重复、错组、旧世代；未来异步时乱序 | 不提前 advance，不将未落盘记录计为持久 |
| R-03 | LightReady 新 commit、消息及 committed entries | 不漏应用；durable commit 不小于 durable applied |
| R-04 | 业务、dedup、ConfState、applied 原子边界崩溃 | 无半批状态，无重复业务效果，拒绝/空记录亦推进水位 |
| R-05 | ACK 前后 kill、整组进程退出与持久盘恢复 | 成功写保留；UNKNOWN 可查证，不自动重执行 SQL |
| R-06 | 少数派、旧 leader、旧 writer、网络恢复 | 无 quorum 不接受新强读写；旧 owner 无法提交 |
| R-07 | ReadIndex context 复用、迟到、领导者变化 | 旧结果不能授权新请求，SQL snapshot 与屏障一致 |
| R-08 | snapshot 传输/安装/替换/purge 任意边界崩溃 | 完整恢复视图，数据和身份不回退 |
| R-09 | learner、joint membership 期间崩溃与分区 | 配置恢复一致，不能通过人工缩小成员获得虚假多数 |
| R-10 | 启动时未提交长后缀、校验错、commit/applied 不一致 | 不应用未提交内容；隔离损坏，不以 max 修补掩盖问题 |
| R-11 | 多 cell 热点、大事务、慢盘、snapshot 与控制请求竞争 | 队列有界，其他 cell 有调度机会；故障按性能口径计入 |

R-01–R-11 是专项断言，映射现有 [验证计划](validation.md)中的分区、恢复及 F-35–F-38，避免用重复场景数量冒充覆盖深度。G0 至少完成真实 RawNode + 持久 store 的关键顺序和崩溃契约；G1 增加三进程 quorum、全重启和分区恢复；跨 AZ 性能与完整单 AZ 失效继续由 G4 门禁验收。

测试产物必须包含准确源码与 codec、工具链、存储同步参数、故障注入点、请求历史、持久/applied 水位和恢复结果。`MemStorage` 可以用于接口学习和确定性协议测试，不能作为 durable quorum 或 RPO=0 的证据。

## 官方源码

所有源码固定到本次候选 commit；这里只引用接口契约，不将其改写成 SCAP 已实现功能。

[readme]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/README.md
[raw]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/raw_node.rs
[lib]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/lib.rs
[storage]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/storage.rs
[read]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/read_only.rs
