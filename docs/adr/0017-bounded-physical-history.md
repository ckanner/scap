# ADR-0017：有界物理历史与确定的旧格式升级

- 日期：2026-11-04。
- 状态：已实现；2026-11-04 完整本地单元、真实故障与独立证据复核通过。生产规模与 SLO 未验收。
- 关联：[ADR-0015](0015-incremental-blocks-and-isolated-execution.md)、[ADR-0016](0016-durable-membership-replacement.md)、[cell 状态机](../engineering/cell-state-machine.md)、[SQLite 恢复](../engineering/sqlite-engine.md)。

## 问题

内容块增量持久化减少了 native WriteBatch 的重复写入，但应用层仍保留每次已接受事务的完整物理增量。即使 SQLite 文件大小稳定，反复更新同一批页面也会累积历史，消耗 8 MiB cell 镜像预算，并让 writer 接管与强读从最早事务开始重放。

物理增量和客户端请求结果有不同的生命周期。丢弃旧的物理增量不能删除原 request ID、fingerprint、receipt、随机 SQL 结果或取消 fence；否则 UNKNOWN 查证与去重会失去依据。恢复基线也必须是同一份 quorum 持久应用状态的一部分，不能以后台生成的本地文件代替。

## 决策

### 1. 分离逻辑记录与物理恢复材料

每个数据库继续保留原有有界逻辑事务表和请求表。revision 仍是已接受事务总数，`RequestRecord::Accepted(sequence)` 仍索引原事务；行政 receipt、当前 owner、权限与取消记录不因物理折叠而退休。

物理材料改为可选 `RecoveryBase` 和连续 tail。基线包含完整 SQLite image bytes、image digest、所覆盖 revision、对应 commit hash 和原提交的 term/index。基线的 source 必须等于该逻辑前缀最后一次提交的位置，commit hash 必须等于保留记录中的值，且不能超过外层持久 applied。

commit hash 证明逻辑前缀，image digest 校验恢复 bytes，二者不能互换。仅有一个通过摘要检查的 image 不授予权限；调用者仍须取得新鲜 Safe ReadIndex 的同一 Store 视图，绑定 cell/database 身份、incarnation、应用位置、当前 READ 权限及目标 head。

### 2. 使用同一个纯物理算法

原 engine 的 SCAPIMG 编解码、页面变换和重放实现移动到正式 `scap_core::physical`。该模块不执行 SQL、不读取时钟或对象存储、不访问 Raft，也不生成权威接受证明。它提供有界 `Image`、`Prepared`、`Snapshot` 和 receipt 重放校验。

`scap-engine` 保留面向调用者的接口与错误语义，负责把纯物理恢复绑定到经过授权的 `CellState`。状态机折叠与 engine 恢复都调用该模块；实验不保存另一套重放算法。共享模块完整进入第一方单元覆盖率分母。

### 3. 在同一 Commit 候选中折叠

新 Commit 通过原有身份、权限、owner、前序、payload digest 和去重检查后，先加入候选事务表。当 tail 满足以下任一条件时，候选状态从已有基线或空镜像逐条重放全部 tail，并生成新基线：

- tail 至少 8 条；
- tail bytes 至少为 `min(max_state_bytes / 4, max_transaction_bytes * 4)`。

这些条件只依赖已复制的 limits 和固定格式规则，不依赖 worker 本地参数。物理重放的页面预算由 `max_state_bytes / 4096` 推导并受物理格式上限约束，单次事务预算保持原值。

成功折叠清除已覆盖记录中的 `physical_changes`，保留其他字段及原结果。新基线、清空的前缀、剩余 tail、当前请求结果和 applied 同属现有 Store 原子持久应用。重放失败或最终编码超过原容量时，整个候选被拒绝；不能先释放旧恢复材料再尝试建立基线。

普通 Commit 的摘要与 opaque payload 边界保持原行为，需要物理折叠时才执行完整 SCAPIMG 校验。正式 SQLite writer 只能生成正式物理格式；自定义 opaque bytes 不因此获得 SQLite 恢复保证。

### 4. 归档与 Cold 状态

归档仍经过准确的不可变对象上传、readback 核验、PublishArchive 与 PruneArchive。新对象携带完整逻辑记录、可选基线和有限 tail。归档 metadata digest 继续只绑定不可变逻辑记录，不能因为内部物理表示改变就撤销一个已发布的旧对象覆盖证明。

Prune 只释放对象已覆盖的物理 base/tail。Cold 保留基线 anchor、全部结果和取消记录，resident tail 数量和 bytes 为零；物理恢复入口仍拒绝 Cold。Hydrate 先核验精确对象及完整覆盖，只补物理材料，不能用归档中的旧权限、旧 owner 或旧请求表覆盖当前状态。

当前对象不删除；本决策没有实现对象 GC、请求结果退休或 PITR。物理基线也不等同于共享 Raft snapshot。application/ConfState/applied 的 checkpoint 和日志裁剪仍遵守原 Store/driver 协议。

### 5. 确定的旧格式迁移

写入 `SCAPCELL` v3 与 `SCAPARC!` v3；保留合法旧 cell v1/v2 与 archive v2 的读取能力。`SCAPCMD!`、`SCAPOUT!` 仍为 v2，`SCAPIMG!` 仍为 v1。旧数据必须绑定相同身份与复制 limits。

读取旧 v1/v2 状态时只校验，继续保留 v2 状态机语义与完整物理历史。其后旧日志的 Commit、容量判断、精确 archive v2 发布和 Hydrate 必须按原规则裁决，编码预算也保持 v2。不能在 decode 时折叠：除了不同旧 applied 可能产生不同 base/tail，旧 quorum 已接受的 PublishArchive 还可能因新归档 bytes 不同而被拒绝，旧 Capacity 拒绝也可能因新折叠腾出空间而反变为接受。

新程序通过一个独立内部 application entry 明确激活 v3。该条目绑定 cell 身份与不可变 bootstrap administrator，使用自己的版本、长度、摘要和结果 envelope，不复用普通业务 `last_outcome`。条目在现存日志之后由 Raft 有序提交；候选对所有热库执行规范迁移，再验证整个 v3 状态预算，全部成功才原子发布 phase 3。失败返回绑定本次精确 term/index 的拒绝，保留 phase 2 和原恢复材料；不得让半个 cell 提前进入新语义。

要求任意合法旧进度切点均满足：**较旧副本先按 v2 追赶旧 suffix，再在同一个有序激活位置转换，与已拥有完整旧前缀的副本得到字节完全相同的状态和归档材料**。迁移按历史顺序使用与新 Commit 相同的条目/bytes 阈值，未达到阈值的尾部保留且必须可恢复。不能把各副本的启动时刻、term 变化或空 Raft entry 当成激活边界。

通用组件的显式新 bootstrap 可直接使用 phase 3；正式 server 的 Initialize、Join 和 genesis 摘要则统一使用固定的 v2 空 genesis，与旧 main `662f04133f6a869d0dae5b05467656e6deca5c12` 逐字节相同，再通过有序激活启用 v3。否则，新 learner 从直接 v3 的 genesis 追赶旧日志前缀，会提前使用新容量/归档语义；不能仅依赖本次追赶碰巧走了 snapshot。固定 genesis 也使 [ADR-0016](0016-durable-membership-replacement.md)的 Join 身份校验跨升级保持一致。

旧状态在激活前继续写 v2，phase 由持久状态版本识别，snapshot 必须携带它。重复激活单调幂等，绝不从 3 回到 2。server 目录维护等待精确持久结果，并通过新的权威读取确认 phase 3 后才开放业务；直接访问业务端点也不能绕过这个检查。激活不是新的租户 HTTP 管理接口。

旧 Cold 不凭空制造 bytes 或基线，激活时保留准确 archive 引用；激活后的 archive v2 Hydrate 才按同一规范规则恢复物理表示。旧归档中的原结果、当前权限变更和较新的取消记录均不得丢失。

v3 的 optional-base 标记有固定编码成本。合法旧 metadata 若已贴近配置上限，迁移后仍可能不符合原预算；此时失败关闭并保留原盘，不放宽 reserve、限额或强制初始化。旧 opaque payload 无法恢复为有效 SQLite image 时同样拒绝。读取兼容并不承诺任何旧输入都能在任何极限预算下升级。

### 6. 通信世代隔离与升级流程

新折叠规则改变相同 Commit 的容量裁决，不能让旧全历史状态机与新状态机共同应用一个 quorum 日志。正式 Raft envelope 的 version 从 1 升至 2，固定 `SCAPRPC1` magic、80 字节头与 codec 1 不变。双方在内部 Raft 解码和 driver step 前拒绝非本世代的消息；没有自动协商或降级。

内层 command/outcome v2 和 gRPC `Received { version: 1 }` 分别表示业务编码与入队回执，不能承担这个世代隔离。所有 runtime 发包使用正式 wire 的 version 常量。

受支持的部署流程是停止整个 cell 的旧程序，保留原磁盘与配置，再让所有 voter 用新程序 OpenExisting；新 quorum 先完成旧日志及有序激活，再开放业务。禁止旧、新版本混合运行来宣称完成无停机升级。隔离测试允许主动构造混合节点，必须证明不同世代不能组成 quorum；旧两个节点仍可能以旧 quorum 服务，这不意味着升级已经完成。

已持久化 v3 application 的目录不能用旧二进制继续打开。降级应保留失败盘及诊断信息，不能删除目录、重建 genesis 或绕过 decode。

### 7. 状态观测与 SDK

fresh status 增加 `base_revision`、`tail_entries`、`tail_bytes`，沿用 JSON 十进制 u64 字符串，全部来自同一次权威视图。SDK 对应 `baseRevision`、`tailEntries`、`tailBytes`，类型为 `bigint | null`。

三项都缺失表示旧服务没有提供这些观测，SDK 返回三个 null；部分缺失、错误类型或超出 u64 均拒绝。不能把缺失字段变成 0，亦不能从有限 tail 推导原请求结果是否存在。原结果继续通过 Lookup 获取。

## 验证出口

合入需要最终相同源码的完整单元、严格 lint、逐文件精确四维覆盖率和真实故障门禁。测试包括：

1. 纯物理 baseline 校验，位置/身份/head 绑定，跨基线恢复，旧结果与取消保留；损坏、预算和原子拒绝。
2. 由真实旧 main `662f04133f6a869d0dae5b05467656e6deca5c12` 生成的 v2 热/冷/归档 fixture；任意旧进度切点在激活前重放成功、容量拒绝、精确发布与 hydration，结果保持旧语义，再确定地激活。
3. 真实旧 daemon 写入与 S3 发布，混代 quorum 隔离，同盘全部升级，重复更新产生的保守物理历史下界超过旧状态预算，并保持实际文件与当前状态有界。
4. 真实 native 提交已接受但尚未 publication 时 SIGKILL，包含基线的 snapshot 安装，全组重启与新 owner/new directory 恢复，逐项核对所有 ACK 与原随机结果。
5. Cold 归档后的权限变更及新取消，经准确 hydrate 和重启保留；旧二进制打开 v3 盘必须失败。
6. learner 在所有原 voter 裁剪过基线存在的应用位置后，通过实际 snapshot 追赶；成员替换及原服务/SDK/S3/隔离/恢复测量全部继续通过。

原始失败、UNKNOWN、超时和全部样本保留；不重发未知非幂等 SQL，不把没有执行的 CI 标为通过。本轮 496 个 Rust 单元、9 套独立 Rust 实验的 81 项测试，以及 9 项升级、8 项成员和 8 项服务合同均通过；计数、失败尝试及实测边界见 [执行证据](../engineering/g0-evidence.md)和[机器可读摘要](../evidence/history-local-2026-11-04.json)。

## 仍保留的边界

每库 256 KiB、128 个请求身份记录、每 cell 32 个配置数据库、4096 条行政记录和 8 MiB application 预算不变。基线避免物理增量无限累积，但完整 metadata/结果编码、校验、全 cell checkpoint 与对象成本仍有上限。

本决策不提供多 cell 调度、动态目录、请求退休、GC、GiB 级恢复、通用滚动升级或三 AZ 的延迟/RTO/可用性验收。生产 SLO 仍需真实故障域和目标负载测量，不能由本地小库故障验证推导。
