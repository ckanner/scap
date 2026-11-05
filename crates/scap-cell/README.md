# scap-cell

有界、确定的 cell 状态机。权限、owner epoch、请求身份、物理提交接受、原结果和取消 fence 都由同一份有序持久应用状态裁决。该模块不执行 SQL、访问对象存储或自行授予本地文件读取权限。

## 业务位置与身份

每个读取方先完成 Safe ReadIndex，再用同一个 Store 持久视图的 cell 身份和 applied term/index 调用 `CellState::decode_bound`。snapshot-only 安装也必须经过这个绑定检查；不能拿较新的外层 applied 位置授权旧的业务镜像。

`CellIdentity` 与 `DatabaseIdentity` 从 `scap-core` 原样 re-export。数据库身份、incarnation、placement generation、owner token 和当前 auth epoch 的校验顺序保持不变。历史 request ID 命中之前仍检查当前主体与权限，不能使用旧权限取回别人的结果。

## v3 物理基线与有界 tail

物理折叠保留完整的逻辑事务 metadata、原 receipt、结果、原 admission 和 commit hash。v4 的显式请求退休可以另外释放已经确认的逻辑前缀，见下节。数据库 revision 始终是全部已接受事务的累计序号，由退休前缀 revision 加当前事务条数构成；不会因退休回到零。取消 fence 和管理 receipt 不会因物理折叠而删除。

物理恢复材料独立表示为：

| 类型 | 内容与合同 |
| --- | --- |
| `RecoveryBase` | `source`、`revision`、`commit_hash`、`image_digest` 和完整 SQLite image bytes；source 等于所覆盖末次提交的应用位置 |
| `RecoverySource` | 可选的基线及从 `base.revision + 1` 开始的连续物理 tail；不是从 revision 0 开始的完整历史 |
| `DatabaseView` | 原 head/owner/lifecycle 之外，提供 `base_revision`、`tail_entries`、`tail_bytes` 的有限观测 |

仅受信恢复代码使用 `CellState::recovery_source`；它仍要求当前 READ 权限，Cold 状态返回 `Reject::Cold`。外部请求结果查询继续使用 `lookup`，不从 tail 推导原结果是否存在。旧的 `recovery_transactions` 接口已移除，以免调用方把被折叠的前缀误当作仍可从空镜像重放的历史。

每次新 Commit 的候选状态达到以下任一条件时，确定地折叠当前全部 tail：

- tail 至少 8 条；
- tail 的物理 bytes 达到 `min(max_state_bytes / 4, max_transaction_bytes * 4)`。

阈值只来自已有复制 limits 和固定 v3 规则，不受 worker 本地配置影响。重放使用与正式 engine 相同的 `scap_core::physical` 算法，从已有合法基线或空镜像重建，逐条检查 receipt、SCAPIMG envelope、页转换及镜像摘要。最多页数由 `max_state_bytes / 4096` 推导并受物理格式上限约束；事务上限沿用复制的 `max_transaction_bytes`。

基线只在这次重放成功后建立。新基线、尾部和完整结果表同属本次 Commit 的候选 application，并由现有 Store applied 路径原子持久化。折叠失败或候选状态超限时，原已接受历史、结果和 fence 不变，不会先清除旧 bytes。native SQLite publication 仍只能由精确的持久接受结果授权，不能用内存中的基线替代 quorum ACK。

普通 Commit 继续采用既有的 opaque payload 摘要校验边界；需要折叠时才进行上述完整物理重放。因此任意自定义 opaque bytes 不能声称具备 SQLite 基线恢复能力。正式 SQLite writer 生成的 SCAPIMG payload 可经同一个纯算法验证。

## v4 显式请求确认与退休

`Admission.request_epoch` 是原始请求身份的一部分，独立于授权与 owner epoch。旧命令、状态及归档中的请求固定属于 epoch 1；刷新凭据或再次查证不能自动把未知请求换到当前 epoch。metadata 和强读可以取得当前 epoch，请求查证、接受、取消和确认则检查调用者携带的原 epoch。

`AcknowledgeRequest` 要求当前 WRITE 权限、原主体、相同 fingerprint，以及准确的终结状态：已提交时提供原 sequence，已取消时提供原 term/index。UNKNOWN 不能确认。成功只在同一 Raft 顺序中标记确认，不增加管理 receipt、不修改 SQL revision，也不立即丢弃原结果。重复确认幂等。确认是调用者明确放弃后续保存该结果的权利，服务和 SDK 不能在普通 SQL 成功后默默替调用者确认。

`RotateRequests(expected_epoch)` 要求当前 ADMIN、原始 admission 与 expected epoch 都等于当前请求 epoch、窗口非空且全部 accepted/cancel 已经确认。Cold 拒绝轮转；热库先强制用共享物理算法把完整 head 建成持久候选基线，再原子执行以下变化：

- 保存退休前缀的累计 revision、commit hash 与原提交位置；
- 清除这一 epoch 的请求、逻辑事务和确认记录；
- checked-add 请求 epoch 并持久保存轮转位置；
- 清除与旧逻辑前缀绑定的 live archive 引用，保留 S3 对象本身。

任一步失败或候选超限都保留全部原数据。未来 epoch 返回 Conflict；旧 epoch 的写、取消、确认与轮转返回 Retired，查询返回 `Lookup::Retired { current_epoch }`。Retired 不意味着 SQL 被取消，也不能解释为 Unknown 后重新执行。基线、提交链、owner/auth fence、SQL revision 和当前权限均连续保留；同一个随机 ID 只有在明确的新 epoch 中才代表一个不同请求。

v4 对每个未确认请求预留 32 bytes，支付未来确认位置的编码空间；已经接受的记录不会因为剩余空间耗尽而无法确认。激活 v4 同样检查这份预算，不提高原 limits。未知或未确认请求会阻止该 epoch 轮转；本机制不声称任意客户端遗弃请求后仍能无限前进。旧管理命名空间继续受原 4096 条 profile 上限约束，v5 另提供下述有界控制命名空间。

`DatabaseView` 新增 `request_epoch`、`retained_requests`、`unacknowledged_requests` 和 `retired_revision`。ACK map 不进入归档物理覆盖摘要，Cold 期间确认也不破坏旧对象恢复；Hydrate 只导入物理材料，保留当前确认、权限和取消记录。v4 对象绑定 epoch 与退休前缀，旧 v2/v3 对象只可用于仍处于 epoch 1、未退休逻辑前缀的数据库。

## v5 有界管理控制

[ADR-0020](../../docs/adr/0020-bounded-administrative-control.md) 为八种管理动作建立独立的每库控制序号：Create、ClaimOwner、ActivateOwner、AuthFence、SuspendDb、PublishArchive、PruneArchive 和 HydrateArchive。`Command.control_revision = Some(r)` 携带首次提交前捕获的期望序号；`None` 明确表示旧命名空间。SQL Commit、请求查证/取消、确认与轮转不能携带控制序号，也不会增加它。

状态机先校验当前身份和权限，再检查控制序号，最后调用与旧协议共享的动作实现。当前序号为 `r` 时，新成功动作、checked-add 的 `r + 1` 和最近回执同属一个候选状态；动作失败、序号溢出或容量不足均原子拒绝。每库只保存一条最近回执，包含 operation ID、原 admission、意图摘要和 `ControlResult { revision, position, result }`；其中 position 和结果始终指向原始成功位置。

| 输入身份 | 裁决 |
| --- | --- |
| 期望当前序号，且动作条件有效 | `ControlApplied`，增加序号并替换最近回执 |
| 期望前一个序号，且 ID、原主体与意图完全匹配 | `ControlAlreadyApplied`，返回原序号、位置和结果 |
| 期望前一个序号但身份/意图不匹配，或期望未来序号 | `Conflict`，不执行动作 |
| 早于最近回执的序号 | `ControlRetired`，永久禁止接受该身份 |

刷新 credential/admission ID 或当前 auth epoch 不改变控制身份；重试不能偷偷获取当前控制序号。`ControlRetired` 不证明原动作未执行，也不是取消证明。迟到 Prune 在 Hydrate 之后即使仍持有相同 suspended owner token，也会被控制序号拒绝。新创建使用序号 0，成功后为 1；旧库激活 v5 时为 0，且没有新命名空间回执。`DatabaseView.control_revision` 在 v5 前为 `None`，激活后为 `Some(r)`；`CellState::control_enabled()` 指示这一持久阶段。

v5 后原管理表保持固定：已有旧 ID 按原主体、数据库和意图返回原结果，未知旧 ID 返回 `ControlRetired`，表不再增长。历史 Create 重放也重新校验当前数据库权限和 auth epoch。新控制操作不消耗旧表额度；旧表已有 4096 条时仍可在复制状态预算内继续。

状态预算为每个数据库预留最大控制回执编码，包含当前空槽或短结果与最大结果之间的差额。已经接受的 SQL 不会挤掉将来 owner fencing 需要的回执空间。这个预留不承诺扩大 policy、新增数据库或安装任意更大物理材料一定成功。原数据库、请求、命令及状态 limits 保持不变。新控制 Hydrate 的完整封装为 202 bytes，归档生成、Publish 和快照校验均按此预留；旧 phase 继续使用原 192-byte 裁决以保持历史重放。v5 激活检查全部已发布旧对象，无论当前为 Hot 还是 Cold，都能装进新 Hydrate 命令，不满足时原子拒绝升级并保留旧 phase 和原有恢复路径，不能成功升级后才暴露无法唤醒的问题。

## 编码与旧格式

| Envelope | 写入版本 | 读取范围 |
| --- | --- | --- |
| `SCAPCELL` | 与已激活 phase 对应的 2、3、4、5 | 1–5；升级先保留旧裁决语义 |
| `SCAPARC!` | phase 2/3 使用对应版本，phase 4/5 均写 4 | 2–4 且不超过当前 phase；旧对象受 epoch 1/零退休前缀约束 |
| `SCAPCMD!` | 原 epoch 1 旧命令仍为 2；请求管理命令或后续 epoch 为 3；带控制序号的命令为 4 | 1–4；旧 envelope 不得携带新协议字段 |
| `SCAPOUT!` | 原结果仍为 2；确认、轮转及 Retired 为 3；ControlApplied/ControlAlreadyApplied/ControlRetired 为 4 | 1–4；旧 envelope 不得携带新结果 |
| `SCAPIMG!` | 1 | 原正式物理格式，不因 cell v3/v4/v5 改写 |
| `SCAPACT!` / `SCAPACR!` | 1 | 独立内部激活 entry / 精确持久结果，不是普通业务 command/outcome |
| `SCAPRET!` / `SCAPRR!1` | 1 | 独立 v4 激活 entry / 精确持久结果，不能与 v3 激活混淆 |
| `SCAPCTL!` / `SCAPCR!1` | 1 | 独立 v5 激活 entry / 精确持久结果，不能与历史或请求退休激活混淆 |

v3 在每个数据库原 lifecycle/archive 字段后追加 optional base；归档在原逻辑事务字段后追加 optional base。v4 状态增加请求世代、退休前缀及当前确认记录；v4 归档增加世代和退休前缀绑定，不保存或覆盖当前 ACK map。v5 状态追加控制序号和可选最近回执，解码检查回执身份、当前序号、原位置、历史 owner/auth 约束以及 last outcome 的对应关系。物理 `SCAPIMG!` 仍为 v1。所有长度、记录数量、位置、前缀覆盖、基线摘要和 tail 上限均在解码时核查；退休 SQL 前缀缺少覆盖基线时，即使对象摘要正确也必须在相对 tail 索引和 Hydrate 安装前拒绝。

读取 v1/v2 状态后，`physical_history_version()` 仍为 2，重新编码、容量判断、Commit、Publish 和 Hydrate 都保留原 v2 语义。仅加载旧磁盘不会启用折叠。这样落后副本重放旧 quorum 已裁决的 Capacity 拒绝、v2 对象发布和 hydrate 时，仍产生原结果与原字节。

受信 catalogue 通过 Raft 提交独立 `SCAPACT!` entry。状态机重新核对 cell 和不可变 bootstrap administrator，再在同一个候选状态中逐条验证所有热库的完整物理历史，按与 v3 Commit 相同的 8 条/bytes 阈值形成基线并保留未满 tail。只有所有库重放及总预算检查成功，才原子发布 phase 3；不能按每台副本任意的升级 head 强制全部折叠。失败返回绑定 cell 与精确 term/index 的内部拒绝结果，保留 phase 2、原结果和全部旧恢复 bytes，不中断后续 Raft apply。重复激活单调幂等，普通 `SCAPOUT!` 不能冒充激活结果。

公开 `bootstrap` 默认建立 phase 3；服务的 Initialize、Join 和固定 genesis hash 使用明确的 `bootstrap_legacy`，其空 genesis 与旧服务逐字节相同。新的 learner 因而可以从原 v2 前缀重放到激活 entry。catalogue 在精确持久激活结果之后重新完成 Safe ReadIndex、确认 phase 3，再推进下述 v4 激活；SQL lane 不自行激活。无法物理恢复的旧 opaque payload、损坏历史或不足的配置预算会使激活失败关闭，不能伪造空基线或自动放宽 limits。

旧 Cold 状态在激活时保留原 archive 引用和全部逻辑 metadata，不猜测或合成缺失的物理 bytes。激活后的 Hydrate 读取并核验准确旧对象，再使用相同规范切点恢复 base 与 tail。旧归档的 `metadata_digest` 继续绑定原不可变逻辑记录；权限更新和新取消 fence 不改变这个覆盖证明，Hydrate 也不能覆盖它们。

旧对象可以继续支持 Prune/Hydrate；迁移后的物理表示与旧归档不同，不等于旧归档已经失效。phase 3 的新 Publish 生成 v3 对象并使用原 previous-object CAS；所有旧对象继续保留，没有 GC。

v4 不重解释旧 `SCAPACT!`：它仍只激活 v3，已有 v4 时也不回退。新 `SCAPRET!` 要求先有 phase 3，核对 cell、bootstrap administrator、整个状态容量及未来 ACK reserve，再原子升至 phase 4；失败保持 v3。仅 decode 旧磁盘不启动退休协议。服务继续提交独立 `SCAPCTL!`：要求已处于 phase 4，核对 cell/administrator 并为每库预留最大控制回执，成功后原子进入 phase 5。失败保持原 phase，重复激活不清空最近回执。三个内部激活协议均不会使较新的 phase 回退；服务在精确持久结果及新鲜权威读取确认 phase 5 后才开放当前准入。

**旧磁盘读取兼容不代表混版本写入兼容。** v3 折叠、v4 确认预留及 v5 管理控制都会改变接受行为。当前运行时使用 Raft peer envelope 版本 4，拒绝旧版本 1/2/3；要求整个 cell 停止旧程序、保留原盘、升级所有 voter 后，再由有序激活开启新语义。不提供混版本滚动激活协议，也不能用 peer 隔离替代对旧日志后缀的语义保留。

## 归档、日志与容量

Publish 仍核对准确 owner、head、previous object、可恢复覆盖和对象 bytes；对象上传及 readback 在 `scap-archive` 完成。Prune 只释放被该已发布对象覆盖的物理 base/tail。Cold 的 resident tail 数量与 bytes 为零，基线 anchor 可继续保留；请求结果和取消记录仍可查询。v5 的新物理对象继续使用不可变 v4 格式；Hydrate 仅恢复 bytes/base，不导入或覆盖控制序号及最近回执，也不覆盖当前 policy、owner 或 ACK。

数据库折叠不是共享 Raft log 压缩。完整 application 的持久 checkpoint、ConfState/applied 原子安装以及 log purge 仍由 driver/Store 的原有协议负责。

本轮不提高数据库大小、同时保留请求数量、结果大小或全 cell 状态上限。完整编码/校验、metadata 与结果保留、checkpoint 的总镜像预算仍有成本；达到上限继续拒绝新增长，显式确认及安全轮转可回收请求窗口。新控制历史的记录数量有界，旧管理表则作为固定升级成本保留。该能力不证明 GiB 恢复性能、PITR、对象 GC 或生产 SLO。

## 验证来源

单元测试包含正常折叠、错误候选的原子保留、基线损坏、原结果/取消、Cold 生命周期、旧归档覆盖及编码边界。`test-fixtures/provenance.json`、`server-provenance.json`、`canonical-provenance.json` 和 `semantics-provenance.json` 记录由实际旧 main `662f04133f6a869d0dae5b05467656e6deca5c12` 已编译库生成的 v2 样本与 SHA；包括各升级前缀、原 Capacity/归档生命周期结果及 server genesis。这些固定 hex 并非通过把新编码版本字节改为 2 生成。真实 native SQLite 和 daemon 升级、故障恢复采用独立实验，不混入单元覆盖率。

`test-fixtures/retention-v3-provenance.json` 另记录实际已合入 main `b9f512819358494f178b01d7f1d960dff8222c1c` 的独立 v3 编译产物、输入源码与 SHA。生命周期 trace 有 37 个持久前缀，容量 trace 有 25 个；每个前缀都逐条重放剩余原日志，检查原 outcome、完整状态和 SHA256 完全一致，再提交同一个 v4 激活 entry。前者确认所有终态后退休并保留相同 SQLite 物理镜像、累计 revision 与提交 hash；后者验证接近旧状态容量上限时，v4 因无法预留全部 ACK 空间而安全拒绝激活。v4 单元测试还覆盖连续 20 个请求 epoch、过期请求永久 fence、Cold ACK 后恢复、强制基线失败的原子保留、重复 ACK key、字段截断及世代/序号溢出。

`tests/control.rs` 覆盖八种动作的原始回执重放、4096 条满旧表升级、超过 4096 次真实新控制动作后的固定记录大小、Hydrate 后迟到 Prune、当前授权、独立请求退休、溢出、最大回执预算、快照与编码截断及旧 v2/v3/v4 归档恢复。当前 crate 本地单元测试 97 项通过；完整候选的精确覆盖率、workspace gates 与真实故障实验由本轮集成验证统一确认，完成前不把局部单元通过写成可合入证据。
