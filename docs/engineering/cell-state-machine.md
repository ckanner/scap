# 有界 cell 数据库状态机

初版日期：2026-10-31；当前实现更新：2026-11-05。正式模块：`crates/scap-cell`。本页描述 G0 事务接受、物理历史和请求世代的当前合同，并保留后续阶段的演进说明。有界服务见 [ADR-0014](../adr/0014-sqlite-service-and-cold-lifecycle.md)，物理基线与显式结果退休见 [ADR-0017](../adr/0017-bounded-physical-history.md)、[ADR-0019](../adr/0019-explicit-request-result-retirement.md)。完整平台生命周期和生产规模仍未验收；基础决策见 [ADR-0010](../adr/0010-cell-acceptance-and-raft-safety.md)，实际测试结果见 [G0 执行证据](g0-evidence.md)。

## 1. 职责与依赖

`CellApplication` 实现正式 driver 的 `Application` 接口：从旧应用 bytes 和连续已提交条目计算下一份应用 bytes。它不访问外部网络、墙钟、文件或权限服务，不发布 SQLite 页面，不重新执行 SQL。driver 继续负责原子保存应用 bytes、ConfState 和 applied。

`scap-core` 的 `CommitTicket`、`PreparedWrite`、`CommitReceipt` 是复用的提交绑定。Raft index 是共享 cell 的日志位置；数据库 revision 只随该库的新接受事务增加。空日志、成员配置、管理命令、重复命中和业务拒绝均推进应用位置，但不凭空增加数据库 revision。

## 2. 初始化与恢复绑定

新组使用明确的 bootstrap：`CellState::bootstrap` 接收 cell 身份、bootstrap 管理员、genesis term/index 和限额，通用构造器建立 phase 3。正式服务的 Initialize、Join 和规范 genesis 摘要统一使用 `bootstrap_legacy` 的固定 phase 2 初始字节，再按有序条目激活 v3/v4/v5，避免新副本重放旧前缀时改变裁决。当前 Store 的新组 genesis 为 `term = index = 1`。`Store::create_new_with_application` 在同一原子镜像中保存非空应用和相同的 genesis snapshot data；所有 founding replicas 必须取得相同配置与逐字节相同的应用状态。

已有组必须走 `open_existing`，不能因业务状态 decode 失败重新 bootstrap。Store 格式继续为既有 v1；新增非空应用初始化不改变已有空应用数据的表示。

业务状态和命令使用分别标识的版本化二进制 envelope：`SCAPCELL` / `SCAPCMD!`、明确长度与 SHA-256。初始版本为 1；正式服务完成三次有序激活后状态写入 v5，旧 phase 2/3 仍按原版本处理。epoch 1 的旧命令写入 v2，新请求世代及确认/轮转命令写入 v3；普通 outcome 保持 v2，确认、轮转和 Retired outcome 为 v3；新的管理控制 command/outcome 为 v4。状态包含 cell 身份、完整限额、bootstrap 管理员、应用位置、数据库元数据、行政记录、未退休事务与取消记录、确认状态及永久请求世代屏障。格式校验与一致性校验都须通过；SHA-256 是损坏检测，不是认证或外部回滚防护。

恢复使用 `decode_bound(bytes, cell_identity, position, limits)`，必须匹配**同一个外层 Store 持久视图**的 term/index。snapshot-only Ready 不调用业务 `apply`，所以快照安装后也不能跳过这项读取校验。应用内旧水位不能借用外层较新的 applied 对外授权。

这里的 term 是 durable applied 对应条目的 `entry.term`；若 applied 恰好等于 snapshot index，则取 `snapshot.metadata.term`。当前 `HardState.term` 或 driver status 的选举 term 不能替代这个日志位置的 term。

限额随状态复制，并与本地预期严格匹配。修改限额需要明确的版本/配置演进；不能让副本各自采用不同限额，对同一条日志作出不同接受结果。

## 3. 身份与权限

所有命令绑定 cell 身份和数据库的 `database_id / incarnation / placement_generation`。准入上下文包含 principal、credential 标识、admission 标识、auth epoch 和原 request epoch。可信认证/准入组件验证凭据并绑定实际请求；客户端携带的 request epoch 只标识原请求，由复制状态校验，不能构成认证或改变 owner/auth epoch。

状态机在应用时再次核对当前复制的权限策略与 auth epoch。首版策略按主体授予数据库范围的 READ、WRITE、ADMIN 位，规范化排序，拒绝重复/非法主体、未知权限位以及没有管理员的策略。

| 操作 | 状态机权限要求 |
| --- | --- |
| 创建数据库 | cell bootstrap 管理员及规定的初始准入版本 |
| ClaimOwner、ActivateOwner、AuthFence | 该库当前 ADMIN 权限和当前 auth epoch |
| Commit、ResolveOrCancel、AcknowledgeRequest | 该库当前 WRITE 权限和当前 auth epoch；原请求世代、主体与指纹继续检查 |
| RotateRequests | 该库当前 ADMIN、当前 auth epoch、admission 与 expected request epoch 双重 CAS |
| 读视图、历史请求查询 | 当前 READ 权限；当前窗口历史请求还须匹配原主体与请求指纹，旧世代只返回 Retired |

授权检查先于幂等命中。历史上有权限不能授权今天查询结果；知道 request ID 也不能读取其他主体的结果。当前 G0 只允许原请求主体查询该请求历史，其他主体即使是管理员也不能借此取得结果。

原始准入标识随接受事务、取消 fence 和管理记录保留；不保存可直接使用的秘密凭据。重复请求使用新的合法准入进行检查，但不能覆盖历史记录的原始准入身份。

bootstrap 管理员轮换、动态凭证分发/外部撤销传播、租户目录和更细粒度权限模型尚未实现。当前 HTTP 服务验证静态 token 的 SHA256 映射，每次操作仍按复制状态的当前 policy/auth_epoch 判定；不把本模块的 Admission 当作可由用户提供的凭证。内部 `database` 检查不能直接暴露为未受保护的用户 API。`recovery_source` 包含整库物理基线、tail 及各主体的未退休事务元数据，即使用户具有 READ 权限也不能作为用户导出接口；它只供可信内部 worker 在绑定经过验证的恢复身份后调用。原结果查询使用独立 Lookup，物理前缀折叠不使结果缺失；显式请求退休后旧身份返回 Retired。

## 4. 所有权与激活

`Create` 创建 inactive、suspended 数据库，owner 尚未分配，revision 为 0；配置目录不会立即给所有冷库创建 native writer。首版没有删除或跨 cell 迁移入口，现有 database ID 不会被静默复用。

写者取得执行权必须经过：

1. `ClaimOwner` 校验当前管理权限与 expected owner epoch，单调增加 epoch，绑定新的 worker instance，并立即令数据库 inactive。
2. worker 按权威历史恢复执行状态；这个实际引擎恢复过程不在纯状态机回调中执行。
3. `ActivateOwner` 校验完整数据库 scope、当前 owner token、恢复 revision 和提交链 hash，匹配后才转为 active。

新 Claim 之后，旧 owner 的新事务会被 fence。声明恢复完成不能替代引擎真实恢复证明；`ActivateOwner` 负责校验提交的恢复身份和水位，可信 worker/引擎适配器仍须保证本地文件确实与之对应。

`AuthFence` 同样是有序命令：检查当前管理员权限和 expected auth epoch，递增 auth epoch 并替换规范化策略。Owner epoch 与 auth epoch 独立，不能用有效写者身份绕过用户权限撤销。

管理操作有稳定 operation ID 与规范化 intent 摘要。刷新 credential/admission 标识或使用新的合法 auth epoch，不改变原管理意图；重复命中返回历史结果，不重复增加 epoch。不同主体、数据库或意图复用同 ID 会被拒绝。

## 5. 事务接受与业务拒绝

新 `Commit` 依次检查当前权限、原请求世代、完整票据 scope、请求身份、活动 owner、前序 revision、物理 payload SHA-256、事务/结果上限和保留容量。通过后原子保留结果 bytes、原准入上下文、原 receipt、接受的 term/index、提交链 hash，以及可恢复的物理 base/tail，并增加该库 revision。v4 接受记录时同时预留未来显式确认所需空间。

必须区分两个摘要：

- **业务 request fingerprint**：由可信入口对事务意图与绑定输入规范化生成，用于跨请求去重；不是物理页面 hash。
- **physical payload digest**：绑定本次封存的不可变物理提案，校验存储和传递的 bytes。

同一业务请求重新执行，可能生成不同随机值、时间或页内容。同一请求世代内，相同 ID、主体和业务 fingerprint 命中历史时，只能返回原 `AlreadyCommitted`，不能把新页作为新的接受结果发布。已退休世代先被永久屏障拒绝，不能因新窗口缺少这个 ID 就重执行旧请求。

业务规则拒绝作为正常的 `Outcome::Rejected` 应用：它推进日志应用位置，不破坏后续 cell 服务。损坏编码、不可恢复的状态不变量或非连续位置则是应用错误，由 driver 停止实例；不能用“业务拒绝”隐藏坏持久状态。

普通 Rejected 只裁决该 term/index 对应的这一次命令，不自动建立永久请求取消 fence。状态变化之后，同身份的另一条提案仍须按当时规则判定；若要建立明确取消终态，必须完成 `ResolveOrCancel`。Retired 是持久请求世代已关闭的明确拒绝，但不证明原操作被取消或从未提交。

普通 Commit 继续先把物理事务作为有界 opaque bytes 校验摘要；达到 v3 折叠阈值时，用正式共享物理算法验证并折叠整个 tail，失败则原子拒绝候选。SQLite 的 native 执行与 publication 仍由引擎适配层负责，不能把摘要匹配或生成基线理解为 native 提交已完成。

## 6. UNKNOWN、取消与结果观察

`Lookup::Unknown` 只说明在已验证的这个业务视图中没有记录；迟到提案仍可能在之后提交。不能将其转换为确定回滚。

`ResolveOrCancel` 经同一 Raft 顺序应用：有已接受结果时返回原提交，已有取消记录时返回已取消；没有记录时持久化终止 fence。后续同身份事务不能再被接受。取消不撤销已提交事务，也不代表 SQL 之外的外部副作用被撤销。

接受记录与取消 fence 不自动删除，旧行政回执在 v5 后封闭保留，新管理控制只保留最近精确回执。v4 仅在应用显式确认当前窗口全部终态后，允许管理员将其原子压缩为永久请求世代屏障；存在 SQL 历史时，物理基线必须先覆盖当前 head。服务 profile 的每库未退休窗口最多 128 条请求，cell 4096 条行政记录仍不退休；达到未释放预算时拒绝新增工作。没有基于墙钟的结果过期或对象 GC。

状态只保留一条带精确 term/index 的 `last_outcome` 作为最近业务命令结果。提交适配器只有在该位置确实对应本次提案时，才能将其解释为本次 Accepted/Rejected。若已被后续命令覆盖，应使用受保护的历史查询或报告 UNKNOWN，不能猜测。

窗口内的历史 `CommitResult` 保持原 receipt 与原接受位置，直到应用确认并经有序退休后释放。对重新执行产生新物理页的同业务请求，不能篡改历史 ticket 来迎合 `scap-core` 的不可变提案绑定。应丢弃新暂存、对齐权威状态并取得原结果；旧世代已退休时明确返回 Retired，不重放 SQL。

## 7. 读取与资源预算

`authorize_read` 只执行当前业务视图中的身份、权限、active owner 校验；调用方必须先完成本次请求的 Safe ReadIndex，并把对应 Store 视图传给 `decode_bound`。返回的 ReadView 仍不是已打开的 SQLite snapshot。

状态、命令、数据库数、权限条目、管理操作、每库请求数、事务 bytes 和结果 bytes 均有上限。总状态容量预留固定的应用水位与结果空间，使业务容量拒绝本身能够正常持久应用；v4 另为每个未确认请求预留 32 bytes，确认写入与预留释放等额。旧 v3 状态无法负担新格式及确认预留时拒绝激活，不扩大限额。候选修改在副本中计算，失败不部分修改原业务状态。

本轮仍使用完整有界镜像，编码、验证和候选复制有明确 CPU/内存与写放大代价。它用于建立正确性边界，规模化布局、索引、大快照和批处理必须另行设计、测量和验证。

## 8. 证据与剩余工作

单元测试覆盖正式 domain、codec、权限、幂等、取消、位置、恢复和限额规则，精确计数由未放宽的覆盖率门禁记录。真实 SQL 接合在独立 [SQLite/cell 合同](../../experiments/sqlite-cell/README.md) 中组合固定 libSQL、正式 driver、backend 和业务状态机，不进入单元 profile。

整个 G0/G1 仍受原有门禁约束：生产 peer RPC/mTLS、通用事务暂存/spill、SDK/Hrana 返回语义、完整 lifecycle、S3/GC、坏副本重建和跨 AZ 性能/RTO 均不能由本模块的局部通过结果代替。

## 后续 v2 冷生命周期（2026-11-02）

本阶段曾将 `SCAPCELL` 与 `SCAPCMD!` 升到 version 2；后续 v3/v4 状态升级见下文。v2 接受相同 identity/持久化 limits 下合法的 v1 数据和旧命令，旧行政 intent digest 不依赖 envelope version，因此合法重试仍是 AlreadyApplied。没有反向降级、混版本滚动协议或自动 limits 迁移。

Suspend 撤销 owner/active 权限，PublishArchive 记录精确物理 head、对象与元数据摘要；PruneArchive 必须匹配发布的精确 head 和 expected_owner，且对象可以在当前 command 上限内完整 Hydrate，才裁剪物理 payload。权限、结果、取消和行政记录不裁剪。Hydrate 按已发布摘要验证所有内容，不替换当前权威元数据。后台旧任务不能在 wake→suspend 换 owner 后裁剪新世代。实现、边界和真实故障合同以 [正式服务](sqlite-service.md)为准。

## 后续 v3 物理历史（2026-11-04）

[ADR-0017](../adr/0017-bounded-physical-history.md)将恢复材料分为 quorum 持久基线与连续有限 tail。每次 Commit 的候选 tail 达到 8 条或 `min(max_state_bytes / 4, max_transaction_bytes * 4)` bytes 时，使用 `scap_core::physical` 的同一个算法重放并折叠；基线绑定原 source position、revision、commit hash 与 image digest。已覆盖记录只清空物理 bytes，原 receipt、结果、请求身份、取消和管理记录继续保留。

该阶段已激活的 cell/archive 写入 v3；读取旧状态先保留原 v2 完整历史、容量裁决和准确归档 bytes，重放完旧日志后，通过独立内部 Raft entry 原子激活。激活候选使用逐次提交的相同规则迁移，避免不同旧 applied 导致状态或归档分歧；失败保留旧材料与 phase 2，结果绑定精确应用位置。旧 Cold 保留引用，激活后准确 hydrate 再恢复物理材料；当前权限和新取消不被替换。该阶段曾用 wire envelope version 2 隔离旧、新程序；当前 v4 服务采用 version 3，仍要求全停全部 voter 升级，不能把磁盘读取兼容解释为混代 quorum 兼容。

`DatabaseView` 增加 base revision、resident tail 条数与 bytes。完整状态编码和逻辑记录保留仍有成本，所有旧容量上限保持不变；本项不实现结果退休或对象 GC。完整本地验证状态以 ADR 和执行证据为准。

## 当前 v4 显式结果退休（2026-11-04）

[ADR-0019](../adr/0019-explicit-request-result-retirement.md)增加独立 `SCAPRET!` 激活条目；原 history activation 仍只负责 v3。服务顺序取得两次精确持久结果并通过 fresh ReadIndex 确认 phase 4，才开放业务。旧日志前缀按原阶段重放，当前 peer envelope 3 拒绝旧 1/2；旧 v3 binary 不能打开 v4 盘。

`AcknowledgeRequest` 绑定原 request epoch、ID、主体、指纹及 committed sequence 或 cancelled term/index。`RotateRequests` 要求当前 ADMIN、两个 epoch 条件均匹配、窗口非空且全部确认、数据库非 Cold；先强制折叠至准确 head，再清除窗口并递增世代。retired revision、commit hash、源提交位置与恢复基线共同保存，累计 SQL revision 不倒退；确认和轮转都不新增永久行政 receipt。

旧世代 lookup 只返回 Retired，旧写/取消/确认/轮转拒绝，不把新窗口同 ID 的结果交给旧请求。Cold 可以确认已知终态，Hydrate 只补物理 bytes，不覆盖新确认；但 Cold 在精确恢复前不能退休。缺失退休前缀所需基线的状态或归档即使外层摘要正确也必须拒绝。请求退休不删除 S3 对象、不回收行政记录，也不提供 PITR/DR 或生产规模结论；最终验证状态以 ADR 与 G0 证据为准。


## 11. 独立管理控制序号

[ADR-0020](../adr/0020-bounded-administrative-control.md) 使用每库 `control_revision` 和最近成功回执，独立于 owner/auth/request epoch、SQL revision 和 Raft 位置。当前序号的八类有效管理动作原子推进序号并替换回执；最近完全相同身份返回原序号、位置和结果；更早身份 `ControlRetired`，未来或冲突身份拒绝。权限检查在回执命中之前，所有业务拒绝仍原子保留原状态。

独立 v5 激活冻结旧至多 4096 条行政记录，仅允许既有旧 ID 按原意图命中，不再接受未知旧 ID。新命名空间不使用这项计数额度。状态预算为每库最大控制回执预留空间；不能通过先接受普通 SQL、后因回执膨胀无法 fence 造成容量死锁。物理 archive 仍写 v4，不携带 v5 控制记录；Hydrate 不能回退最新控制序号或回执。
