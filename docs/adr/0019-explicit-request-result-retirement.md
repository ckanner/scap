# ADR-0019：显式结果确认与有序请求世代退休

- 日期：2026-11-04（实现及初次验收）；2026-11-05（主分支对齐与全新验收）。
- 状态：已实现并通过完整本地验证；最终执行结果记录在 [G0 证据](../engineering/g0-evidence.md)和[机器可读摘要](../evidence/retention-local-2026-11-04.json)。与主分支整合后的新执行记录见 [2026-11-05 摘要](../evidence/retention-reconciled-local-2026-11-05.json)。本地正确性通过不代表生产 SLO 或整个 G0 通过。
- 关联：[ADR-0017](0017-bounded-physical-history.md)、[API 合同](../architecture/api-contracts.md)、[Node SDK](../../sdk/node/README.md)、[真实退休实验](../../experiments/retention-network/README.md)。

## 1. 问题与范围

物理基线让重复更新页面的历史有界，但原请求结果、receipt 与取消 fence 仍累计到每库 128 条。仅删除这些记录会把旧随机 request ID 重新解释为新请求，使迟到的非幂等 SQL 再执行；直接提高常数不能提供持续运行的回收规则。

本决策增加应用显式确认和请求世代屏障。在一个有界窗口内，原结果仍可查询；应用确认已经处理结果后，管理员才可在满足全部条件时退休整个窗口。数据库内容、提交序号、当前权限和 owner 不随请求窗口退休。

此协议不回收 S3 对象，不退休 4096 条 cell 行政记录，也不实现 PITR、跨 cell 迁移、GiB 级容量或生产 SLO。SDK 不自动替应用确认结果。应用若需要永久查询原结果，必须继续保留窗口或自行持久保存它，不能同时要求有限服务器存储与无限原结果留存。

### 1.1 对 ADR-0018 提案的落实与调整

[ADR-0018](0018-request-retention-windows.md)保留为历史提案；本决策明确替代其中尚未实现的模式切换、错误命名和 owner 处理选择。其核心约束继续成立：完整请求身份不可刷新，旧世代永久拒绝新的接受，UNKNOWN 不自动重放，恢复材料必须先于逻辑结果回收得到证明。

| 提案中的候选选择 | 本次实际实现及理由 |
| --- | --- |
| 默认 `LegacyPinned`，管理员显式启用 `Windowed` | 不增加数据库模式开关。改为原主体逐条显式确认已知终态，再由独立 ADMIN 凭据执行有序轮转。升级或普通 SQL 成功不会确认任何结果；任一未确认结果都会阻止退休，管理员不能代替其他主体确认。旧应用不接入确认流程时，结果继续保留，到原上限后拒绝增长。 |
| 窗口模式缺少 epoch 时返回 `REQUEST_EPOCH_REQUIRED` | 缺省永远绑定固定 epoch 1，而非当前 epoch。首次轮转后，缺头的写、取消和确认同其他旧世代操作一样被拒绝；它们不能意外进入新窗口。强读和 metadata 继续独立校验权限。管理员轮转会使尚未迁移的旧写客户端不可用，因此必须先协调该库所有写入方，后续新业务请求显式携带新世代；不能为修复可用性而给旧操作补当前值。 |
| 轮转时必须撤销 owner，并重新恢复 writer | 轮转保持现任 owner、精确 revision 和 commit hash。它只把同一物理 head 折叠成基线，并推进独立请求世代；Commit、取消和确认在有序应用时再次校验原世代。因此晚到的旧请求仍被拒绝，保留同一正确 SQLite head 的 writer 无须仅为结果回收重建。轮转前已接受但未确认的请求会阻止轮转；已接受事务的本地发布也不成为新世代的另一次接受。原有 owner fencing、强读屏障和权限检查继续生效。 |
| 单独建立 `DatabaseHead` 结构 | 使用持久 `RetiredPrefix { revision, commit_hash, source }` 作为恢复锚点，配合覆盖它的基线与连续保留事务推导当前 head。事务向量为空时仍保留真实 revision、hash 和最后提交位置；相对下标必须由该锚点及完整解码校验支撑。仅删除 Vec 前缀或调整长度不能建立这些证明。 |
| `REQUEST_EPOCH_RETIRED` / `RESULT_RETIRED` | 实际变更接口使用 `REQUEST_RETIRED`；Lookup 使用 `state: "retired"` 和 `current_epoch`。后者只说明原结果已退出保留范围且原身份不能再次接受，不声称过去未提交或已取消。ResolveOrCancel 对旧世代明确拒绝，不制造取消回执。 |
| 有界轮转证明，禁止永久管理记录 | 轮转使用 expected-epoch CAS，保存当前世代、退休前缀和最近退休位置，不追加 `AdminRecord`；重复旧 CAS 返回退休拒绝。响应丢失保留 UNKNOWN，由 fresh status 查证世代，不重发 SQL。一般行政操作仍受原 4096 条上限约束。 |

对应证据分别来自[状态机退休单元合同](../../crates/scap-cell/src/tests/retention.rs)、[真实 SQLite worker 合同](../../crates/scap-server/src/worker/tests.rs)和 [SDK 身份与能力探测单元合同](../../sdk/node/tests/client.test.mjs)。它们检查未确认结果阻止轮转、旧世代各入口拒绝、head/owner 保持、基线覆盖和管理记录不增长。独立[九项网络合同](../../experiments/retention-network/README.md)进一步验证三轮满窗口、丢失响应、旧归档水合、snapshot 与进程退出恢复。以上选择不宣称旧客户端能够无感跨窗口继续写，也不解除未确认结果、行政记录、对象保留或生产规模的剩余门禁。

## 2. 完整请求身份

每库新增单调 `request_epoch`，初始为 1。可信 Admission 同时携带原世代和原 request ID；SQL/参数 fingerprint、原主体及当前权限继续校验。请求世代与 owner epoch、auth epoch、数据库 incarnation 相互独立。

HTTP 使用正 u64 十进制 `x-scap-request-epoch`。缺省严格解释为 1，不得解释为当前值。SDK `RequestIdentity` 保存 `requestEpoch`，lookup、resolve、ack 和错误对象继续使用它。新业务操作可显式使用 fresh status 或成功轮转返回的世代；旧操作不能通过刷新世代获取重试许可。

非初始世代的写入、取消、确认和轮转在每个候选节点实际发送前，SDK 用同一原身份和 deadline 查询该节点的 status，确认它支持请求世代协议。能力检查不跨调用或节点缓存；探测响应不支持新协议、回显世代缺失或不匹配时，不向该节点发送后续变更。实际变更已经发出后若响应丢失或回显异常，仍保留不确定结果，不自动重放。普通 query 无此能力探测。该额外请求属于原调用预算，不能据此延长超时或刷新身份。

检查当前权限后，旧世代 lookup 返回 `retired` 及当前世代；旧世代写入、取消、确认、轮转明确拒绝为 `REQUEST_RETIRED`。未来世代为冲突。`retired` 不宣称原请求取消，也不返回新世代同 ID 的结果。普通强读和 metadata 不以请求世代授权，因此读取不会因窗口退休而被错误撤销。

## 3. 显式确认

`AcknowledgeRequest` 经同一个 Raft 组有序应用，绑定原 request ID、fingerprint、原主体、当前授权和原世代，并要求调用者给回已知终态证明：

- 提交：原 `sequence`；
- 取消：原 `term/index`。

记录不存在、证明不匹配、主体或权限不符时拒绝。只有合法 committed/cancelled 记录能确认，UNKNOWN 不能直接确认。重复确认幂等，保留第一次确认位置；不生成永久行政 operation ID。

SDK 的 `executeTracked` / `batchTracked` 返回 `{ request, result }`，让成功路径也能保留完整身份。应用先处理或持久保存结果，再 lookup 获得原终态并调用 `acknowledge(request, outcome)`。普通 execute/batch 不隐式 ACK；响应丢失后也不自动重发 SQL。

这里的显式结果确认是应用放弃继续保留该终态的要求，与服务在 durable quorum 和 native publication 完成后向客户端返回写成功的 ACK 不同。收到成功响应并不会自动授权删除结果；同一数据库的多个调用方需要协调确认与轮转，管理员不能代替其他主体确认请求。

v4 状态容量在接受记录时同时预留其后确认所需的编码空间。确认增加的记录字节与减少的预留等额，避免“请求接受成功、窗口接近容量后却无空间确认和释放”的死锁。预留来自原预算，不提高 limits。

## 4. 原子退休

`RotateRequests(expected_epoch)` 需要当前 ADMIN 权限，入口还检查该具体凭证的 ADMIN scope，不能借同主体其他 token 的权限。复制状态再次检查权限、两个世代值和以下条件：

1. 当前格式已激活 v4；
2. 当前窗口非空，全部 accepted/cancelled 请求都已显式确认；
3. 数据库不是 Cold，物理数据可完整验证；
4. 新世代未溢出，候选状态符合原预算。

候选状态先用正式物理算法强制折叠到精确 head，再记录已退休前缀的 revision、commit hash、source term/index 与退休位置，清除该窗口的逻辑事务、请求和确认记录，递增世代。原子持久应用发布前，旧窗口和恢复材料仍有效；折叠、容量或持久化失败不能先释放它们。

revision 改为 `retired_revision + retained_transactions.len()`，原 sequence 继续单调；恢复 base/tail 的相对索引以退休前缀为起点。即使当前事务表为空，也能从基线恢复完整 SQLite 内容并继续提交。

已经提交但客户端未确认的请求阻止退休。尚未应用的迟到请求若排在轮转后，会被旧世代屏障拒绝；若先提交，就生成未确认记录并阻止轮转。轮转响应丢失仍按 UNKNOWN 处理，客户端用 fresh status 确认当前世代，不能盲发 SQL。重复旧 CAS 返回退休拒绝。

## 5. 归档与恢复

v4 归档绑定请求世代和退休前缀。确认标记属于当前 cell 元数据，不进入不可变物理归档的匹配摘要，Hydrate 也不能用旧归档覆盖它。因此 Cold 状态下仍能确认已经获知的原结果，之后唤醒必须保留这些确认。

Cold 拒绝轮转，避免在缺少唯一恢复 bytes 时删除逻辑覆盖。热态轮转清除当前 live archive 引用，不删除已有对象；旧 Publish/Prune/Hydrate 不能恢复旧世代。复用已执行的行政 operation ID 仍按原幂等合同返回原 receipt，不产生新状态变更；用新 operation ID 引入已退休世代的旧对象会被拒绝。后续重新归档绑定新世代。epoch 1、空退休前缀保持旧摘要规则，使合法 v2/v3 Cold 归档可以经过真实升级后准确恢复。

所有 snapshot 和 native 重开均包含世代屏障、退休前缀、基线、当前请求及确认。落后副本必须从该权威状态追赶，不能从自己的旧请求表恢复业务。

归档解码先验证退休前缀仍有覆盖它的可恢复基线，再计算相对 tail 位置。即使对象和外层 envelope 的摘要正确，缺失该基线也必须拒绝 Hydrate；不能把空事务表解释为空数据库。回归覆盖热态与 Cold、有无保留 tail，并验证拒绝后原恢复材料与确认元数据不变。

## 6. 独立激活与部署

固定 v2 genesis、原 v2 重放与原 history activation 保留不变。原 history activation 只激活到 v3；新增独立内部 retention activation 在有序日志位置把 v3 变成 v4。它绑定 cell 和 bootstrap administrator，验证所有库和预留空间，返回精确持久 term/index 的结果。旧前缀在此前继续按原容量和格式裁决。

正式 server 的 catalogue 顺序完成 v3、v4 激活，再经 fresh ReadIndex 确认 v4 才开放业务；tenant 请求不能触发格式升级。磁盘和归档写 v4，请求世代扩展与新操作使用业务 envelope v3，正式 Raft peer envelope 从 2 升到 3。不同 peer 世代在进入 Raft 之前拒绝，不能组成混版本 quorum。

支持停止整个 cell 旧程序、保留原目录、所有 voter 使用新程序 OpenExisting 的升级。它不是不停机滚动升级。旧 v3 二进制拒绝 v4 盘；禁止删除盘、重新初始化或绕过校验来降级。旧状态若在新格式和确认预留下不满足原容量，安全拒绝激活并保留原数据。

## 7. 验证出口与剩余目标

单元覆盖必须独立达到原逐文件四维精确 100%；真实旧 daemon 升级、超过 128 次提交、未知响应、容量拒绝、确认与退休竞态、S3 Cold 确认、snapshot 追赶、leader/全组 SIGKILL 和旧程序拒绝新盘分开验证。所有失败与尝试保留，验收以最终相同源码和构建为准。

本轮冻结源码的 **538 个 Rust 单元测试**已通过，52 个生产文件的 **12680 行、1166 函数、18661 regions、2842 branches** 均精确覆盖。SDK 的 **23 个单元测试**通过，行/语句 **429/429**、函数 **38/38**、分支 **331/331**。独立真实退休 **9/9**、旧 v2 物理历史升级 **9/9**、成员替换 **8/8**、完整服务 **8/8**，真实 SDK 集成 **5/5**；三个满请求窗口和合计 388 条显式确认并退休的身份均通过。全部失败尝试、UNKNOWN、检查器修复及重新执行结果保留在 G0 证据中；网络合同独立于单元覆盖计数，生产 SLO 仍未通过。

本协议解除经显式管理的请求窗口累计上限；每个未释放窗口仍为 128 条。未确认结果、永久离线的调用者或无法恢复的 Cold 对象可以阻止退休，这是保留查证权与恢复链的结果。后续仍需行政记录退休、对象引用闭包与 GC、动态目录/多 cell、完整灾备及生产规模验收。
