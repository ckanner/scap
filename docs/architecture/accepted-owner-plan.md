# 可恢复的 owner 计划：权威状态与取消屏障

状态：**独立有限模型已验证，生产实现与正式验收进行中**。`58b2f986` 的 985/45/3
历史结果保留；提交 `f8cc2613` 的干净源码另通过 987 条固定正向轨迹、47 个语义负控和
3 个正控，补入同身份、不同 descriptor hash 的边界。core/service/SDK 已在 `3f0b1ad`
发布开发检查点；后续修正仍按新源码冻结验证，不能把模型或局部开发检查认证成产品通过。本文件细化
[owner controller 方案](owner-controller-plan.md)的 V2 路线，不能据此宣称自动接管、
跨重启管理恢复或新格式已交付。HEAD6/HEAD7 的验证不认证本文的新状态机。

## 1. 要解决的缺口

现有 OwnerIntent 记录两个客户端阶段，但服务器只知道单个 expected revision 与 nonce。
原 takeover 已接受、响应丢失、调用进程退出后，另一进程不能安全地重新派发其余阶段。
把原意图写入 S3 journal 并不能撤销已经在途的 HTTP，也不能让服务端知道一个计划已取消。

新方案把**接受哪一个计划、允许哪一个后继阶段**放进同一个数据库 HEAD。每个具体 S3
请求仍固定自己的原 ETag、候选字节和期限；跨重启恢复的是已接受计划的后继阶段，不是
换条件重试某个旧 CAS。业务 SQL 的 UNKNOWN 仍只走原 request lookup/cancel。

## 2. 三类持久对象

| 对象 | 固定内容与作用 |
| --- | --- |
| OwnerDescriptor | 完整 Scope、原创建 principal/operation identity、目标 worker、takeover 或 activate 模式、原 HEAD canonical hash 与同次 exact GET 的 ETag、原 revision/head serial/owner tuple、固定 claim/cancel/activate/abort nonces、schema 与输入摘要。条件创建并 exact 回读，第一次持久输入胜出。 |
| HEAD 中的 owner plan marker | descriptor identity/hash，accepted admission revision/serial、阶段及其稳定原始字段。只有 HEAD 中的绑定授予推进权；孤立 descriptor 不是 owner，也不是 accepted plan。 |
| OwnerTerminalProof | 绑定 descriptor 与已接受终态 marker 的不可变证据。在后继计划覆盖当前 marker 前持久化并 exact 回读。普通 SQL/ACL 变更保留 marker，不重新用较晚 revision 拼装旧结果。 |

这些对象属于永久控制元数据，不进入 storage-generation payload prefix，也不由现有
GC 删除。下述数值已接入开发实现；其产品保证以绑定新源码的完整正式验收为依据。

### 2.1 固定编码与预算

首版采用 HEAD8，增加 `owner_plan`，必须非 null；HEAD6/7 必须完全省略该字段。
HEAD8 可以有或没有 storage terminal seal，仍分别遵守 HEAD6 的 live storage 规则与
HEAD7 的永久 terminal 规则。不可变数据库 payload 继续采用 SCAPOBJ2；owner 控制记录
另用严格 `version: 1` JSON。重复字段、未知字段、未知 enum、非规范整数或 hash、显式
null 代替必需对象，一律拒绝。解码和重新编码只使用严格结构，不能用不校验重复字段的
通用 map 先归一化原输入。

| 项目 | 首版上限与固定语义 |
| --- | --- |
| 完整 HEAD | 仍为 256 KiB；新增 marker 不提高原 HEAD 上限 |
| OwnerDescriptor | 16 KiB；仅保存原 HEAD canonical hash、原同次 ETag 和必要 counters/owner/原 marker 摘要，不复制完整 HEAD 或 policy |
| OwnerTerminalProof | 8 KiB；只从已验证 marker 的稳定字段构造 |
| 单个 marker | 4 KiB；每个 HEAD 恰有一个，不增加无界历史数组 |
| ETag | 2–1,024 字节，沿用受支持的带双引号、不含控制字符的 opaque ETag；不把它解释成 MD5 |
| 控制 key | 完整 key 至多 512 字节，所有身份为非零 u64 的规范十进制；不接受调用人自定义路径 |
| 输入身份 | 完整 Scope 加 creator/operation；四个 nonce 均非零且在一个 descriptor 内两两不同 |
| 请求期限 | 每个 prepare/claim/inspect/resume/abort 调用只有一个原总 deadline；本轮任何 I/O 都不得延长它 |
| 控制元数据 I/O | 每次调用至多 8 次 HEAD/owner 元数据精确 GET/条件 PUT；按原总期限执行 |
| owner 恢复 payload I/O | 每个新的 resume 独立累计，默认至多 1,048,576 次 GET、64 GiB 返回体预算；本地配置可降低，不能继承目录 RecoveryJob 的 meter 或冒称既有保证 |

控制对象 key 固定为
`scap-object/v1/{deployment}/{tenant}/{database}/inc/{incarnation}/gen/{generation}/owner/v1/{descriptor|proof}/{creator}/{operation}`。
它同时绑定完整 Scope，且与 `storage/{generation}/objects/` 不相交。descriptor 的输入
摘要绑定版本、完整身份、mode、target、原 hash/ETag、原 counters/owner 和全部 nonce。
`prepare` 不读取旧历史列表；旧 descriptor/proof 只能通过具体身份精确读取。

owner 恢复的 payload meter 先把 GET cap 收窄到原 cap 与剩余字节额度中的较小值，
在调用底层 Objects 前预留一次请求和实际授予的 cap；
成功且原总期限仍有效时，只退还最大值与实际返回字节的差额；失败或返回时期限已到不退。额度不足在该次 I/O 开始前失败，
不隔离数据库、不发布 Active，也不向调用人返回 native Session。下一次明确发起的 resume
有自己的预算和原期限，仍须重新鉴权、读取当前阶段并完成全部恢复。成功返回的 Session
不继承已经耗用的恢复 meter。该预算约束 Objects 接口的读取与返回体，不是底层 HTTP
重试的实际线缆流量，也不是进程 RSS、SQLite 或本地临时盘的硬总量上限。

marker 固定包含 descriptor 的 creator/operation/hash，admission 的 kind（claim 或
cancel）、原接受 revision/serial，以及 phase 的原接受 revision/serial/nonce 和 owner
tuple。pending 时 phase 与 admission 的接受 counters 相同，后续 ACL/quota 不改变这些
字段。terminal phase 的 counters 必须严格晚于 admission；Active 只允许来自 claim。
当前 HEAD 的 counters 不得早于 phase counters。如果当前业务 revision 与 phase.revision
相等，HEAD.transition.nonce 必须等于 phase.nonce；只增加技术 serial 也不能改变该
nonce。后续业务 revision 已增加时，新的 transition nonce 可以不同。这是单份 HEAD
即可判断的严格格式约束，不需要跨对象读屏障。proof 由完整 Scope、descriptor 身份和
上述稳定字段组成；其中不包含 proof 创建时的最新 HEAD revision、ETag、墙上时间或 ACL。

HEAD8 的 Active marker 是历史上的一次激活结果；之后 Maintenance/compaction 可以使
当前 `active=false`，但不能改写这个历史结果。重新激活必须创建独立 activate-only plan。
Claimed/Cancelling/Aborted 必须 inactive。`resume` 观察到 Active 只报告已接受阶段，不能
据此假设当前进程仍持有可用 native Session；需要执行时仍走完整的 Session 准入与恢复。

## 3. 权威阶段

`Prepared` 是 descriptor 的存在事实，不是 HEAD 阶段。HEAD 阶段分为：

| 阶段 | 含义 | 允许的后继 |
| --- | --- | --- |
| Claimed | 原 admission 已接受，目标 owner 已绑定，inactive，等待完整恢复 | Active 或 Aborted |
| Cancelling | 原 admission 已被取消屏障占用，inactive，不允许任何 activation | Aborted |
| Active | 本计划已完成完整恢复、最终 HEAD barrier 与激活 | 仅保留历史，或持久 proof 后被新计划替换 |
| Aborted | 本计划永久终止，owner 保持 inactive | 仅保留历史，或持久 proof 后被新计划替换 |

`Cancelling` 专门关闭 **descriptor 已持久化但 claim 尚未确定** 的窗口。仅看到当前
HEAD 未引用计划，不能断言旧 claim 不会迟到；仅向独立 key 写一份取消记录，也不能
阻止已经 admit 的原 HEAD CAS。

### 3.1 Prepare

调用人在派发前保存 `PrepareOwnerInput`：creator/operation、原 expected revision 与
head serial、mode、target worker，以及四个 nonce。这些字段在准备响应丢失后仍能取得；
服务器根据原 exact HEAD 计算的 descriptor hash 不能成为唯一的找回入口。

1. 精确查找该完整 Scope 与 creator/operation 对应的 descriptor，暂存原读取结果；
   随后 fresh exact GET HEAD，检查完整 Scope 和当前 ADMIN。鉴权之后才处理 descriptor
   的成功、缺失、损坏或输入冲突，避免延迟的 descriptor 读取跨越撤权后仍返回历史内容。
   已存在且与上述原完整输入逐字段相同时返回原 descriptor/ref。即使 HEAD 已
   推进，也不据此重建原 base。不得在 current ADMIN 检查之前返回历史内容或输入冲突。
2. 仅 Missing 时，在上述同次 HEAD body/ETag 上验证 Ready、creator 等于本次调用主体、
   原 expected revision/head serial 一致、没有
   storage copy/sweep/terminal，以及计数空间。activate-only 还必须要求原 base inactive、
   target 等于原 owner instance；不能把已经 active 的 owner 静默停活再恢复。
   若有其他 pending plan，只返回明确的 Pending 身份，不为它准备替代 descriptor。
   若当前 marker 引用相同 creator/operation，或该 operation 的永久 proof 已存在，
   descriptor 的缺失是权威损坏，必须拒绝，不能用新 base 重新填充旧 key。
3. 构造有界 descriptor，固定所有输入；条件创建并 exact 回读匹配原 bytes。
4. 返回 Prepared 或 Pending 的明确分支。restore 只恢复原保存输入/描述，不改变
   operation、base、目标或 nonce。Pending 不是调用人新计划的准备成功。

prepare 的成功不改变 owner、active 或 HEAD。相同 ID 的不同内容冲突；descriptor PUT
Unknown 可以通过 exact GET 查证，缺失时也不能把调用人的原 UNKNOWN 改写为过去已确定失败。

另有只读的 `inspect-by-operation(creator, operation)`，按当前 ADMIN 返回实际已存在的
descriptor 身份。SDK 必须将其原完整输入与保存输入比较，匹配后才能使用读回的 hash ref。
claim/resume/abort 始终需要完整的 hash ref；不能仅凭 operation 号或恢复出来的任意 JSON
取得 mutation 资格。原 prepare 已生效但 ACK 丢失、调用进程退出、HEAD 又推进的组合，
必须能找回同一 descriptor，而不能生成新 base 或让调用人永远缺少必要的 hash。

### 3.2 Claim

claim 要求当前 HEAD 与 descriptor 的完整原 base 一致，包括 canonical hash、原 ETag、
Scope、owner tuple、revision、head serial 及此前 marker。目标实例必须通过实际 worker
guard；当前调用主体必须仍为 ADMIN。takeover 增加 owner epoch，绑定原目标并置 inactive；
activate 模式重新验证原 base inactive 且 target 等于原 owner instance，保持 owner/epoch。
二者都增加一个 business revision 与 head serial，
安装 Claimed marker，固定本次原 ETag 后发布。

同一个 descriptor 的重复 claim 只能观察已有同计划 marker，或提交同一个原条件候选。
如果原 base 已变化，不能更新 descriptor 或用最新 ETag 重建原 claim。观察到另一个计划、
不同 owner 或任何较晚 HEAD，必须分别报告 current authority 与原调用的未知历史。

### 3.3 Resume

fresh HEAD 引用同一 Claimed plan，descriptor/proof 身份完整，当前 ADMIN 与实际目标 worker
匹配时，服务器才能恢复完整数据和全部保留结果。恢复后重新 exact 读取 HEAD；只有原阶段
和本次完整 base 仍一致，才构造 Active 后继并按原 ETag 发布。全部 native publication、
recovery permit、执行/传输预算与原总 deadline 保持现有合同。

如果 metadata 在恢复过程中变化，本次具体候选失效。后续新 resume 可从仍然 Claimed
的最新 HEAD 开始新一步，保留新的 ACL/quota/roots，重新鉴权并重新建立自己的期限；旧
候选仍不能换 ETag。两个恢复者竞争同一阶段只有一个 HEAD 后继生效。

Active/Aborted 是稳定观察结果；不再次增加 epoch、不重新执行 SQL、不把过去的 UNKNOWN
改成调用人当时收到了 ACK。目标实例已替换时，新实例不能借原 worker ID 继续激活；应由
当前 ADMIN 取消旧计划，再为新实例准备独立计划。

现有 worker guard 只比较配置中的 `worker_instance` 数值，不能识别复用了同一数值的
新进程。以上实例隔离要求以部署端**每次进程 incarnation 分配不复用的 worker identity**
为前提；若要由产品保证，必须另实现持久实例分配/登记并纳入验收。不得把现有数值比较
描述成已实现进程身份认证。原 S3 CAS fencing 与完整恢复不因此被省略。

### 3.4 Abort，包括未确定的 claim

abort 不要求调用落在原目标 worker，但每一步都要求当前 ADMIN 和同一完整 Scope：

- HEAD 为同计划 Claimed：按本次原 ETag 发布 Aborted，revision/serial 各加一，保持 inactive。
- HEAD 为同计划 Cancelling：完成 Aborted 后继，revision/serial 各加一，保持 inactive。
- HEAD 仍等于 descriptor 原 base：发布 Cancelling，revision/serial 各加一、inactive，
  保持原 owner tuple。再由下一步完成 Aborted。旧 claim 与取消屏障竞争同一原 ETag。
- HEAD 已到同计划 Active/Aborted：仅返回稳定阶段，不把 Active 改成 Aborted。
- HEAD 已被别的合法后继推进、且不引用本计划：报告原 admission 已被 fence；其过去结果
  只能由原 proof/marker 查证，不能凭最新 HEAD 报告 NotApplied。

先 Cancelling 再 Aborted，使完整终态至少晚于原 base 两个 business revision，并且中途
不能激活。第一步之后进程退出，任意当前 ADMIN 都能完成第二步；不依赖本地 sent 标记、
wall-clock TTL、租约或原进程死亡证明。取消未接受计划可能使原 owner inactive，这是显式
管理取消的效果，不能悄悄恢复 active 来跳过完整恢复。

### 3.5 独立历史观察

`inspect` 及具体 operation 的历史查询始终重新 exact GET HEAD，并检查完整 Scope 与
**当前 ADMIN**。Deleted，包括已 terminal seal 且 final-A 已被回收的数据库，仍允许
这条 metadata-only 路径；它用 permission 检查而不是普通数据路径的 lifecycle 准入。
普通 `status`/`lookup` 的 Deleted 拒绝保持不变。观察不创建 ObjectContext 或 native
Session，不读取已删除 payload，不授予 activation/GC，也不要求调用位于目标 worker。

当前 marker 属于原 descriptor 时，可直接报告该稳定阶段。marker 已被后继覆盖时，只能
精确读取原 operation 的 descriptor/proof，校验完整身份与 hash；不能从请求重建缺失记录。
在历史读取之后再次读取 HEAD 并检查当前 ADMIN 与同一 body/ETag。两次 HEAD 不一致时
返回本次观察不稳定，不能把跨时序的 Missing 归结为历史未发生或历史损坏。
若原终态 marker 已被替换，原 proof 的 phase revision/head serial 必须严格早于当前
marker 的 admission counters，且当前仍为 HEAD8。仅检查 proof counters 小于当前 HEAD
不足以排除 marker 回退后又有普通 SQL 推进的矛盾；必须先完成稳定双读，再判断损坏。

当前 marker 若使用同一 creator/operation，却绑定不同 descriptor hash，也必须先完成
最终 HEAD 屏障：HEAD 已变化返回 Conflict；HEAD 稳定则为权威矛盾并隔离，不能因为
全 ref 不相等而落到缺 proof 的 fenced 分支。第一次持久 descriptor 的身份不能被新 hash
重新解释。

若稳定的当前 HEAD 已不再允许原 base CAS，但没有该 operation 的终态证明，只能报告
原 admission 的未来效果已被 fence、过去效果尚不确定。缺失证明不能推出 NotApplied，
更不能恢复旧 mutation 派发权。已验证的 terminal proof 也只证明接受过的历史阶段；
它不证明原调用人收到了 ACK、不证明当前 owner/active，也不证明当前进程持有 Session。

按 Scope 的 API 同样适用于具名数据库。若提供 Catalogue wrapper，输入必须是原完整
Creation，并验证其 own 身份；不能重新用已复用的 name 解析出另一库，再把新库状态当成
旧计划的历史。ForeignOccupied 不提供 losing Scope 的 owner 历史或清扫权。

## 4. 旧入口与新格式的封闭边界

仅把 terminal revision 推到 base+2，**仍不足以关闭所有在 pending 期间才准备的旧式两阶段
意图**。旧服务器没有计划身份，其迟到 activation 可能正好带着后继 revision。因此：

1. 第一次接受 Claim 或 Cancelling 时明确升级为 HEAD8；旧 HEAD6/HEAD7 wire 保持精确
   schema，旧 binary 对新格式失败关闭。编码与数值上限见 §2.1。
2. 一个数据库进入 owner-plan 格式后，legacy takeover/activate 入口永久拒绝，包括 Active
   或 Aborted 之后。后续所有 owner 变化和显式激活都必须使用新的计划 API。
3. pending 时拒绝业务写 SQL、旧 owner 管理、生命周期、窗口、compaction/GC 与删除；允许
   必要的 ADMIN ACL 撤回和 quota 更新，但保留 marker 与 inactive，遵守下面的计数预留。
4. terminal plan 允许正常业务继续；原 marker 随普通业务变化保留。后续 compaction/lifecycle
   若使 owner inactive，其激活也走新的 activate-only plan。
5. 永久存储 seal 不得与 pending owner plan 共存。Deleted 的 terminal seal 继续冻结业务字段，
   保留最终 marker 与 proof；控制对象和永久 HEAD 不被 payload GC 删除。

服务、SDK、目录恢复、发现、所有 HEAD 构造器与独立原始判定器必须一起理解这个格式。
只在一个 HTTP 路径加 guard 不算封闭。新 SDK 的严格状态解码也须包含 owner-plan 信息；
旧 SDK 不能把 pending metadata 误当作可新建 legacy intent 的普通 status。

pending 的普通入口必须逐项决定，不能用“拒绝 SQL”代替审计：fresh status、只读 query、
原 request lookup 可以按原 READ 权限与固定数据闭包继续；它们不能返回 writer/activation
资格。`cancel` 已有确定结果时可只读返回原结果，Unknown 时不得追加新的取消条目。
`open` 若仅物化只读 Session，不能绕过 inactive/pending writer gate；`execute`、commit、
`close_full`/epoch 变更、set_lifecycle、目录删除/恢复的 HEAD publication、全部 storage
维护都显式拒绝 pending。quota 若读取 manifest，仍绑定本次 Snapshot，并保持根和窗口
不变；ACL/quota 的发布要在最终 HEAD CAS 前重新检查 pending 的计数预留。

## 5. 计数耗尽不能制造永久 pending

原 base 必须至少为完整两阶段终态预留两个 business revision 和两个 head serial。
Claimed/Cancelling 期间任何允许的 ACL/quota 更新，都必须继续为至少一个 terminal
后继保留空间。不能用 saturating/wrapping 算术，也不能让管理员最后一次 ACL 更新消耗
剩余的 MAX 值、导致 abort 永远无法表达。

owner epoch 在 takeover admission 前检查空间；activate-only 不另增 epoch。证明记录使用
已接受阶段的固定 counter，不靠创建 proof 时较晚的当前计数决定内容。

## 6. 历史替换和资源边界

新计划的 Claim **或 Cancelling** 覆盖旧 Active/Aborted marker 前，都必须按 marker 中的原稳定字段持久化并 exact
核实旧 terminal proof。Unknown、缺失、损坏、身份不同或预算不足时不覆盖 marker。
故障恢复可以继续查证同一 proof；不得用新 operation ID 绕过尚未保全的旧历史。

marker/proof 中的 owner tuple 同样是历史字段。后续合法的具名删除可以增加当前
HEAD owner epoch；不得因此修改旧 phase owner，或用当前 owner 重建原 proof。

每个 HEAD 只保留一个 plan marker，descriptor/proof 的永久保留有明确成本。首版不承诺
管理元数据无限免费，也不把 payload compaction 说成控制历史回收。controller 的每轮
Scope 数、并发探测、恢复数、响应大小和总期限分别有界；没有 S3 心跳租约写入。

## 7. 独立验收要求

有限模型必须把 HTTP admission、S3 invoke/effect/response、进程退出分别表示；Unknown 或
crash 不撤销已经 invoke 的请求。oracle 只接受原始事件，不导入候选构造器或 model。

至少覆盖：prepare/claim Unknown；claim 与未接受取消竞态；Cancelling 后崩溃；两个 resume；
恢复中 ACL 更新/撤回；旧 HTTP 在 abort 后才 admit；旧 CAS 在 abort 后才生效；目标替换；
legacy 在 pending 时新准备、terminal 后迟到；proof Unknown 与后继计划；同 ID 改输入；
计数耗尽与 metadata 消耗预留；存储 copy/sweep/terminal 组合；已 accepted 阶段永不回退。

必须提供对应的错误实现或原始记录变异，并证明 oracle 在所声明的语义处拒绝。有限模型
通过后，生产 core/service/SDK 仍需新冻结源码、逐文件精确单位覆盖、真实 SQLite/HTTP/S3
暂停切点、独立原历史审计和负对照。没有这些证据，产品交付状态保持 NOT_RUN；有限模型
通过与产品、自动 controller、真实 AWS 的验证状态分别记录。
