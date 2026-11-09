# 候选扩展：世代 fence 与可中止普通操作

状态：场景清单 v3，追加权限/owner 交错；原35个程序及其初始状态保持不变。
原35场景已有仅producer开发枚举，尚未独立验收；新增2场景在展开冻结前不探索。
本清单不修改已验收的 N3 模型、26 个 profile 或原来的 41 个负控制。
v1 原文保留在 `SCENARIOS-v1.md`，SHA-256 为
`743551f1ced3fec6837bce815dbd7d6ce4caad6670103088de3d9fb7bb5b2fae`。
v2 保留其 30 个 profile，新增 5 个 checkpoint transport UNKNOWN profile。

## 选择与非目标

候选方案不给普通冷读、原结果 lookup 或 SQL attempt 登记 durable pin，也不为
这些操作新增 HEAD 元数据写。普通操作仍从一次 fresh exact HEAD 获得原权限和
Snapshot，捕获原 Scope、物理世代、根、请求身份和 deadline。Freeze 是显式受权的
HEAD CAS；它增加 `head_serial`、固定当前根并分配新的 T。它不声称所有旧读者已经
退出，也不依赖 TTL、时钟或者进程死亡判断。

成功读仍可线性化在原始受权 HEAD。只要完整取得并验证所有原始 hash、边、身份和
原始字节，最后 GET、materialize 和 return 都可以发生在 fence 之后。部分内容
不能成为成功结果。不增加“读完以后再 GET HEAD”的新步骤来制造即时撤销的承诺。

保留快照的根和复制计划不是普通操作寿命：前者在本模型中用显式 durable
retained-generation hold 表示；后者由当前 A/T 和完整计划身份保护。普通 fence
不能删除 hold；hold 只能从当前 active generation 创建，必须通过单独受权释放。
因此一旦某个世代永久退休，就不能重新给它加 hold、选作 active 或分配作 target。
此 hold 是保护语义的有界抽象，不是已实现的快照/PITR API。

永久退休谓词为：

`1 <= g <= allocated_through && g != active && g != current_target && no_retained_hold(g)`。

绝不能改成 `g < active`。例如 A=1、M=3、T=3 时，已经 abort 的 G2 可以退休；
G1 仍是正在使用的源。迟到的 G2 target-verify 失败不能 poison G1，也不能进入
G3 的验证集合。

## 独立探索的有限边界

- 固定一个完整 Scope；另一个 Scope 只作为错误响应/错误 key 的负控制输入。
- 每个 profile 最多 4 个 actor，最多 3 个分配过的世代、6 个对象定义、1 个
  retained-generation hold、1 个当前复制计划；普通操作 durable pin 数恒为 0。
- v2 的 inline checkpoint 最多 2 个精确 candidate object，同时最多一个 batch。
  当前 copy plan 与当前 sweep checkpoint 互斥；已经发出的旧网络 token 不受
  当前记录清除影响，必须继续保持 enabled。旧 T2 可以先被 sweep，再开始 T3；
  T2 的未交付 GET/DELETE 仍可在 T3 存在时应用/被观察。
- 使用固定内容 hash 的真实物理 key，不能用对象的诊断名称代替存储 key。
  每个对象最多 2 条引用边；根图最大深度 2。Result 中的旧 data-root 身份字段
  单列为 non-edge，不能自动扩张闭包。
- 每个 actor 使用有限、显式、无循环程序。每个 actor 最多 128 条展开步骤，
  每个 profile 最多 96 个网络 token。步骤展开清单必须在第一次探索前冻结。
- 原始 HEAD GET、HEAD CAS、immutable GET/Absent PUT、conditional DELETE 均有
  dispatch、backend apply/discard、response observation 分界。GET 的 HEAD body 和
  ETag 来自同一次 backend observation。PUT 返回值不能制造 Snapshot。
- 原请求已经发出后，即使 caller UNKNOWN、actor 退出或本地 abort，它仍是独立的
  enabled network delivery。Backend 只使用原 key/body/ETag；不按当前 ACL 重新
  解释旧请求。所有 pending token 的 apply/discard 都必须出现在邻接清单中。
- observe 可以在未确定原请求结果时产生 UNKNOWN，但不能随后把同一次 caller
  observation 改写成 ACK。效果只能由之后另一次 exact HEAD/GET 调查。
- 每个 profile 的上限为 50,000 states / 150,000 edges；达到上限、超时、缺 map、
  缺 mandatory witness 都只能报告 INCOMPLETE，不得报告 PASS。上限是探索资源预算，
  不是生产数据库最多只能有 3 个世代或 6 个对象的接口限制。

独立 oracle 不导入 producer 的 reducer、enabled-choice 函数或派生闭包。它从
冻结输入、实际 key/raw frame、原始条件和已枚举 state/edge 重新检查网络结果、
权限、完整结果、原 CAS、计划和退休不变量，并独立检查所有 enabled choice 是否
都有边。witness 使用图中的实际路径，不用输入中一句“本场景覆盖了某情况”代替。

## 暂定状态与错误语义

HEAD 包含 serial、业务 revision、owner、ACL、lifecycle、A/M、当前计划、当前
数据/结果根及一个可选 retained-generation hold。计划必须绑定完整 Scope、唯一
acquisition identity、source、target、根集合和开始的原 authority。新 capture
清空旧的 copy/verify 证据；每个响应仍携带它自己 dispatch 时的完整保护身份。

完整 materialized 结果拥有自己的不可变字节，不再依赖远端对象仍存在。本地 stop
阻止新 dispatch/public success，但不撤回已经发出的请求。caller detach 与本地
stop 是两种事件；模型不把 caller 退出当成 worker absolute deadline。

对象失败先形成带 captured Scope/generation/hash/plan 的 failure capsule，再
取得一次针对该失败的 fresh exact authority；不能先设置当前 Database 的全局
quarantine，再假装随后已经恢复了健康状态。

| 证据 | 候选结果 |
| --- | --- |
| fresh 同 Scope authority 证明 captured g 永久退休 | 旧远端对象 Missing/损坏拒绝返回数据，可给 scoped SnapshotExpired；不 poison 另一个 active generation。 |
| captured g 仍为 active 或当前 target/hold 保护的世代 | 保持 Corrupt/fail-closed；计划已经过期也不能掩盖 active-generation corruption。 |
| fresh authority Unknown/不可用 | 不给 SnapshotExpired，不给成功，不宣称当前健康；保留 captured-generation 的 unresolved incident。后续 fresh authority 若仍选该世代，必须先失败关闭/确定 Corrupt。 |
| fresh authority 格式或 Scope 不合法 | AuthorityCorrupt；不能当作退休证明。 |
| 本地已经完整 materialize 的结果 | 可以从原授权 Snapshot 返回，即使 fence/ACL/Delete/物理 sweep 已发生。 |
| durable HEAD CAS 已知成功，native publication 失败 | CommittedButUnavailable，保留原 receipt；不撤回 HEAD、不重放 SQL、不伪造 ACK。 |
| 原 CAS UNKNOWN | 原 caller 仍 UNKNOWN；之后实际应用/冲突是独立 backend 事实，不能倒填原 ACK。 |

retired-generation 对象错误的 scoped 处理不自动覆盖 native InvalidImage、完整
结果的 SQL 语义错误或相同 root 的语义损坏。新世代可能复制了相同内容；这些情况
仍需保持根/内容层面的 Corrupt 处理。真实 Rust 的 health 表示、内存界限和错误
映射属于后续生产设计；有限模型只定义必须保留的知识与隔离边界。

## v1 保留的 30 个独立 profile 与强制可达 witness

所有 profile 都要穷举自己的全部有限程序交错。表中 witness 是必须实际到达的
路径；表外安全不变量仍在该 profile 的每个已枚举 state/edge 上检查。

| ID | 场景 | 必须实际可达的证据 |
| --- | --- | --- |
| A01 | 原读最后 GET 和 materialize 在 Freeze 后 | 全部原引用字节验证完成后成功；普通操作没有 PinAdd/Release 或其它 HEAD 写。 |
| A02 | 完整 materialize 后暂停，随后全部 sweep 再 return | 原结果成功返回；不重新读当前世代。 |
| A03 | GET 已在旧世代取得 FOUND，响应到达在 sweep 后 | 原始响应仍有效；backend apply 与客户端 observe 明确分离。 |
| A04 | 旧读不完整，退休对象 Missing | fresh authority 证明退休后 SnapshotExpired；新 active 不被 poison。 |
| A05 | 退休命名空间中的错误 raw/hash | 不返回坏数据；fresh 退休证明后仅旧 context 失败。 |
| A06 | active generation Missing | Corrupt，后续同 active admission 不得恢复健康或伪造空库。 |
| A07 | active generation raw/hash 损坏 | Corrupt，即使发生了无关技术 serial/ACL 变化也不能 Expired。 |
| A08 | active 对象失败后 fresh authority Unknown | 无成功、无 Expired；unresolved incident 后遇到同 active 的 fresh authority 仍失败关闭。 |
| A09 | 实际已退休，但失败调查的 authority Unknown | 旧 caller Unknown 而非猜测 Expired；之后独立 fresh 新 active 操作不借旧失败污染新世代。 |
| A10 | ACL 更新穿过旧读 | 原受权读完整完成可返回；更新后才观察 HEAD 的新 reader 被拒绝。 |
| A11 | Delete 穿过旧读 | 已受权旧读完整完成可以返回；新 admission 被 lifecycle 拒绝；不 sweep Deleted 的最后 active。 |
| W01 | 原 writer CAS 先于 Freeze | 新根/原结果进入随后 fresh Freeze 的闭包；已知 native commit 才 ACK。 |
| W02 | Freeze 先于原 writer CAS | 原 ETag 冲突；不换 ETag、不换 generation、不重放 SQL。 |
| W03 | caller UNKNOWN 后原 writer CAS 迟到成功 | backend 先成功、后来的 Freeze 包含新根；原 caller 不获补造 ACK。 |
| W04 | caller UNKNOWN 后原 writer CAS 迟到冲突 | fence 已生效；原 body/ETag 不变，仍无 ACK。 |
| W05 | durable commit 成功后 native failure | CommittedButUnavailable；迁移后原 Result 仍可验证，不能“回滚”权威。 |
| W06 | 旧 Absent PUT 在 sweep 后重建 orphan | 只重建 captured old key；后续 sweep 可再删；同 hash 的新 active key 保持完整。 |
| F01 | Freeze CAS UNKNOWN | 只能 fresh exact HEAD 观察完整 own plan 后开始 copy；相同 serial/target 或 PUT 回执不能替代。 |
| P01 | 两个 Complete，旧 verifier 在 Ready→迁移→sweep 后恢复 | 旧 verifier 不假 ACK/不 poison 新世代；独立 already-Ready metadata 返回与闭包证明明确分开。 |
| P02 | 既存 Provisioning AbortFence 与 Complete 竞争 | 两种原 CAS 顺序都可达；Deleted 不复活，Ready 后旧 Abort 不重绑；旧 manifest 读按实际世代分类。 |
| P03 | 尚无 HEAD 的 bootstrap 被另一个创建者超越 | 后者创建并迁移后，前者 readback Missing 只能经 fresh 退休证明退出；原 Absent 不能胜出。 |
| P04 | Absent AbortFence 与普通/命名创建竞争 | 只一个永久 HEAD 创建成功；Deleted barrier 不被后续 bootstrap 重建为 Ready。 |
| C01 | abort T2，A1 保持、T3 当前，迟到 G2 verify Missing | G2 虽然大于 A1 仍能退休；仅 G2 Expired，G1 健康，不能给 G3 加验证证据。 |
| C02 | 旧计划已 abort，但其 source G1 仍 active 且 Missing | 必须 Corrupt；PlanExpired 不得成为抑制当前损坏的理由。 |
| C03 | T2 的成功 verify 响应在新 T3 capture 后才 observe | 清空/绑定证据正确；不能利用旧成功将未复制的 T3 Seal。 |
| H01 | 显式 retained-generation hold 穿过 Freeze/Promote | 普通 fence 不删除 hold；被 hold 的旧世代不能 sweep，明确受权 release 后才有资格。 |
| D01 | Delete 放弃 Copying target，与旧 Promote 交错 | 同一 CAS 保留 M/A/当前 ACL/owner/hold并清除 T；迟到 Promote 不复活 Deleted。 |
| X01 | caller detach、本地 stop 与在途网络分离 | detach 不自动取消 worker；stop 后无新 dispatch/公开成功；旧网络请求仍能应用。 |
| X02 | raw 原字节、实际 key 与 receipt non-edge | 保留非规范原始帧字节；使用完整 captured key；未保留旧 data_root 身份不自动变成复制边。 |
| X03 | 失败调查返回错误 Scope/坏 HEAD | 不给退休证明，不给 SnapshotExpired 或新权限，不退回缓存 HEAD。 |

## v2 新增：有界 inline checkpoint 的实际请求边界

checkpoint 与退休资格在同一永久 HEAD 中排序。它保存独立的 plan identity、
batch identity、checked sequence、被清扫世代、最多 2 个原始完整 key/opaque ETag、
每项 disposition 及原请求曾经 UNKNOWN 的信息。每个客户端 candidate 的完整身份
还包括原 Scope、原 checkpoint observation 和 entry position。不能只匹配 serial
或相同 hash；不能把一个批次里的判断授予另一个批次。

安装、记录 disposition、清理 checkpoint 都是实际 HEAD GET → 构造原 ETag
候选 → dispatch → backend apply/discard → observe 的动作。它们增加技术 serial，
保留业务根、ACL、owner、lifecycle 和 hold。任何 checkpoint PUT 的成功回执都不能
直接制造新 Snapshot；DELETE 能力必须来自之后 fresh exact HEAD 对完整 own
batch/entry 的观察。重新开始的一次技术步骤可使用新的 exact authority；这不是
给旧 SQL attempt 更换 ETag。

安装 UNKNOWN 后，若 fresh HEAD 仍是原 serial 且 batch 缺失，结果只能是
pending_absent。原 CAS 仍可迟到成功，不能退款为“从未持久化”、制造 DELETE
能力或删除 pending network token。若另一个合法技术 fence 先成功并使 serial
增加，原 CAS 只能按原条件失败；这种证据不等于原 caller 看到了 Applied。

### 确定采用的 UNKNOWN disposition 选择

1. 原 DELETE UNKNOWN 始终保留自己的 captured key、原 opaque ETag 和 UNKNOWN
   caller 知识。backend 后来应用或另一次重试成功都不会把这个旧 caller 结果改成
   Applied/Missing。请求与 candidate disposition 是两个层次。
2. 针对同一个精确 key 的 fresh、typed `NoSuchKey` 可建立 `ObservedAbsent`。
   `NoSuchBucket`、transport unavailable、未经验证的普通 `StoreError::Missing`
   都不能建立这个结论。
3. 用新的 fresh-original-condition HEAD CAS 持久化 `ObservedAbsent` 等有界
   disposition；要清理 batch，必须再次观察到完整对应的持久化状态，再提交清理
   CAS 并通过 fresh HEAD 确认。disposition/clear 自身 UNKNOWN 时也保留原请求。
4. 所有 entry 已有已知安全 disposition 后，已观察的清理 CAS 可以移除有界
   checkpoint，即使某个原 DELETE token 仍在途中。这不等待一个可能永久丢失的
   网络响应。独立不变量必须证明：被清扫世代已经永久退休，永不能成为 A/T 或
   新 hold；旧 token 始终只带原物理 key/ETag。清理、新 batch、新 plan 或新世代
   均不能给旧 token 换目标。
5. 所有迟到 token 仍在模型网络集合中。即使 batch 被清理，原 DELETE 仍可能在
   旧 key 重建后应用；它只会影响退休垃圾，不得影响同 hash 的新 active/target
   key。证据仍保留原 UNKNOWN，不声称永久空前缀。
6. 如果 fresh candidate GET 看到不同 ETag，不能在 RAM 中替换旧 entry 后发
   DELETE。先显式重发同一个原条件并取得本次自己的结果，例如 Conflict，以此
   结束旧 candidate disposition；然后在新 batch identity 下持久化那个新精确
   ETag、fresh 观察该批次，才可发新 DELETE。新的已知结果不追认旧 UNKNOWN。

模型的 HEAD ETag 继续由完整 body 派生，避免用隐藏唯一版本号掩盖 ABA。
不可变对象 ETag 则是独立的 opaque 条件值，不把它当内容 hash：相同 raw bytes
在旧 key 删除后重建可以产生不同 ETag。测试实际 key/hash 的内容身份与 DELETE
的 opaque ETag 是不同检查。CP05 明确包含这样的重建，而不是让 codec 接受一个
错误内容 hash 的对象来伪造“正常 ETag 变化”。

| ID | 场景 | 必须实际可达的证据 |
| --- | --- | --- |
| CP01 | intent CAS UNKNOWN，backend 实际应用 | fresh exact own plan/batch/entry 观察之前无 DELETE；观察之后只按持久化 key/ETag 删除；PUT 回执不能当 Snapshot。 |
| CP02 | intent CAS 仍 pending，同 serial HEAD 中缺失 | 必须仍是 pending_absent；随后原 CAS 可迟到应用；无虚假“未提交”或提前 DELETE。 |
| CP03 | 后来的 metadata fence 先成功 | 原条件被 higher serial fence；原 CAS 迟到只能 Conflict，不发明原 Applied，也不从旧 RAM candidate 取得删除权限。 |
| CP04 | DELETE UNKNOWN 的 typed absence 与记录清理 | NoSuchKey → 新 CAS 持久化 ObservedAbsent → fresh 观察 → 清理并 fresh 确认；NoSuchBucket/不可用分支不作 absence。至少一条路径在清理、新 batch/plan 后才交付原 DELETE，仍保留原 key/ETag/UNKNOWN。 |
| CP05 | 原 key 重建为不同 opaque ETag | RAM 换 ETag 的删除被拒绝；原条件的新重试取得自己的 Conflict 后，新 distinct batch 持久化并 fresh 观察 ETag2，才可删除该版本；旧 token 仍不改写。 |

CP04 的迟到旧 DELETE 在 clear/new-batch 之后应用必须同时成为强制 witness 与
独立负控制边界。至少一个相同内容 hash 的新 active 或 target key 始终存在，
用于证明旧请求不会被错误重定向。checkpoint 被清理并不删掉已有网络 token。

v2 的探索器会对所有 checkpoint 原请求分别保留 applied/discarded/pending、
原 caller known/unknown、candidate disposition、以及 current HEAD 是否仍包含
该 batch 四种不同信息。不能把它们压成一个布尔“完成”。

## 新的反例控制与生产缺项

新的负控制应至少分别破坏：原 key、原 ETag、无重绑、完整读、authority 不可用、
active 损坏、`g < A` 错误退休规则、retained hold、旧计划证据、错误 Scope、
native-before-ACK、UNKNOWN 知识、完整 raw 字节、以及 enabled delivery 完整性。
v2 再分别破坏：未观察持久化批次即 DELETE、同 serial 缺失被当不提交、higher
fence 被误记原 Applied、NoSuchBucket 当 NoSuchKey、清理时丢弃旧 pending DELETE、
clear 后重定向旧 key/ETag、未持久化的新 ETag 替换、以及新重试结果倒填旧 UNKNOWN。
它们放在新包中，不改已有 41 个控制，也不把旧模型的通过数字加到新模型上。

本扩展仍明确不证明：SQLite 内部原生正确性、真实对象/SQL codec 完整性、S3 协议
与签名、云端一致性本身、真实 LIST 分页、所有 Catalogue
Name/Descriptor/Proof 跨 key 原子关系、PITR、Deleted 最后 active 的回收、实时
deadline、RSS、无限 actor/无限计划公平性和吞吐。v2 显式覆盖上述有界 checkpoint
网络 UNKNOWN 与原条件交错，不再把该步骤当作原子持久化黑箱；它仍不证明真实
生产 checkpoint codec、物理游标遍历或部署的 S3 capability。生产 DELETE 接入前
还需要独立实际传输与完整生产实现验收。

程序展开版本、source manifest、所有原始失败、每个 profile 的 state/edge 分母、
mandatory witness 路径与独立 oracle/控制结果都必须保留。任何输入或 reducer 变化
产生新版本/新证据目录；不把旧失败文件覆盖成通过。

## v3：fresh 技术步骤的权限边界

v2 原文保留在 `SCENARIOS-v2.md`（SHA-256
`85c7f30bae233917d40c91329cd71dedfa71ef15cb4cfc9254816e65e4ed64c7`）。
v3 保留原35个 profile 的全部程序、初始状态和 mandatory witness，追加下列2个。

| ID | 显式程序假设和交错 | 必需 witness |
| --- | --- | --- |
| T01 | 第二名 admin 在旧 DELETE 已发出后撤销维护 principal 的 admin；旧 actor 随后重新 GET HEAD，另一 actor 也尝试新的 Freeze。 | fresh checkpoint/维护都拒绝；已经发出的原 DELETE 仍按原 key/ETag 交付。 |
| T02 | 第二名 admin 修改 owner/epoch，原 Freeze CAS 迟到；原 principal 的独立 admin 权限仍保留。 | 原 CAS 冲突；保留 admin 的 fresh Freeze 可成功；旧 worker 的新普通写 admission 拒绝。 |

每个技术动词的 required rights 在 `inputs.json.required_current_rights` 列出：
copy/Freeze/Seal/Promote、checkpoint 和 retained hold 管理要求当前 fresh HEAD
的 admin；它们不要求调用 worker 等于普通写 owner。普通写要求 read+write、
Ready、当前 active owner 和无复制计划。Complete/Abort 使用精确创建身份。
失败调查只判断原 Scope 的退休，不产生新的 READ grant。Deleted 允许已有
checkpoint 的受权 disposition/clear；它不允许新 DELETE admission。

因此，owner 变化能通过原 ETag fence 阻止已经准备的旧 HEAD CAS，但不会凭空
撤销另一项独立保留的 admin 权限。fresh 技术步骤必须重新检查它实际需要的
权限；普通读按原授权返回的规则不能被复用成维护授权。原请求 dispatch 后的
网络执行不重新检查当前 ACL/owner，仍然只用不可变的原请求条件。

所有 `await`/`mark` 是显式 fixture 暂停/继续假设，只约束本有限程序的调度。
验收报告只声称这些冻结程序内所有 enabled interleaving 已遍历，不声称已经
枚举任意业务程序、任意时刻的暂停或所有无限请求序列。新增 T01/T02 的控制
必须分别检测 fresh 权限跳过、把 owner 变化错误当成 admin 撤销，以及丢失旧
请求交付边。
