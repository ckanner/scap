# 候选扩展：世代 fence 与可中止普通操作

状态：场景清单 v1，等待独立审查；尚未编写 explorer/oracle，尚未开始状态探索。
本清单不修改已验收的 N3 模型、26 个 profile 或原来的 41 个负控制。

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

## 30 个独立 profile 与强制可达 witness

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

## 新的反例控制与生产缺项

新的负控制应至少分别破坏：原 key、原 ETag、无重绑、完整读、authority 不可用、
active 损坏、`g < A` 错误退休规则、retained hold、旧计划证据、错误 Scope、
native-before-ACK、UNKNOWN 知识、完整 raw 字节、以及 enabled delivery 完整性。
它们放在新包中，不改已有 41 个控制，也不把旧模型的通过数字加到新模型上。

本扩展仍明确不证明：SQLite 内部原生正确性、真实对象/SQL codec 完整性、S3 协议
与签名、云端一致性本身、真实 LIST 分页、checkpoint 网络 UNKNOWN、所有 Catalogue
Name/Descriptor/Proof 跨 key 原子关系、PITR、Deleted 最后 active 的回收、实时
deadline、RSS、无限 actor/无限计划公平性和吞吐。Sweep 仍以已知有效的有界 durable
计划作为抽象前提；生产 DELETE 接入前还必须另外关闭 checkpoint transport UNKNOWN。

程序展开版本、source manifest、所有原始失败、每个 profile 的 state/edge 分母、
mandatory witness 路径与独立 oracle/控制结果都必须保留。任何输入或 reducer 变化
产生新版本/新证据目录；不把旧失败文件覆盖成通过。
