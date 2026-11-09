# 世代作用域的失败判定与准入设计

状态：**STATIC_DESIGN；本次生产测试、模型 checker、BFS 与实际验收均为 NOT_RUN。** 当前 HEAD5 仍严格接受 `active_generation = allocated_through = 1`。本文件不放宽它，也不把有限模型当成已经实现的回收协议。

本文依据 HEAD5/raw-frame 基线 [f6c9073a924297f5cd1704fa3c677101ad451d3f](https://github.com/ckanner/scap/commit/f6c9073a924297f5cd1704fa3c677101ad451d3f)、闭包前置切片 [c516ceb1166bd1bf082da33697bef0ae074710e8](https://github.com/ckanner/scap/commit/c516ceb1166bd1bf082da33697bef0ae074710e8)（[PR #44](https://github.com/ckanner/scap/pull/44)），以及独立有限模型 [d158b44f18475038eee1a904af2cf0ba0722ecf4](https://github.com/ckanner/scap/commit/d158b44f18475038eee1a904af2cf0ba0722ecf4)（[PR #43](https://github.com/ckanner/scap/pull/43)）。闭包切片自身的 scoped 单位门禁与组合 workspace / actual 是不同范围；本文不新增或扩大任何验证结论。takeover / policy 的 metadata-only 管理方案尚未提交，只作为设计前置项。

本次来源哈希、精确提交及 NOT_RUN 范围记录在 [静态设计审阅记录](../evidence/scoped-generation-design-review-2026-11-09.json)。原模型源码、原始验证记录与已有结论保持不变。

## 1. 本轮建议与已具备的前置片段

**当前 1/1 不增加失败后的 fresh HEAD GET，也不增加 SnapshotExpired。** 没有可退休世代时，这个请求只会增加故障路径的延迟和预算消耗。不能为未来消费者先放入未使用的 failure、plan 或 health 类型。

现有、已经有真实调用方的最窄前置片段是：

1. `ObjectContext` 固定原 backend、完整 Scope、physical generation 和 quarantine 归属；SQL attempt 固定原 Snapshot、请求身份和 deadline。
2. 闭包切片的 `with_raw` 保留原 GET 字节，区分源验证与 visitor 失败；owned Cursor 的错误退出消费 prefix，完整校验实际接入 Activate 与 named Complete。
3. metadata 管理方案只为 takeover / policy 构造封闭候选，并沿原 `PreparedHead` 做一次 CAS。它不会因管理 ACK 而证明 payload 健康。

这些片段可在 1/1 下独立使用。**不建议为本主题另做一轮没有行为收益的全库观察器重构。** 当前多个 `observe` 调用确实会丢失更细的来源，但在真正需要分世代分类时才一起替换；只改函数名或携带当前无人消费的字段不能关闭该风险。

本地预算与真正对象超限混同，是一个需要解决的真实边界；若单独立项，应先给出当前受影响调用方和可观察反例，保持现有 HTTP `LIMIT`。本文件不提前增加 StoreError 变体。独立逻辑 Delete / existing AbortFence 的 metadata-only 构造可另作有现有消费者的切片，但它不是世代退休或本文件失败处理的实现。

## 2. 判定矩阵：不能只看最终 Error::Corrupt

下面的“可调查”表示未来完整多世代协议启用后，允许对**这一次失败**尝试至多一个严格同 Scope 的 HEAD GET。它不是当前行为。没有足够原 deadline / budget 时可零次；绝不重试到成功为止。

| 失败来源 | 需要保留的证据 | 未来退休调查与结果 | 隔离边界 |
| --- | --- | --- | --- |
| 原 immutable GET / exact read-back 的 `Missing` | 原 key/hash、g、backend、operation identity、原错误 | 可调查；确证该 g 永久退休才返回 SnapshotExpired；active / target / held 时保留原缺失错误与故障阻断 | 原 physical g；不能先写跨世代 bool 再清除 |
| 超过完整 immutable wire 上限的真实响应 | 原完整上限、实际超限事实、未截短的 allowance 来源 | 可作为物理对象故障调查；protected g 保留当前 Limit/隔离语义，retired g 才可 expiry | 原 physical g；“损坏类别”不意味着要把现有 HTTP LIMIT 强改成 CORRUPT |
| 本地 GET 次数/字节预算耗尽，或 allowance 被本地预算截短 | 本次调用的预算来源与实际 allowance | 不调查；仍为资源失败，不是对象损坏或退休证明 | 不产生远端 corruption incident；不得为它再借一份调查额度 |
| adapter 自身配置的最大响应小于合法对象格式上限 | 本次有效 cap 与格式 cap | 仅知道超过本地 cap，不能宣称超过格式上限；先按资源/配置边界处理 | 不能自动隔离源；生产接线必须明确 port 的 cap 合同 |
| hash 不符、截断响应、错误 range 等原始对象验证失败 | 原 expected hash、实际验证阶段、原 key/g | 可按物理读取故障调查；任何路径都不能接受这些 bytes | 即使 expiry，也保留原 incident 的原因，不能称 bytes 曾经合法 |
| hash 已验证后仍存在格式/Scope/type 内语义矛盾 | hash 是否已验证、具体校验阶段、原 root/edge | **不能笼统把所有 FormatError::Corrupt 都当 namespace 消失。** 首片按内容/关系损坏保守处理；只有单独证明适用的 raw failure 才进退休分类 | 当前 parse 的最终错误已抹去阶段，未来需共享同一 parser 的内部 provenance，不另写第二套 codec |
| typed tree/index edge 错误 | 父边、child hash、期望 span/level/epoch/summary、原 roots | 不自动 expiry；相同 bytes/错误关系可能已被复制，换 g 不是修复 | 内容/原根语义故障；不能只用 HEAD 上“不再 active”清除 |
| retained SQL wire、完整 Request/长度/sequence/revision 错误 | 原 Result hash/request/receipt、验证阶段 | 不自动 expiry；当前 durable wire 与身份约束保持 | 与原内容/请求绑定；不重新跑 SQL，不恢复缺失历史根 |
| native `InvalidImage` | 验证过的原 source roots、native 打开/校验阶段 | 不通过退休调查变成 expiry；raw closure 不证明 SQLite 有效 | 保留现有语义故障阻断；本地 I/O、Interrupted、内存不足另分类 |
| visitor、目标 PUT、本地文件写入、结果图内存不足 | 原产生错误的端口；是否已知 durable commit | 不归为源 Missing/Corrupt；已提交结果无法物化仍是 CommittedButUnavailable | 源与 sink 分开；已知 receipt 不被 retirement 抹掉 |
| copy 的 target verify GET 失败 | 完整原 plan identity、target g、target key/hash | 用实际 target g 判定；不是按 source A 判定。Abort T2 后 A1/T3，T2 可退休 | 不 poison A1，也不能给 T3 加入 T2 的成功/失败证据 |
| HEAD / Catalogue 的 authority 错误 | 严格原 Scope、永久 slot、Name/Descriptor/Control/Proof 身份 | 永不作为 payload expiry 的借口；坏 HEAD/Scope 失败关闭，authority 不可得不产生退休证明 | authority 层；不能递归调查调查本身 |

现有 `StoreError::Missing` 来自泛化 NotFound；它不是 typed NoSuchKey/NoSuchBucket 的 DELETE 证据。本设计只用它说明旧操作未取得所需 bytes。未来若同 backend 的严格 HEAD 证明退休，expiry 也不等于“某次 DELETE 已成功”或“原对象永久不存在”。

现有 `RecoveryMeter` / discovery meter 将本地 allowance 截短和远端超限投影为 `StoreError::Limit`。未来必须以**本次返回值中的 provenance**区分，不能读取一个全局 mutable last-error 来猜。adapter 的有效 cap 也要一并处理；不能通过降低格式上限来绕过这个区别。

## 3. 一次失败调查的精确边界

### 3.1 捕获与停止

原操作的 admission 记录必须固定：authority domain、完整 Scope、原 HEAD body+ETag、head_serial、captured g、根集合、原请求身份、backend/meter、绝对 deadline，以及停止/publication gate。bootstrap 明确为“无原 Snapshot，原条件 Absent”，不能伪造一个 HEAD。

物理失败另外固定原 key/hash、访问种类、校验阶段、第一原因；copy 还固定完整 plan acquisition identity 和 source/target 角色。数据来源不能在顶层遇到 Corrupt 后才从最新 HEAD 重新推断。

第一失败关闭该操作继续普通对象/SQL dispatch、扩张 prefix 与新成功出口的能力；唯一可能新增的请求是下节受原预算和原 deadline 约束的诊断 probe。Cursor 已具备 Error 消费语义；普通 attempt 与所有 wrapper 必须有同样的终止边界。已发请求仍可能在远端生效，关闭 gate 不是取消 S3 请求。

### 3.2 单次 probe

原操作只有一个共享的 probe 机会；不是每个 `map_err` 各发一个 HEAD GET。顶层重复观察、request-index wrapper、PublishGate 都不能再次触发调查。

1. 保留原失败为 unresolved；不能先设置当前跨世代最终 quarantine 再撤销。
2. 检查原 stop/deadline，以及同一 meter 的剩余请求和 metadata bytes；不足则零次 GET，保留未证实结果。
3. 消费 probe 机会，沿原 backend/meter 请求 `head_key(original Scope)`，最多 `MAX_HEAD_BYTES`，沿用原 absolute deadline。不能走裸 S3 Arc 绕过 RecoveryMeter。
4. 使用严格同 Scope decoder 和同一 GET 的 body/非空 ETag。永久 slot 的 key 不包含完整 incarnation/logical generation；`Catalogue::read_slot` 能表示 foreign occupied，不适合作退休证明。
5. 只返回内部判定，不把新 Snapshot/ETag 暴露给原 writer、cursor 或 CAS candidate。调查不取得新的 READ/ADMIN grant；ACL 已撤回也不能通过诊断泄露新的 HEAD 内容。

普通成功路径不加 probe，更不增加 read materialize 后的 closing HEAD GET。原来必须结束时再 exact GET 的 Activate、Complete、RecoveryJob，仍保留各自的 barrier；失败调查不能取代它们。

### 3.3 永久退休与原条件

必要谓词是：

```
1 <= captured_g <= allocated_through
captured_g != active_generation
captured_g != current_plan.target
no retained hold(captured_g)
```

此外，所有受支持的 HEAD 转移必须保证世代不复用、不重新 active、不对已退休 g 添加 hold。不能用 `g < A`：A1/M3/T3 下被 Abort 的 G2 可以退休，而 G1 仍受保护。logical Delete 保留的 A 和 holds 也不是可退休对象。

对原先从 HEAD active g 捕获的普通候选，还应审计新 authority 与原 base 的 serial / ETag 一致性：原条件必须已被永久 fence，不能接受倒退 serial、错误 Scope 或与原条件仍相容的异常 authority 当成退休证明。bootstrap 则要求同完整 Scope 的永久 HEAD 已存在并证明 G1 退休；HEAD 仅存在、foreign occupied 或一个更高业务 revision 都不够。

fresh authority 得到的是原失败的分类依据。它不能换掉原 PreparedHead 的 key/body/ETag/deadline，不能重放 SQL，也不能把原 UNKNOWN CAS 改记成 Applied/NotApplied。已经已知 durable commit 的 receipt 保持 committed；之后的 native/资源失败仍保留 CommittedButUnavailable。

### 3.4 证据不足

| probe 结果 | 原操作的结局与保留状态 |
| --- | --- |
| 同 Scope、合法、确证永久退休 | 允许物理 snapshot expiry；只影响原 g 与原失败，不把原 bytes 当作有效结果 |
| g 仍为 A / T / held，或从未分配 | 不给 expiry；保留原故障和该归属的阻断 |
| deadline/transport/authority unavailable、缺少预算 | Unknown 或原本的资源 Limit；保留 unresolved，不能声称健康，也不再 probe |
| HEAD 缺失 | 对原有 Snapshot 不是退休证明；bootstrap 也只是尚无可证明的后继 authority，不能报告“已退休” |
| 坏 HEAD、空 ETag、错误完整 Scope、serial 合同破坏 | authority/identity 失败关闭；不能清除既有 source 或 semantic incident |

另一个全新操作可能后来完成独立调查或读取；这不追溯改变原调用方的 UNKNOWN，也不复活原 prefix。

## 4. 健康状态与 admission：新增明确阻塞项

### 4.1 模型抽象并非现实共享状态

PR43 冻结模型的 `state["health"]` 按 generation 对模型 actors 共享；`authority_corrupt` 也有全局可见性。实际 f6 / 闭包源码中，quarantine 是 Database handle 与 clones 共享的 Arc。Catalogue、RecoveryJob、同 worker 的另一个 `Database::new` 都可以构造独立状态。

因此只把模型改成 worker-scoped 仍不匹配生产。最小知识域应为：

```
(trusted authority domain, full Scope, handle lineage)
```

clones、该 handle 创建的 Session/ObjectContext 保留同一 lineage；新 handle 具有独立 lineage，即使 worker 相同。meter wrapper 不能因另一个 Arc 地址就变成另一 authority domain。不同 endpoint 后面的真实存储域同样不能靠字符串巧合视为相同。

**这是打开多世代前必须完成的模型 refinement，不是此次生产已经解决的问题。** 建议新增独立有限模型输入检验这些现实知识域，不增加未设计的 durable health HEAD 字段。原 41 profiles / 图 / 负控制与其限定结论保持不变。

### 4.2 原失败与其他操作必须分开

原失败 attempt 永久丢失可继续执行的 prefix，不能改用新 handle、新 HEAD、新 g 或更长 deadline。其他独立 handle 可以执行自己的新操作，但必须获得自己的 fresh 权限、验证自己的全部必需 bytes，并遵守自己的原 CAS。它的成功不能清除旧 handle 的 unresolved/authority/semantic latch。

正确的 retained lookup 可以从新 handle 重新证明原请求已 committed；这与 adopt 原 UNKNOWN token、回写原 ACK 或重跑 SQL 完全不同，不能一并禁止。

当前 `healthy()` 主要阻断 writer/publication；lookup、cold read 和 warm `Session::query` 不一概检查该 bool。未来模型不能在细化 map key 时悄悄将它扩大为“所有新读都被 quarantine”。新只读尝试若完成 fresh authorization 和完整自有验证，可以成功而不清 latch；同 lineage 的新 writer/管理 publication 仍受已知故障约束。warm query 的 fresh READ、root/quota 对齐和完整本地 image 合同需单独保留；新 handle 不得暗中继承旧 Session/image 当作自己已完成验证。

### 4.3 健康检查不是远程 I/O 锁

`healthy()` 是本地共享状态的一次检查；它与后续 S3 调用并不构成原子临界区。另一个同 lineage 操作可能在最后一次检查之后设置 latch。生产没有因此取得撤销已 enabled PUT、取消已发网络 token 或让 S3 重新执行健康检查的能力。

这里必须区分三个时刻：

1. **尚未通过最后 publication 检查。** 检查观察到已知故障时，拒绝建立新的发布能力；本地 latch 约束这一阶段。它不等于后端原子健康条件。
2. **已经通过最后检查、固定原 PUT，但可能尚未调用网络端口。** 调度暂停后才出现的 latch 不能追溯撤销这一次已 enabled 的原请求。模型若把 check 和 dispatch 拆开，必须保留这一可达交错，不能在 dispatch 时凭空增加生产没有的第二次健康检查。
3. **已经 dispatch 的 token。** 远端只按原 key/body/condition 及存储合同决定效果，不检查后来改变的本地 latch、权限缓存或模型 health。原条件 CAS 可以 Applied、Conflict 或仍 Unknown；caller timeout、HTTP 结束、plan Abort 或本地 gate 关闭都不能把它改写为 NotApplied。

ACK 也不能仅由“后来 latch 已置位”推导为允许或禁止。若另一个操作设置 latch，而原 writer 已完成自己的全部依赖验证、原条件 CAS 已知成功、native publication 成功，且原 caller / gate 仍允许返回，则现有实现没有额外的最新健康检查作为 ACK 前置条件。模型不得偷偷增加这道检查以获得更强结论。反过来，**本身已失败或已结束的原 attempt** 不得凭其他 handle 的成功恢复 prefix 或回写 ACK；已知 commit 后的本地失败仍保留 receipt / committed-unavailable，未决 token 仍可由后续独立 lookup 证明结果。

下一版有限模型需要把 local check / enabled publication、dispatch、backend delivery、native publication 与 caller ACK 分成可辨识事件。要验证的是阻止未经准入的新发布、原请求不重绑及成功出口的自身条件；不能声称 latch 是远程 I/O 锁，或已发请求会被异步撤销。

### 4.4 生产有界存储的最低要求

未来必须区分 authority/内容语义 latch、物理 g 的 confirmed incident、以及 unresolved incident。状态不能由一次好 GET 清除；不能先共享 bool=true，再因为旧 g retired 把并发新 g 真故障也清掉。

不建立按全部历史世代永久增长的 HashMap。每个实际共享域需有明确的 live-context / generation-incident 容量；容量满时失败关闭，不可静默逐出 unresolved 或 confirmed 状态。无活跃引用且已经由严格同 Scope authority 证明退休的**物理**条目可以释放；这不清 authority/semantic latch，不改变原 caller outcome。旧 context 仍保留自己的不可变归属。

不能假设“缓存 actor 被淘汰”就等于持久清除了数据库故障，也不能声称有跨进程全局 quarantine。新 handle 的创建、旧 lineage 的最后引用释放、临时 Catalogue/Recovery handle 的生命周期必须纳入 refinement 和真实 factory 测试。先完成这个知识域与容量设计，再选择具体 Rust 结构；本轮不引入空壳 registry。

## 5. 真正启用 A/M/T/holds 时必须同片闭合的调用点

“同片”是指开启这些状态的 decoder / API 不能先发布；可以在隔离分支分步骤实现和审阅，但接受新状态的版本必须包含以下全部消费者。

| 边界 | 必须同时交付的内容 |
| --- | --- |
| HEAD codec、所有 business/technical constructors | 精确 A/M/T/holds、serial 与业务 revision、单调分配和永久退休、Freeze/Abort/Promote/Delete allowed delta、真实编码上界；不能放宽现有 PreparedHead storage 相等检查让普通 writer 任意换 g |
| 普通 metadata admission | 原 fresh Scope/权限/owner/lifecycle；纯 status、metadata 管理和 request-epoch Retired fast path 不引入 payload GET/pin |
| `ObjectContext::load/with_raw/save` | 原 g/key/hash 与错误阶段；readback 与 PUT UNKNOWN 分开；source 与 sink 分开；一次 probe 消费点及同 meter authority |
| data tree / request index / retained Result | typed edge 与 SQL 语义不能丢成无来源 Corrupt；legacy global observer 不能重新误分类已处理的物理 expiry |
| `admit → AttemptContext → PublishGate → commit` | 同一原 context；失败消费 gate；原 ETag/CAS 不 rebase；移除或缩窄 PublishGate 的 blind Database::observe 必须以每条 commit 错误已经归属为前提 |
| `decode_retained_admission`、native finish | 物化失败保持原 receipt；语义错误保留来源；committed-unavailable 优先于任何 expiry 解释 |
| cold/session/query、warm Session | 新远端依赖 admission 与完全已物化 local image 分开；不增加 closing GET；不暗中扩大只读 quarantine |
| Activate / activate_session | 完整闭包/native/history、原 fresh equality barrier、原 CAS 都保留；错误调查不是成功激活 |
| named Complete / existing AbortFence / bootstrap | 同原创建身份；Provisioning exclusion 不保护已暂停 verifier；Absent 发布前仍 exact readback；foreign occupied 不是本 Scope 退休证据 |
| Catalogue authority/discovery | Name/Descriptor/Control/Proof 不属可回收 payload；不把这些 Missing 或错误 Scope 变成 expiry |
| RecoveryJob / RecoveryMeter | 调查读继续计 exact_gets/metadata_bytes 和原 job deadline；预算 origin 明确；pending Scope / image lease / final HEAD barrier 保留；未完成不增加 verified |
| future copy source / target closure | 独立且封闭的 plan capability。现有 Cursor::new 只允许 context.g 等于原 HEAD.active；不能修改 Snapshot.storage 来伪造 target authority。target 验证需原 plan 根集合和 target g 的真实构造器 |
| 错误投影与 SDK | core / service / HTTP / Catalogue / Recovery 全部显式映射，不能落入当前默认 Corrupt。未来 SNAPSHOT_EXPIRED 可保持 RemoteError 的 unresolved/request reference；绝不表示原写未提交或允许自动 SQL 重试 |

原计划的 source 仍 active 而坏，即使计划已 Abort 也必须失败为源故障。旧 target 退休后的失败可以局部 expiry；旧 target 的成功 bytes 也不能并入新计划验证集合。前者是失败作用域，后者是成功证据归属，两项都要实现。

## 6. 最小独立 refinement 场景

1. H1 原读取失败，probe UNKNOWN：原 attempt 不续 prefix/成功；clone 共享的 publication latch 保留。
2. 同 lineage 的全新只读尝试重新授权并完整验证成功，原 latch 不清；同 lineage 新写/管理发布仍受约束。
3. 同 worker H2 独立 handle 完成自己的 fresh HEAD 和完整读取，可以成功；这是必须实际可达的正例，不能用全局误阻断把负控制做绿。
4. 后端依赖持续缺失时，H2 也由自己的 GET 失败；独立 handle 不免除验证。
5. 原 g1 退休、H2 使用 g2：旧 attempt 仅凭自身失败后的同 Scope fresh proof 可 expiry，不能 poison g2；T2 Abort 后 A1/T3 与 old source A1 真坏分别覆盖。
6. 新 handle / worker 不能 adopt 原 UNKNOWN CAS、回写原 ACK、重绑原 context 或重跑原 SQL；允许新 lookup 独立证明原 receipt。所有已发 token 的原条件 backend delivery 保留。
7. 旧 handle 的 Session/image 不因新 handle 创建而更换归属；完全物化的原授权读跨 fence 返回的正例继续保留。
8. 错误 authority domain / 完整 Scope、坏 HEAD、只更高 serial、ACL 变化和 H2 成功，都不能清除 H1 的未知或 semantic/authority 状态。
9. Writer 已通过最后 healthy 检查后，同 lineage 另一操作设置 latch：仍允许原已 enabled PUT dispatch、按原条件 delivery；原 writer 的 ACK 只按自己的依赖、已知 CAS、native 和 caller/gate 条件判定。与“检查之前已有 latch，拒绝新的 publication”形成成对场景；失败/结束的原 attempt 不因此获得 ACK。

本 refinement 还须审查 `authority_corrupt` 的知识域，不能只修改 generation health。若首版不建模 warm cache、retained lookup 或 native image 语义，必须明列不涵盖的合同，不能从普通 raw read 的通过推导这些入口正确。

## 7. 后续验证与当前限制

未来生产 slice 的单位矩阵须包含判定表每一行、一次 probe 精确计数、0 次预算拒绝、原 deadline/backend/meter、同原失败 token 的 HEAD 绑定、并发两个 generation 的 incident 不互清、所有 publicly reachable 错误投影。实际合同还需暂停原 GET/PUT/CAS、迁移与回收之后释放、核对零 SQL replay、old/new handle 与缓存销毁后的知识域。

本次没有运行这些测试。没有提出 durable incident 协议；没有启用 production generation/DELETE；也没有把已验证的 raw closure 当成 native SQLite、跨进程健康封锁或 GC convergence 的证明。

## 8. 精确源码依据与验证范围

下表使用精确提交链接；文件哈希见本次 [静态设计审阅记录](../evidence/scoped-generation-design-review-2026-11-09.json)。闭包相关源引用已提交的前置切片，不能据此声称该切片与其他分支的组合已完成 workspace / actual 验收。

| 依据 | 对应边界 |
| --- | --- |
| [crates/scap-object/src/object_context.rs](https://github.com/ckanner/scap/blob/c516ceb1166bd1bf082da33697bef0ae074710e8/crates/scap-object/src/object_context.rs) | `with_raw/save/observe` 的原 backend、Scope、g、源错误与 visitor 错误 |
| [crates/scap-object/src/lib.rs](https://github.com/ckanner/scap/blob/c516ceb1166bd1bf082da33697bef0ae074710e8/crates/scap-object/src/lib.rs) | handle/clones quarantine、`healthy/admit/restore/decode_retained_admission/commit/finish`、PublishGate 与 Session；最后健康检查不与远端 PUT 原子化 |
| [crates/scap-object/src/closure.rs](https://github.com/ckanner/scap/blob/c516ceb1166bd1bf082da33697bef0ae074710e8/crates/scap-object/src/closure.rs) | 原 Snapshot、generation、deadline 与消费式 cursor；不能伪造 target authority |
| [crates/scap-object/src/object_frame.rs](https://github.com/ckanner/scap/blob/c516ceb1166bd1bf082da33697bef0ae074710e8/crates/scap-object/src/object_frame.rs)、[format.rs](https://github.com/ckanner/scap/blob/c516ceb1166bd1bf082da33697bef0ae074710e8/crates/scap-object/src/format.rs) | 共享 raw frame 校验、错误阶段，以及严格 storage 1/1 |
| [data_tree.rs](https://github.com/ckanner/scap/blob/c516ceb1166bd1bf082da33697bef0ae074710e8/crates/scap-object/src/data_tree.rs)、[request_index.rs](https://github.com/ckanner/scap/blob/c516ceb1166bd1bf082da33697bef0ae074710e8/crates/scap-object/src/request_index.rs) | typed edge / retained Request、序号和 SQL wire 语义 |
| [head_publication.rs](https://github.com/ckanner/scap/blob/c516ceb1166bd1bf082da33697bef0ae074710e8/crates/scap-object/src/head_publication.rs) | 原 Snapshot/ETag/deadline 的一次 publication；不提供取消既有请求的能力 |
| [catalogue/mod.rs](https://github.com/ckanner/scap/blob/c516ceb1166bd1bf082da33697bef0ae074710e8/crates/scap-object/src/catalogue/mod.rs)、[create.rs](https://github.com/ckanner/scap/blob/c516ceb1166bd1bf082da33697bef0ae074710e8/crates/scap-object/src/catalogue/create.rs) | 独立 handle、foreign occupied、Complete/bootstrap/AbortFence 和错误投影 |
| [catalogue/recovery_budget.rs](https://github.com/ckanner/scap/blob/c516ceb1166bd1bf082da33697bef0ae074710e8/crates/scap-object/src/catalogue/recovery_budget.rs)、[recovery_job.rs](https://github.com/ckanner/scap/blob/c516ceb1166bd1bf082da33697bef0ae074710e8/crates/scap-object/src/catalogue/recovery_job.rs) | 本次 allowance、原 job deadline、独立 recovery lineage 与 final barrier |
| [crates/scap-object-store/src/lib.rs](https://github.com/ckanner/scap/blob/c516ceb1166bd1bf082da33697bef0ae074710e8/crates/scap-object-store/src/lib.rs) | S3 response cap、`read_object/read_error` 和通用 NotFound 投影 |
| [crates/scap-service/src/lib.rs](https://github.com/ckanner/scap/blob/c516ceb1166bd1bf082da33697bef0ae074710e8/crates/scap-service/src/lib.rs)、[http.rs](https://github.com/ckanner/scap/blob/c516ceb1166bd1bf082da33697bef0ae074710e8/crates/scap-service/src/http.rs) | 显式 Failure / HTTP code 与 committed receipt |
| [sdk/node/src/errors.js](https://github.com/ckanner/scap/blob/c516ceb1166bd1bf082da33697bef0ae074710e8/sdk/node/src/errors.js)、[wire.js](https://github.com/ckanner/scap/blob/c516ceb1166bd1bf082da33697bef0ae074710e8/sdk/node/src/wire.js)、[transport.js](https://github.com/ckanner/scap/blob/c516ceb1166bd1bf082da33697bef0ae074710e8/sdk/node/src/transport.js) | unresolved / unknown / committed 区别、严格 wire code 和不自动重放 |
| [独立模型 README](https://github.com/ckanner/scap/blob/d158b44f18475038eee1a904af2cf0ba0722ecf4/experiments/object-reclamation-abortable-model/README.md)、[SCENARIOS](https://github.com/ckanner/scap/blob/d158b44f18475038eee1a904af2cf0ba0722ecf4/experiments/object-reclamation-abortable-model/SCENARIOS.md)、[model.py](https://github.com/ckanner/scap/blob/d158b44f18475038eee1a904af2cf0ba0722ecf4/experiments/object-reclamation-abortable-model/model.py) | 冻结程序中的退休/失败规则与共享 knowledge 抽象；本文指出的 refinement 尚未执行 |

原模型的结果只由其 [已有验证记录](https://github.com/ckanner/scap/blob/d158b44f18475038eee1a904af2cf0ba0722ecf4/docs/evidence/abortable-generation-model-local-2026-11-09.json) 描述。本文没有运行或修改 checker，没有把新知识域、最后 healthy 检查交错或未来生产接线追加到旧证明中。本文新增设计的可执行模型、生产单位、组合 workspace 与实际合同验证均为 **NOT_RUN**。
