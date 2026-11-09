# Owner 自动协调：最小 controller 与下一版可恢复协议

状态：owner controller / V2 owner-plan 协议为 **STATIC_DESIGN / NOT_RUN**。本文由已冻结的静态 handoff 整理而来；原 handoff 与 source inventory 保持不变。本文不把静态推导、既有 owner 验收或本片 guarded status 接线当作 controller 已实现或新协议已证明。

## 1. 实施决定与本片范围

**先交付 guarded probe，随后优先研究和实现 V2 accepted owner plan。当前不先投产可能永久停在 InspectOnly 的 V1 journal controller。**

1. 本仓库切片只实现现有 `status` 的可选 `expected_worker_instance`、`Client.guardedStatus` 和 `OwnerClient.probe`，合同见[guarded status](owner-guarded-status.md)。它不增加 controller、journal、HEAD 格式或新 endpoint。本片源码基线为 [`778a4d25dc186b3afc7958cbd522e5e0316703c8`](https://github.com/ckanner/scap/commit/778a4d25dc186b3afc7958cbd522e5e0316703c8)；编写本文时新增代码的 Node、Rust 和实际门禁均未运行。
2. 后续优先 V2：将不可变 intent 与 accepted phase 纳入 HEAD 权威状态，或采用不可变 descriptor + HEAD 绑定，让服务端按固定计划与当前 phase 幂等推进。先做独立模型，再完整接线和验收；旧 `OwnerClient.restoreIntent` 永远不能因此获得派发权。
3. §4–9 保留 V1 controller + S3 admission journal 的完整候选与成本比较，**不是当前实施承诺**。它可处理正常路径并保存重启后的知识，但部分 UNKNOWN 会永久阻止安全自动进展，不能完成全部自动恢复目标。

S3 journal 既不能把不可靠探测变成死亡证明，也不能填平旧 HTTP 的不确定窗口。§7 的完整 future-phase fence 区分未来不可能再生效与过去是否已生效；该区别对 V2 仍然必要。

## 2. 静态基线接口及限制

原静态设计基线为 [`f6c9073a924297f5cd1704fa3c677101ad451d3f`](https://github.com/ckanner/scap/commit/f6c9073a924297f5cd1704fa3c677101ad451d3f)。原 source inventory 绑定该提交的 23 个文件、280,085 字节；其身份清单和原 handoff hashes 记录在[静态设计证据](../evidence/owner-controller-design-review-2026-11-09.json)。下表描述该基线，不能当作本片新增 guard 之前之后均未变化的声明。

| 已有实现 | 当前实际合同 |
| --- | --- |
| [sdk/node/src/owner.js](https://github.com/ckanner/scap/blob/f6c9073a924297f5cd1704fa3c677101ad451d3f/sdk/node/src/owner.js) | `reconcile` 在第一次 status 之前消费一次性 intent；takeover 模式最多 takeover→activate，activate 模式最多 activate；每一步重新调用现有服务，只有精确匹配当前阶段结果才进入下一步 |
| [owner_intent.js](https://github.com/ckanner/scap/blob/f6c9073a924297f5cd1704fa3c677101ad451d3f/sdk/node/src/owner_intent.js) | prepare 产生新的内存派发资格；restore 永远是 inspect-only；base/target/nonces 不变；takeover 的 R+2 和 epoch+1、activation 的 R+1 都先检查 u64 上界 |
| [routed.js](https://github.com/ckanner/scap/blob/f6c9073a924297f5cd1704fa3c677101ad451d3f/sdk/node/src/routed.js) | fresh status 后最多一次原业务 POST；controller 不进入这个路径、不接收 SQL、不帮助重放 SQL |
| [route_registry.js](https://github.com/ckanner/scap/blob/f6c9073a924297f5cd1704fa3c677101ad451d3f/sdk/node/src/route_registry.js) | worker→endpoint 是本地受信白名单；registry digest 绑定 mutation routes，bootstrap 可以换成受信存活入口用于 inspect；禁止服务端 URL 指定 token 目的地 |
| [Database::control](https://github.com/ckanner/scap/blob/f6c9073a924297f5cd1704fa3c677101ad451d3f/crates/scap-object/src/lib.rs) | 管理 RPC 到达服务端后才 exact GET，检查当前 ADMIN 与 `expected_revision`；不是客户端已经捕获了一个 ETag |
| [Database::takeover / activate_session](https://github.com/ckanner/scap/blob/f6c9073a924297f5cd1704fa3c677101ad451d3f/crates/scap-object/src/lib.rs) | takeover 用本次原 ETag 增加 owner epoch、改 owner 并置 inactive；activation 完整恢复、校验 retained 结果、最终 exact HEAD 相等检查后按原 ETag 激活 |
| [service Action::expected_worker / Engine::execute](https://github.com/ckanner/scap/blob/f6c9073a924297f5cd1704fa3c677101ad451d3f/crates/scap-service/src/engine.rs) | 当前仅 takeover / activate 支持 guard；认证与 Scope admission 后、S3/cache/恢复之前检查实际 worker |
| [status / healthz](https://github.com/ckanner/scap/blob/f6c9073a924297f5cd1704fa3c677101ad451d3f/crates/scap-service/src/http.rs) | status 是 fresh READ 权限的 HEAD 元数据；没有实际响应 worker 的 guard。healthz 只是进程 liveness，不证明 owner、数据库、S3 或恢复可用 |

当前 `OwnerInspection.state` 是观察分类，不是“所有潜在阶段已关闭”的证明。特别是 `takeover_accepted`、`target_inactive`、`superseded` 不能直接作为自动清除 pending 的布尔值。

## 3. 独立小片：guarded status

### 3.1 Wire 与兼容行为

沿用 `POST /v1` 与现有 status 响应，只增加可选字段：

```json
{"operation":"status","expected_worker_instance":"42"}
```

完整请求仍包含原 `version` 和完整 `scope`。无字段的旧 status 继续按原行为工作。字段存在时必须为规范、非零 u64 decimal string；显式 null、0、非规范文本拒绝，沿用 `present_worker` 的规则。

guard 在当前 bearer / Scope admission 之后、任何 S3/cache/恢复效果之前判断。不匹配返回现有 `TARGET_MISMATCH`。成功响应仍是原 `DatabaseStatus`，不增加字段、不改变 READ 权限、不隐式授予 ADMIN。takeover / activate 的 guard 完全保留。

建议 SDK 增加而不重载旧 options：

```ts
Client.guardedStatus(workerInstance: Decimal, options?: CallOptions): Promise<DatabaseStatus>
OwnerClient.probe(workerInstance: Decimal, options?: CallOptions): Promise<DatabaseStatus>
```

`OwnerClient.probe` 只从 RouteRegistry 取得目标 endpoint，用一个 OperationBudget 派发一个 guarded status。它不 prepare intent，不恢复数据库，不返回 controller 的 failure ticket。普通 `status(options)`、`observe(options)`、OwnerIntent schema 和 restore 语义保持原样。

不新增 challenge 的首片依赖现有可信 TLS endpoint、禁止 redirect 的单次 POST 与服务端本次 exact GET。guard 成功证明实际服务实例与请求期望匹配；它不证明未来可达或数据面可用。若将来设计独立挑战/签名探测，要另列合同，不能从本方法推导出来。

### 3.2 精确 patch plan

| 范围 | 文件与改动 |
| --- | --- |
| Rust 生产 | `crates/scap-service/src/wire.rs`：Status 可选 guard、纳入 `expected_worker`；`engine.rs`：Status 匹配改成 `{ .. }`，复用原 guard 顺序 |
| Node 生产 | `sdk/node/src/client.js`：guardedStatus；`owner.js`：受信 route probe；`client.d.ts`：两方法声明 |
| Rust 单位 | `wire/tests.rs`：absent/null/0/非规范；`engine/tests.rs`：正确/错误 worker、认证先行、错误 guard 零 S3/cache；既有 Status literal 的兼容修改见下 |
| 既有 literal | `daemon/tests.rs`、`http/intake_tests.rs`、`scheduler/tests.rs` 增加 `expected_worker_instance: None`；resource-limits 已使用 `{ .. }` 匹配，无需修改；不改夹具预算或行为 |
| Node 单位/类型 | 对应 client / owner / declaration 测试：规范输入、未知 route、错误 worker、一次 POST、原总 deadline、无 mutation、旧 status 请求不变 |
| 文档与门禁 | Node README、coverage policy 如确有新模块才登记；现有生产模块按完整精确分母验收 |

本片在上述 778a4d2 基线的独立工作树接线；其他已冻结的源码与验证输入保持不变。此处给出代码范围，不宣称尚未运行的门禁已经通过。

## 4. Controller 的输入与故障策略（待实现）

首片只管理显式配置的有限 Scope 集合，不用 LIST 动态发现数据库。每个 Scope 固定 authority domain、READ+ADMIN principal、受信 bootstrap、worker routes、有向无环 failover 次序及资源预算。

自动 takeover 只允许目标 rank 严格高于当前 owner；健康 owner 不因偏好或负载回迁。当前 owner 不在 registry、无更高目标、身份不匹配、计数溢出、非 Ready lifecycle 时停止该 Scope 的自动 mutation。当前 owner inactive 且没有未关闭的旧 intent 时，允许按明确策略准备新的 activation-only；不为恢复同一 owner 再增加 epoch。

有限 registry 下，所有合规自动 takeover 的已接受 rank 严格增加，因此在没有人工反向迁移、身份复用或非法 registry 改写时，成功自动迁移最多 N−1 次。这个界限不保证探测准确，也不限制失误次数或总运行成本；后者由周期、并发和字节预算控制。人工管理可与 controller 竞争，但人工回迁不在这个 churn 证明中；维护流程应先暂停新自动派发，并单独处理既有 pending。

第一片 controller 使用一个固定、不可变的 registry/policy digest。不同配置的 controller 不能另开 journal 绕过同 Scope 的 pending。配置滚动追加、历史 route 还原、principal 变更和安全清理旧成员均需显式迁移流程；旧实例遇到未知 digest/owner 失败关闭。不要将“previous_digest 存在”当作所有存活实例已经切换或全局共识。

### 4.1 FailureObservation 只在内存中调度

每条观察固定 full Scope、完整 owner tuple、业务 revision、active/lifecycle、原 registry digest、候选目标和 monotonic 首末探测时间。进程重启丢弃观察窗口，从零开始，不从持久化 wall-clock 时间推导剩余租期。

| 事件 | 策略结果 |
| --- | --- |
| owner guarded status 成功，当前 tuple 仍相符 | owner 的控制路径可达；清除失败怀疑，不抢主 |
| fresh HEAD revision/owner/active/lifecycle 变化 | 旧窗口作废，重新观察；不能用旧窗口接管新 owner |
| owner 连接失败或 deadline，同时另一个受信入口可 fresh 读取同 Scope authority | 仅增加故障怀疑；满足次数与最短间隔后才可能准备新候选 |
| 401/403、TARGET_MISMATCH、未知 route、redirect/异常 wire | 配置、认证或协议问题；不累计为死亡证据 |
| 429、恢复忙或已知资源压力 | 有界 backoff；不因限流夺主 |
| authority 不可得、坏 HEAD、Scope 不同 | 失败关闭；不使用缓存 owner 权利、不新建 intent |
| 数据缺失/损坏、native InvalidImage | 保留损坏阻断；不靠更换 owner 掩盖问题 |

目标 worker 也要通过 guarded status，最终 takeover/activate 仍带 guard；探测和发送之间重启由最终 guard 拦住。目标探测成功不是恢复已完成，`active=true` 仍只能来自原完整 activation。

这种探测不能识别所有“数据 actor 挂住但 control status 正常”的故障，也不能区分进程死亡和网络分区。空闲无写不是故障，慢 SQL/长恢复不是死亡。首片不承诺“健康 owner 永不误接管”或无条件 RTO。

## 5. V1 比较方案：最小 S3 admission journal

### 5.1 责任与身份

跨重启保留一次性管理意图需要持久域；当前不假定本地盘可保留。建议每个 `(authority domain, full Scope)` 一个有界 S3 control object，共用已有 S3 的 exact GET / conditional PUT 合同。它位于单独受限的控制前缀，不在数据库 payload 世代中。

key **不按 controller、principal 或 registry 分裂**，避免换进程/配置就绕过旧 pending。body 绑定完整 Scope、principal、policy/registry digest、schema 和 checked monotonic record serial。只有可信 controller 的 journal IAM 可以修改此对象；HTTP principal 的当前 ADMIN 仍由数据库 HEAD 每次重新验证。journal 不授予数据库写权，不替代 HEAD CAS，也不提供租约。

建议 body 最多 64 KiB，至多一个 pending intent，加一个最近 closed summary；严格字段、重复键、decimal、完整 Scope、digest 与 body/ETag 校验。历史管理操作不是完整审计账本：旧记录被有界保留策略替换后，只能说未保留历史，不能把 past UNKNOWN 改为成功。需要永久管理历史的部署另接持久 audit；首片不为此无界增长 journal。

概念字段：

```text
schema, authority_domain, scope, principal, policy_digest, registry_digest
record_serial, next_nonce, mode = running | paused
pending = null | { issuer_boot_identity, exact_saved_intent, intent_digest }
last_closed = null | { intent_digest, past_effect_by_phase, future_effects,
                        closure_evidence, observed_status_identity }
```

counter 溢出、body 超限、journal 缺失/损坏/foreign、未知 schema/digest 均停止自动 mutation。nonce 从 journal 的 checked counter 分配，每个 takeover intent 占两个不同非零值，activation-only 占一个；并发只有 journal CAS 胜者使用其分配。这个分配约束只覆盖参与该 journal 的 controller，不能据此声称未受控的人工管理 nonce 永不碰撞。

daemon 不在 journal Missing 时自动重建。首次启用由显式初始化动作按 Absent 条件创建；运行中的 journal 不得删除、恢复到旧版本或用新 key 逃避 pending。初始化/丢失后的人工恢复不是通过一次 404 就能证明安全的自动操作。

### 5.2 派发资格不是 journal 里的 Sent 布尔位

只有**本次 prepare 得到的新 OwnerIntent**、本进程赢得该 pending 的条件写、并保持一次性本地资格时，才能调用一次 `OwnerClient.reconcile`。保存的是原 `saveIntent` 字节；派发前 exact 读回并校验原记录的完整 bytes/身份与非空 ETag。这个 GET 只验证持久记录，不能单独产生派发权。其他 controller 或重启后的进程读取同一记录，只取得描述与 inspect 能力。

不能用 `sent=false`、超时、issuer 不可达或 journal TTL 推断从未发送。写“sent”前后都有崩溃窗口。journal 原 ETag CAS 与数据 HEAD CAS 不组成跨对象事务，原 pending 可能在 issuer 崩溃后永久停住；这是首片明确接受的边界。

journal reserve 的结果 Unknown 时，首片不派发 owner RPC。原进程若还能证明自己从未进入管理派发，并先不可逆销毁该次本地资格，可以按条件写记录 not-sent；若它先崩溃，其他进程不能继承这个内存事实。任何 journal CAS 自身 Unknown 都保留原条件/原 bytes，不无条件覆盖、删除或重置记录。

journal 的写入只发生在初始化、reserve 和结果/闭合记录；每次增加 checked record_serial 防止该对象自身 ABA，正常健康探测不写 S3 心跳。record_serial 不等于数据库 business revision，也不能 fence 数据库 RPC。即使 controller 的 journal reserve 已通过，现有 OwnerClient 仍做原 base preflight，服务端仍重新鉴权并用本次 original ETag。

## 6. V1 controller 状态机

| 状态 | 允许动作 | 下一步 |
| --- | --- | --- |
| `Boot / ReadJournal` | strict exact journal GET；fresh authority；丢弃所有旧探测时间 | pending→InspectOnly；无 pending→Observe；缺失/损坏/未知配置→Blocked |
| `Observe` | guarded owner probe，更新有限内存观察 | 健康保持；inactive 且无旧 obligation 按策略准备 activation；失败进入 Suspect |
| `Suspect` | bounded probe、fresh authority、较高 rank 目标探测 | 窗口失效则清除；达到策略且目标合格→PrepareFresh |
| `PrepareFresh` | 固定当前 status、target、两阶段 nonce；保存完整 intent；固定本次总 deadline | 不再改变 base/target/nonces；进入 CASReserve |
| `CASReserve` | 用原 journal ETag 一次条件写 pending，确认持久 | 胜者保留新鲜本地资格；Conflict 读赢家；Unknown 不派发 |
| `DispatchOnce` | 一次 `OwnerClient.reconcile`，使用剩余总预算 | 完整结果→RecordOutcome；其他结果保存原 intent/lastConfirmed 并进入 InspectOnly/Blocked |
| `InspectOnly` | restore 原 intent；仅 fresh inspect；计算完整 future-phase fence | 未闭合继续有界 inspect；闭合后可条件记录 closed；永不 reconcile(restored) |
| `RecordOutcome / Closed` | 保留 past/future 两种知识；原 journal ETag 条件写 | 确证闭合后重新建立新的观察窗口；不沿用旧失败窗口换 nonce 重试 |
| `Blocked / Paused` | 只读诊断、明确理由；其他 Scope 仍可继续 | 人工修复/决策或严格新证据；不自动换 scope、credential destination 或 journal key |

同一进程对同 Scope 至多一个 in-flight tick；多个进程依靠同一个 journal CAS 竞争新派发资格。失败方不会加入赢家的 HTTP 调用，也不会重建赢家的 OwnerIntent。恢复得到的同一个 pending 无论 issuer_boot_identity 是否恰好相同，都不恢复资格。

future-phase fence 成立后关闭 journal，不等于远程撤销旧 issuer 的内存资格。暂停的旧进程仍可能醒来派发它原来最多两个 RPC；安全性来自这些 RPC 的固定条件已经永久关闭。不能把 journal close 事件当作“此后再也没有旧 POST”或“旧 S3 请求已取消”的证据。

停止 controller/AbortSignal 只终止本地等待，不能清除 pending、返还已发恢复工作或撤销服务端 Job/S3 token。旧服务仍遵守现有 per-db actor、recovery permit 与原 deadline。控制器不执行 SQL、不替换业务 request，不会因为 route/owner 错误重发业务操作。

## 7. 哪些 UNKNOWN 可以继续：完整 phase-fence 证明

### 7.1 固定意图的所有未来分支

设已保存的合法意图 base business revision 为 R。由当前 `owner_intent.js::normalize/expected` 与 `owner.js::reconcile`：

| mode | 可能派发的管理 RPC | 固定输入 |
| --- | --- | --- |
| activation-only | activate，最多一次 | expected_revision=R，activate_nonce 固定，guard=原 target |
| takeover | takeover，最多一次 | expected_revision=R，takeover_nonce 固定，guard=原 target |
| takeover | 只有第一步收到精确候选结果且预算仍允许，才 activate，最多一次 | expected_revision=R+1，activate_nonce 固定且不同，guard=同原 target |

reconcile 没有第三阶段，没有刷新 base 的循环，也没有把最新 status 的 revision 代入原 intent。restore 丢弃派发权。因此 takeover 意图在所有未来分支中，能派发的 expected_revision 集合最多是 `{R, R+1}`；activation-only 只能是 `{R}`。即使旧进程在第一阶段响应后暂停，后续分支也不能超过这个集合。

R+1/R+2 采用 checked u64 算术。原 normalize 已拒绝不能表达完整候选的 intent；controller/journal 恢复验证也必须独立拒绝越界或非规范 descriptor。不能 wrap、saturate 或把超限当作已经关闭。takeover 同时需要 owner_epoch+1 可表示。

### 7.2 为何必须看 business revision

服务端 `control` 在收到 HTTP 后 fresh GET，然后检查 `head.revision == expected_revision`。一个只使 `head_serial` 增加的技术 CAS，虽然能拒绝**已经捕获旧 ETag 的 S3 PUT**，却不能拒绝尚未 server-admit 的旧 HTTP：该 HTTP 到达后仍可读取新的 ETag，并发现同一个 business revision。

因此客户端整个 intent 的保守永久关闭谓词是：

```text
fresh status 的完整 Scope 与原 intent 相同
HEAD 业务 revision 单调、不回滚、不复用且溢出失败关闭
activation-only: current.revision >= checked(R + 1)
takeover+activate: current.revision >= checked(R + 2)
```

对尚未 admit 的 RPC，上述条件使所有固定 expected_revision 永久不相等。对已经 admit 的 candidate，后继 HEAD 的 no-ABA 条件变化拒绝其原 ETag PUT。已返回的旧 takeover HTTP 响应即便后来才交付，最多使旧进程派发 expected_revision=R+1 的 activation，仍被同一判据关闭。

nonce 用于识别候选结果，不是服务端 admission 的 fence；guard 防止打错实际 worker，也不是旧实例在途请求的撤销。当前 Denied、worker 不可达、owner 不同、body 里的 last transition 不同，都不能单独替代这个完整 revision 证明。首片不使用更复杂的 owner/lifecycle 推导优化。

### 7.3 结果矩阵

| 已知情况 | 自动行为 | 能报告的知识 |
| --- | --- | --- |
| 本进程完整 reconcile 返回精确 active 结果 | 条件保存 closed；后续重新 Observe | 原调用确认的阶段结果；不存在这个调用的新阶段 |
| 本进程明确尚未派发任何管理 RPC，并先不可逆销毁本地资格 | 可保存 not-sent；以后重新建立观察 | 仅该调用没有管理效果，不推断其他 controller/人工动作 |
| restored / Unknown，fresh HEAD 仍是 R | 只 inspect；可无限停住 | 旧 takeover/activate 可能尚未 admit 或迟到；不是未发送 |
| takeover intent，fresh HEAD 为 R+1 且精确 takeover_accepted/target_inactive | 仍只 inspect；不新建 activation 绕过旧 intent | claim 可已生效，旧 activate(R+1) 仍可能派发/在途 |
| 完整 future-phase fence 成立，但最后 transition 已被覆盖 | 可关闭 future obligation，再建立新的观察/intent | **futureEffects=closed，pastEffect 仍可能 UNKNOWN**；不是 NotApplied，也不补旧 ACK |
| fence 成立且 current owner inactive | 新的独立 activation-only 可以按新 status/nonce 准备 | 新 intent 使用新 base；原两个阶段已经不能再生效 |
| authority/journal 不可得、坏 Scope/格式、counter 溢出 | 停止 mutation | 未证明闭合，不因普通 authority 失败恢复健康 |
| partial/unresolved/error code，不能从当前公开结果证明整次调用无未来效果 | 首片保守进入 inspect/人工处理 | 不把一个通用 RemoteError、partial 标签或本地超时当成全阶段 NotApplied |

如果仅有 R+1 且原 activation 未产生效果、issuer 又已经消失，V1 可以永久卡住。即使探测证明进程现在不可达，也不能撤销尚在传输中的请求。人工可以使用独立显式管理操作作出新决策；controller 自身仍保存旧 UNKNOWN，直到完整条件满足。不能把人工决策描述成旧 intent 被恢复派发。

## 8. 资源、认证、配置和历史边界

每个 passive tick 有自己的短绝对 deadline；一次实际 effect attempt 从最终观察/保存开始持有一个总 deadline，journal I/O、OwnerClient preflight、takeover、恢复/activation 都使用其剩余时间。进入 recovery 不重新发放预算。后续 inspect 是独立只读操作，不延长原 mutation 的 deadline。

明确配置 managed Scopes、每租户/全局活跃 tick、并发 probe、并发 reconcile、journal bytes、响应 bytes、探测频率和 backoff 上限。固定 registry 最多复用现有 256 routes；不持锁跨 I/O。控制器本地限额不是整个 fleet 的全局限额；S3 journal 保证每 Scope 一条自动 pending，服务的 actor/recovery 池继续约束真实工作。HTTP 结束不提前归还实际后台 permit。

S3 journal 凭据只用于受限控制前缀；服务 token 只到受信配置 endpoint。两者不能互相冒充授权。S3 adapter 必须严格限制一次物理尝试、redirect/region redirect、响应 cap、AbortSignal 和 absolute deadline；不能假定 SDK 默认 retry 适合条件写。journal CAS Unknown 不伪造 absent/NotApplied。

首片固定 principal 与 policy/registry 配置。相同 principal 的凭据轮换可走已有认证配置；变更 principal/route map 不能因 restore 检查失败就重建 intent。若原 registry 仍作为受信历史配置存在，可以用新的可信 bootstrap inspect；不能采用 journal 内未经配置验证的 URL。

原 HEAD 管理 transition 不是完整历史账本。这个 admission journal 也只保留有界历史。exact candidate observation、当前 owner 状态、过去某个 HTTP 的结果和未来效果是否关闭，分别报告，不混成一个 success 布尔值。

## 9. V1 可落地模块与接口（记录成本，不先投产）

建议 controller 保持可选，不把 S3 signing 依赖塞入所有普通 Node 客户端。核心 reducer / driver 复用正式 OwnerClient；可运行 CLI 必须同时交付真实 S3 journal adapter，不能只留下外部 adapter interface 就宣称完成。

```ts
interface OwnerJournal {
  read(options: CallOptions): Promise<JournalSnapshot>; // bounded exact bytes + nonempty ETag
  compareAndSet(original: JournalSnapshot, exactNextBytes: Uint8Array,
                options: CallOptions): Promise<'applied' | 'conflict' | 'unknown'>;
}
class OwnerController {
  tick(options?: CallOptions): Promise<ControllerReport>;
  run(options: { signal: AbortSignal }): Promise<void>;
}
```

JournalSnapshot、phase-fence 证据、派发资格是模块内部的封闭类型；调用者不能通过构造对象恢复资格。所有 journal 条件写使用原 snapshot 的 ETag 与固定 bytes。`init` 是显式安装动作；`run` 遇到 Missing 只停住。`inspect` 始终只读；不提供伪装成恢复的 `force/resume-old-intent` 开关。

| 文件组 | 预计范围 |
| --- | --- |
| `sdk/node/src/owner_controller.js`、`owner_controller_state.js`、`owner_journal.js`（新） | 有限状态/纯判据、单次 driver、有界 journal codec；不导入 SQL 路由作为失败重试 |
| `sdk/node/src/client.d.ts` 与可选导出 | ControllerReport、journal adapter 合同；旧 OwnerClient/Intent schema 不变 |
| `tools/owner-controller/{package.json,src/s3_journal.js,src/cli.js,README.md}`（新） | 真正的 S3 adapter 与显式 init/run/inspect；复用成熟 signing 库，版本/lock/重试与传输边界在实现前单独固定 |
| Node 单位/类型/coverage | 每个新生产模块正常进入独立 V8 分母；不以 CLI smoke 或真实网络 profile 代替单位 |
| `experiments/object-owner-controller/`（新） | 多 controller、journal 条件历史、真实旧 HTTP/S3 切点、独立 oracle 与 mutation controls |
| docs | 与既有 owner-reconciliation 明确区分：guarded probe、V1 journal controller、V2 recoverable plan |

这约为 5 个新生产 JS 模块，加 guarded status 的 4 个现有 JS/Rust 生产模块及 types。实际行数、依赖版本与验收时长要在 root 选择基线/实现方案后冻结，不用未经实现的估算冒充门禁。

## 10. 下一版：真正跨重启继续同一管理计划

### 10.1 为什么 journal 不能替代计划绑定

目前 server 只收到 expected_revision、nonce 和 target guard，不知道客户端完整两阶段计划，也没有 durable phase 记录。即使 journal 记着 pending，服务端也不会据此拒绝已取消的旧 HTTP 或帮助恢复该阶段。只给 journal 增加更多本地 Sent/TTL 标记无法补足这条权威缺口。

下一版必须是明确的新协议，例如 `OwnerPlanClient` / server `prepare_owner_plan`、`resume_owner_plan`、`abort_owner_plan`、`inspect_owner_plan`。旧 OwnerClient 的 restored intent 仍不能 reconcile；不能把新协议的恢复能力注入其 WeakMap。

### 10.2 两种权威布局

| 布局 | 优点与成本 |
| --- | --- |
| HEAD 内联一个有界 OwnerPlan + phase | 每次 exact GET 直接发现计划；增加 HEAD 格式、最大长度与所有构造器的不变式；历史结果仍需独立保留规则 |
| 不可变 OwnerDescriptor + HEAD 的 plan hash/identity/phase 绑定 | 复用 catalogue 的 first-persisted-input、冲突检测、控制意图/权威绑定模式；HEAD 保持较小，新增 exact descriptor/proof GET/PUT、身份闭合和元数据预算 |

建议优先研究第二种。descriptor 单独存在不是 ownership 或被接受的计划；只有 HEAD 引用的计划/phase 才具有权威。原 `catalogue::prepare/precheck_control/control_exists` 和 Name/HEAD deletion marker 可借鉴，但不能直接假定其创建/删除证明已经证明 owner 协调。

### 10.3 最小协议状态与身份

不可变 descriptor 固定：完整 Scope、principal/operation identity、目标 worker、模式、原 admission 的 business revision/head_serial/owner tuple、原 HEAD ETag 加 canonical Head value hash、固定阶段 nonce、输入 digest。ETag 与 Head 必须来自同一次 exact GET；恢复 claim 时需要同一完整 base，而不是仅相同 business revision。相同 operation identity 改输入必须 Conflict；第一次持久化的输入胜出，不能恢复时采用新的 base 或默认值。descriptor 的 ETag 字段和总 bytes 也需要明确上限，不能直接复用 catalogue record 上限而未重算。

HEAD 保存有界 plan identity/hash、单调 plan/phase identity、`claimed` / `active` / `aborted` 等状态，以及足以构造稳定终态证明的 phase revision。具体字段和新格式版本必须由独立设计/大小证明决定；当前 HEAD5 不能提前接受。

一个最小 takeover 计划可按如下逻辑前进：

1. prepare 持久化并 exact 读回不可变 descriptor；无 ownership 效果。
2. claim 在固定 admission 条件上原 ETag CAS，同时绑定 plan、增加 owner epoch、设目标 owner 且 inactive。旧 CAS 的 body/condition 不被修改。
3. resume 读取 fresh HEAD 与原 descriptor。只有同一 accepted plan、允许的 predecessor phase、目标 worker guard 和当前权限全部匹配，才恢复完整数据并准备一个 activation step。最后 exact HEAD/CAS、native 与资源合同全部保留。
4. phase 已是 active 时，resume 返回同一个计划的已接受进度，不再次增加 epoch 或重做 SQL。
5. 当前 ADMIN 可显式 abort 尚未完成的计划。abort 与迟到 activation 在同一 HEAD 上排序；已 terminal 的计划不能重新进入 pending。目标进程重启后使用新 worker identity，不能用新实例冒充原 target；应终结旧计划再准备新目标计划。

每个具体 step 仍固定本次原 Snapshot、ETag、body 和 deadline。新 `resume` 是服务端计划状态机允许的幂等进度：若 predecessor phase 仍存在，服务器必须按完整计划规则构造合法下一步，并保留 fresh ACL/quota/roots；不能直接把一个旧 candidate 的 ETag 换成最新值。相同 base 的重复尝试可采用同一候选/条件；若 metadata 已变化，必须证明旧具体 candidate 已被 fence，重新验证当前 phase 的全部条件，才能建立新的 step attempt。这需要模型明确定义，不能用“管理操作可重试”一句话带过。

### 10.4 能关闭 legacy revision 之外的旧 HTTP

新 wire 操作携带 plan identity 与 expected predecessor phase。迟到、尚未 server-admit 的旧 HTTP 也必须 fresh 检查该计划是否仍允许推进；计划已经 aborted/terminal/superseded 时，不得重新 admission。已经 admit 的原 CAS 仍仅按原 ETag 生效。

因此 resume/abort 可以在无本地持久状态的进程中重新调用同一个计划，得到已接受 phase 或推进它。这里依靠的是 HEAD 的 durable phase 合同，而不是本地 lease、restore 派发权或只增加 head_serial。

所有旧 takeover/activate 入口、普通管理构造器、Delete/maintenance/named 操作必须显式决定遇到 pending plan 的行为。旧 RPC 不能绕过 plan guard；ACL 撤回不能被 plan 锁住，也不能被 activation 恢复成旧 ACL。允许的 metadata 更新保留 plan 状态；不允许的变更明确拒绝或通过正式 abort/supersede。旧 SQL/native attempt 仍使用原 CAS，不归新计划重跑。

### 10.5 终态历史与发现

仅保存“当前 plan”会在后继计划覆盖后丢失旧进度。若要求跨任意后续变化仍能证明原管理操作结果，需要不可变 terminal proof 或有界、明示的保留窗口。

可借鉴 catalogue：在覆盖旧 terminal plan 引用前，先持久化并 exact 验证其稳定终态 proof；proof 的身份来自 plan/phase 固定字段，不从某次任意较晚的 SQL revision 拼出不同候选。proof PUT Unknown 时不覆盖引用，直到 exact 读回得到匹配 proof。相反，普通数据/ACL更新应保留当前 plan/terminal marker，不能抹去尚未证明的管理历史。

这会增加不可变控制元数据及其保留成本。没有保留 proof 时，只能报告 superseded/历史未知，不能声称完整管理账本。无论采用何种历史策略，旧 caller 的 UNKNOWN 响应不会被追溯改成当时收到了 ACK。

### 10.6 新协议的必要独立门禁

至少独立建模：prepare/claim Unknown 与重启；两个 resume 同 phase；旧 HTTP 在 abort 后才 admit；原 S3 PUT 在 abort 前后 delivery；ACL 更新/撤回；目标 worker 重启；legacy 入口与 pending plan；proof Unknown 与后继计划；相同 ID 改参数；计数耗尽；已 accepted phase 不回退；所有写保留原条件。

生产需要新格式/最大 HEAD 编码证明、全部构造器与 admission gates、current authority/worker/phase 验证、完整恢复/最终 barrier、错误与 SDK 映射、资源上限及真实网络门禁。它应采用新的 API 类型与明确版本，不能作为 V1 journal controller 的小修补发布。

可落地的边界是新 `crates/scap-object/src/owner_plan.rs` 中的封闭 planner/resume/abort；`format.rs` 与 `head_publication.rs` 定义严格 HEAD plan 状态和合法 delta；`lib.rs` 及 catalogue 的所有 HEAD 构造路径处理 pending/terminal 计划。service 的 wire/engine/scheduler/http 接入新的只读控制与恢复步骤；Node 新 `owner_plan.js`/wire/types 提供新 API。另建独立 owner-plan 模型、真实网络夹具和 oracle。原 OwnerClient 文件只记录与新 API 的区别，不放宽其派发权。

这片不自动接受 storage generation/pin/freeze 等状态。将来与 N3 协议组合时，owner-plan admission、abort 和 activation 仍要服从该版本的完整存储准入合同，不能从这个独立 owner 设计推导组合安全。

## 11. 确定性合同与反例清单

以下均为待实现验收，**本次 NOT_RUN**：

| 场景 | 必须区分/证明 |
| --- | --- |
| 长期空闲 owner、guarded probe 正常 | 零自动 takeover；没有 S3 heartbeat 写 |
| 两个 controller 同 Scope 同 base | journal 只有一个 fresh issuer；失败者没有管理 POST；最终 owner 仍由 HEAD CAS 决定 |
| 目标 endpoint 换成新 worker | guarded status 与 mutation 均在 S3/cache 前拒绝；不向新 URL 自动发 token |
| reserve 写已接受、响应丢失 / issuer 在派发前崩溃 | 无恢复派发；base 不动可以永久 inspect，不能以 sent=false 解锁 |
| takeover 已接受但 HTTP 响应丢失 | R+1 不足以关闭整个 intent；不自动新建 activation |
| 旧 HTTP 尚未 server-admit，先做 head_serial++ | 原 expected_revision 仍可能通过；必须保留这个反例 |
| 旧 activation 预期 R+1 被暂停，HEAD 到 R+2 | 释放旧 HTTP/原 PUT 均不能新生效；原历史效果仍可 UNKNOWN |
| fence 后 last transition 已被其他管理覆盖 | future closed 与 past unknown 分开；不伪造原 nonce 结果 |
| overflow / Scope / lifecycle / auth / journal 损坏 | 无 mutation；不 wrap、不切换 journal key、不借缓存权限 |
| 网络分区、多目标、忙/限流、S3全不可用 | 只在允许策略下严格增加 rank；顶端耗尽停住；401/403/429 不当死亡 |
| 断连后实际恢复仍运行 | 不提前释放服务端 permit；controller 不把超时当停止，也不 replay SQL |
| V2 resume/abort/terminal proof | 另建独立分母，不能计入 V1 或旧 owner fixture 的通过 |

独立 oracle 必须记录原 intent 字节、journal 的 exact body/ETag/条件历史、每个真实管理 HTTP、原 HEAD GET/conditional PUT、实际 phase/nonces/worker guard、原 SQL 请求计数和进程退出。负控制至少包含 restore 解锁、新 nonce 绕过 pending、technical serial 误作完整 fence、R+1 清除 takeover intent、future closed 误报 NotApplied、错误 endpoint 转发 token、过早归还后台 permit。

## 12. 已选择的实施顺序与不能宣称的完成项

先交付并验证本片 guarded status，随后优先投入 V2 accepted owner-plan 独立模型与完整协议。当前不投产 V1 journal controller；其设计保留为比较和 future-phase fence 的边界论证。模型与静态方案不等于生产自动恢复。

如果以后另行决定完整交付 V1，且其全部门禁通过，才可以宣称：有明确故障策略的自动正常路径、同 Scope journal 协调、重启后不重复派发、严格有界 inspect 和完整 phase-fence。不能宣称：所有 UNKNOWN 自行恢复、完整管理历史、无条件 RTO、全局 controller 共识、精确故障检测或全部自动恢复目标已完成。

V2 只有在独立协议、全部生产消费者和真实门禁完成后，才可以宣称“相同 accepted owner plan 可跨进程重启继续幂等进度”。普通业务 SQL 的 UNKNOWN 仍走原 request lookup/cancel，永不因为 owner controller 的存在而自动重放。
