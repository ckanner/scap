# Owner 路由、故障观察与接管协调

## 1. 状态、范围与决定

本文包含当前 SDK 实现切片和后续完整设计，**不是整体能力已验收声明**。
`RoutedClient`、`OwnerClient`、固定 `OwnerIntent` 及现有 takeover/activate 的可选目标 worker
guard 已有实现；使用方法与精确范围见[Node SDK](../../sdk/node/README.md)。本文其余的
服务端 `OwnerRegistry`、`FailureObservation`、`/v1/owner`、服务端去重与自动 controller
仍是后续方案，不把它们计入 SDK 切片的完成范围。
不恢复交接文档中未公开的本地提交，也不把旧候选的测试结果用于本方案。

最小完整工作包分成三层，分别实现、分别验收：

| 层次 | 责任 | 不具有的权力 |
| --- | --- | --- |
| 静态 owner 路由 | fresh HEAD 查当前 owner，将新请求交给受信注册的 endpoint | 不凭路由表授予写权，不改变 owner |
| 显式 reconcile | 当前有 ADMIN 权限的协调者，根据固定观察与转换身份完成一次接管及恢复激活 | 不重放 SQL，不把失败或超时当作接管成功 |
| 可选自动 controller | 按有界探测和单向 failover policy 触发同一个 reconcile 协议 | 不创建另一套 fencing，不保证准确区分故障与网络分区 |

第一、二层可以保持现有持久 HEAD 格式。第三层必须有单独的启用配置和故障合同；
只实现 `reconcile` 接口不能宣称已经实现无人值守的自动故障检测。
这份工作包也不替代 N2 的恢复风暴、冷热负载和生产 SLO 验收。

当前实现切片限定为 **Node SDK 的受信静态路由，以及基于现有 `status`、
`takeover`、`activate` 的显式、可保存意图协调**。该切片要求协调凭据明确具备
READ+ADMIN，增加原管理 Action 的可选 `expected_worker_instance` guard，不新增服务端路径、自动探测或自动接管。下文的 ADMIN-only 观察、
`/v1/owner`、服务端去重与自动 controller 是之后的扩展设计，不是首个切片的前置条件。

## 2. 已有源码与可复用合同

| 现有能力 | 实际位置 | 对新方案的约束 |
| --- | --- | --- |
| `Database::status` | [core](../../crates/scap-object/src/lib.rs) | exact GET 解码 HEAD，要求当前 READ；返回 Head，不返回 ETag |
| HTTP `status` | [wire](../../crates/scap-service/src/wire.rs) | 已返回 `owner_instance`、`owner_epoch`、`active`、`revision`、`transition`、scope；不泄露完整 policy 或对象凭据 |
| `Database::takeover` | [core](../../crates/scap-object/src/lib.rs) | 当前 ADMIN、精确 `expected_revision`；用同次 GET 的 ETag CAS，增加 owner epoch，置 `active=false` |
| `activate_session` | [core](../../crates/scap-object/src/lib.rs) | 本 worker 必须是未激活 owner；完整恢复数据及保留结果，再 exact GET 复核原 HEAD/ETag，CAS 激活并保留新 Session |
| 每次 SQL 重新准入 | [Session](../../crates/scap-object/src/lib.rs) | 缓存和路由不能替代 fresh HEAD、当前权限、数据根及 owner 检查 |
| 每库 actor 与独立 control pool | [scheduler](../../crates/scap-service/src/scheduler.rs)、[Engine](../../crates/scap-service/src/engine.rs) | 冷恢复在对应库 actor 执行，不能堵住别的热库，也不能搬进控制线程做整库恢复 |
| Bearer 准入 | [auth](../../crates/scap-service/src/auth.rs) | 可信 principal 来自 token 映射，客户端字段不能指定或冒充协调主体 |
| 固定业务身份与单次运输 | [Node Client](../../sdk/node/src/client.js)、[Transport](../../sdk/node/src/transport.js) | `prepare/save` 固定原 SQL、参数和 request；原 Client 不自动重试或跟随 HTTP redirect |
| `GET /healthz` | [HTTP](../../crates/scap-service/src/http.rs) | 仅进程 liveness，不证明某个 owner、S3、恢复或数据库可用 |

现有 `status` 已足够给 READ 主体做路由发现，因此首版无需向业务客户端公开 ETag。
协调者可能只有 ADMIN 而没有 READ；应新增仅返回 owner 元数据的
`Database::observe_owner`，按当前 ADMIN 鉴权，不能暗中给协调者补 READ 权限。
另一种部署选择是明确授予 READ+ADMIN；这必须是管理员的 ACL 配置，不是隐式提权。

现有新实例必须使用新的 `worker_instance`，见[服务说明](../../crates/scap-service/README.md)。
endpoint 地址相同不代表仍是同一个计算实例，重启不能复用旧 owner 身份。

## 3. 静态 registry 只负责地址与调度

拟新增可选 `owner` 配置，缺失时保持现有显式接口行为。
以下是候选字段，不是当前可用配置：

| 字段 | 语义 |
| --- | --- |
| `schema_version` | registry 配置结构版本 |
| `registry_revision` / `registry_digest` | 运维配置身份及规范内容摘要；不是 HEAD revision |
| `previous_digest` | 滚动升级时用于验证上一版配置，不能单独充当远端控制权证明 |
| `members[].worker_instance` | 唯一、不可复用的计算启动身份 |
| `members[].route_id` | 有界的 opaque 路由名；SDK 只映射预先允许的 route |
| `members[].api_endpoint` / `owner_endpoint` | 固定数据与协调 API 地址 |
| `members[].failover_rank` | 可选自动策略中的单调次序；不改变 worker 身份本身的含义 |
| `coordination_domains[]` | 明确的 deployment、tenant、协调 principal 与允许的目标 worker |
| `automatic_failover` | 默认关闭，启用须满足第 10 节额外合同 |
| `probe_timeout_ms`、`observation_min_ms`、`required_failed_probes` | 故障怀疑策略，不能作为租约或写权 |
| `max_observations`、`max_observation_bytes`、全局/租户恢复额度 | 独立、显式的资源边界 |

Registry 可回答“owner 42 在哪个 endpoint”，不能回答“42 已经失去写权”。
未知 owner 返回 `UNROUTABLE`，不能自动选择当前收到请求的节点夺主。
`active=false` 表示未激活或恢复中，也不能据此推断那个进程已死亡。

Registry 必须拒绝重复 worker、重复 route、循环或倒退的自动 failover 关系、
不合法 URL、凭据嵌入 URL、超限条目和相互矛盾的 local worker 配置。
静态配置变更不改变任何数据库的 owner；迁移仍通过 HEAD CAS。

### Endpoint 信任

- SDK 使用预配置的 `route_id/worker_instance → endpoint` 白名单，不把服务器任意返回的 URL 当作可携带 token 的目的地。
- 生产 peer 流量使用受信 TLS endpoint；沿用现有显式 HTTP 开关，不能因为接管而降级安全传输。
- peer client 禁止 redirect、自动 POST 重试和无界响应；ambient proxy 的使用须显式配置，不能偷偷扩大凭据目的地。
- probe 返回实际 `worker_instance` 并回显一次性 challenge。地址被新进程接管时，旧 worker 身份不匹配是“该 route 不能证明旧 owner 活着”，不是授权绕过 HEAD。
- endpoint 身份或授权不匹配属于配置/认证错误。不得把 401/403 当成可自动夺主的故障证据。

## 4. 业务自动路由：只发送一次 SQL

当前 SDK 提供可选 `RoutedClient`，保留原 `Client` 的单次直接调用合同。
它复用原来的 `prepare/save/restore`、request fingerprint、结果 decoder 与错误类型。

一次 routed `execute` 的顺序：

1. 在调用开始时固定总 deadline；校验并保留原 prepared request。
2. 向受信 bootstrap endpoint 调用现有 `status`，读取 fresh HEAD 的 owner 元数据。
3. scope 必须完全一致，lifecycle 必须允许该操作；只有已注册且 `active=true` 的 owner 才是此次写入目标。
4. 用剩余时间向该 endpoint 发送原 request，最多一次业务 `execute` POST。
5. 目标仍执行全部现有 native/core 准入和 HEAD 条件发布；路由观察不授予任何 SQL 权限。

查询可选择 owner 路由以复用热缓存，但强读正确性仍来自目标端 fresh HEAD。
`lookup`、`cancel` 和元数据查询可在任一有权访问同一 authority 的受信服务执行，
无需等待 owner 恢复。管理员主动迁移的目标不能被 routed client 改写为旧 owner。

route 到 execute 之间发生接管是合法竞争。收到 `FENCED`、`STALE_SNAPSHOT`、
`CONFLICT` 或 transport UNKNOWN 后，不换 endpoint 重发 SQL。
客户端保留原 scope/request/fingerprint，按现有 `lookup/cancel` 协议处理。
路由发现失败且尚未派发业务请求时，可以明确报告本次未发送 SQL；
业务 POST 已派发后的异常继续保留现有 UNKNOWN 语义。

一次 routed 调用可以包含元数据 POST 与一个业务 POST，不能继续宣称其总共只发一个 POST。
无论内部几步，都不能给每一步重新发放完整 `timeoutMs`。

## 5. 观察不等于租约，不等于接管

使用名称 `FailureObservation`，避免将故障怀疑误称为写租约。
观察由受权协调入口在服务端建立；客户端不能提交一个时间戳就宣称 owner 超时。
时长使用本进程的 monotonic clock，时钟只控制等待和调度。

观察至少绑定：

```text
coordinator_instance
registry_digest
scope
observed_revision
observed_owner_epoch
observed_owner_instance
target_worker_instance
observation_id
first_failed_probe_at / last_probe_at
failed_probe_count
```

服务端同时保留 exact GET 的 HEAD 身份和 ETag，或等价的不可变、受限内部观察对象。
业务客户端不需要得到 ETag 或完整 policy。

| 事件 | 观察状态的处理 |
| --- | --- |
| 正确 worker 响应已认证 challenge | 清除失败怀疑，继续路由当前 owner |
| fresh HEAD revision/owner tuple 变化 | 原观察失效；不能用旧失败窗口接管新 owner |
| 连接失败或 peer deadline | 增加怀疑；只有策略满足后才允许准备候选 |
| peer 401/403、错误 worker、未知 route | 报认证/配置/路由问题；不自动视为满足故障门槛 |
| peer 429、恢复排队或已知资源压力 | 报忙；不因限流而抢走健康 owner |
| authority GET 失败、格式不合法或生命周期不允许 | 失败关闭，不准备 takeover |
| 当前 owner 正在恢复且 probe 正常 | 保持恢复中，不重置 owner epoch |

probe 必须走独立、有界的 owner-control/control 路径，不排在目标库长 SQL 或整库恢复后面。
它只检查计算启动身份和必要的 fresh authority 元数据，不执行 SQL 或恢复镜像。
长期空闲库没有写入不是故障；不得要求每个闲置库不断向 S3 写心跳。

网络分区下探测可能误判仍然存活的进程。方案不声称消除这种不确定性；
可接受的接管必须依靠后续 HEAD CAS fencing，活性策略还受第 10 节约束。

## 6. 固定的 OwnerIntent 与去重

准备阶段不修改 HEAD。拟新增受限 `OwnerIntent`：

```text
intent_id
scope
registry_digest
principal
target_worker_instance
observed_revision / observed_owner_epoch / observed_owner_instance
takeover_nonce
activate_nonce
mode = takeover_then_activate | activate_current_owner
```

内部候选还绑定原 base HEAD/ETag、候选内容摘要、候选 revision 及两个阶段的身份。
nonce 在第一次可能产生效果的请求前固定并保存，不能遇到超时后自动生成新 nonce。
`target_worker_instance` 必须与实际接管服务进程一致；不是客户端可用于冒充其他 worker 的字段。

本地协调去重按 **HEAD key** 做互斥，完整 scope、principal、registry digest 和 intent
必须相同才能加入既有工作。incarnation/generation 不进入 actor key，但每次必须单独精确验证，
不能让旧 scope 的观察附着到新库。
不同 intent 同时争同一个 HEAD，只接受预算内的一个本地执行者；其余返回稳定的 busy/conflict。

跨节点去重的最终机制仍是同一个 HEAD 的 CAS。两个目标读取相同 base 后准备候选，
只能有一个发布成功；失败方不得换成新 revision 再发起 takeover。

观察、意图和 waiter 都需要全局/租户数量及字节上限。HEAD 的当前格式上限为 256 KiB；
保存几十份完整 Snapshot 也是实际内存，不能只限制 Map 条目个数。
所有锁只覆盖短状态变更，不在持锁期间 probe、GET、PUT、等待 actor 或做 native 恢复。

## 7. Reconcile 状态机

拟定的状态与含义如下：

| 状态 | 可执行动作 | 退出条件 |
| --- | --- | --- |
| `Observed` | 验证 fresh authority，按策略 probe | 健康则返回已有路由；失败进入 `Suspected` |
| `Suspected` | 等待有界观察窗口，重复独立 probe | 正常响应/HEAD 进展清除怀疑；条件满足才准备 intent |
| `Prepared` | 再验证当前 ADMIN、原观察和 registry；封存候选 | 不匹配则 `Superseded/Blocked`；匹配后发一次 takeover |
| `TakeoverIssued` | 等待该次结果或用 fresh HEAD 检查 | 成功进入 `Recovering`；冲突停止；不确定进入 `Unknown` |
| `Recovering` | 在该库 actor 恢复、校验、复核原 HEAD/ETag并发一次 activation | 接受后观察 active；失败保留 owner/inactive，不能再次夺主 |
| `ActiveObserved` | 返回当前已授权、已激活 owner 的状态 | 不替代下一次 SQL 的 fresh 准入 |
| `Unknown` | 仅观察和查证原意图，不派发业务 SQL | 明确证明、被后续状态取代或显式新管理动作 |
| `Superseded` | 返回原意图已不适用及当前安全元数据 | 不跟随新 HEAD 自动重造候选 |
| `Blocked` | 报生命周期、权限、损坏、资源或配置原因 | 显式修复后重新观察，不能靠换 owner掩盖损坏 |

`owner_instance` 已是本 worker 且 `active=true` 时，reconcile 只观察，不增加 epoch。
已是本 worker 且 `active=false` 时，只准备 activation，不再次 takeover。
已激活的其他健康 owner 始终返回其路由；普通 `ensure` 不能成为隐式抢主操作。

核心原语可以扩展为 `observe_owner` 与 `takeover_observed`：
前者提供只经过 ADMIN 授权的内部观察；后者重新 exact GET、比较原观察身份和权限，
使用原候选对应的 ETag 发布一次。既有 `takeover(expected_revision, nonce)` 可保留为
管理员显式强制迁移接口，但不能被自动 controller 当作无观察的后门。

激活复用现有 `activate_session`，不得仅做一次 HEAD 状态切换就报告已恢复。
其完整数据/保留结果/native 验证、最终 fresh HEAD 比较及私有目录清理全部保留。
发生 cold recovery 时，HTTP orchestration 只等待对应 actor；控制线程不执行恢复。

## 8. UNKNOWN、丢失响应和重启

每个阶段返回其原始引用。`takeover_nonce` 与 `activate_nonce` 是不同转换，
不能把“看到目标 owner”直接当作两个阶段的原响应均已得到证明。

| fresh HEAD 结果 | 允许得出的结论 |
| --- | --- |
| revision、transition nonce、owner tuple 精确匹配 takeover 候选 | 可确认该候选生效；当前仍须满足 ADMIN 和 lifecycle 才继续激活 |
| 精确匹配 activation 候选 | 可确认其激活状态；后续 SQL 仍重新准入 |
| revision 已推进，目标 owner/epoch 仍有效 | 可报告 `observed_state`，不能凭最后一个 transition 证明已经被覆盖的原 nonce |
| 更高 epoch 或不同 owner | 原意图被取代，不重新抢回 |
| 仍是旧 base | 不能证明旧 PUT 永远不会迟到，不能自动更换 nonce/ETag继续尝试 |
| S3 不可用、依赖缺失或损坏 | 保留 Unknown/Blocked，不伪造 Ready 或 rollback |

第一版不自动重发不确定的 administrative CAS。若未来支持重发，只能发送已封存的
**相同 body、相同条件 ETag、相同 nonce**，且须单独验证；不得以新的 HEAD 重绑旧候选。
这与重放 SQL 是不同问题，不能因为纯管理重发可设计为安全，就允许业务 SQL 重做。

协调进程重启或观察被回收时，旧观察句柄失效。客户端保留的原 `OwnerIntent`
仍可通过独立 `inspect` 获取授权后的 fresh 状态；不能将丢失内存状态解释成“从未发送”。
若目标仍为当前未激活 owner，可明确准备一个新的 activation 管理步骤继续恢复，
它不是重新执行旧 takeover，也不是修改原业务 request。

如果所有原转换结果已被后续 HEAD 覆盖，当前格式没有完整管理操作历史账本，
就必须保留精确原 outcome 未知这一事实。业务事务的原 receipt/result 仍由既有请求索引查证。
需要跨任意后续变更证明每次管理动作的精确原结果时，应另行设计持久 intent ledger，
不能声称仅靠当前 HEAD 已实现该能力。

## 9. HTTP、SDK 和资源接口

拟新增 `POST /v1/owner`，严格解析且明确分成独立 owner-control / owner-recovery admission。
候选操作如下，不复用普通业务 body 的类声明来绕过额度：

| 操作 | 权限与资源 | 效果 |
| --- | --- | --- |
| `probe` | 已认证协调主体、当前 ADMIN；owner-control | 返回实际 worker、challenge 及必要 owner 元数据；无 CAS |
| `observe` | 当前 ADMIN；owner-control | 创建/更新有界 `FailureObservation`；无 CAS |
| `prepare_reconcile` | 当前 ADMIN、配置允许的目标和协调域；owner-control | 固定原观察、nonces及目标；无 CAS |
| `reconcile` | 每步重查 ADMIN；owner-recovery | 执行一个固定 intent，最多一次 takeover 与一次 activation |
| `inspect` | 当前 ADMIN；owner-control | 查证原引用和 current observed state；无 SQL/CAS |

新的配置 capability，例如 `owner_coordinate`，只能限制哪些已认证主体可使用协调入口，
不能取代当前数据库 HEAD 的 ADMIN。协调者凭据由部署配置显式供给，不能复制未鉴权 body
中的 principal。数据库创建和 ACL 配置必须显式授权该主体，服务不能自动插入权限。

`OwnerClient` 提供对应严格类型和原意图的 `save/restore`；
`RoutedClient` 只持有普通业务 credential，不自动获得协调者 token。
旧 `Client.takeover/activate` 保持显式、单次请求合同。

所有步骤共享请求开始时的 deadline。probe、排队、恢复、native scan、编码和响应都消耗
剩余预算，不因进入 recovery 阶段续期。跨次显式管理调用可以有新的执行预算，
但保留原 intent 的 outcome 与不重发规则，不能伪装成原调用仍未超时。

HTTP 超时、断连或返回 Unknown 不代表实际 worker 已停止；
owner-recovery permit、Job 及关联 lease 必须保留到实际工作完成。
body、解析、响应、保留 frame/Bytes 和 native/临时盘分别遵守
[资源预算设计](resource-budgets.md)，不能只加两个 semaphore 就宣称资源隔离完成。
恢复至少同时受全局、租户和单 HEAD 的显式并发限制；同一租户换 principal 不能放大额度。

## 10. 可选自动 controller：防止健康 owner 争抢

自动模式应作为独立组件调用同一套观察、准备和 reconcile 原语，不把夺主嵌进
`Engine::execute` 的 FENCED 错误分支。
候选第一版使用受信、静态、有序的启动实例 registry，**只允许自动向更高 failover rank 转移**。
业务 owner 健康时不为了负载偏好或配置变化回迁；正常 rebalance 走显式管理动作。

同一 registry 的自动 failover 图必须无环，当前 owner 和目标均必须在该 registry 中，
目标必须有相应协调域权限。多候选并发仍只竞争原 HEAD；失败方结束该 intent，
不把冲突后看到的新 owner 当成已经满足了旧失败观察窗口。

在固定有限 registry、没有人工反向迁移或身份复用的前提下，每次自动接管严格增加 rank，
因此一条 owner 历史最多进行成员数减一的成功自动转移。这是控制 churn 的策略约束，
不是网络故障判断准确性的证明，也不限制失败探测次数；探测仍需要队列、频率及总预算。

网络分区可能使仍在运行的 owner 被怀疑并被后继接管；其迟到 SQL 由 HEAD CAS 拒绝。
某个分区中更高 rank 的恢复节点也可能不可达，自动模式此时应停止并报告不可用，
不能为获得可用性绕回低 rank 形成循环。
仅靠本地 timeout 不可能承诺“健康进程永不被误接管”或无条件有界 RTO。

### Registry roll-forward

生产自动模式要求按前一版配置审核 roll-forward：

- 旧 worker ID、route 绑定、rank 和既有自动边保持不变；新增计算启动使用全新 ID，并追加到既有 rank 之后。
- endpoint 发生进程重启或身份变更时新增 member，不将原 worker ID 改指新进程。
- 新版本保留旧配置摘要，部署门禁对实际前一版配置验证追加关系；单个新配置文件不能证明所有存活旧实例已经更新。
- 旧实例遇到不认识的新 owner 时 fail closed，不选择旧 registry 中的“默认主节点”。
- 不允许用配置回滚复活旧身份或重新引入反向自动边。清理旧成员或重排 rank 必须先停止相关自动协调者，并按显式迁移计划完成，不属于普通滚动更新。

当前 HEAD 没有 registry epoch 或 controller lease。上述配置约束是自动模式的部署信任边界，
不能冒称 S3 已原子 fencing 了配置更新。
若无法证明 append-only roll-forward，就只能启用静态路由与显式 reconcile，
或另行引入有完整合同的控制面权威；不能靠“全局应当只有一个 controller”假设通过验收。

## 11. 实现切片与完整能力工作清单

### 首个 SDK 切片

`RoutedClient` 使用显式配置的 `worker_instance → endpoint` 映射和 bootstrap endpoint。
每次业务调用先获取当前 status，再将原 prepared request 最多派发一次；未知 owner、
不可接受的生命周期或写 owner 尚未激活时，在派发 SQL 前返回明确错误。
lookup/cancel 继续使用原 scope、principal、request 和 fingerprint，不触发 takeover。

独立的 `OwnerClient` 使用 READ+ADMIN 凭据，显式准备、保存并恢复 `OwnerIntent`。
`reconcile(intent)` 消耗新准备意图的一次性派发资格，最多执行一次 takeover 和一次 activation；只有上一步返回的
revision、nonce、owner、epoch 及 active 状态全部符合固定意图时，才允许下一步。
`inspect(intent)` 只读取 fresh status，区分精确转换证据、当前观测状态、取代与未知。
restore 只恢复描述和查证能力，不恢复派发资格；超时、丢失响应或 restore 后均不能默认为尚未发送，再次发送旧管理动作。
同一 owner 的未激活恢复可以明确准备一个新的 activation-only 意图，不重新 takeover。

每次 takeover/activate 都提供 `expected_worker_instance`，服务端在已有 bearer 与 scope
准入之后、任何 S3/cache/恢复效果之前检查实际 worker，不匹配返回 `TARGET_MISMATCH`。
显式接口可省略 guard 保持兼容，但显式 null/零/非规范值拒绝。

这个切片不承诺 ADMIN-only 账户可使用 status，不增加隐式 READ 权限，也不在
网络故障、FENCED 或 owner 未激活时自行选择接管目标。它不需要新的服务端缓存、
owner endpoint 或持久格式；原接口仍在每次管理操作重新 exact GET、检查当前权限和
expected revision，并以同一次 GET 的原 ETag 发布。所有组合调用共享一个总 deadline。

SDK 切片的验收至少覆盖 OR-01、OR-03 的 endpoint/redirect 部分、OR-06 至 OR-10 的
显式管理部分、OR-14、OR-15 的持久意图部分；自动观察、服务端去重及 registry
roll-forward 的验收不能计入该切片的完成范围。

### 后续完整能力

| 文件或模块 | 拟定改动 |
| --- | --- |
| `crates/scap-object/src/owner.rs`（新）及 core 导出 | `OwnerObservation`、ADMIN-only `observe_owner`、绑定原观察的 takeover 原语；不改 HEAD codec |
| `crates/scap-service/src/owner_registry.rs`（新） | endpoint/worker/协调域验证、registry digest、roll-forward 检查与可选有向策略 |
| `crates/scap-service/src/owner.rs`（新） | 有界观察/intent 状态机、逐 HEAD 去重、probe effect boundary、固定转换身份与 Unknown 解析 |
| `crates/scap-service/src/owner_wire.rs`（新） | 严格 wire schema、scope/principal/nonce 绑定、有限状态响应 |
| `crates/scap-service/src/http/owner.rs`（新） | 独立鉴权、owner-control/recovery intake、总 deadline、真实 Job/response 生命周期 |
| `config.rs`、`auth.rs`、`daemon.rs`、`http.rs`、`lib.rs` | 可选配置/角色/装配；不在 data error 路径偷偷夺主 |
| `engine.rs`、`scheduler.rs` | 只增加明确的内部协调调度接点，恢复仍复用原 per-HEAD actor 与共享恢复预算 |
| `sdk/node/src/owner.js`、`owner_wire.js`、`routed.js`（新）及导出/类型 | OwnerClient、RoutedClient、固定意图保存、endpoint 白名单与总 deadline |
| 独立可选 `owner_controller.rs`（后续） | 有界自动触发、单向 failover policy；不与前两层混称已经实现 |
| `experiments/object-owner/`（新）与独立 oracle | 多真实进程/S3条件请求/HTTP/SDK/原请求账本及负控 |

实现时优先复用现有 scheduler，避免建立另一套不共享配额的“全局恢复池”。
内部纯状态机、peer I/O、authority、调度和 wire 分层；实验只装配正式代码。

## 12. 确定性真实合同与验收

每项都需要冻结配置、source manifest、实际 release/native 身份和原始失败记录。
单元四维覆盖、真实 HTTP/S3/进程合同、AWS 与生产负载分别报告。

| ID | 场景与可控制切点 | 必须证明的结果 |
| --- | --- | --- |
| OR-01 | 从非 owner 入口 routed execute 到健康 owner | fresh status 后仅一个业务 POST；原请求/receipt/result 不变，无 takeover CAS |
| OR-02 | 长期空闲但 probe 正常的 owner | 超过观察窗口也不抢主；HEAD/owner epoch不因观察而改变 |
| OR-03 | 401/403/429、错误 worker、未知 route、恶意 URL/redirect | 不将认证/资源/地址问题升级成夺主，不向未允许 endpoint 发送 token |
| OR-04 | 等待旧 writer 到 native gate/HEAD PUT 前，随后接受新 owner | 释放旧 writer 后其迟到候选不能 ACK；原 request 用 lookup/cancel 处理，无 SQL重放 |
| OR-05 | owned kill + wait4 确认旧进程退出，空缓存新实例接管 | takeover→完整恢复→复核→activate 顺序正确，所有既有 ACK 的原 receipt/result/data 完整 |
| OR-06 | 两个目标对同一观察同时 reconcile | 只有一个原 ETag CAS成功；失败者不刷新 revision 再夺主 |
| OR-07 | takeover 已接受但响应丢失 | 原意图保留，inspect区分精确证据与 observed state；不额外增加 owner epoch |
| OR-08 | activation 已接受但响应丢失，随后 HEAD 再推进 | 不谎称最后 transition证明原nonce；已确认业务仍可按原身份查证 |
| OR-09 | 恢复中缺失/损坏依赖或 native open失败 | 不发布 active、不伪造 healthy、不借换 owner掩盖损坏；修复后的明确activation不再次takeover |
| OR-10 | observe后撤销ADMIN、变更lifecycle或scope代际 | 当前权限与完整scope重新验证，旧票据/旧观察拒绝 |
| OR-11 | 整个 S3不可用或claim PUT结果Unknown | 无缓存写权降级，无TTL授权；保持Unknown/Blocked及原意图 |
| OR-12 | 某库恢复被门控，另一已热库同时工作 | 热库执行和control不等待该恢复；同库仍串行，全局/租户恢复额度不泄漏 |
| OR-13 | HTTP超时、断连、慢body、慢响应、保留最后Bytes | 实际Job/最后持有者结束前不退款；后台任务不重新执行SQL |
| OR-14 | route耗掉大部分总deadline，随后尝试execute | 不续期；dispatch前过期时无SQL，dispatch后异常仍保持Unknown |
| OR-15 | prepare后协调进程重启或观察被有界回收 | 旧句柄失效不等于原操作未发送；固定intent可授权inspect，不自动重新claim |
| OR-16 | 静态有向registry上的双向网络分区和多次恢复 | 每次已接受自动迁移rank严格增加，无回迁循环；未知新owner时旧配置停止 |
| OR-17 | 新registry追加、非法重排、复用旧ID及回滚 | 追加门禁通过；不合法变化拒绝自动模式，不借“版本更大”绕过绑定 |
| OR-18 | 人工显式强制迁移与自动controller竞争 | 自动候选仍绑定原观察；人工操作不被错误纳入固定registry的churn上界证明 |

真实合同的独立 oracle 必须记录实际 HTTP POST次数、原 request/fingerprint、
同一次 GET 的 HEAD bytes/ETag、每个条件 PUT、完整原响应和 owned child回收结果。
至少加入“错误endpoint仍带token”“冲突后换ETag继续”“恢复未验就active”“SQL重发”
“旧配置抢回新owner”“把一次timeout当死亡”“恢复中提前释放permit”等行为负控。

## 13. 后续边界

本方案不增加多 writer、跨库事务、lease read、同库reader pool、lazy VFS、group commit、
物理 GC/pin、PITR 或多区域灾备。未来启用物理GC时，恢复及依赖读取仍须接入正式pin/generation
协议；故障观察票据不是对象保留pin。

动态成员发现、任意重新平衡、跨配置的强一致controller选举、完整管理动作历史账本、
可证明的生产RTO和多区域自动接管都有独立合同。它们不能从一个成功的本地takeover示例推导出来。
实现完成前，README和运行手册继续明确区分现有显式操作与本文拟议能力。
