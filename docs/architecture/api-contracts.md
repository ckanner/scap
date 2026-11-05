# 客户端、接口与错误契约

> **新目标路线：**[新 API 设计](<object-storage-native-proposal.md#implementation>)按 greenfield 定义，不要求兼容本文的旧 SDK、Hrana 子集、回执或请求窗口接口。本文仅记录当前原型行为；新协议必须独立验收。

状态：2026-11-04 实现更新；已有有界 HTTP/Hrana、Node SDK、独立强读、按原请求世代查询结果、显式确认与窗口退休，以及数据库状态接口。本轮验证状态见 [ADR-0019](../adr/0019-explicit-request-result-retirement.md)；通用管理 API 和跨请求事务会话仍为 planned。当前可调用接口以 [正式协议模块](../../crates/scap-service/README.md)、[Node 客户端](../../sdk/node/README.md)及 [SQLite 服务实现](../engineering/sqlite-service.md)为准，本文同时保留后续完整平台的语义约束。

## 1. 接入目标

当前 `sdk/node` 是基于固定 `@libsql/client` 0.18.0 的薄 TypeScript 客户端，保留常用 `execute` / `batch` 输入和结果形态，并提供 `query`、稳定请求身份、`lookup`、`resolveOrCancel`、`status`、`executeTracked` / `batchTracked`、`acknowledge` 和 `rotateRequests`。它使用明确配置的候选节点，只在确定未进入提交窗口的 `NOT_LEADER` 等安全边界上重新选择节点，不自动重放 UNKNOWN 写入。

直接使用该版本第三方 SDK 的 execute/batch 也可访问已经验证的 Hrana 子集；独立强读需选择 SCAP read 模式。Drizzle / Prisma、同步 `libsql` 包及 `better-sqlite3` 迁移仍需逐项验证，不承诺任意程序仅修改 import 即可迁移。

SQLite SQL 兼容、数据库文件兼容、驱动 API 兼容、分布式故障语义是四个独立维度。兼容矩阵须记录确切客户端、ORM、server 和引擎版本。

```ts
// 从仓库根目录运行；先按 sdk/node/README.md 构建本地 SDK。
import { createClient } from "./sdk/node/dist/client.js";

const db = createClient({
  endpoints: JSON.parse(process.env.SCAP_ENDPOINTS!),
  database: "agents",
  authToken: process.env.SCAP_TOKEN!,
});

const result = await db.query({
  sql: "SELECT id, state FROM agents WHERE id = ?",
  args: [agentId],
});
```

`query` 不增加 accepted-write 历史；普通第三方 `execute("SELECT ...")` 仍走有记录的兼容事务入口。以上示例只说明业务调用形态；完整启动、错误查证和凭据配置见 [服务文档](../engineering/sqlite-service.md)，上游客户端资料见 [libSQL TypeScript](https://github.com/tursodatabase/libsql-client-ts)。

## 2. 协议和会话

- 正式 `scap-service` 直接实现经过验证的 Hrana HTTP v2 子集，没有把完整旧 `sqld` 服务并入当前进程。
- 每个 pipeline 自包含，baton 为空，包含至多一次 execute 或 SDK 的固定原子 batch，并以 close 结束。所有协议、参数和控制步骤在 SQL 开始前完成验证。
- `query` / read batch 取得新的 Safe ReadIndex 和精确 revision 的只读 SQLite 快照；写 batch 整体原子提交，不能跨数据库。
- 未支持的 interactive transaction、跨请求 stream、任意条件 batch、named args、cursor、WebSocket 和 embedded replica 明确拒绝。
- writer 故障后从权威历史恢复数据库，不恢复旧连接的临时表、游标、prepared statement 或进程内对象。

未来若增加跨请求事务，会话必须固定到 owner，后续 RPC 仍需当前授权；未完成事务不能在故障后无感搬迁。同步驱动、完整 ORM 与陈旧读模式另行验证。

当前 HTTP body 为 1 MiB、响应为 512 KiB、在途请求最多 32、单请求服务预算最多 10 秒；SQL/事务及 mailbox 还有独立上限。排队、恢复、执行和返回共用原绝对 deadline，客户端只能缩短预算。完整 profile 见 [服务容量边界](../engineering/sqlite-service.md#6-当前容量与兼容边界)，这些上限不是吞吐或延迟 SLO。

### 2.1 已实现的 HTTP 入口

| 方法与路径 | 当前行为 |
| --- | --- |
| `POST /v2/pipeline` | 使用配置的默认数据库执行有界 Hrana 程序 |
| `POST /db/{database}/v2/pipeline` | 路由名经鉴权映射为不可变数据库身份 |
| `POST /db/{database}/v1/requests/{request_id}` | 携带原 statements，执行 lookup、resolve_or_cancel 或带原终态证明的 acknowledge |
| `POST /db/{database}/v1/request-epoch` | 独立 ADMIN 凭证，CAS 推进已全部确认的非空请求窗口 |
| `GET /db/{database}/v1/status` | 通过新的 ReadIndex 和当前 READ 权限返回有限元数据，不唤醒冷库 |

请求必须携带 Bearer 凭据。`x-scap-request-id` 接受非零 128-bit 十六进制身份；`x-scap-deadline-unix-ms` 只能缩短预算；`x-scap-mode: read` 选择独立强读。`x-scap-request-epoch` 为正 u64 十进制，缺省固定为 1，不能自动刷新旧身份。status 只返回 revision、base/tail、请求世代/保留计数、suspended、cold、owner_active、archived_revision，不泄露对象 key、其他数据库或完整状态机。SQL HTTP 默认只允许 loopback；非 loopback 必须显式配置 `proxy_terminates_tls=true` 并由部署提供 HTTPS 终止，开关本身不会启动 TLS 代理。Peer RPC 已使用 mTLS。

## 3. 每次操作携带的身份

当前静态 token 的 SHA-256 配置绑定数据库路由名、不可变 `db_id` / incarnation / placement、principal、credential、权限和 auth_epoch。每次数据操作、历史结果查询及 status 仍通过 cell 当前状态复核授权；客户端不能自行提供复制的 Admission。通用 tenant 目录、外部身份提供方、令牌到期与自动轮换属于后续控制面设计。

客户端不自行决定数据库 incarnation、owner epoch 或 auth epoch，路由 header 也不是授权。请求世代 `requestEpoch` 是另一项持久身份：新业务请求可以显式使用当前值，已有请求必须保留原值。真正写入仍由 cell 校验当前数据库代次、请求世代、owner epoch、前序 `db_seq` 与有效权限状态。

不允许客户提交任意文件路径、S3 key 或 cell 管理命令。数据库显示名称可变，内部身份不可复用。

## 4. 写入结果的三种状态

| 状态 | 含义 | 客户端处理 |
| --- | --- | --- |
| 明确未提交 | 请求在权威接受前被拒绝，且能证明不会被迟到命令接受 | 按错误类别重试或修正 |
| 明确已提交 | cell 已接受事务，数据与恢复信息满足持久化合同 | 使用结果或查询返回的提交标识 |
| 结果未知 | 超时 / 断连发生在可能提交的窗口 | 用原请求世代、ID 和 statements 查证；需要封闭迟到提交时有序 resolveOrCancel；不盲目重发 SQL |

网络断开、请求取消、网关 502/503 不自动意味着事务未提交。错误状态与 transport status 必须分别编码，并尽可能保留 `request_id`、数据库代次、已知提交标识和重试建议。

窗口退休后返回的 `retired` 描述历史结果已不再保留及旧身份空间永久封闭，不能将其归为“明确未提交”或“已取消”。需要原结果时由应用使用退休前保存的记录核对，不给同一未知操作更换请求世代重新执行。

写成功的返回边界是完整事务已被 cell durable quorum 提交、状态机接受，并由 worker 完成已接受事务的本地发布。自动提交的写语句使用 `RETURNING` 时，所有结果行必须先进入有大小上限的暂存缓冲；在这一边界之前，Hrana 响应、游标或结果流均不得把行作为成功写入结果交给 SDK，也不能让 SDK 的成功 Promise 提前完成。结果超过限额应在权威提交前明确拒绝；已经进入可能提交的窗口时，不能再以结果过大为由声称必然回滚。

显式事务中的语句结果可以是事务内的暂定结果，只有最终 `COMMIT` 按上述边界完成才表示整笔事务成功。已接受但 worker 发布失败或响应丢失时，返回可辨识的未知结果或中断并查询权威状态，不能将该事务改报为已撤销。

### 4.1 默认第三方 SDK

标准 SDK 不一定能为业务请求持久携带稳定的幂等键。其默认合同是数据库事务原子性与已确认提交的持久性，不是任意网络重试 exactly-once。

对未知结果的非幂等写入，网关和 SDK 均不自动重放。业务可使用唯一业务键、条件更新或应用级事务记录解决重复执行风险。

### 4.2 已实现的 SCAP 请求封装

`sdk/node` 已携带稳定 `request_id` 和原 `requestEpoch`，保留原 SQL/参数；服务端重新计算业务指纹并绑定数据库身份。去重结果由同一 cell 状态机原子记录，客户端不能用自报指纹替换实际请求。以下相同 ID 的规则均限定在同一数据库身份和同一请求世代内。

- 相同 ID、相同请求指纹：返回原事务结果或状态，不再次接受写入。
- 相同 ID、不同指纹：拒绝冲突，不覆盖原记录；具体 wire 错误以当前服务模块为准。
- 并发重复请求：最多一个 accepted commit，其余引用该结果。
- accepted/cancel 及原结果随 cell snapshot 保留，Prune 不删除它们；每库未退休窗口最多 128 条。显式终态确认且全部记录已确认后，ADMIN 才能原子推进世代并释放窗口，不自动过期或淘汰未确认记录。
- 旧世代 lookup 返回 `retired`，旧写/取消/确认拒绝为 `REQUEST_RETIRED`。当前没有基于 TTL 的自动结果过期，也没有 `REQUEST_EXPIRED` wire 协议；不能把已删除记录的普通 UUID 当成可证明的新请求。

请求指纹覆盖 SQL / 参数 / 事务边界或规范化操作，不用物理页面 hash 冒充业务请求指纹。SQL 重新执行可能生成不同的时间或随机值，但重复接受必须由同一请求身份阻止。

### 4.3 状态查询与取消

`LookupRequest` 的未找到结果只证明读取屏障处没有记录，不能证明一个迟到提交以后不会到达。当前已提供同 cell 有序的 `ResolveOrCancel`：先记录取消或返回已有结果，使后到的同 ID 命令不能再被接受。两个入口都重新检查当前权限和原请求主体，冷库结果查证不要求先访问 S3。

取消已接受事务不能撤销提交；需要业务补偿事务。没有稳定 ID 的请求不能使用这一机制假装精确取消。

取消 tombstone 是阻止迟到提交的持久 fence，生命周期独立于普通响应缓存。首版必须将其保留到该 incarnation 结束，或通过 Raft 原子压缩到覆盖该请求身份、能够永久拒绝其迟到提交的持久退休边界；响应体到期不能触发取消 fence 的回收。取消记录和退休边界随 snapshot、迁移及恢复保留。同 ID 的已取消请求不能被当作新请求重新执行；业务需要重新发起动作时，必须先确认原请求的终止结果，再作新的业务决定。

## 5. 错误模型

当前 wire 映射已由正式协议模块实现：`UNAUTHORIZED` 为 HTTP 401，`INVALID_REQUEST` / `UNSUPPORTED_FEATURE` 为 400，`EXPIRED` 为 408，`COMMIT_UNKNOWN` 为 504，`NOT_LEADER` / `OVERLOADED` / `COMMITTED_RESULT_UNAVAILABLE` 为 503，`REQUEST_RETIRED` 为 422。HTTP 状态不能独自证明提交结果，最终查证使用稳定请求身份。`NOT_LEADER` 必须表示本次尚未进入可能提交窗口；状态机已接受后响应过大或结果不可用也不能改报回滚。

下表保留完整平台的目标语义类别，其中尚无当前 wire 映射的名称是 planned，不能当作已稳定的错误码。准确支持列表见 [HTTP 合同](../../crates/scap-service/README.md)。

| 类别 | 说明 | 默认行为 |
| --- | --- | --- |
| `DB_WAKING` | 唤醒尚未完成，SQL 未开始 | 有界退避或等待 operation |
| `NO_QUORUM` | 无权威多数派 | 不降级为本地读写；区分本请求是否已进入未知窗口 |
| `NOT_OWNER` / `STALE_EPOCH` | 路由或写者已过期 | 刷新路由；已经执行的写不盲目重放 |
| `COMMIT_UNKNOWN` | 可能提交但未得到确定回复 | 使用原请求身份查询或有序取消，不自动重发 SQL |
| `REQUEST_RETIRED` | 原请求世代永久关闭，原结果不再保留 | 查询应用已保存的结果；不换新世代重试旧操作 |
| `BACKPRESSURE` | 日志空间、吞吐或归档压力 | 返回有限 retry hint，不承诺无限排队 |
| `TX_TOO_LARGE` | 暂存事务超过限制，未接受提交 | 回滚后让业务拆分 |
| `TX_EXPIRED` | 事务超过限制 | 只有明确未提交才能报告已回滚 |
| `DATABASE_DELETED` | 数据库代次已 tombstone | 不把请求发到同名新库 |
| `RECOVERY_REQUIRED` | 状态或校验不满足服务条件 | 隔离数据库，禁止自动建空库 |
| `AUTH_UNAVAILABLE` | 无法验证足够新的权限 | fail closed，不沿用无限旧缓存 |
| `UNSUPPORTED_FEATURE` | 未通过兼容门禁的 SQL / 协议 / 文件特性 | 明确拒绝，不静默更改语义 |

## 6. 管理 API 草案

下列计划中的通用管理操作要求 operation ID、权限校验和审计；长任务返回任务身份与阶段，允许查询和幂等继续。当前请求窗口退休使用另一项有序世代 CAS，不产生永久行政 operation ID。没有跨 etcd / cell 事务，所以 API 不能在只写入意图后返回“数据库已就绪”。

| 方法与路径（计划） | 行为 |
| --- | --- |
| `POST /v1/databases` | 创建独立数据库身份与初始化任务 |
| `GET /v1/databases/{db_id}` | 状态、配置、生命周期、已知提交/归档水位 |
| `PATCH /v1/databases/{db_id}` | 调整经允许的配额和休眠策略 |
| `POST /v1/databases/{db_id}/wake` | 幂等唤醒任务 |
| `POST /v1/databases/{db_id}/sleep` | 受控排空并提交 SuspendDb；释放计算资源，cell 保留必要 tail；归档与 Cold 卸载进度单独报告 |
| `POST /v1/databases/{db_id}/restore` | 恢复到新的数据库身份 |
| `POST /v1/databases/{db_id}/migrate` | 首版离线跨 cell 迁移 |
| `DELETE /v1/databases/{db_id}` | 先 tombstone，后按保留策略物理删除 |
| `GET /v1/operations/{operation_id}` | 查询可恢复的任务阶段与错误 |

不开放“强制清空 cell 重建”“跳过 fencing 激活”“忽略 checksum 恢复”等一般管理 API。灾难恢复执行单独的受控运维流程。

`sleep` 的成功表示 owner 已被权威撤销且约定的计算资源已释放，不表示全部数据已上传 S3 或持久热数据已经回收。状态查询区分平台 `Suspended` 与满足完整归档及回收条件的 `Cold`；二者都对应 cell lifecycle `SUSPENDED`。S3 故障可使后续冷卸载等待，但不能删除唯一 committed tail，也不能把已完成的 Suspend 谎报成完整冷卸载。具体转换见 [存储生命周期](storage-lifecycle.md)。

## 7. 内部 RPC 规划

正式 daemon 已通过 `Mailbox`、`CellPort`、`EngineFactory` 和 `Objects` 窄端口装配同进程 SQL、共识与归档；跨节点使用正式 mTLS peer RPC。没有另行公开一个允许客户端提交 cell 命令的业务 gRPC 服务。

未来拆分 worker/controller 时的职责边界包括 `GetReadBarrier`、`SubmitTransaction`、`LookupRequest`、`ResolveOrCancel`、`GrantOwner`、`SealDatabase`、`PublishArchive`、`FetchCommittedRange` 与 `InstallRecoveryState`。这些职责名不等于已经定义的 Protobuf 服务。

所有协议需有版本、最大消息大小、校验、deadline、请求身份和错误分类。Raft 消息、SQL 数据和控制面请求使用不同的限流与执行队列，防止冷启动或慢查询阻塞选举和复制。

详细字段须与 [一致性协议](consistency.md) 一起评审后生成代码；不能先把未经确定的 protobuf 当作稳定公共接口。

## 8. 兼容性验收

当前验证入口为 [真实三节点服务实验](../../experiments/service-network/README.md)和 [Node SDK 测试](../../sdk/node/README.md)，覆盖已经接入的 SQL/结果类型、原子 batch、强读、身份和 UNKNOWN 边界；具体执行清单与统计以实验记录为准。

扩展兼容范围时还需覆盖 interactive transaction、savepoint、cursor、迁移工具、实际 ORM 和同步驱动。对自动提交 `RETURNING`、游标和结果流注入 quorum 前失败，验证结果行及 SDK 成功返回均未提前泄露；对显式事务验证语句结果与最终提交的区别。未来允许响应缓存到期后，再投递原提交必须仍被 tombstone 或退休边界拒绝。

当前不默认允许跨库 ATTACH、动态原生扩展、不受控 UDF 或改变平台 WAL / 同步 / 文件布局的 PRAGMA。范围和理由见 [租户隔离](tenancy-security.md)。

部署 profile、leader 自动恢复、后台归档及并发 Prune 的有限刷新由 [ADR-0014](../adr/0014-sqlite-service-and-cold-lifecycle.md)约束。当前接口可运行，不代表完整管理平台、无限历史或生产 SLO 已通过。

## 9. 已实现的显式结果退休

请求身份是原 `requestEpoch`、request ID 和 SQL/参数指纹。`executeTracked` / `batchTracked` 同时返回完整身份和结果；普通 execute/batch 不自动确认。应用先保存或处理结果，lookup 取得原 committed sequence 或 cancelled term/index 后，调用 `acknowledge(request, outcome)`。UNKNOWN、缺失终态证明和旧世代不能被当成合法确认。

非 `1n` 世代的 write、resolveOrCancel、acknowledge 和 rotateRequests，在每个候选节点发出变更之前额外查询该节点的 status，确认支持退休协议。探测使用同一原请求 ID、世代和绝对 deadline，不跨节点或调用缓存，也不自动改变世代。探测失败或旧端点不理解协议时不会继续发送该变更；普通 query 不执行这一探测。Tracked 方法只增加本地身份返回，相较对应 execute/batch 不另增 RPC，但同样遵守上述能力探测。

管理员通过 `rotateRequests(expectedEpoch)` 推进非空且全部确认的热窗口。成功返回新世代；响应丢失要用 fresh status 查证，原请求不得更换世代重试。旧身份 lookup 返回 `{state:"retired",current_epoch:"N"}`，旧写/取消/确认明确拒绝。`retired` 只说明这整个身份空间永久封闭，不宣称该请求取消，也不返回新世代同 ID 的结果。读取和 SQL 内容不会因退休回退，revision 继续单调。

每库当前窗口仍至多 128 个 accepted/cancelled 记录；同库其他主体尚未确认的结果也会阻止轮转。结果确认与退休不消耗永久行政 operation ID，但不会释放已有的 4096 条 cell 行政记录预算，也不删除 S3 对象。Cold 可确认已有终态，轮转前必须先通过精确对象恢复到非 Cold；对象不可用时不能通过退休绕过恢复链。

入口按具体 token 检查 scope，状态机检查当前 principal policy 与 auth_epoch。配置 `retention_admin:true` 的独立凭证仅绑定当前数据库、已有 bootstrap administrator、READ|ADMIN(5)，credential_id 必须不同于内部 service credential。它不允许 SQL 写或代其他主体确认结果。普通 token 原有 permissions 1–3 保持不变；具体配置和升级边界见 [server 说明](../../crates/scap-server/README.md)与 [ADR-0019](../adr/0019-explicit-request-result-retirement.md)。
