# 客户端、接口与错误契约

状态：拟实现接口。路径和字段是 v0 设计，不是已经可调用的服务。

当前已有 [Rust 层 SQLite adapter](../engineering/sqlite-engine.md)，输入为有界 statement batch，返回已接受的完整结果；它不提供本文的 HTTP/Hrana 服务，也不意味着 Node.js 客户端已经可连接。其前置 Lookup、历史回执和 UNKNOWN 分类将作为后续客户端边界的基础。

## 1. 接入目标

Node.js 默认通过 `@libsql/client` 的远程模式访问；Drizzle / Prisma 使用与实际版本匹配的 libSQL adapter。存量 `better-sqlite3` 应用可以验证 `libsql` npm 包，但不承诺任意程序仅修改 import 即可迁移。

SQLite SQL 兼容、数据库文件兼容、驱动 API 兼容、分布式故障语义是四个独立维度。兼容矩阵须记录确切客户端、ORM、server 和引擎版本。

```ts
// 目标接入形式示例；SCAP 服务尚未实现。
import { createClient } from "@libsql/client";

const db = createClient({
  url: process.env.SCAP_DATABASE_URL!,
  authToken: process.env.SCAP_DATABASE_TOKEN!,
});

const result = await db.execute({
  sql: "SELECT id, state FROM agents WHERE id = ?",
  args: [agentId],
});
```

以上示例只说明业务调用形态，不包含完整重试、错误处理和凭据管理。官方客户端资料见 [libSQL TypeScript](https://github.com/tursodatabase/libsql-client-ts)。

## 2. 协议和会话

- 优先复用 Hrana 协议和 `sqld` 实现，首版以经测试的协议子集为合同。
- 一个会话及其 interactive transaction 固定到一个数据库 owner，不逐语句随机切换 worker。
- worker 失效时会话可中断，未完成事务不能无感搬迁。客户端重新建立连接后决定是否按幂等规则重试。
- 读事务具有固定快照；自动提交查询默认在新的强一致屏障后执行。
- 禁止将多个数据库的 SQL 包装成原子 batch；每个 batch / transaction 只作用于一个数据库身份。
- 不默认启用 embedded replica 或离线写入。若以后增加陈旧读，需要显式 API 和落后范围，不改变默认强读。
- 同步兼容驱动会等待远程结果，主线程 event loop 延迟必须实测。

客户端必须获得明确的 deadline、事务持续时间上限、在途请求数、结果大小、参数大小及提交字节上限；初始数值由 PoC 和容量验证确定。

## 3. 每次操作携带的身份

外部鉴权绑定 tenant 和不可变 `db_id` / incarnation。网关或 worker 在内部附加经验证的 cell、owner instance、epoch、权限版本、请求 deadline 和 trace ID。

客户端不自行决定 epoch，路由 header 也不是授权。真正写入仍由 cell 校验当前数据库代次、owner epoch、前序 `db_seq` 与有效权限状态。

不允许客户提交任意文件路径、S3 key 或 cell 管理命令。数据库显示名称可变，内部身份不可复用。

## 4. 写入结果的三种状态

| 状态 | 含义 | 客户端处理 |
| --- | --- | --- |
| 明确未提交 | 请求在权威接受前被拒绝，且能证明不会被迟到命令接受 | 按错误类别重试或修正 |
| 明确已提交 | cell 已接受事务，数据与恢复信息满足持久化合同 | 使用结果或查询返回的提交标识 |
| 结果未知 | 超时 / 断连发生在可能提交的窗口 | 查询提交状态或以稳定请求 ID 幂等重试；不能换 ID 盲目重放 |

网络断开、请求取消、网关 502/503 不自动意味着事务未提交。错误状态与 transport status 必须分别编码，并尽可能保留 `request_id`、数据库代次、已知提交标识和重试建议。

写成功的返回边界是完整事务已被 cell durable quorum 提交、状态机接受，并由 worker 完成已接受事务的本地发布。自动提交的写语句使用 `RETURNING` 时，所有结果行必须先进入有大小上限的暂存缓冲；在这一边界之前，Hrana 响应、游标或结果流均不得把行作为成功写入结果交给 SDK，也不能让 SDK 的成功 Promise 提前完成。结果超过限额应在权威提交前明确拒绝；已经进入可能提交的窗口时，不能再以结果过大为由声称必然回滚。

显式事务中的语句结果可以是事务内的暂定结果，只有最终 `COMMIT` 按上述边界完成才表示整笔事务成功。已接受但 worker 发布失败或响应丢失时，返回可辨识的未知结果或中断并查询权威状态，不能将该事务改报为已撤销。

### 4.1 默认第三方 SDK

标准 SDK 不一定能为业务请求持久携带稳定的幂等键。其默认合同是数据库事务原子性与已确认提交的持久性，不是任意网络重试 exactly-once。

对未知结果的非幂等写入，网关和 SDK 均不自动重放。业务可使用唯一业务键、条件更新或应用级事务记录解决重复执行风险。

### 4.2 可选 SCAP 请求封装

计划提供薄 TypeScript wrapper 或显式 request envelope，携带稳定 `request_id`、请求指纹、数据库代次及重试窗口。去重结果由同一 cell 状态机原子记录。

- 相同 ID、相同请求指纹：返回原事务结果或状态，不再次接受写入。
- 相同 ID、不同指纹：`IDEMPOTENCY_CONFLICT`。
- 并发重复请求：最多一个 accepted commit，其余引用该结果。
- 去重记录受明确保留期约束，并随 cell snapshot 恢复。
- 保留期外不能继续承诺去重。可识别的过期服务端 receipt 返回 `REQUEST_EXPIRED`；普通自定义 ID 没有永久历史时，不宣称能够识别所有过期重试。

请求指纹覆盖 SQL / 参数 / 事务边界或规范化操作，不用物理页面 hash 冒充业务请求指纹。SQL 重新执行可能生成不同的时间或随机值，但重复接受必须由同一请求身份阻止。

### 4.3 状态查询与取消

`LookupRequest` 的未找到结果只证明读取屏障处没有记录，不能证明一个迟到提交以后不会到达。需要确定未提交时，计划使用同 cell 有序的 `ResolveOrCancel`：先记录取消或返回已有结果，使后到的同 ID 命令不能再被接受。

取消已接受事务不能撤销提交；需要业务补偿事务。没有稳定 ID 的请求不能使用这一机制假装精确取消。

取消 tombstone 是阻止迟到提交的持久 fence，生命周期独立于普通响应缓存。首版必须将其保留到该 incarnation 结束，或通过 Raft 原子压缩到覆盖该请求身份、能够永久拒绝其迟到提交的持久退休边界；响应体到期不能触发取消 fence 的回收。取消记录和退休边界随 snapshot、迁移及恢复保留。同 ID 的已取消请求不能被当作新请求重新执行；业务需要重新发起动作时，必须先确认原请求的终止结果，再作新的业务决定。

## 5. 错误模型

下表是语义类别，具体 Hrana error code / HTTP / gRPC 映射须由兼容 PoC 确认。

| 类别 | 说明 | 默认行为 |
| --- | --- | --- |
| `DB_WAKING` | 唤醒尚未完成，SQL 未开始 | 有界退避或等待 operation |
| `NO_QUORUM` | 无权威多数派 | 不降级为本地读写；区分本请求是否已进入未知窗口 |
| `NOT_OWNER` / `STALE_EPOCH` | 路由或写者已过期 | 刷新路由；已经执行的写不盲目重放 |
| `COMMIT_UNKNOWN` | 可能提交但未得到确定回复 | 查询 / 同 ID 重试 |
| `BACKPRESSURE` | 日志空间、吞吐或归档压力 | 返回有限 retry hint，不承诺无限排队 |
| `TX_TOO_LARGE` | 暂存事务超过限制，未接受提交 | 回滚后让业务拆分 |
| `TX_EXPIRED` | 事务超过限制 | 只有明确未提交才能报告已回滚 |
| `DATABASE_DELETED` | 数据库代次已 tombstone | 不把请求发到同名新库 |
| `RECOVERY_REQUIRED` | 状态或校验不满足服务条件 | 隔离数据库，禁止自动建空库 |
| `AUTH_UNAVAILABLE` | 无法验证足够新的权限 | fail closed，不沿用无限旧缓存 |
| `UNSUPPORTED_FEATURE` | 未通过兼容门禁的 SQL / 协议 / 文件特性 | 明确拒绝，不静默更改语义 |

## 6. 管理 API 草案

所有有副作用的管理操作要求 operation ID、权限校验和审计；长任务返回任务身份与阶段，允许查询和幂等继续。没有跨 etcd / cell 事务，所以 API 不能在只写入意图后返回“数据库已就绪”。

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

首期边界包括 `GetReadBarrier`、`SubmitTransaction`、`LookupRequest`、`ResolveOrCancel`、`GrantOwner`、`SealDatabase`、`PublishArchive`、`FetchCommittedRange` 与 `InstallRecoveryState`。这些是职责名，不是已经定义的 Protobuf 服务。

所有协议需有版本、最大消息大小、校验、deadline、请求身份和错误分类。Raft 消息、SQL 数据和控制面请求使用不同的限流与执行队列，防止冷启动或慢查询阻塞选举和复制。

详细字段须与 [一致性协议](consistency.md) 一起评审后生成代码；不能先把未经确定的 protobuf 当作稳定公共接口。

## 8. 兼容性验收

覆盖 prepared statements、batch、interactive transaction、savepoint、DDL、回滚、64 位整数、BLOB、NULL、SQLite 错误码、连接断开、写结果未知、重连、迁移工具以及实际 ORM 查询。对自动提交 `RETURNING`、游标和结果流注入 quorum 前失败，验证结果行及 SDK 成功返回均未提前泄露；对显式事务验证语句结果与最终提交的区别。取消响应缓存到期后再投递原提交，必须仍被 tombstone 或退休边界拒绝。

当前不默认允许跨库 ATTACH、动态原生扩展、不受控 UDF 或改变平台 WAL / 同步 / 文件布局的 PRAGMA。范围和理由见 [租户隔离](tenancy-security.md)。
