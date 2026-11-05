# SCAP Node.js 客户端

此目录是尚未发布 npm 的本地 TypeScript 包，固定使用 `@libsql/client` **0.18.0**、其锁定的 Hrana 客户端和 Node.js **24**。`npm ci` 后运行 `npm run build`；应用可以从 `dist/client.js` 引入。正式协议实现见 [`scap-service`](../../crates/scap-service/README.md)。

## 调用方式

```ts
import { createClient, ScapError } from "./dist/client.js";

const db = createClient({
  endpoints: ["http://127.0.0.1:8011", "http://127.0.0.1:8012", "http://127.0.0.1:8013"],
  database: "agents",
  authToken: process.env.SCAP_TOKEN!,
  timeoutMs: 2000,
});

await db.execute("CREATE TABLE IF NOT EXISTS agents(id INTEGER PRIMARY KEY, name TEXT)");
await db.execute({ sql: "INSERT INTO agents VALUES (?, ?)", args: [1n, "example"] });
const result = await db.query({ sql: "SELECT name FROM agents WHERE id = ?", args: [1n] });
console.log(result.rows[0].name);
db.close();
```

`execute` 与 `batch` 沿用 libSQL 的常用输入/结果形式；64 位整数统一使用 `bigint`，BLOB 返回 `ArrayBuffer`。`query` 明确选择新的 ReadIndex 和只读 SQLite 事务，服务端拒绝其中的写操作。普通第三方 `@libsql/client.execute("SELECT ...")` 仍进入写事务兼容入口，需要相应权限并保留事务结果。

不需要封装时，可直接使用固定版本的 `@libsql/client/http`，URL 为 `http://host:port/db/agents/`。此方式没有 SCAP 的每次调用稳定身份、原始 deadline 和多副本探测封装；业务不得对断连后的未知写进行盲目重放。

## 故障与请求身份

每次方法调用在任何排队或网络探测之前生成 request ID、捕获 `requestEpoch`、复制参数并固定 deadline。每个调用使用独立 libSQL client，不让并发调用共享可变请求头。配置中的所有 endpoint 必须服务同一数据库身份。

`/readyz` 只是选择候选节点的提示。只有服务端明确返回 **NOT_LEADER，且保证尚未提案**时，客户端才会在原 deadline 内使用同一 ID 尝试下一个配置地址。网络失败、超时、COMMIT_UNKNOWN、响应超限或身份不匹配均停止自动写尝试。客户端不跟随 HTTP redirect，也不向探测请求附带数据库凭据；实际请求必须保持在选定 origin 和数据库路径内。

```ts
try {
  await db.execute({ sql: "INSERT INTO events VALUES (?)", args: ["business-key"] });
} catch (error) {
  if (!(error instanceof ScapError)) throw error;
  const outcome = await db.lookup(error.request);
  // unknown 仅表示一次线性化查询时未找到记录，不能推断该写永远不会提交。
  // 明确决定放弃时，调用 db.resolveOrCancel(error.request) 建立有序终态。
  console.log(outcome.state);
}
```

`lookup` / `resolveOrCancel` 要求原 ID、原请求世代和原 SQL/参数，指纹由服务端重新计算。已提交结果会返回原始结果和序号；取消不会撤销已提交事务。保留结果的查询重新验证当前权限。调用方提供 `requestId` 时，只能复用到完全相同的业务操作。只读 `query` 不登记 accepted-write 结果，不能以其 ID 查询出一次写提交。

所有普通方法未传 `requestEpoch` 时**固定使用 `1n`**。旧保存身份缺失该字段时也固定为一，调用 `lookup`、`resolveOrCancel`、`acknowledge` 时传入的 options 不能覆盖身份中的原世代。客户端不在错误、路由重试或查询之后隐式刷新世代；服务端响应如回显不同世代，同样视为不确定结果，不重放写。

`await db.status()` 使用受鉴权的强一致元数据查询，返回 `revision: bigint`、`suspended`、`cold`、`ownerActive` 和 `archivedRevision: bigint | null`，以及 `baseRevision`、`tailEntries`、`tailBytes: bigint | null` 三个物理恢复计数。旧服务完全未提供这三个字段时统一返回 `null`，不会将未知水位伪装成零；部分缺失或非法值会拒绝解析。新服务返回精确 u64 计数，Cold 状态的尾部计数为零，保留的基座 revision 不代表镜像字节当前驻留。该操作不构建 SQLite writer，不使冷库恢复；可以用于验证归档和休眠状态。

结果保留状态另外返回 `requestEpoch`、`retainedRequests`、`unacknowledgedRequests`、`retiredRevision: bigint | null`。旧服务全部缺少这四个字段时统一返回 null；部分缺失和非法值拒绝解析。新的业务请求可以显式使用 status 给出的世代，已存在的请求始终使用原身份。

## 应用确认结果后回收请求窗口

`executeTracked(statement, options?)` 和 `batchTracked(statements, mode?, options?)` 返回 `{request, result}`。`result` 保持原 libSQL 结果类型，`request` 包含原 `requestId`、`requestEpoch` 和已复制的 statements。这两个方法相较普通 `execute` / `batch` 不增加 RPC，也不会自动确认结果；非初始世代的变更仍会对每个候选节点执行一次 status 能力核验，探测与实际请求共享原 deadline。原 `execute` / `batch` 返回类型保持不变。

以下是单个写请求的显式确认流程。`saveProcessedResult` 代表应用自己的持久处理步骤，需由业务实现：

```ts
const status = await db.status();
if (status.requestEpoch === null) throw new Error("服务不支持结果退休协议");
const completed = await db.executeTracked(
  { sql: "INSERT INTO events VALUES (?)", args: ["business-key"] },
  { requestEpoch: status.requestEpoch },
);

await saveProcessedResult(completed.request, completed.result);
const terminal = await db.lookup(completed.request);
if (terminal.state === "committed" || terminal.state === "cancelled") {
  await db.acknowledge(completed.request, terminal);
}
```

`acknowledge(request, terminalOutcome)` 必须给出已知终态：committed 使用原 sequence，cancelled 使用原精确 `{term,index}`。成功返回 void。取消结果来自旧服务且缺失 position 时会显示 `position: null`，不能作为确认凭据；unknown 和 retired 也不能确认。服务端仍会核对当前权限、原指纹与终态证明。

只有应用已持久处理并确认**该库所有保留请求**后，具有 ADMIN 权限的客户端才可执行 `const nextEpoch = await db.rotateRequests(expectedEpoch)`。调用方显式把 `nextEpoch` 用于下一批新请求。未确认结果、错误世代或其他状态机拒绝不会变成成功；超时或网络错误不会自动重发轮转。可用新的 status 判断当前世代，再决定后续管理操作。

轮转永久拒绝旧世代的写入，并让旧 lookup 返回 `{state: "retired", currentEpoch}`。这不是未提交证明，也不能据此给未知业务操作换新世代重试。`acknowledged` 的含义是应用主动放弃该结果的后续保留要求；SDK 不会在结果交给应用之前替它做这个决定。多客户端共享数据库时，需要协调窗口轮转并处理当前窗口仍未确认的其他客户端结果。

当前服务对部分原生 SQL 执行错误采用保守的 `COMMIT_UNKNOWN`，不承诺完整透传 SQLite 扩展错误码。应用若依赖约束错误的特定代码，需要显式查证终态并按当前支持的错误合同调整。

支持范围为位置参数、单语句 execute/query，以及 SDK 生成的自包含原子 batch。暂不支持 named args、interactive `transaction()`、cursor、WebSocket、embedded replica、`migrate()` 的 PRAGMA 切换或完整 ORM 兼容承诺。服务端会在 SQL 开始前拒绝不支持的协议程序。

## 验证

```bash
npm ci --ignore-scripts
npm test
```

单元测试使用真实固定 SDK 和受控 HTTP 端口，不启动真实数据库。c8 对全部 `dist/**/*.js` 收集 V8 计数并映射回 TypeScript，检查全部语句、行、函数、分支均为 100%；源码映射缺失或新增文件未覆盖不能作为通过。`--test-isolation=none` 明确在同一进程串行运行测试，确保测试内对默认 fetch 的替换可控，并使 V8 profile 完整落盘。

真实服务契约使用独立命令，不进入单元 profile：

```bash
export SCAP_ENDPOINTS='["http://127.0.0.1:8011","http://127.0.0.1:8012","http://127.0.0.1:8013"]'
export SCAP_DATABASE=agents
export SCAP_TOKEN='local-test-credential'
npm run test:integration
```

调用方必须先启动真实三副本 SCAP 服务；缺少配置会失败。该测试包含原生 SDK batch、整数/BLOB、事务回滚、原随机结果去重、无提交历史的强读、丢失成功响应后的明确查询、取消 fence 和权限拒绝。进程重启、网络分区与 S3 故障由外层真实集群测试另行调度，不由此脚本伪造。

## 上游依据

查询日期：2026-11-02。版本和完整性由 [package-lock.json](package-lock.json)固定；协议实现对照官方 [HTTP client](https://github.com/tursodatabase/libsql-client-ts/blob/main/packages/libsql-client/src/http.ts)、[Hrana batch](https://github.com/tursodatabase/libsql-client-ts/blob/main/packages/libsql-client/src/hrana.ts)及 [Hrana HTTP stream](https://github.com/libsql/hrana-client-ts/blob/main/src/http/stream.ts)。实际兼容验证使用安装的固定 npm 包源码，不以未来上游 main 的行为替代。
