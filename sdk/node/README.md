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

每次方法调用在任何排队或网络探测之前生成 request ID、复制参数并固定 deadline。每个调用使用独立 libSQL client，不让并发调用共享可变请求头。配置中的所有 endpoint 必须服务同一数据库身份。

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

`lookup` / `resolveOrCancel` 要求原 ID 和原 SQL/参数，指纹由服务端重新计算。已提交结果会返回原始结果和序号；取消不会撤销已提交事务。保留结果的查询重新验证当前权限。调用方提供 `requestId` 时，只能复用到完全相同的业务操作。只读 `query` 不登记 accepted-write 结果，不能以其 ID 查询出一次写提交。

`await db.status()` 使用受鉴权的强一致元数据查询，返回 `revision: bigint`、`suspended`、`cold`、`ownerActive` 和 `archivedRevision: bigint | null`。该操作不构建 SQLite writer，不使冷库恢复；可以用于验证归档和休眠状态。

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
