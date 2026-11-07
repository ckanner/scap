# Node.js S3 原生 HTTP SDK

这个无第三方运行时依赖的 ESM 客户端连接新的 `scap-service`，使用 `POST /v1`。它复用 [node-codec](../node-codec/README.md) 的精确 SQL 指纹及结果编解码，保留 u64 身份、i64 整数、负零、Unicode 和 BLOB；没有引入旧 Raft 协议。包目前标记 `private`，从仓库使用，尚未发布到 npm。

每次方法调用最多发出一个 HTTP 请求。SDK 不自动重跑 SQL、不换 request ID、不重新取得 epoch、不自动接管 owner，也不跟随重定向。HTTP 超时或 Abort 只能结束客户端等待，服务端可能已经提交或仍在执行。

## 使用

固定验收环境为 Node **22.16.0**。`endpoint` 是完整 API 地址，包括 `/v1`；默认接受 HTTPS，以及用于本地连接的 `127.0.0.1`、`localhost`、`[::1]` HTTP。其他明文 HTTP 必须在配置中显式设置 `allowInsecureHttp: true`。URL 中不能带凭据、查询参数或 fragment。

```javascript
import { Client, UnknownError, CommittedResultError } from './sdk/node/src/client.js';

const db = new Client({
  endpoint: 'http://127.0.0.1:8080/v1',
  token: process.env.SCAP_TOKEN,
  principal: '7',
  scope: {
    deployment: '1', tenant: '2', database: '3',
    incarnation: '1', generation: '1',
  },
});

// 只在显式创建新身份时执行；既有库丢失 HEAD 不应通过 create 修复。
const created = await db.create({ nonce: '101' });
await db.activate({ expectedRevision: created.revision, nonce: '102' });

const current = await db.status();
const request = db.prepare([
  { sql: 'CREATE TABLE item(id INTEGER PRIMARY KEY, value TEXT)', parameters: [] },
  { sql: 'INSERT INTO item VALUES (?1, ?2) RETURNING id, value', parameters: [1n, '原结果😀'] },
], { epoch: current.request_epoch, id: '103' });

// save 是纯序列化。应用应将这些字节写入自己的持久请求日志，完成同步
// 后再发送，才能在进程丢失后恢复同一身份；SDK 不代替应用持久日志。
const saved = db.save(request);

try {
  const committed = await db.execute(request);
  console.log(committed.result.statements[1].rows);
} catch (error) {
  if (error instanceof UnknownError) {
    const original = db.restore(saved);
    const resolution = await db.lookup(original);
    // unknown 不是取消：仍需按原身份继续查证，或显式调用 cancel。
    // 不要生成新 ID 后自动重做原 SQL。
    console.log(resolution.state);
  } else if (error instanceof CommittedResultError) {
    // 已核对提交回执；可能是客户端结果对象预算不足，或原生发布后不可用。
    // 保留 receipt 与可用的 rawResult，不重做已提交业务。
    console.log(error.code, error.receipt.request.id);
  } else {
    throw error;
  }
}

const result = await db.query([{ sql: 'SELECT * FROM item', parameters: [] }]);
```

`principal` 是客户端用于核对原请求的预期身份。服务端实际主体由 bearer token 的可信配置决定，并检查它与请求一致；客户不能通过修改 `principal` 切换授权身份。`scope` 的五个字段和所有 revision、nonce、epoch、ID 都使用**规范十进制字符串**，不接受 JS Number 或带前导零的字符串。

ID 必须在一个数据库的同一请求世代中唯一，所有主体共享这个命名空间。应用负责协调和持久化 ID；SDK 不把随机数碰撞概率当成唯一性保证。`prepare` 复制 BLOB 并冻结原请求，之后修改调用者的 SQL、参数数组或字节不会改变已保存的指纹。恢复时重新计算指纹、核对 scope 和 principal，拒绝被修改的保存内容。

## API

| 方法 | 输入与结果 |
| --- | --- |
| `prepare(statements, { epoch, id })` | 纯本地生成不可变 `TrackedRequest`，主体使用客户端配置 |
| `save(request)` / `restore(text)` | 保存／恢复同一请求；不发送 SQL，不分配新身份 |
| `status(options?)` | 返回当前 scope、revision、owner、生命周期、容量和请求留存边界 |
| `open(options?)` | 显式重建本地只读快照，返回 status；后续查询仍检查新的 HEAD |
| `create({ nonce }, options?)` | 显式创建，返回尚未 active 的 status；存在的身份不能覆盖 |
| `query(statements, options?)` | 强读，返回 `TransactionResult`，每个 SQL 值保持原类型 |
| `execute(request, options?)` | 只接受 `prepare`／`restore` 的原请求，成功返回 `Committed` |
| `lookup(request, options?)` | 返回 committed、cancelled、unknown、closed 或 retired |
| `cancel(request, options?)` | 在原身份上有序查证或取消；可能返回已经 committed 的原结果 |
| `activate({ expectedRevision, nonce }, options?)` | 显式完成恢复并激活当前 owner |
| `takeover({ expectedRevision, nonce }, options?)` | 显式推进 owner fence；随后仍需 activate |
| `closeFull({ expectedRevision, nonce }, options?)` | 显式关闭已满请求世代；不重做旧请求 |
| `setQuota({ expectedRevision, nonce, maxBytes }, options?)` | 页对齐字节数的十进制字符串；`null` 取消业务配额 |
| `setPolicy({ expectedRevision, nonce, permissions }, options?)` | 有界且主体不重复的 `{principal,read,write,admin}` 列表，保留管理员 |
| `setLifecycle({ expectedRevision, nonce, lifecycle }, options?)` | `ready`、`maintenance` 或 `deleted` |

`options` 只含 `{ timeoutMs?, signal? }`。`open` 和 `activate` 使用恢复预算，其他方法使用普通预算；所有等待、响应读取、解析和结果物化沿用同一个客户端 deadline。Admission header 自动区分 data、control 和 recovery，不能借控制预留提交 SQL。管理成功响应会核对 scope、`expectedRevision + 1` 与原 nonce，不接受另一个转换的 status 作为成功。

`Committed` 的形状为 `{ state: 'committed', receipt, rawResult, result }`。`rawResult` 为独立 Node Buffer，`result.statements` 保存 `{columns,rows,affectedRows,lastInsertRowid}`；整数、受影响行计数与 lastInsertRowid 为 bigint。重复列名仍占独立数组位置，不覆盖为对象属性。

## 原始结果和回执校验

客户端逐字段校验 scope、epoch、ID、principal、原 SQL 指纹、序号、转换身份及两个 SHA-256 字段。**`receipt.result_hash` 是整个 `SCAPOBJ2` Result 对象的摘要，并不是裸 `SCAPRES1` 的摘要。** 客户端按固定 v2 格式构造 metadata、长度头和原结果 bytes，以无损数字编码重算对象摘要，再解释 SQL 结果。其他 wire 版本或结构不能被猜测接受。

这项校验检查被服务端返回的数据和回执是否一致；它不是不信任服务端时的远程证明。服务端仍负责 S3 权威、当前权限与实际提交判断，传输依赖部署的 TLS 与凭据边界。

`lookup` 的 `unknown` 表示当前没有找到终态；`cancelled` 才表示原身份的取消屏障。`closed`、`retired` 表示接受空间已关闭或原结果已退休，均不能解释为该业务从未提交。`status.retention` 能读取世代留存边界，不提供承诺的墙钟保留天数。

## 错误与预算

| 结果／异常 | 含义 |
| --- | --- |
| `ClientError` | 本地输入无效、读取失败、预算或 Abort；不包含自动重放策略 |
| `RemoteError` | 经过 HTTP 状态与协议核对的服务器错误；`outcome: 'unresolved'`，例如 FENCED、CONFLICT、WINDOW_FULL |
| `UnknownError` | 有副作用调用的传输／响应不确定，或原请求查证不可用；保留只含身份的 `reference` |
| `CommittedResultError` | 已有核对后的提交回执，结果物化失败、deadline 超过或 native publication 不可用；保留 receipt，完整原 bytes 可用时保留 rawResult |

未验证的 HTTP 200、意外 201、重定向、重复 JSON 键、非法 UTF-8、不完整响应、伪造回执、摘要不符都不能产生成功 ACK。异常不保留服务器的任意 message、任意 fetch 错误文本、bearer token 或原 SQL。`save` 的内容包含 SQL 和参数，应用应按业务数据保护它。

默认普通超时 30 秒、恢复 30 分钟，请求和响应 wire 各最多 96 MiB；构造参数可收紧，不能高于 wire 能力上限。响应限制施加在实际解压后的字节流，`Content-Length` 也先做界限检查。HTTP 表示包含 JSON/base64 开销，因此它和 SQL 原始字节预算不同；预算是逻辑准入限制，不是进程 RSS 硬隔离。

`resultLimits` 收紧 [node-codec 的持久格式解析能力](../node-codec/README.md)，`allocation` 独立设置 `{maxRows,maxValues,maxColumns}`，默认分别为 1,000,000、1,000,000、100,000。如果摘要完整通过后只因客户端物化预算不足而失败，事务仍是 committed，可保留 `rawResult` 后显式调用导出的 `decodeResult(raw, limits, allocation)` 选择更合适的预算；不能重发业务作为读取结果的方法。

## 验证入口

```bash
# unit-only：默认新建独立 profile 目录，也可由调用方提供空目录。
npm --prefix sdk/node test

# 独立的真实 loopback Fetch：重定向不转发凭据、流式超时、解压预算。
# 它不向单元 profile 补覆盖，也不冒充 SQLite／S3 测试。
npm --prefix sdk/node run test:http
```

`npm test` 同时执行 Node 内置 100% 行／函数／分支阈值与 raw V8 gate。后者自动发现每个生产 JS 模块，检查完整 function/range map，拒绝缺失模块、重复 profile、空分母、非法或零命中 counter；负对照同门禁运行。`.d.ts` 是无可执行代码的类型声明，明确分类，不掩盖 JS 源。传入已有 `coverage-*.json` 的目录会被拒绝，防止混入集成运行或旧样本。

真实 Rust HTTP／S3 数据库联调由[服务实验](../../experiments/object-service/README.md)另行记录，确认最终冻结候选的回执、原结果、权限、故障和恢复。SDK 单元或 loopback Fetch 成功均不能替代该验收。
