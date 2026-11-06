# Node.js 对象原生协议编解码基础

这是 S3 主线的独立客户端基础模块，不是完整数据库 SDK 或服务。它实现既有 Rust `SCAPSQL1` 精确请求指纹和 `SCAPRES1` 原始结果读取，不改变服务器格式、10 GiB 默认配额、HEAD/CAS、权限、取消或 ACK 语义。

模块仅使用 Node 内置库，没有 npm 依赖，包标记 `private`，未发布到 npm。自测固定 Node **22.16.0**，不是声明此版本为最新部署建议。当前没有 HTTP、重试、凭据、目录路由、会话或 S3 调用。现有 Rust 原生修复 PR 的门禁仍独立保留，不能用 Node 测试替代。

## API

```javascript
import { fingerprint, validateResult, decodeResult } from './src/codec.js';

// 参数使用 Rust 对应的显式类型；整数用 bigint。
const hash = fingerprint([{ sql: 'SELECT ?1', parameters: [42n] }]);
// hash 为精确原 SQL 与有序 typed 参数的 SHA-256，不是 Request ID 或认证凭据。

// raw 是未来可信传输返回、已经核对 scope/request/receipt/hash 的原结果字节。
// 本模块只负责编码语法，不核对 HEAD，不决定事务成功。
const raw = Buffer.from('534341505245533100000000', 'hex');
validateResult(raw);                  // 不保留结果行图，成功返回 undefined。
const parsed = decodeResult(raw);     // { statements: [] }
```

三个函数均为同步纯编解码，不访问网络或文件。不得把 `fingerprint` 的成功当成授权或提交，不能把 `decodeResult` 失败解释成原事务没提交并自动重做 SQL。

### 参数与结果类型

| JavaScript | Rust / wire | 约束 |
| --- | --- | --- |
| `null` | Null | 不把 undefined 当作 null |
| `bigint` | Integer / i64 | 精确支持 -2^63 到 2^63-1，越界拒绝 |
| `number` | Real / f64 | 必须有限；42 与 42n 指纹不同，保留 -0 |
| `string` | Text / UTF-8 | 拒绝孤立 UTF-16 surrogate，不静默替换；值中 NUL 可保留 |
| `Uint8Array` / Buffer | BLOB | 尊重视图 offset/length；拒绝 SharedArrayBuffer；解码返回独立字节副本 |

SQL 文本不可为空或含 NUL，空参数数组必须显式给出。请求指纹不规范化 SQL 空白、不重排参数，返回 64 位小写 hex。

解码结果形状为 `{ statements: [{ columns, rows, affectedRows, lastInsertRowid }] }`。SQL 整数、`affectedRows` (u64)、`lastInsertRowid` (i64) 始终是 `bigint`，避免经过 JS Number 丢失高位。列名和行均为数组，不把重复列名覆盖成对象属性。UTF-8 的初始 U+FEFF 和 NUL 保留，BLOB 不尝试当作文本。

返回结构含 bigint，不能直接 JSON.stringify 当作下一层网络协议；未来 HTTP 协议必须显式定义无损整数编码。不得在适配层静默转成 Number。

## 两类预算

导出的 `FORMAT_LIMITS` 对齐 [`durable_sql_limits`](../../crates/scap-object/src/options.rs) 的持久格式能力，并包含 64 MiB 完整请求指纹编码预算。它不是今天 SQL 新请求的准入默认值。可传第二个参数收紧，但不能提高格式能力、使用非整数/零值或未知参数。

- `maxStatements` 65,536；`maxSqlBytes` 64 MiB；`maxParameters` 32,766。
- `maxColumns` 每语句 2,000；`maxRows` 整事务 u32 最大值。
- `maxResultBytes`、`maxValueBytes`、`maxInputBytes` 各最多 64 MiB。

`validateResult` 不构造结果行集合或复制 Text/BLOB，但游标视图和数值解析仍有少量分配；它不是整个进程零分配或硬内存隔离的保证。

`decodeResult` 另外接受第三个参数的本地对象图预算：默认总行数 1,000,000、值单元数 1,000,000、列名总数 100,000。列名也单独预算，避免许多零行语句绕过行/值预算。所有分配预算必须为正整数，最高 u32；提高时由调用方承担资源成本。这些预算不改变数据库容量、格式或历史结果的合法性。

格式合法但超出本地对象图预算的结果会返回 `LIMIT`，调用方可保留原字节、用验证模式检查或显式选择更合适的读取策略，不能因此重新执行原写事务。实际输入 Buffer 已经存在，内存/并发隔离、网络体限额和 streaming 尚未实现。

## 错误

`CodecError.code` 为 `INVALID`、`LIMIT`、`MALFORMED`。分别表示调用/类型或有限值违规、明确预算不足、非法/不完整 wire。有限 Number、UTF-8、计数、零列非零行、截断和尾字节均严格检查；不猜测格式、不剥除多余尾字节、不自动恢复。

这些错误没有提供 `Committed`、`Cancelled`、`Closed` 或 `Retired` 裁决。S3 结果查证、当前权限及请求身份必须由服务端现有统一路径决定。

## 本轮已执行验证

```bash
npm --prefix sdk/node-codec test
```

Node 内置 test runner 执行 **13 个测试，0 failed / skipped / cancelled**；单一生产模块的行、分支、函数均为 **100%**，并独立检查原始 V8 function/range 记录没有零命中。无网络 mock，也未下载安装 npm 包。

用例包含 main 的[独立 Rust v1 固定向量](../../crates/scap-sql/src/tests.rs)、全部有符号整数边界、u64 计数、负零/BOM/UTF-8/BLOB、256 组确定生成数据与测试专用独立编码器对照、完整截断、计数炸弹、每个类型/预算边界及逐位置 256 种字节替换。

逐字节对照执行的是本模块的语法验证和解码加测试专用重编码；**没有执行 Rust，不是原生跨语言差分、S3 联调或完整 SDK 验收**。新网关未来接线必须再用实际 Rust 编解码、真实认证及 S3 数据库验证原始 Request/Receipt/结果路径。

CI 为该无依赖模块设独立 job，固定 Node 版本，先执行内置三维 100% 阈值，再按 `src` 清单核查实际 V8 报告。缺失模块、重复不明报告、空分母或零命中拒绝通过。它不改变或填补 Rust 覆盖率分母。
