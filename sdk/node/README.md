# Node.js S3 原生 HTTP SDK

这个无第三方运行时依赖的 ESM 客户端连接新的 `scap-service`。`Client` 使用 `POST /v1`，`CatalogueClient` 使用 `POST /v1/catalogue`。它复用 [node-codec](../node-codec/README.md) 的精确 SQL 指纹及结果编解码，保留 u64 身份、i64 整数、负零、Unicode 和 BLOB；没有引入旧 Raft 协议。包目前标记 `private`，从仓库使用，尚未发布到 npm。

原 `Client`、`CatalogueClient`、`DiscoveryClient` 的每次方法调用最多发出一个 HTTP 请求。可选 `RoutedClient` 先读取 fresh status，再派发至当前 owner，仍最多发送一个业务 SQL 请求。`OwnerPlanClient` 逐次执行持久 owner 计划，支持 prepare 响应丢失后的原输入查证；旧 `OwnerClient` 保留 HEAD8 之前的显式 takeover 与 activation 流程。SDK 不自动重跑 SQL、不换 request ID、不重新取得 epoch，也不跟随重定向。HTTP 超时或 Abort 只能结束客户端等待，服务端可能已经提交或仍在执行。

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
| `guardedStatus(workerInstance, options?)` | 一个只读 status POST，同时要求接收服务实例匹配指定 worker；HEAD 的 owner 可以是另一个 worker |
| `open(options?)` | 显式重建本地只读快照，返回 status；后续查询仍检查新的 HEAD |
| `create({ nonce }, options?)` | 显式创建，返回尚未 active 的 status；存在的身份不能覆盖 |
| `query(statements, options?)` | 强读，返回 `TransactionResult`，每个 SQL 值保持原类型 |
| `execute(request, options?)` | 只接受 `prepare`／`restore` 的原请求，成功返回 `Committed` |
| `lookup(request, options?)` | 返回 committed、cancelled、unknown、closed 或 retired |
| `cancel(request, options?)` | 在原身份上有序查证或取消；可能返回已经 committed 的原结果 |
| `activate({ expectedRevision, nonce, expectedWorkerInstance? }, options?)` | 显式完成恢复并激活当前 owner；可校验接收进程身份 |
| `takeover({ expectedRevision, nonce, expectedWorkerInstance? }, options?)` | 显式推进 owner fence；随后仍需 activate；可校验接收进程身份 |
| `closeFull({ expectedRevision, nonce }, options?)` | 显式关闭已满请求世代；不重做旧请求 |
| `setQuota({ expectedRevision, nonce, maxBytes }, options?)` | 页对齐字节数的十进制字符串；`null` 取消业务配额 |
| `setPolicy({ expectedRevision, nonce, permissions }, options?)` | 有界且主体不重复的 `{principal,read,write,admin}` 列表，保留管理员 |
| `setLifecycle({ expectedRevision, nonce, lifecycle }, options?)` | `ready`、`maintenance` 或 `deleted` |

`options` 只含 `{ timeoutMs?, signal? }`。`open`、`activate`、`compactCopy`、`gcPrepare`、`gcResume` 和 `ownerResume` 使用恢复预算，其他方法使用普通预算；所有等待、响应读取、解析和结果物化沿用同一个客户端 deadline。Admission header 自动区分 data、control 和 recovery，不能借控制预留提交 SQL。旧单阶段管理响应会核对 scope、`expectedRevision + 1` 与原 nonce；持久 owner 计划按下述固定 descriptor、准入与历史 phase 校验。

`Committed` 的形状为 `{ state: 'committed', receipt, rawResult, result }`。`rawResult` 为独立 Node Buffer，`result.statements` 保存 `{columns,rows,affectedRows,lastInsertRowid}`；整数、受影响行计数与 lastInsertRowid 为 bigint。重复列名仍占独立数组位置，不覆盖为对象属性。

## 显式物理代压缩与 GC

`status()` 还返回物理 `head_serial` 和有界 `storage` 状态。`storage.terminal` 是必填字段，
未退休时为 `null`，退休后为 `{serial}`；新 SDK 需与提供该投影的服务一起部署。
`scope.generation` 仍是原逻辑
身份；业务 receipt、请求 ID 和原结果 hash 不随物理搬迁改变。六个管理员方法均只有一次 POST：

| 方法 | 含义 |
| --- | --- |
| `compactBegin({expectedHeadSerial})` | 固定完整源闭包、分配新物理代，返回带原 plan serial 的 inactive status |
| `compactCopy({planSerial})` | 复制、回读校验并封口同一 plan；使用恢复预算 |
| `compactPromote({planSerial})` | 将封口目标发布为新 A，保持 inactive；不自动 activate |
| `compactAbort({planSerial})` | 中止原 plan；已分配目标不复用 |
| `gcPrepare({expectedHeadSerial,generation,after})` | 最多扫描 32 项，安装原 ETag checkpoint，不执行 DELETE |
| `gcResume({batchSerial})` | 按同一持久 batch 继续退休代条件删除；不接任意 key 或新 ETag |

这里的 `generation` 是物理代；`after` 必须显式为 `null` 或上一页返回的 64 位小写 hash。
GC 返回 `SweepReport {status,generation,scanned,next_after,exhausted}`，checkpoint 摘要位于
`status.storage.sweep`。整页 inspect 都是 Missing 时，scanned 可以大于零而没有 checkpoint；
`exhausted` 只说明本次 LIST 遍历边界，不保证退休 prefix 永久为空。

```javascript
const before = await db.status();
const begun = await db.compactBegin({ expectedHeadSerial: before.head_serial });
const planSerial = begun.storage.plan.serial;
// 应用先持久保存 scope、planSerial、source 和 target，再继续明确的阶段。
await db.compactCopy({ planSerial });
const promoted = await db.compactPromote({ planSerial });
// 新 owner 仍 inactive。明确决定后，按当前 owner 协议接管/激活，不自动发送 SQL。
const page = await db.gcPrepare({
  expectedHeadSerial: promoted.head_serial,
  generation: begun.storage.plan.source,
  after: null,
});
if (page.status.storage.sweep !== null) {
  // 应用先保存原 batch serial，再明确继续一次有界删除批。
  const batchSerial = page.status.storage.sweep.serial;
  console.log(await db.gcResume({ batchSerial }));
}
```

新方法的 UnknownError.reference 保存 `expectedHeadSerial` / `planSerial` / `batchSerial`、
`storageGeneration` 和 `after` 中实际使用的原条件。先显式 `status` 查证；不自动更换 serial
重发。`SNAPSHOT_EXPIRED`、`GC_DISABLED` 和 `GC_UNSUPPORTED` 保留为未决的 RemoteError。
快照过期不是业务请求窗口的 RETIRED，不授权重做已提交 SQL。

服务默认不授予 GC，需配置与普通读写身份分离的固定 namespace 凭据。当前没有 retained
snapshot/持久 reader pin；未退休 Deleted 的最后 active 代仍受保护。完整 HTTP 字段、
32 项预算、重启/UNKNOWN 处理及部署约束见[服务文档](../../crates/scap-service/docs/reclamation.md)。

## 删除后的显式存储退休

逻辑删除后，普通 SQL、`lookup` 和 `status` 仍返回生命周期错误。专用管理入口只查询
Deleted 元数据，或发布不可逆的终态存储屏障；两者都要求 fresh HEAD 的当前 ADMIN。

| 客户端 / 方法 | 输入与结果 |
| --- | --- |
| `Client.storageStatus(options?)` | 直接创建库的 Deleted `DatabaseStatus`；使用 control 准入 |
| `Client.retireStorage({expectedHeadSerial}, options?)` | 同一直接创建库的终态 status；使用 control 准入 |
| `CatalogueClient.storageStatus(creation, options?)` | 核实原 Creation 后返回 Deleted status；使用 catalogue 准入 |
| `CatalogueClient.retireStorage({creation,expected_head_serial}, options?)` | 同一命名库的终态 status；使用 catalogue 准入 |

直接入口只适用于没有目录 Creation 的库。命名库要保留原 Creation，使用目录客户端；
当前管理员可以不同于 creator，也不要求 provision。目录入口不会把已重用的名称解析成
另一个新库。四个方法都使用普通请求预算，每次最多一个 POST。

```javascript
const deleted = await db.storageStatus();
const original = { expectedHeadSerial: deleted.head_serial };
// 应用先持久保存 scope 和 original，再显式授权退休。
const terminal = await db.retireStorage(original);
console.log(terminal.storage.terminal.serial);

// 命名库先保存可恢复的原管理意图；此处 catalogue 为 CatalogueClient。
const named = await catalogue.storageStatus(creation);
const intent = catalogue.prepareIntent({
  operation: 'retire_named_storage',
  creation,
  expected_head_serial: named.head_serial,
});
const saved = catalogue.saveIntent(intent);
// 应用持久保存 saved 后，才发送这一次原意图。
const retired = await catalogue.submit(catalogue.restoreIntent(saved));
```

成功要求 `terminal.serial === head_serial === 原 expected serial + 1`。封口只推进物理序号，
保持原业务 revision、请求身份、结果与目录删除意图不变；它不会执行 SQL 或对象 DELETE，
也不要求启用 GC。已存在 seal 或 serial 不符返回 `CONFLICT`，不能把冲突当作旧调用未发生。
所有终态响应都严格要求 `M < terminal.serial <= head_serial` 和 `revision < terminal.serial`；
后续 checkpoint 的 serial 也必须晚于 seal。
`UnknownError.reference` 在直接调用中保存 `expectedHeadSerial`，在目录调用中保存完整
`intent.action`。UNKNOWN 后显式调用对应的 `storageStatus` 查证，不自动更换 serial 重发。

seal 之后，既有 `gcPrepare` / `gcResume` 才能扫描已分配代中的最后一个 A。GC 继续使用
独立凭据、recovery 准入、最多 32 项的原 ETag checkpoint；seal、A 和 M 永不回退，永久 HEAD
与目录证明不被删除。一轮 `exhausted` 不代表 prefix 永久为空，迟到旧 PUT 仍需后续扫描。
HEAD7 终态接口需要新候选的独立原生/HTTP/S3 验收，不能沿用 HEAD6 的通过结论。

## 受信 owner 路由

`RoutedClient` 使用本地静态 endpoint 白名单，每次 `execute/query` 都先向 bootstrap 读取当前 status。
它不接受服务端提供的新 URL，不把 token 转发给未知 owner，也不发起接管。bootstrap 和所有 route
必须绑定同一受信 S3 authority、scope 和 bearer 主体；配置本身不是写权，真正的权限与 owner
仍由目标服务的 fresh HEAD 准入和条件发布决定。

```javascript
import { RoutedClient, RouteError, UnknownError } from './sdk/node/src/client.js';

const routes = [
  { workerInstance: '1001', endpoint: 'https://worker-a.example/v1' },
  { workerInstance: '1002', endpoint: 'https://worker-b.example/v1' },
];
const routed = new RoutedClient({
  bootstrapEndpoint: 'https://worker-a.example/v1', routes,
  token: process.env.SCAP_TOKEN, principal: '7', scope,
});
const current = await routed.status();
const request = routed.prepare([
  { sql: 'INSERT INTO item VALUES (?1, ?2)', parameters: [2n, 'fixed input'] },
], { epoch: current.request_epoch, id: '301' });
const saved = routed.save(request);
// 应用持久化 saved 后，执行这一调用。
try {
  await routed.execute(request, { timeoutMs: 10000 });
} catch (error) {
  if (error instanceof RouteError) {
    // outcome=not_sent：本次没有调用底层 Fetch 派发业务 SQL。
    // 它不能证明同一 request 在其他调用中从未发送或提交。
    console.log(error.code);
  } else if (error instanceof UnknownError) {
    console.log(await routed.lookup(routed.restore(saved)));
  } else throw error;
}
```

`prepare/save/restore/status/lookup/cancel` 与原 `Client` 语义相同；`lookup/cancel` 直接使用 bootstrap，
不等待 owner 恢复。`query` 在等待路由前复制调用者 SQL 和参数，允许 Maintenance 强读；
`execute` 要求 Ready、active 的 owner。未知 owner 返回 `UNROUTABLE`，未激活写 owner 返回
`OWNER_INACTIVE`；它们不会触发 takeover。路由后 owner 变化产生的 FENCED、CONFLICT、
STALE_SNAPSHOT、SNAPSHOT_EXPIRED 或 UNKNOWN 直接返回，不刷新路由后重发业务。

每个 registry 至多 256 项，每项输入 endpoint 至多 2048 字节，总规范地址与 worker 字符串
至多 64 KiB。重复 worker 或 endpoint 拒绝。构造器复制 scope、route 和结果预算，调用者之后
修改配置对象不改变已构造客户端；变更路由须构造新客户端。SDK 内部只保存固定地址，不动态
发现成员或在多个 bootstrap 之间自动重试。

bootstrap 不属于管理目标映射的 digest：原 bootstrap 不可用时，应用可以明确构造使用另一
受信 metadata endpoint、相同 worker routes/scope/principal 的 `OwnerClient`，恢复并只读查证原意图。
这不恢复派发资格；任何 worker endpoint 绑定变化仍会使原意图的上下文检查失败。

一次 routed 调用最多包含一个 status POST 和一个 SQL POST。二者共用调用开始时的总 deadline，
包括同步编码和结果物化；底层 Fetch 前再次检查绝对期限，因此编码耗尽预算后不会继续派发。
已经派发后的异常仍保留原 UNKNOWN 或已核对的 committed 回执。

## 持久 owner 计划与原输入恢复

`OwnerPlanClient` 使用 HEAD8 的持久 descriptor、HEAD marker 和不可变终态 proof。
每次 prepare、inspect、observe、claim、resume 或 abort 都最多一个 POST，没有自动阶段循环。
所有操作都要求数据库的当前 ADMIN；这里不把创建计划的 `creator` 当成当前调用者，也不以
历史成功替代当前 ACL。命名库可以使用已核实的原完整 Scope；不得在恢复途中按名字重新解析
并把旧计划发送给一个新库。

新 `DatabaseStatus.owner_plan` 是必填字段：未接受过持久计划的库返回 `null`；首次 claim
或 Cancelling 发布后一直保留非空 marker。旧服务缺少这个字段会被拒绝，需配套部署新 SDK
与服务。marker 包含 `reference`、`admission` 和 `phase`；descriptor 的原 HEAD ETag/hash
由服务持久保留，客户端不会获得换一个 ETag 重试的接口。

```javascript
import { OwnerPlanClient } from './sdk/node/src/client.js';

const ownerV2 = new OwnerPlanClient({
  bootstrapEndpoint: 'https://metadata.example/v1',
  routes: [
    { workerInstance: '1001', endpoint: 'https://worker-a.example/v1' },
    { workerInstance: '1002', endpoint: 'https://worker-b.example/v1' },
  ],
  token: process.env.SCAP_ADMIN_TOKEN,
  principal: '7', scope: db.scope,
});
const before = await db.status();
const original = ownerV2.prepareInput({
  creator: '7', operation: '201',
  expected_revision: before.revision,
  expected_head_serial: before.head_serial,
  mode: 'takeover', target_worker: '1002',
  nonces: { claim: '202', cancel: '203', activate: '204', abort: '205' },
});
const saved = ownerV2.saveInput(original);
// 应用必须先把 saved 持久写入并同步自己的管理日志，再发第一次请求。
const preparation = await ownerV2.prepare(original);
if (preparation.state === 'prepared') {
  // 以下是显式授权的两次操作，库内部不会自动调用下一步。
  const claimed = await ownerV2.claim(preparation.prepared);
  console.log(claimed.state, claimed.status.owner_instance);
  const resumed = await ownerV2.resume(preparation.prepared, { timeoutMs: 120000 });
  console.log(resumed.state, resumed.status.active);
}

// UNKNOWN 或客户端重启后的另一条显式恢复路径：
const restored = ownerV2.restoreInput(saved);
const inspected = await ownerV2.inspect(restored);
console.log(inspected.state, inspected.accepted, inspected.status);
// 应用根据已核对的当前状态和授权决定是否再调用一次 resume 或 abort。
// inspect 本身不 claim、不恢复 SQLite、不执行 SQL，也不分配新 operation。
```

`prepareInput` 是纯同步操作，复制并冻结 Scope、完整原输入和四个非零互异 nonce。
`saveInput` 返回最多 16 KiB 的版本化 JSON；应用负责持久化和日志完整性。输入中不保存 URL、
bearer token 或 server 计算的 descriptor hash。允许另一位当前 ADMIN 在新的可信 bootstrap
恢复同一日志。显式 takeover 可以保持相同 worker 数值并推进 owner epoch；activate 模式
只允许原 base 的未激活 owner，目标不能改变。

| 方法 | 单次行为及返回 |
| --- | --- |
| `prepareInput(input)` / `saveInput(input)` / `restoreInput(text)` | 纯本地保存或恢复完整原 `PrepareOwnerInput`，不联系服务 |
| `prepare(savedInput, options?)` | bootstrap 上一次 `owner_prepare`；返回 `prepared` 或独立 `pending` 状态 |
| `inspect(savedInput, options?)` | 按原 creator/operation 一次 `owner_inspect`，再逐字段核对实际 descriptor 的完整 input 与 Scope |
| `observe({creator,operation}, options?)` | 只读历史；返回普通 `OwnerRecord`，不授予后续 SDK mutation brand |
| `claim(prepared, options?)` | 在固定 target 的本地受信 route 上一次 `owner_claim`，必填 worker 实例校验 |
| `resume(prepared, options?)` | 同一 target、同一原 plan reference，一次 `owner_resume`；使用 recovery 准入及恢复总预算 |
| `abort(prepared, options?)` | bootstrap 上一次 `owner_abort`；不要求旧 target 仍可路由，不把取消请求当作已完成取消 |

准备结果为 `{state:'prepared', prepared:{scope,input,reference}}` 或
`{state:'pending', reference}`。Pending 指向当前阻塞新准备的 accepted plan，可以属于另一位
creator 和另一个 operation；不表示本次输入已准备成功，也不能直接传给 claim。
prepare 响应全部丢失时，应用依然有发送前保存的原输入：
`inspect(restored)` 只用 creator/operation 查询，核对服务返回的真实 descriptor，而不要求客户端
事先知道 hash。同一身份对应另一份输入会被拒绝；不会根据今天的新 revision 重建旧计划。

其它响应均为 `OwnerObservation {state,status,prepared,accepted}`。六种 state 分别是
`prepared`、`claimed`、`cancelling`、`active`、`aborted` 和 `fenced`。`accepted` 是历史 marker，
可以早于今天的 status：历史 Active 不代表当前 active、当前目标进程拥有 native Session，
也不把原 UNKNOWN 改写成当时已经收到 ACK。Fenced 且 accepted 为 null 只说明不能再按旧 base
取得新准入、过去结果仍未知；绝不是 NotApplied。当前 marker 被新计划覆盖后，旧终态 proof
的 R/S 必须严格早于新 marker 的 admission；SDK 还检查原 input、reference、phase nonce、
counter reserve、phase 顺序和 storage/lifecycle 互斥，拒绝矛盾投影。
同一 HEAD 的业务 revision 仍等于 phase.revision 时，transition.nonce 必须等于
phase.nonce；只增加技术 head_serial 不解除这个约束。较晚的业务 revision 可以有新的
transition nonce，不能据此改写原历史 phase。

只有 `prepare` 的 Prepared 结果，或者 `inspect(savedInput)` 完整核对后的结果，能传给
claim/resume/abort。纯 history、反序列化的任意 reference 和 Pending 都不能绕过该检查。
这个不透明 brand 是 SDK 防误用机制；真正的授权仍由服务的当前 ADMIN、原 descriptor、原
HEAD ETag、目标 worker 与条件发布共同决定。SDK 不把它当成凭据或防篡改签名。

`Client` 也提供同样的一次 POST 低层方法：`ownerPrepare(input)`、`ownerInspect(input)`、
`ownerObserve(identity)`、`ownerClaim(prepared)`、`ownerResume(prepared)`、`ownerAbort(prepared)`。
前两者接受完整原输入；claim/resume 自动从已经核对的 Prepared 中派生必填的
`expected_worker_instance`。低层 Client 使用固定 endpoint，不替调用者挑 route。

UNKNOWN 保存原 `scope`、`operation` 及适用的 `ownerInput` / `ownerIdentity` / `ownerPlan`、
`expectedWorkerInstance`，不保留 token 或任意服务端错误文本。普通超时默认为 30 秒，resume
默认为 30 分钟；路由、发送、读取和解码共用原 deadline。超时不撤销已 invoked 的 CAS、
恢复或 SQL；旧请求结果仍按原业务 request 身份 lookup/cancel，绝不由 owner 协调重放。

服务端的 descriptor/proof 留存、Cancelling 两阶段关闭、旧 owner 永久拒绝、原 ETag 绑定和
资源上限见[持久 owner 计划设计](../../docs/architecture/accepted-owner-plan.md)。SDK 单元和
loopback Fetch 通过不等于原生/S3 故障验收通过；最终候选的实际验收单独记录。

## 旧 owner 协调与保存意图

`OwnerClient` 与业务客户端独立配置，凭据必须被数据库当前 ACL 明确授予 **READ+ADMIN**：
status 使用 READ，takeover/activate 每次重新检查 ADMIN。SDK 不隐式增加权限，也不检测 owner
是否死亡。接管健康 owner 是一个明确的管理员操作，不能放在普通 execute 的失败重试分支。
这一接口只用于尚未接受持久 owner 计划的库。一旦 `owner_plan` 非空，SDK 不再生成新的旧式
intent，旧意图 inspect 返回 blocked；服务端也永久拒绝旧 owner 发布。既有 restoreIntent
仍然只能查证，不能通过 reconcile 恢复派发资格。

```javascript
import { OwnerClient, OwnerReconcileError } from './sdk/node/src/client.js';

const owner = new OwnerClient({
  bootstrapEndpoint: 'https://worker-a.example/v1', routes,
  token: process.env.SCAP_ADMIN_TOKEN, principal: '9', scope,
});
const observed = await owner.observe();
const intent = owner.prepareTakeover(observed, {
  targetWorker: '1002', takeoverNonce: '401', activateNonce: '402',
});
const savedIntent = owner.saveIntent(intent);
// 应用将 savedIntent 持久化并完成同步后，再调用 reconcile。
try {
  const active = await owner.reconcile(intent, { timeoutMs: 120000 });
  console.log(active.status.owner_instance);
} catch (error) {
  if (!(error instanceof OwnerReconcileError)) throw error;
  const original = owner.restoreIntent(savedIntent);
  const inspected = await owner.inspect(original);
  console.log(error.phase, error.outcome, error.lastConfirmed, inspected.state);
  // inspect 不改变 HEAD；这里不重新 reconcile 原意图。
}
```

| API | 合同 |
| --- | --- |
| `observe(options?)` | fresh status，只读；不创建服务端观察票据或租约 |
| `probe(workerInstance, options?)` | 在显式配置的该 worker route 上发一次 guarded status；使用普通总预算，需要 READ，不执行恢复或接管 |
| `prepareTakeover(status, {targetWorker,takeoverNonce,activateNonce})` | 纯本地固定原 revision、owner tuple、完整 scope、principal、registry digest、目标和两个不同 nonce；目标须不同于原 owner |
| `prepareActivation(status, {activateNonce})` | 只接受当前未激活 owner，保持 owner epoch；不重新接管 |
| `saveIntent(intent)` | 纯序列化，不负责持久化；保存内容不含 token，但仍含管理身份与条件 |
| `restoreIntent(text)` | 严格验证同一上下文，至多 16 KiB，恢复的意图**仅可查证** |
| `reconcile(intent, options?)` | 消耗新准备意图的一次性派发资格；fresh status 仍须匹配原观察；最多一次 takeover 与一次 activation |
| `inspect(intent, options?)` | 一个 fresh status POST；报告原转换证据或当前观测状态，不发送 CAS、恢复或 SQL |

`reconcile` 在第一次读取前就消耗派发资格，连读取失败也不会重置。重复使用或使用 restore 的
意图返回 `INTENT_USED`。这防止进程丢失后把“保存了描述”误解为“从未发送”；它不是持久管理
操作账本，也不阻止管理员明确创建另一个新意图。所有 u64 增量在发送前校验，绝不回绕。

协调内部总是给 takeover 和 activate 发送 `expected_worker_instance`。服务在已有 bearer 与
scope 准入后、任何 S3、cache 或恢复动作前检查实际接收进程的 `worker_instance`；不匹配返回
`TARGET_MISMATCH`（409）。这可拒绝错绑地址或重启后的旧 route，不能证明原 owner 已死亡。
服务端仍用原 `expected_revision` 与同一次 fresh HEAD 的 ETag 发布；新字段不创建额外 fencing。
路由地址仍应指向单一启动实例；普通 SQL 路由竞争由原 owner 检查拒绝。

`probe` 可以检查候选接收实例，例如 `await owner.probe('1002')`。它只使用已配置的可信 route，
不先访问 bootstrap；无对应 route 时在网络派发前返回 `UNROUTABLE`。正确的接收实例仍会读取
fresh HEAD 并检查 READ，所以返回的 `owner_instance` 可以属于另一台 worker。探测成功只证明
此次身份核对与元数据读取成功，不证明当前 owner 已失效、SQL/恢复可用或旧 UNKNOWN 已被关闭。
失败不触发备用地址、takeover、activate 或 SQL。整个 `probe` 共用进入调用时的普通绝对期限，
包括本地路由、编码、响应读取和校验；不会采用更长的 recovery 默认值。

旧 `status()` 请求保持不带 guard。新 `guardedStatus` / `probe` 不在旧服务拒绝该字段时自动重发
无 guard 请求。可选字段若显式传入 `null`、`0` 或非规范文本，服务会拒绝为 `INVALID`；SDK 也
在派发前检查规范非零十进制 worker。详见[guarded status 合同](../../docs/architecture/owner-guarded-status.md)。

每一阶段只有经过 revision、nonce、owner、epoch、active、lifecycle 的完整核对才推进下一步。
`OwnerReconcileError` 保留原 intent、`phase` 和 `lastConfirmed`；其 `outcome` 区分本次未派发
管理动作的 `not_sent`、明确返回错误但未证明原结果的 `unresolved`、已确认 claim 的 `partial`、
阶段结果不确定的 `unknown`，以及已核对 activation 但总预算超时的 `active`。这些都不授权 SQL 重放。

`inspect.state` 的 `takeover_accepted`、`activation_accepted` 要求原转换所有字段精确匹配。
`target_active/target_inactive` 只证明此时看到的目标 owner 状态，不能证明已经被后继 HEAD 覆盖的
原 nonce；`base_observed` 也不证明旧请求永远不会迟到。`superseded`、`blocked` 和 `unresolved`
分别保留取代、生命周期和无法确认的情况。旧 HEAD6/7 没有完整管理转换历史；HEAD8 的
持久计划历史使用前一节的独立接口。

发生 UNKNOWN 或重启后，若显式 `inspect/observe` 确认目标仍是当前未激活 owner，可准备一个新的
`prepareActivation` 意图，保存后明确执行。这只继续恢复，不增加 owner epoch。总 deadline 默认
采用恢复预算，status、claim、恢复和 activation 不逐步续期。没有自动 failover、后台重试、
自动故障检测或配置滚动选主。这段旧式恢复只适用于 owner_plan 为 null 的库；持久 owner
计划通过独立 OwnerPlanClient 恢复。有限 Scope 自动 controller 仍是后续工作，见
[controller 与 owner-plan 边界](../../docs/architecture/owner-controller-plan.md)和
[owner 协调设计](../../docs/architecture/owner-reconciliation.md)。

## 名称目录与完整原意图

`CatalogueClient` 的 `deployment`、`tenant`、`principal` 是应用配置中预期的服务 authority 和调用者。它们用于校验 Creation 和拒绝跨上下文 restore，不作为 HTTP 授权输入；服务端使用自己的配置与 bearer token 取得这些身份。应用须正确绑定 endpoint、凭据和预期上下文。数据库 ID 由持久创建 descriptor 分配，SDK 不生成或替换它。

```javascript
import { CatalogueClient, UnknownError } from './sdk/node/src/client.js';

const names = new CatalogueClient({
  endpoint: 'http://127.0.0.1:8080/v1/catalogue',
  token: process.env.SCAP_TOKEN,
  deployment: '1', tenant: '2', principal: '7',
});

const intent = names.prepareIntent({
  operation: 'prepare_create',
  name: 'notes', create_operation: '201', expected_name_revision: null,
  options: { quota: { mode: 'default' } },
});
const savedIntent = names.saveIntent(intent);
// 应用先将 savedIntent 持久化并完成同步，再执行下面这一次提交。
// saveIntent 本身只返回字符串，不负责磁盘、数据库或浏览器持久化。
try {
  const prepared = await names.submit(intent);
  // prepared 仅证明 descriptor 持久化，还没有承诺名字 Bound 或数据库 Ready。
  // 后续 resume 也是新的明确调用，宜保存它自己的完整原意图。
  const resume = names.prepareIntent({ operation: 'resume_create', creation: prepared.creation });
  const savedResume = names.saveIntent(resume);
  // 将 savedResume 持久化后，再执行 names.submit(resume)。
} catch (error) {
  if (!(error instanceof UnknownError)) throw error;
  const original = names.restoreIntent(savedIntent);
  const observed = await names.inspectCreateOperation(original.action.create_operation);
  // 依据明确 phase 决定下一步。not_reserved 不等于已经取消旧请求。
  console.log(observed.phase, observed.creation);
}
```

本地 `prepareIntent(action)` 复制、严格校验并深度冻结所有原条件；它不会联系服务或分配新的身份。`saveIntent` 返回版本化 JSON，包含 deployment、tenant、principal 及完整 action；`restoreIntent` 校验同一上下文、规范 u64、字段与版本，恢复后仍使用原 create/control operation、Scope、revision、nonce 和 quota choice。保存的内容不是授权证明，也不是防止存储介质篡改的签名；服务端始终与持久 descriptor、控制意图和当前权限重新比较。

| 方法 | 精确输入与结果 |
| --- | --- |
| `prepareIntent(action)` | 本地生成 `CatalogueIntent`；action 使用下列 wire 字段及 `operation`，不含外层 version、scope、tenant 或 principal |
| `saveIntent(intent)` / `restoreIntent(text)` | 保存／恢复最多 64 KiB 的完整原意图，不发请求 |
| `submit(intent, options?)` | 使用原意图发出一个版本化 POST，校验返回身份与阶段 |
| `prepareCreate({name, create_operation, expected_name_revision, options}, callOptions?)` | 创建持久 descriptor，返回 `PreparedCreate`；`expected_name_revision` 必填，首次名称用 `null`，重用需准确 tombstone revision |
| `resumeCreate(creation, options?)` | 按原 Creation 继续有限阶段，返回 `CreationProgress` |
| `abortCreate({creation, control_operation, expected_name_revision, nonce}, options?)` | 保存同一控制身份与名称条件，返回 `AbortProgress` |
| `inspectCreateOperation(createOperation, options?)` | 严格只读，按当前调用者的原 create operation 查进度 |
| `resolveName(name, options?)` | 严格只读，按当前 READ 权限返回 `{creation, binding_revision, head}` |
| `deleteName({creation, control_operation, expected_name_revision, expected_head_revision, nonce}, options?)` | 使用当前 ADMIN 和两个原预期 revision 正常删除，返回 `DeletionProgress`；调用者可不同于 creator |

六个便利方法各自在内部构造意图后发出一次 POST。需要发送前持久化时，用显式的 `prepareIntent` → `saveIntent` → `submit`。所有目录操作使用 `x-scap-admission: catalogue` 和普通调用 deadline，`callOptions` 仍只有 `timeoutMs`、`signal`；SDK 不循环推进阶段、不自动刷新预期 revision、不重新准备另一 Scope、不重投 SQL。

创建 options 固定为 `{quota: {mode: 'default'}}`、`{quota: {mode: 'unlimited'}}` 或 `{quota: {mode: 'limited', max_bytes: '4096'}}`。limited 值必须为有效页对齐十进制字节数；其他 mode 不接受 `max_bytes`。名称按原 UTF-8 字节保留，长度 1–128 字节，不接受控制字符或非法 surrogate，不做 Unicode 归一化。operation、nonce 等 u64 始终使用规范十进制字符串。应用负责在相应的部署／租户／主体命名空间分配和持久化操作 ID。

`Creation` 固定为 `{creator, operation, name, scope, expected_name_revision}`，其中 operation 永远是原创建 ID。控制响应顶层的 operation 则是原 control ID，删除者不得把 Creation.creator 改成自己。`PreparedCreate` 返回的 `initial_quota` 与 `retention` 是最初 descriptor 的策略；当前数据库 quota 仍以 fresh `head` 为准。

| 响应 | 完整阶段 |
| --- | --- |
| `CreationProgress` | `not_reserved`、`reserved`、`provisioning`、`bound`、`ready`、`aborting`、`aborted`、`deleting`、`deleted`、`name_conflict`、`identity_conflict` |
| `AbortProgress` | `not_reserved`、`cannot_abort_bound`、`aborting`、`aborted` |
| `DeletionProgress` | `not_deleted`、`deleting`、`deleted` |

所有 progress 保留 nullable `binding_revision`、`head_revision`；名称重用后属于后继 Creation 的 revision 不能当成原操作的新条件。创建进度还包含 `initial_quota` 和 `retention`；控制进度包含原 `operation` 和 `nonce`。目录的 `provisioning` phase 不会成为可供普通 SQL 操作的 DatabaseStatus。

目录 mutation 的 `UnknownError.reference.intent` 保留完整原意图。查创建用 `inspectCreateOperation`；它不证明某个 abort/delete control ID 已成功。原 abort/delete 的查证及收敛应在应用明确决定后，用保存的原完整 intent 再调用 `submit`；这可能继续尚未完成的阶段，不能当作只读查询。`NOT_FOUND`、`IDENTITY_CONFLICT`、`CONFLICT`、`DENIED`、`CORRUPT`、`LIMIT`、`UNKNOWN` 分开返回。未知或 malformed phase 拒绝，不能转成 ready/aborted/deleted。

## 原始结果和回执校验

客户端逐字段校验 scope、epoch、ID、principal、原 SQL 指纹、序号、转换身份及两个 SHA-256 字段。**`receipt.result_hash` 是整个 `SCAPOBJ2` Result 对象的摘要，并不是裸 `SCAPRES1` 的摘要。** 客户端按固定 v2 格式构造 metadata、长度头和原结果 bytes，以无损数字编码重算对象摘要，再解释 SQL 结果。其他 wire 版本或结构不能被猜测接受。

这项校验检查被服务端返回的数据和回执是否一致；它不是不信任服务端时的远程证明。服务端仍负责 S3 权威、当前权限与实际提交判断，传输依赖部署的 TLS 与凭据边界。

`lookup` 的 `unknown` 表示当前没有找到终态；`cancelled` 才表示原身份的取消屏障。`closed`、`retired` 表示接受空间已关闭或原结果已退休，均不能解释为该业务从未提交。`status.retention` 能读取世代留存边界，不提供承诺的墙钟保留天数。

## 错误与预算

| 结果／异常 | 含义 |
| --- | --- |
| `ClientError` | 本地输入无效、读取失败、预算或 Abort；不包含自动重放策略 |
| `RemoteError` | 经过 HTTP 状态与协议核对的服务器错误；`outcome: 'unresolved'`，例如 FENCED、CONFLICT、WINDOW_FULL |
| `UnknownError` | 有副作用调用的传输／响应不确定，或原请求查证不可用；SQL 保留身份 `reference`，目录额外保留完整原 `reference.intent` |
| `CommittedResultError` | 已有核对后的提交回执，结果物化失败、deadline 超过或 native publication 不可用；保留 receipt，完整原 bytes 可用时保留 rawResult |
| `RouteError` | `outcome: 'not_sent'`；本次 routed 调用尚未派发业务 Fetch，不能推断其他调用的原 request 结果 |
| `OwnerReconcileError` | 保存固定管理 intent、失败阶段及 lastConfirmed；不授权自动管理重发或业务重放 |

未验证的 HTTP 200、意外 201、重定向、重复 JSON 键、非法 UTF-8、不完整响应、伪造回执、摘要不符都不能产生成功 ACK。异常不保留服务器的任意 message、任意 fetch 错误文本、bearer token 或原 SQL。`save` 的内容包含 SQL 和参数；目录错误引用与 `saveIntent` 含名称、身份、Scope 和控制条件，应用应按业务数据保护它们。

默认普通超时 30 秒、恢复 30 分钟，请求和响应 wire 各最多 96 MiB；构造参数可收紧，不能高于 wire 能力上限。响应限制施加在实际解压后的字节流，`Content-Length` 也先做界限检查。HTTP 表示包含 JSON/base64 开销，因此它和 SQL 原始字节预算不同；预算是逻辑准入限制，不是进程 RSS 硬隔离。

`resultLimits` 收紧 [node-codec 的持久格式解析能力](../node-codec/README.md)，`allocation` 独立设置 `{maxRows,maxValues,maxColumns}`，默认分别为 1,000,000、1,000,000、100,000。如果摘要完整通过后只因客户端物化预算不足而失败，事务仍是 committed，可保留 `rawResult` 后显式调用导出的 `decodeResult(raw, limits, allocation)` 选择更合适的预算；不能重发业务作为读取结果的方法。

## 验证入口

### 自动 owner controller 实现草稿

`createControllerPolicy` 与 `OwnerController` 目前为独立开发检查点，不能继承 HEAD8 的
SQLite/HTTP/S3 验收结论。固定策略用四个 u64 nonce 无损承诺全部 SHA-256，operation
使用原 `head_serial`；每个 tick 最多 8 POST、一个持久管理阶段，不接受 SQL。
首次重启发现 Claimed 先完成只读观察，下一轮才从起点取得恢复总期限。一次 UNKNOWN
记录原输入/引用；后续成功观察不把旧调用改写为收到过 ACK。完整策略、rank、并发和
网络资源范围见[控制器设计](../../docs/architecture/owner-controller-v2.md)。

本检查点已有 policy 与单 Scope 开发单位。Fleet、默认有界 HTTP、CLI、全模块精确
单位覆盖、独立模型和真实网络合同继续实施，尚不满足合入门禁。注入普通 Fetch 的
单 Scope API 不自行证明进程 FD、后台 DNS、RSS 或整个 fleet 的资源上限。

```bash
# unit-only：默认新建独立 profile 目录，也可由调用方提供空目录。
npm --prefix sdk/node test

# 独立的真实 loopback Fetch：重定向不转发凭据、流式超时、解压预算。
# 它不向单元 profile 补覆盖，也不冒充 SQLite／S3 测试。
npm --prefix sdk/node run test:http
```

`npm test` 同时执行 Node 内置 100% 行／函数／分支阈值与 raw V8 gate。后者自动发现每个生产 JS 模块，检查完整 function/range map，拒绝缺失模块、重复 profile、空分母、非法或零命中 counter；负对照同门禁运行。`.d.ts` 是无可执行代码的类型声明，明确分类，不掩盖 JS 源。传入已有 `coverage-*.json` 的目录会被拒绝，防止混入集成运行或旧样本。

真实 Rust HTTP／S3 数据库联调由[服务实验](../../experiments/object-service/README.md)另行记录，确认最终冻结候选的回执、原结果、权限、故障和恢复。SDK 单元或 loopback Fetch 成功均不能替代该验收。
