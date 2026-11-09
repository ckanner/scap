# 原始 Fetch 的受限传输观测

这是实际 HTTP 夹具的诊断 sidecar，不是 SDK 的重试、路由、超时或结果协议。
`client_ledger.mjs` 仍对每个原始 SDK 调用只执行一次收到的 Fetch，并原样传入
URL、options 和 signal；不会因传输失败再发送 POST。已有 `http-client-ledger.jsonl`
的请求／完整回复分母不变。新的 `http-client-transport.jsonl` 只帮助解释失败发生在哪个
可观察阶段，不能把原来的 `TRANSPORT`、`UNKNOWN` 或未完成验收改成成功。

## 解决的证据缺口

旧 ledger 只有 `await response.clone().arrayBuffer()` 成功后才记录 `http_response`。
缺少这条记录只证明没有完整克隆回复体，不能证明 Fetch 没有收到响应头。原 SDK 隐去
任意底层错误文本，避免凭据和 URL 泄露；本片保留这个产品行为。

新增事件区分 `fetch_started`、`fetch_response_headers`、`fetch_body_started` 和
`fetch_body_complete`。失败记录原阶段 `fetch`、`response_headers`、`body` 或 `evidence`。
`evidence` 表示完整克隆体之后写证据出错，不应归因为网络。证据写入成功时，原 Fetch／
body 错误对象仍向调用者抛出；若 catch／finally 的同步写入失败，夹具证据错误可能覆盖
它并使本轮失败。观测本身不根据诊断改写产品结果。原 ledger 的完整回复字节、SHA-256、调用 ID 和原一次尝试仍是
独立协议 oracle 的输入；sidecar 不参与已有结果 oracle 的放行条件。

## 关联与数据边界

固定 Node 22.16.0 随带 Undici 6.21.2。本实现订阅这些官方 diagnostics channel：

| Channel | 唯一允许的关联／读取 |
| --- | --- |
| `undici:request:create` | 当时的 `AsyncLocalStorage` 原调用上下文和 request 对象身份 |
| `undici:client:sendHeaders` | 已绑定的同一 request 与 socket 对象身份 |
| `undici:request:headers` | 已绑定 request、100–599 的整数 status |
| `undici:request:trailers` | 已绑定 request；不读取 trailers |
| `undici:request:error` | 已绑定 request、受限错误名称和代码 |

`AsyncLocalStorage.run` 只包围收到的原 Fetch。request 绑定一旦创建就不改变；后续
diagnostics 必须携带同一 request 对象。没有上下文或没有原绑定时不按最近调用、时间、
URL、origin 或地址推断归属。没有实际诊断关联时，结束事件明确给出
`request_identity: UNKNOWN` 或 `connection_identity: UNKNOWN`。

`sendHeaders` 的官方 payload 同时含敏感 headers；实现完全不读取它。也不订阅无法
唯一归于一次请求的 beforeConnect／connected／connectError。每个已关联 socket 只装
一次 `end`、`close`、`error` 监听器，不调用写入、销毁、连接、超时或地址 API。
`socket_close` 只带 connection ID，不绑定最近调用；不同原调用可观察到相同 connection
ID。`socket_observed` 是首次观察，不是 TCP 建连时刻。`socket_end` 是 Node 可读侧 EOF
事件，不是网络包记录。observer 停止时仅移除监听器，不关闭 socket，也不把剩余连接
计数当成泄漏或仍然存活的证明。

错误只读取 `name`、`code`、`cause.code`，且必须精确命中源码中的固定集合。集合外的
字符串、非字符串、缺失或抛异常的 getter 都记为 `UNKNOWN`。不记录 error.message、
stack、headers、token、URL、path、origin、地址或任意异常文本。事件名、阶段和原因均
由夹具源码固定；status 是受限整数，ID 是夹具生成的有限字符串。timestamps 来自
`process.hrtime.bigint()`；它们是进程内观察时刻，不能反推 TCP 包发送时刻或 daemon
内部 deadline。任何一条 sidecar 都不能证明没有其他未观察到的连接行为。

## 有界暂存与失败

| 暂存对象 | 固定上界 | 超出后的行为 |
| --- | ---: | --- |
| 单调用普通事件 | 64 | `call_event_limit`，该调用 `INCOMPLETE` |
| 单调用 request 身份 | 8 | `call_request_limit`，拒绝新的关联并标记 |
| 单调用 connection 身份 | 8 | `call_connection_limit`，额外关联记 `UNKNOWN` |
| 单 connection 事件 | 16 | 独立 `connection_event_limit` 标记 |
| 同时安装 listener 的 socket | 128 | `active_connection_limit`，额外身份记 `UNKNOWN` |
| 待写事件 | 1024，加一个独立 overflow 标记 | `pending_event_limit`，observer 和受影响调用 `INCOMPLETE` |

request 和 socket 对象索引用 WeakMap；每个 call 的数组／集合有上述上界，监听器的
强引用表也有上界。缓冲写出在正常 ledger 边界或 observer 停止时执行。diagnostics
回调不做 fsync，避免把同步文件 IO 插入 Undici 的请求内部；写证据仍可能增加整个夹具
的时间开销，因此这不是生产吞吐测试。出错的 batch 保留到同步写入成功，不因失败重写
不断扩大暂存。证据写入失败使夹具失败；不会以缺失证据宣称完成。overflow 标记和最终
observer 状态都必须保留；不能仅引用某个 `RECORDED` 行忽略全局 `INCOMPLETE`。
异常复用已绑定 request 或已关闭 socket 身份也会显式标记，不转移到下一调用。

## 有限测试与验收状态

`test_client_ledger.mjs` 使用受限 fake Fetch、受控 ReadableStream、官方 channel 的
合成发布和 EventEmitter socket 替身。覆盖一次原调用、参数／signal 保留、收到头后
阻塞／失败、原异常重抛、允许码／隐私 getter、并发 ALS 身份、socket 复用与独立 close、
所有暂存上界和失败写入。它不监听 TCP、不连接 S3，也不证明真实 Undici 调度。

```sh
node --test experiments/object-service/test_client_ledger.mjs
```

冻结时：上述测试 **NOT_RUN**；实际定向连接诊断 **NOT_RUN**；原 HEAD5 discovery
`4329f30-01` 仍 **FAILED**。其六次原分页回复之后的第七次调用在约 39.27 ms 产生
`TRANSPORT`，原证据只有 TypeError，不能区分 Fetch 失败与克隆 body 失败。没有原 socket
身份／EOF／安全 cause code，不能归因为 keepalive timeout 或 daemon 崩溃。

固定 Hyper 1.12.0 的源码表明：完整请求头解析后清除本次 header timer；同连接下一轮
读取需本次 service／回复 IO flush 完成，因此不能把上一条约 4 s handler 的等待直接
算进下一条 header timeout。进入 keepalive idle 后，下一轮 header timer 可以在尚无
新请求字节时启动，所以当前配置也限制闲置连接。客户端不同的池内 socket 可以分别
到期。这些是源码行为，不是对原失败根因的观察证明。

官方依据：

- [Undici 6.21.2 DiagnosticsChannel](https://github.com/nodejs/undici/blob/v6.21.2/docs/docs/api/DiagnosticsChannel.md)
- [Undici 6.21.2 request 发布点](https://github.com/nodejs/undici/blob/v6.21.2/lib/core/request.js)
- [Node 22.16.0 AsyncLocalStorage](https://github.com/nodejs/node/blob/v22.16.0/doc/api/async_context.md)
- [Node 22.16.0 net.Socket 事件](https://github.com/nodejs/node/blob/v22.16.0/doc/api/net.md)
- [Hyper 1.12.0 HTTP/1 connection 状态机](https://github.com/hyperium/hyper/blob/v1.12.0/src/proto/h1/conn.rs)
- [Hyper 1.12.0 HTTP/1 dispatch](https://github.com/hyperium/hyper/blob/v1.12.0/src/proto/h1/dispatch.rs)
