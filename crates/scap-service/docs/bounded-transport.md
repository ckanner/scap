# TCP 连接与 HTTP/1 header 边界

## 范围

`scapd` 在原有鉴权、body intake、scheduler 与 native worker 之前增加连接边界。
实现位于 [transport.rs](../src/transport.rs)，配置通过 [config.rs](../src/config.rs)
进入实际 [daemon](../src/daemon.rs)。本文件说明实现合同；候选源码身份与运行结果必须
分别记录，不能继承其他提交的覆盖或真实网络通过记录。

连接是未鉴权资源，计数按一个 daemon 的 listener 共享。现有 data、control、recovery、
catalogue 与 discovery 的应用准入预算继续独立；连接层不知道可信 tenant 或最终 operation。
同一端口全部连接额度被占用时，control 请求也需要等待连接名额，不声称它能绕过 TCP 饱和。

## 配置

顶层 `transport` 可以省略，省略时使用下列固定 v1 默认值。显式对象必须提供全部字段；
未知字段、缺字段、未知版本及超出边界的数值均返回启动 `CONFIG` 错误。
直接调用 `daemon::serve(Prepared, ...)` 同样先验证，再创建 S3 客户端及 worker。
仅构建 router/state 的 `assemble` 不打开 TCP；自建 listener 的库调用者须自行承担连接合同。

```json
{
  "transport": {
    "version": 1,
    "max_connections": 128,
    "max_headers": 64,
    "max_header_bytes": 16384,
    "max_buffer_bytes": 32768,
    "header_timeout_ms": 5000,
    "response_timeout_ms": 30000,
    "shutdown_timeout_ms": 30000
  }
}
```

| 字段 | 允许范围 | 计量对象 |
| --- | --- | --- |
| `max_connections` | 1–4096 | 正在运行及已完成但尚未 join 的连接任务总数 |
| `max_headers` | 1–256 | 一个请求的 header 数量 |
| `max_header_bytes` | 1–65536，且不大于 `max_buffer_bytes` | 包含 request line 的完整 header 字节数；同时约束 chunked trailer 大小 |
| `max_buffer_bytes` | 8192–1048576 | Hyper HTTP/1 缓冲策略配置 |
| `header_timeout_ms` | 1–60000 | 从开始读本次 header 到读完整段 header 的时间窗口 |
| `response_timeout_ms` | 1–86400000 | handler 产出响应后，完成 body 和实际 socket flush 的绝对时间窗口 |
| `shutdown_timeout_ms` | 1–86400000 | 停止 accept 后所有连接 graceful drain 的共同绝对时间窗口 |

这些值不缩小 SQL 输入、业务结果 wire、数据库配额或 body intake 上限。
它们明确限制运输层请求头；额外代理 header 也计入大小及数量。默认 16 KiB 请求头可以
容纳现有最大 1024 字节 Bearer token，但调用方仍须核对整段 header。

## 接纳、协议与所有权

只有 `JoinSet::len() < max_connections` 时才调用 accept 并生成 Tokio 连接任务。
没有“先生成任务、再等 semaphore”的队列，也没有后台积累的未回收 JoinHandle。
满额时暂停 accept；内核 backlog 中的连接不进入用户空间 handler。因此，TCP connect
成功不能证明 daemon 已经接纳或执行请求。backlog、socket 内核内存另有操作系统边界，
本配置不声称对它们逐字节计费。

listener 沿用 Axum 对 accept 错误的重试政策。HTTP 继续运行在 daemon 原有两个 Tokio
runtime 线程上；连接层不生成任意 OS 线程，不改变 SQLite worker 的线程归属。
连接结束、I/O 错误或连接任务 panic 都会在同一 JoinSet 回收；错误连接不阻止其他连接继续服务。

实际协议使用固定 Hyper 1.12.0 的 `server::conn::http1::Builder`，显式安装
`TokioTimer`，不使用 auto builder，不启用 upgrades。S3 客户端即使经 Cargo feature
合并启用 HTTP/2，也不能把入站 listener 变成 HTTP/2 服务。反向代理的后端连接应使用 HTTP/1。

完整 header 必须在一个固定时间窗口内到达，后续单字节输入不重置窗口。
首次 header、keep-alive 后的下一次 header 和闲置等待都受到这一机制约束。
超出 header 字节或数量时，Hyper 在应用派发前返回 431 并关闭连接；header 读取超时
可以返回 408 或直接关闭。协议层错误不是 SCAP JSON 业务响应，不能要求它包含业务 receipt。
HTTP/2 preface 在这一入口被拒绝。

`writev(true)` 让 Hyper 保留应用提供的 Bytes 队列，避免 flatten 策略复制整个响应帧后
过早销毁原 Bytes owner。[现有 intake 绑定](intake-reservations.md)因此继续随最后一个
未发送 Bytes 持有者存活。大响应帧仍可以大于 `max_buffer_bytes`，该配置不是响应字节池。

## Deadline 与关闭

header 完成后仍由原 handler 在进入时记录 `received`；body 读取、解析、排队和 worker
共用既有绝对 deadline，recovery 也不重新起算。运输层不延长业务 deadline，不提交 SQL，
也不添加重试、回滚或身份替换。

发送期限从 handler 产出响应开始，SQL 执行和长时间恢复仍使用原业务 deadline；等待
handler 期间不会启动发送计时。期限直到 body 已销毁、Hyper 的最后排队 frame 已写入
底层 I/O 且 flush 成功后才解除。仅仅 `Body::is_end_stream()`、取出最后一个 frame 或
客户端读走一个字节都不会提前解除或重置期限。分块响应中间的 flush 和数据间歇也不续期。
keep-alive 后的新响应有新的发送窗口；若 pipeline 的多个响应尚有共同未 flush 的字节，
它们沿用这批字节中最早的期限，不能用后一个响应延长前一个。

实现给每个响应 body 增加一个销毁观察，并在原始 AsyncWrite 的成功 flush 处核对是否
已无存活 body；它不转移或退款业务预算。固定 Hyper 1.12 的 flush 在其 write queue
排空后才到达底层 I/O。`writev` 继续传递原 Bytes；响应期限到达时丢弃实际连接 future，
其 body、排队 Bytes 和底层 socket 随真实所有权释放，再 join 回收连接名额。这里的
flush 只证明数据交给 socket，不证明对端应用已经完整收到响应。

关闭信号先停止 accept、销毁 listener，再通知现有连接调用 Hyper graceful shutdown。
所有连接共享一个不续期的 shutdown 窗口；提前完成的正常回收，到期仍存在的连接统一
abort 并逐项 join，不能留下 detached task。响应发送期限在 graceful drain 期间继续生效。
之后 daemon 按原有顺序销毁请求 runtime，再 join/drop 实际 S3/native worker。
因此连接 drain 有界；不合作的同步/native worker 仍可能延迟整个进程退出，不能把这个
窗口宣称为所有数据库工作可强制终止的保证。

连接超时、半截响应或断连不证明事务未提交，也不撤销已经派发的 Job 或 S3 请求。
客户端保留原请求身份并查证，不自动重放 SQL。running Job 的 intake/WorkHold 独立
存活到实际工作结束；已知提交的 receipt 也不会因传输关闭而被改写为未提交。客户端
最多只能以完整且通过既有 SDK 校验的响应认定成功，截断响应保持 UNKNOWN。

显式 `transport` 对象现在必须同时提供两项新字段；省略整个对象仍采用默认配置。
旧的不完整显式对象返回 CONFIG，避免在部署时悄悄选取发送/关闭政策。
这些期限依赖 Tokio 任务获得运行机会，不是可抢占任意同步代码的硬实时保证。
独立 control listener 尚未实现；它仍不能绕过同端口的 TCP 连接饱和。

## 不能由本实现推导的结论

`max_connections × max_buffer_bytes` 不是进程 RSS 上限。Hyper 的分配容量、应用 response
frame、JSON、原生 SQLite、TLS、线程栈和内核 socket 都不能从这两个数推算为已经计费。
连接数和请求 header 上限不构成总体吞吐、租户 CPU 隔离、响应字节预算或生产抗攻击证明。

## 验证入口

[单元测试](../src/transport/tests.rs)使用内存 DuplexStream 和暂停的 Tokio 时钟，覆盖
接纳饱和、回收、首次/keep-alive deadline、parser 大小和数量边界、trailer、h2 拒绝、
连接失败、慢响应 Bytes 所有权、drip/分块响应的绝对发送期限、keep-alive 与长 handler
隔离、空 body/HEAD、最早 pipeline 期限、I/O 失败及有界 graceful drain。它们进入正式
Rust unit 四维覆盖。

[真实 TCP 实验](../../../experiments/bounded-transport/README.md)另启实际 `scapd`，使用原始
socket 验证用户空间接纳、header deadline、431、h2 拒绝和 owned child 回收。
真实实验不产生 unit profile；其只调用 `/healthz`，不表示 S3、数据库提交或总 RSS 已验收。
