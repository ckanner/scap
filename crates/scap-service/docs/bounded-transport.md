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
    "header_timeout_ms": 5000
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

关闭信号先停止 accept、销毁 listener，再通知现有连接调用 Hyper graceful shutdown。
每个连接继续被 poll 到响应完成并 join。之后 daemon 按原有顺序销毁请求 runtime，
再 join/drop 实际 S3/native worker。客户端断连不提前释放实际 running Job 所持的 intake 租约。

这一版保留原有 graceful 合同，没有强制 drain deadline。慢读响应仍可能长期占用一个
连接名额并延迟进程关闭。独立 control listener、write-progress timeout 和强制关闭政策
需要另外冻结行为与提交状态合同，不能以“连接数有上限”代替这些能力。

## 不能由本实现推导的结论

`max_connections × max_buffer_bytes` 不是进程 RSS 上限。Hyper 的分配容量、应用 response
frame、JSON、原生 SQLite、TLS、线程栈和内核 socket 都不能从这两个数推算为已经计费。
连接数和请求 header 上限不构成总体吞吐、租户 CPU 隔离、响应字节预算或生产抗攻击证明。

## 验证入口

[单元测试](../src/transport/tests.rs)使用内存 DuplexStream 和暂停的 Tokio 时钟，覆盖
接纳饱和、回收、首次/keep-alive deadline、parser 大小和数量边界、trailer、h2 拒绝、
连接失败、慢响应 Bytes 所有权及 graceful drain。它们进入正式 Rust unit 四维覆盖。

[真实 TCP 实验](../../../experiments/bounded-transport/README.md)另启实际 `scapd`，使用原始
socket 验证用户空间接纳、header deadline、431、h2 拒绝和 owned child 回收。
真实实验不产生 unit profile；其只调用 `/healthz`，不表示 S3、数据库提交或总 RSS 已验收。
