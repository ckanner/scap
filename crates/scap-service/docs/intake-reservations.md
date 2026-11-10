# HTTP 请求准入与实际工作生命周期

本批实现给 `/v1` 的 data、control、recovery 和 `/v1/catalogue` 各自建立独立的
共享准入池。主体来自鉴权结果；同一 `(deployment, tenant)` 的不同凭据和 principal
共享租户额度。请求头中的 admission 仍必须与实际解析出的 operation 一致。

## 预留与释放

读取请求 body 前，同时检查全局请求数、租户请求数、全局 body 字节和租户 body 字节。
一次失败不会插入租户记录或留下部分额度；操作只持有短锁，不等待网络或 SQLite。
此时每个请求预留 `max_body_bytes`。完整有界读取成功后，退还未使用的 body extent。
已用 extent 保守保留到该请求的最后持有者释放，不能因解析结束推定工作已经完成。

同一租约绑定原可信主体和固定入口类别，只能派发一次。它随队列中的 Job 进入实际
worker。HTTP 超时、客户端断开或结果接收方消失，不会提前释放正在执行的工作。
队列中已取消的请求只有在实际移除时才释放。关闭队列和 worker unwind 也按真实所有权
释放额度，不延长原 deadline、不重新执行 SQL。

HTTP body 和它发出的每个数据 frame 继续携带租约。最后一个 `Bytes` clone 或非空
slice 仍持有原响应数据时，额度继续占用；不能只在上层 body drop 时退款。
空闲租户记录在最后一个请求释放时删除，拒绝请求不会使租户表无限增长。

## 配置兼容与明确边界

现有 `data_intake`、`control_intake`、`recovery_intake`、catalogue 的 `intake`
继续表示各类全局请求数，`max_body_bytes` 继续表示单个请求 body 上限。
本批不缩小单请求上限。新增 profile 可省略；省略时使用固定 **version 1** 兼容值：

| 字段 | 缺省值 |
| --- | --- |
| `requests_per_tenant` | `max(1, 全局请求数 / 2)`，整数除法 |
| `body_bytes` | `min(全局请求数 × max_body_bytes, 256 MiB)` |
| `body_bytes_per_tenant` | `min(全局请求数 × max_body_bytes, 128 MiB)` |

单请求最大值仍为 128 MiB，因此这些缺省值至少能容纳一个最大 body。
这会限制同一租户同时占满所有全局名额；需要不同并发度的部署可显式配置。
三个普通入口分别使用 `admission.data_profile`、`admission.control_profile`、
`admission.recovery_profile`，目录入口使用 `catalogue.intake_profile`。
例如在既有 `data_intake = 8`、`max_body_bytes = 1048576` 的配置中：

```json
{
  "version": 1,
  "requests_per_tenant": 2,
  "body_bytes": 8388608,
  "body_bytes_per_tenant": 2097152
}
```

上面的对象作为 `admission.data_profile` 的值。显式 profile 必须完整，拒绝未知字段。
租户请求上限须在 1 与既有全局请求上限之间；两种字节上限均至少容纳单个最大 body，
租户字节上限不得大于全局字节上限。配置错误在打开监听器前拒绝。

`/v1/discovery` 保持独立的固定准入域：全局两项、每租户一项、每请求 64 KiB body，
其实际 worker 与响应原有租约继续生效。普通入口不能借用 discovery 或其它类别的额度。

## 这些计数证明什么

本批计费的是**请求数和原始 body extent**。它不声称限制 JSON/typed request 图、
原生 SQLite allocator、结果图、Base64/JSON 响应转换、最终响应总字节、TCP/header 缓冲、
私有磁盘或整个进程 RSS。响应携带的是本请求的准入租约，不能把它称为独立响应字节池。
这些独立预算按[资源设计](../../../docs/architecture/resource-budgets.md)分别实现与验证。

直接调用内部 `Scheduler::submit` 的可信 Rust 调用方仍遵守 scheduler 原有队列界限；
HTTP 的 body 准入保证只适用于经过本次 HTTP 入口和 `submit_reserved` 的路径。
未来新增 owner 入口必须另行接入，不能靠复用旧配置自动获得本合同。

## 原生结果图的独立配置

服务配置可额外给出 `"execution": { "result_memory_bytes": 134217728 }`。
省略 execution 时，默认每次操作的 typed Rust 结果图预算为 128 MiB。
这个字段控制容器、Value、字符串/BLOB capacity 及扩容重叠的结果物化预算，
由 `ServiceConfig.options` 传入实际 Engine 与 catalogue 对象选项。
它不改变 50 MiB 新执行结果、64 MiB 持久格式或已有数据库配额，也不限制 SQLite
allocator、HTTP response 或总体 RSS；并发操作仍分别拥有自己的结果图预算。

预算必须至少容纳 `TransactionResult` 本身；更小的配置在读取凭据和启动服务前拒绝。
由于这是本地物化预算，管理员可以调小或调大，但不能据此把合法保留结果判为损坏。
原生收集或 codec 分配不足映射到 `LIMIT`；已有提交证明的结果物化失败，仍保留原
receipt 并遵守 `COMMITTED_BUT_UNAVAILABLE`。lookup/cancel 的原结果字节查证不重放 SQL。
Discovery 的元数据分页不物化 typed SQL 结果图，因此仍使用其独立固定预算合同。

## 验证范围

生产实现位于 [intake.rs](../src/intake.rs)、[HTTP](../src/http.rs)和两个 scheduler。
本批单元覆盖原子预留、计数与字节独立拒绝、checked addition、同租户换凭据、不同部署、
poisoned lock、最后引用、一次派发，以及实际 HTTP body 尚未 poll 时的拒绝。
受控 worker 测试覆盖 data/control/recovery/catalogue 超时后继续执行和队列取消，
并沿用 frame/clone/slice 的真实 `Bytes` 所有权测试。

测试源码存在不等于门禁通过。完整本地单元、精确覆盖、真实 TCP/S3 合同及其源身份
以最终验收记录为准；本文件不继承 PR #35 或其它历史 tree 的测试结果。
