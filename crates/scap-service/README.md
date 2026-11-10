# S3 原生 HTTP 服务

`scapd` 把正式 `scap-object` / SQLite 提交路径接到 HTTP，支持不可变数据库 ID、可信主体鉴权、有界调度、独立强读与显式接管。它不自动重放 SQL，不用本地目录作为数据库权威；S3 不可用时热缓存也不能产生新的成功强读。

普通数据库接口以完整 `deployment / tenant / database / incarnation / generation` 标识接入；调用方必须持久保存原始身份。可选的独立 [名称目录接口](catalogue.md)使用 `POST /v1/catalogue`，协调原创建意图、同名 reservation、取消和删除；其新增实现仍须单独冻结验收。HEAD 的 key 保持单库固定以隔离旧身份，本地缓存键另包含 incarnation 和 generation，不能用缓存把两代身份混用。

## 启动

```bash
cargo build --release -p scap-service --bin scapd --locked
mkdir -p /absolute/private-cache
./target/release/scapd /absolute/scap-service.json
```

配置采用严格 JSON，未知字段和不合法整数拒绝。身份数值使用规范十进制字符串；`worker_instance` 为本次计算实例的非零独立 ID，每次重启及其他服务实例必须使用新 ID。不要复制一个仍在运行的实例 ID。重启后先查询 HEAD，再显式 `takeover` 和 `activate`；过程不依赖旧计算目录。

```json
{
  "version": 1,
  "listen": "127.0.0.1:8080",
  "transport": {
    "version": 1,
    "max_connections": 128,
    "max_headers": 64,
    "max_header_bytes": 16384,
    "max_buffer_bytes": 32768,
    "header_timeout_ms": 5000,
    "response_timeout_ms": 30000,
    "shutdown_timeout_ms": 30000
  },
  "worker_instance": "5001",
  "cache_directory": "/absolute/private-cache",
  "s3": {
    "endpoint": "https://s3.REGION.amazonaws.com",
    "region": "REGION",
    "bucket": "BUCKET",
    "access_key_env": "SCAP_S3_ACCESS_KEY",
    "secret_key_env": "SCAP_S3_SECRET_KEY",
    "session_token_env": "SCAP_S3_SESSION_TOKEN",
    "allow_http": false,
    "timeout_ms": 30000
  },
  "admission": {
    "active_database_actors": 16,
    "active_database_actors_per_tenant": 8,
    "actor_idle_timeout_ms": 60000,
    "control_workers": 2,
    "queued_total": 128,
    "queued_per_tenant": 16,
    "queued_per_database": 8,
    "reserved_controls": 2,
    "data_intake": 8,
    "control_intake": 4,
    "recovery_intake": 2,
    "max_body_bytes": 100663296,
    "timeout_ms": 30000,
    "recovery_timeout_ms": 1800000
  },
  "cache": {
    "pages_per_actor": 5242880,
    "parallel_recoveries": 2
  },
  "execution": {
    "result_memory_bytes": 134217728
  },
  "credentials": [
    {
      "sha256": "REPLACE_WITH_64_LOWERCASE_HEX_SHA256_OF_A_RANDOM_BEARER_TOKEN",
      "deployment": "1",
      "tenant": "1",
      "principal": "1",
      "provision": true
    }
  ]
}
```

示例中的占位值必须替换。没有临时 session token 时明确写 `null`。程序只读取配置中指定的环境变量，不搜索本机 AWS 配置或实例元数据。S3 单对象预算取当前持久格式上限；数据库默认 10 GiB，管理员可经 `quota` 修改或取消业务配额。可选 `execution.result_memory_bytes` 单独配置每次操作的 Rust typed 结果图预算，省略时为 128 MiB；它不改变 SQL 结果 wire 上限、持久结果格式或已有库配额。其实际 Engine 接线和失败语义见[资源边界](docs/intake-reservations.md)。

配置的 Bearer token 应为独立生成的高熵值；服务接受 32–1024 字节的可打印 ASCII token，通过固定长度 SHA-256 摘要比较映射到可信 deployment、tenant、principal 和 provisioning 权限。摘要不是 HEAD 权限替代品：每次正式数据库操作仍由当前 HEAD 授权。请求中的 `principal` 只是原请求身份的一部分，必须等于 token 对应的主体。

监听器只接受 loopback 地址。生产外部入口须由同机 TLS 反向代理终止 TLS，并转发 Authorization 和 `x-scap-admission`，不应改写响应或自动重试 POST。`GET /healthz` 只说明进程活着，不证明 S3、某个库或写入可用。配置更新通过新实例部署，不存在运行时凭据轮换或自动 owner 迁移。

入站只启用 HTTP/1。可选 `transport` 省略时使用示例中的固定 v1 默认值；显式配置需提供全部字段。
连接名额在 accept/spawn 前限制，header 有独立字节、数量及绝对读取期限；keep-alive 后的下一次
请求同样受限。配置范围、graceful shutdown、协议层 431/408 与内存声明的边界见
[TCP 与 HTTP/1 说明](docs/bounded-transport.md)。同一 listener 的连接额度在鉴权前共享，
不等于为 control 保留独立 TCP 通道，也不等于总体 RSS 或响应字节上限。

## HTTP 协议

以下数据库调用为 `POST /v1`，`Content-Type: application/json`，`Authorization: Bearer …`。重复认证或 admission 头拒绝；body 有字节上限与读取 deadline。`x-scap-admission` 必须与操作匹配，避免大 SQL 消耗控制预留。

| admission | 操作 | 总时间预算 |
| --- | --- | --- |
| `data`（可省略） | `create`、`query`、`execute` | `timeout_ms` |
| `control` | `status`、`lookup`、`cancel`、`takeover`、`close_full`、`policy`、`quota`、`lifecycle` | `timeout_ms` |
| `recovery` | `open`、`activate` | `recovery_timeout_ms` |

两种时间预算都从最初接收请求时开始；body 读取仍须在短预算内结束，排队也占用原预算。数据库内部更短的操作期限继续有效。HTTP 超时或响应消失不表示 SQL 已回滚。

```json
{
  "version": 1,
  "scope": {
    "deployment": "1", "tenant": "1", "database": "42",
    "incarnation": "1", "generation": "1"
  },
  "operation": "status"
}
```

`create` 还需非零 `nonce`，仅允许 provisioning 凭据；成功后库处于未激活状态。`activate`、`takeover`、`close_full`、`policy`、`quota` 和 `lifecycle` 必须给出 `expected_revision` 与 `nonce`；冲突或 UNKNOWN 不会被服务自动换 revision 重发。

`activate` 和 `takeover` 可额外给出非零规范十进制字符串 `expected_worker_instance`。
在 bearer 与 scope 准入之后，Engine 将其与实际接收进程的启动身份比较，不匹配返回
`TARGET_MISMATCH`（409），此时尚未访问 S3、改变 cache 或获取恢复额度。字段省略时保留
原显式接口行为；显式 `null`、零或非规范值拒绝。该 guard 用于防止静态 route 错绑或实例重启，
不是 owner 租约，也不替代当前 ADMIN、原 expected revision 与 same-HEAD ETag 条件发布。
Node `OwnerClient` 的协调步骤总是提供这个 guard，参见[SDK](../../sdk/node/README.md)。

`open` 显式重建独立的本地快照，返回与 `status` 相同的结构，不改变 HEAD、owner 或数据。它可用于预热独立 reader，也用于刷新 stale session；下一次 query 仍会重新读取 HEAD，不能把 open 当作长期授权或最新根保证。`activate` 在验证完整恢复闭包后，按原 revision 发布 owner 激活。

`query` 与 `execute` 使用 `statements: [{sql, params}]`。每个参数为显式对象：`{"type":"null"}`、`{"type":"integer","value":"42"}`、`{"type":"real","bits":"8000000000000000"}`、`{"type":"text","value":"…"}` 或 `{"type":"blob","base64":"…"}`。Real 的 bits 是大端书写的 16 位小写十六进制 IEEE-754 位图，保留负零；不接受非有限实数。整数、Base64 与十六进制都采用规范唯一编码。

`execute` / `lookup` / `cancel` 的 `request` 包含 `epoch`、`id`、`principal`（均十进制字符串）与 `fingerprint`（64 位小写 SHA-256）。服务重新计算 execute 的精确原 SQL/类型参数指纹。ID、世代与指纹必须保持原值，不能在网络失败后自行分配新请求重做随机 SQL。

成功响应为 `{"ok":true,"value":…}`。query 的 value 含 `result`，为原始 `SCAPRES1` 的 Base64；execute 的 value 为 `state: "committed"`、`receipt` 和 `result`。lookup/cancel 返回明确的 committed、cancelled、unknown、closed 或 retired。receipt 的 `result_hash` 是完整持久 Result 对象 envelope 的摘要，不能直接按 SQL 结果字节摘要核对。

错误为 `{"ok":false,"error":{"code":"…","message":"…","receipt":…}}`。error message 只返回稳定代码，不包含 SQL、对象端点、凭据或内部原生错误。`COMMITTED_BUT_UNAVAILABLE` 可附带已持久化回执；所有不确定状态均使用原身份查证。客户端实现见 [Node SDK](../../sdk/node/README.md)。

## 并发与资源边界

SQL / 恢复请求按固定 HEAD key 定位专属 actor；同一库的 SQLite 会话在同一线程创建、恢复、调用和销毁。`active_database_actors` 与 `active_database_actors_per_tenant` 分别限制全实例及每租户的活跃库数，actor、control worker 加固定一个 reaper 的总数最多 256。首次访问在限额内懒创建 actor；容量满时新库返回 `BACKPRESSURE`，已有热 actor 继续运行。空闲达到 `actor_idle_timeout_ms` 后线程自行关闭 Session；固定 reaper 在请求路径之外等待旧线程完整退出，再释放槽位。慢 native / TLS 析构只延迟旧槽位回收，提交请求本身不执行 join。

全局、每租户、每 HEAD 的排队预算跨所有 actor 与 control lane 统一计算，`queued_total` 不随线程数倍增。`reserved_controls` 预留只允许真正 control 请求使用，`open` / `activate` 不得挤占。actor 内的 priority burst 最多三次后让排队 SQL 前进；独立 control worker pool 在租户及数据库间轮转。`lookup`、`cancel` 及元数据转换不占 SQL / 恢复执行线程。严格 JSON 拒绝原 `workers` / `queued_per_worker` / `sessions_per_worker` / `pages_per_worker`，应显式迁移配置。

HTTP 的 data、control、recovery 与 catalogue 各有独立 intake 池；鉴权后、读取 body 前，原子预留全局与租户的请求数及 body 字节。相同租户换凭据不能增加配额；完整读取后退还未用 body extent。租约贯穿实际排队、worker、响应 body 及其发出的最后字节，HTTP 超时也不提前释放仍在执行的任务。配置兼容值、显式 version 1 profile 和精确资源边界见[准入说明](docs/intake-reservations.md)。底层 HTTP 在发出最后一帧后可先销毁 body，传输缓冲中的字节及其 clone／slice 仍持有配额，慢客户端不能靠这个生命周期差异提前释放名额。绑定不会复制响应 payload。执行开始后，即使客户端断开，worker 也只完成该次原请求；它不会回滚一个已发布 HEAD，也不会重做 SQL。尚未开始且接收端已消失的排队请求会被丢弃，超出原 deadline 的排队请求不会执行。

每个 actor 最多保留一个完整 scope 的 Session，`pages_per_actor` 按操作完成后的实际页面数决定缓存保留；失败 session 不复用。此阈值不预留恢复期间所需磁盘，单库超过阈值时会在操作后丢弃 Session。`parallel_recoveries` 限制全实例同时下载完整数据库。SQLite cache 与 HTTP/队列限额不是进程 RSS 或文件系统总量硬隔离；typed JSON、编码结果及原生 SQLite 仍可能有额外内存开销。

一个库的冷恢复不再阻塞另一热库的执行线程，但所有线程仍共享 S3 客户端、CPU、磁盘和网络；本批不是这些资源的硬隔离，也不增加单库多写者、并发 reader pool 或 group commit。活跃库数受线程上限约束，详见[执行隔离设计](../../docs/architecture/execution-isolation-and-throughput.md)。缓存目录应置于编排管理的私有临时卷；SIGKILL 后遗留的旧实例目录由该卷的生命周期清理，新实例不会把它们当权威或直接复用。服务另有独立 discovery 与部署恢复入口；动态 owner 路由、自动接管、物理对象 GC、PITR 和跨区域灾备仍有后续实现与验收门禁。

## 验证

```bash
cargo test -p scap-service --lib --locked -- --test-threads=1
cargo clippy -p scap-service --all-targets --locked -- -D warnings
```

生产文件全部进入精确四维单元覆盖，实际二进制入口也由 unit 目标调用同一源文件。单元中的对象存储 oracle 不等于真实 S3；真实 Rust 服务 + Node SDK + S3 故障与全计算恢复由 [服务实验](../../experiments/object-service/README.md)独立执行。最终完成范围与候选身份以仓库证据记录为准。

2026-11-07 的[完整本地验收](../../docs/engineering/http-service-validation.md)已通过独立审计：冻结候选 stable／nightly 各 199 项 workspace 单元、23 个生产文件精确覆盖、SDK 逐模块 V8 计数、真实服务 18 次成功响应恢复比较，以及同候选 1 GiB 回归。原始不完整日志与首次失败构建保持拒绝，完整成功重跑单独保存。AWS Standard、生产 SLO、名称目录和自动 owner 路由不在本批通过范围内。
