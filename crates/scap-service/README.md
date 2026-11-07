# S3 原生 HTTP 服务

`scapd` 把正式 `scap-object` / SQLite 提交路径接到 HTTP，支持不可变数据库 ID、可信主体鉴权、有界调度、独立强读与显式接管。它不自动重放 SQL，不用本地目录作为数据库权威；S3 不可用时热缓存也不能产生新的成功强读。

服务以数据库的完整 `deployment / tenant / database / incarnation / generation` 标识接入。当前没有名称目录或同名 reservation 协调；调用方必须持久保存原始身份。HEAD 的 key 保持单库固定以隔离旧身份，本地缓存键另包含 incarnation 和 generation，不能用缓存把两代身份混用。

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
    "workers": 4,
    "control_workers": 2,
    "queued_per_worker": 32,
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
    "sessions_per_worker": 4,
    "pages_per_worker": 5242880,
    "parallel_recoveries": 2
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

示例中的占位值必须替换。没有临时 session token 时明确写 `null`。程序只读取配置中指定的环境变量，不搜索本机 AWS 配置或实例元数据。S3 单对象预算取当前持久格式上限；数据库仍使用正式 `Options::default()`：默认 10 GiB，管理员可经 `quota` 修改或取消业务配额。

配置的 Bearer token 应为独立生成的高熵值；服务接受 32–1024 字节的可打印 ASCII token，通过固定长度 SHA-256 摘要比较映射到可信 deployment、tenant、principal 和 provisioning 权限。摘要不是 HEAD 权限替代品：每次正式数据库操作仍由当前 HEAD 授权。请求中的 `principal` 只是原请求身份的一部分，必须等于 token 对应的主体。

监听器只接受 loopback 地址。生产外部入口须由同机 TLS 反向代理终止 TLS，并转发 Authorization 和 `x-scap-admission`，不应改写响应或自动重试 POST。`GET /healthz` 只说明进程活着，不证明 S3、某个库或写入可用。配置更新通过新实例部署，不存在运行时凭据轮换或自动 owner 迁移。

## HTTP 协议

所有业务调用为 `POST /v1`，`Content-Type: application/json`，`Authorization: Bearer …`。重复认证或 admission 头拒绝；body 有字节上限与读取 deadline。`x-scap-admission` 必须与操作匹配，避免大 SQL 消耗控制预留。

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

`open` 显式重建独立的本地快照，返回与 `status` 相同的结构，不改变 HEAD、owner 或数据。它可用于预热独立 reader，也用于刷新 stale session；下一次 query 仍会重新读取 HEAD，不能把 open 当作长期授权或最新根保证。`activate` 在验证完整恢复闭包后，按原 revision 发布 owner 激活。

`query` 与 `execute` 使用 `statements: [{sql, params}]`。每个参数为显式对象：`{"type":"null"}`、`{"type":"integer","value":"42"}`、`{"type":"real","bits":"8000000000000000"}`、`{"type":"text","value":"…"}` 或 `{"type":"blob","base64":"…"}`。Real 的 bits 是大端书写的 16 位小写十六进制 IEEE-754 位图，保留负零；不接受非有限实数。整数、Base64 与十六进制都采用规范唯一编码。

`execute` / `lookup` / `cancel` 的 `request` 包含 `epoch`、`id`、`principal`（均十进制字符串）与 `fingerprint`（64 位小写 SHA-256）。服务重新计算 execute 的精确原 SQL/类型参数指纹。ID、世代与指纹必须保持原值，不能在网络失败后自行分配新请求重做随机 SQL。

成功响应为 `{"ok":true,"value":…}`。query 的 value 含 `result`，为原始 `SCAPRES1` 的 Base64；execute 的 value 为 `state: "committed"`、`receipt` 和 `result`。lookup/cancel 返回明确的 committed、cancelled、unknown、closed 或 retired。receipt 的 `result_hash` 是完整持久 Result 对象 envelope 的摘要，不能直接按 SQL 结果字节摘要核对。

错误为 `{"ok":false,"error":{"code":"…","message":"…","receipt":…}}`。error message 只返回稳定代码，不包含 SQL、对象端点、凭据或内部原生错误。`COMMITTED_BUT_UNAVAILABLE` 可附带已持久化回执；所有不确定状态均使用原身份查证。客户端实现见 [Node SDK](../../sdk/node/README.md)。

## 并发与资源边界

SQL / 恢复 worker 按固定 HEAD key 路由，以便同一库的 SQLite 会话只在所属线程创建、调用和销毁。每个 lane 在租户间轮转，再在该租户的数据库间轮转。每库、租户和 lane 均限制排队请求数，并为控制请求预留槽位；控制 burst 最多连续三次后让排队 SQL 前进。`lookup`、`cancel` 及元数据转换另有独立 control worker pool，慢恢复不会占用它们的执行线程。

HTTP 的 data、control、recovery 各有独立 intake 配额，保留到响应 body 及其发出的字节均被释放。底层 HTTP 在发出最后一帧后可先销毁 body，传输缓冲中的字节及其 clone／slice 仍持有配额，慢客户端不能靠这个生命周期差异提前释放名额。绑定不会复制响应 payload。执行开始后，即使客户端断开，worker 也只完成该次原请求；它不会回滚一个已发布 HEAD，也不会重做 SQL。尚未开始且接收端已消失的排队请求会被丢弃，超出原 deadline 的排队请求不会执行。

每个 worker 按会话数及实际页面数 LRU 丢弃本地缓存；失败 session 不复用。`parallel_recoveries` 限制全实例同时下载完整数据库。SQLite cache 与 HTTP/队列限额都是明确资源预算，并不是进程 RSS 或文件系统总量硬隔离；typed JSON、编码结果及原生 SQLite 仍可能有额外内存开销。

同一个 data lane 中的冷库可能延迟映射到该 lane 的其他库。控制独立与队列公平不等于完整冷热点性能隔离，须由后续负载验收量化。缓存目录应置于编排管理的私有临时卷；SIGKILL 后遗留的旧实例目录由该卷的生命周期清理，新实例不会把它们当权威或直接复用。服务未实现全局名称目录、动态路由、自动接管、物理对象 GC、PITR 或跨区域灾备。

## 验证

```bash
cargo test -p scap-service --lib --locked -- --test-threads=1
cargo clippy -p scap-service --all-targets --locked -- -D warnings
```

生产文件全部进入精确四维单元覆盖，实际二进制入口也由 unit 目标调用同一源文件。单元中的对象存储 oracle 不等于真实 S3；真实 Rust 服务 + Node SDK + S3 故障与全计算恢复由 [服务实验](../../experiments/object-service/README.md)独立执行。最终完成范围与候选身份以仓库证据记录为准。

2026-11-07 的[完整本地验收](../../docs/engineering/http-service-validation.md)已通过独立审计：冻结候选 stable／nightly 各 199 项 workspace 单元、23 个生产文件精确覆盖、SDK 逐模块 V8 计数、真实服务 18 次成功响应恢复比较，以及同候选 1 GiB 回归。原始不完整日志与首次失败构建保持拒绝，完整成功重跑单独保存。AWS Standard、生产 SLO、名称目录和自动 owner 路由不在本批通过范围内。
