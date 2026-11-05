# 有界 HTTP 与 Hrana 接入

正式 `scap-service` 将自包含 Hrana HTTP v2 程序翻译为一次类型化业务调用。`Backend` 必须完成真实凭证验证、数据库身份映射、当前复制权限、ReadIndex、提交及恢复；协议层不接受客户端自报的 tenant、owner epoch、cell、S3 key 或文件路径。客户端提交的 `request_epoch` 仅标识原请求世代，由状态机校验，不能改变权限或 writer 身份。

## 端点

| 路径 | 行为 |
| --- | --- |
| `POST /v2/pipeline` | 使用构造时固定的默认数据库 |
| `POST /db/{database}/v2/pipeline` | 路由名经验证后交给 Backend 映射不可变身份 |
| `POST /db/{database}/v1/requests/{request_id}` | 显式 `lookup`、`resolve_or_cancel` 或 `acknowledge`；提供原业务 statements 与原请求世代 |
| `GET /db/{database}/v1/status` | 新的 ReadIndex 与当前 READ 授权后返回有界元数据；不唤醒数据库 |
| `POST /db/{database}/v1/request-epoch` | ADMIN 有序轮转；要求精确原世代和所有保留终态已确认 |

必须携带 Bearer 凭证，POST 必须使用 `application/json`，GET status 的 body 必须为空。外部 TLS 和监听进程由服务装配层提供。可选的 `x-scap-request-id` 为非零 128-bit 十六进制；没有该头时根据独立服务 boot 身份和单调序号生成。`x-scap-request-epoch` 是正 u64 十进制字符串，缺省**始终为 1**；服务端不会替旧请求换成当前世代。已准入响应回显原 ID 与原世代。`x-scap-deadline-unix-ms` 只能缩短服务端最大预算，入站时转换为单调绝对 deadline。`x-scap-mode: read` 选择 Backend 的独立 SQL 强读，默认 `write`。

status 返回 `revision`、`base_revision`、`tail_entries`、`tail_bytes`、`request_epoch`、`retained_requests`、`unacknowledged_requests`、`retired_revision`、`suspended`、`cold`、`owner_active` 和 `archived_revision`。所有 u64 使用十进制字符串，尚未归档时 `archived_revision` 为 null；不返回复制状态机全量内容、对象 key 或其他数据库信息。读取 status 不要求请求世代等于当前世代，因而旧客户端仍可获知新世代；当前 READ 权限检查保持不变。

## 显式结果确认与世代轮转

`lookup` 的 committed 结果附带 `sequence` 与 `acknowledged`；cancelled 结果附带精确 `position: {term,index}` 和 `acknowledged`。调用者必须先取得终态并持久处理其业务结果，再显式发送：

```json
{
  "action": "acknowledge",
  "statements": [{"sql": "INSERT INTO items VALUES (1)"}],
  "expected": {"state": "committed", "sequence": "42"}
}
```

取消确认的 `expected` 使用 `{"state":"cancelled","position":{"term":"3","index":"80"}}`。请求仍使用原 ID、原世代、原 SQL/参数；该终态证明由 Backend 对照当前保留记录验证。协议拒绝 unknown、retired、缺失证明和非法位置。确认成功返回 `{"state":"acknowledged"}`，不会执行 SQL，也不会替调用方确认其他请求。

轮转 body 为 `{"action":"rotate","expected_epoch":"7"}`，其世代必须与 `x-scap-request-epoch: 7` 一致。Backend 负责当前 ADMIN 权限、全部记录已确认、物理恢复条件及 Raft 有序 CAS；成功返回 `{"state":"rotated","request_epoch":"8"}`。轮转后的旧请求查询返回 `{"state":"retired","current_epoch":"8"}`，表示原世代已永久禁止接受，**不能解释为 unknown、取消或从未提交**。原请求的历史结果不再可查，不能改用新世代重新执行该未知业务操作。

## 精确的协议子集

- 每个 pipeline 必须以唯一 `close` 结尾，baton 为空，最多执行一个 `execute` 或一个原子 `batch`。
- SQL cache 的 `store_sql`、`sql_id`、`close_sql` 在同一 pipeline 内完整生效并检查数量、累计字节及重复 ID。返回空 baton，不冒充跨请求会话。
- batch 只识别固定 SDK 的完整 `BEGIN → ok(previous) 业务语句 → COMMIT → not(ok(commit)) ROLLBACK` 程序。参数、条件、控制语句及 want_rows 均验证。所有请求、缓存与控制步骤在任何 SQL 效果前检查，之后交给 Backend 一次原子执行；没有删除字符串后任意执行的替代路径。
- 跨请求 stream、interactive transaction、任意条件程序、sequence、describe、cursor、WebSocket、named args 与 replication_index 等未验证特性明确拒绝。
- Null、64 位整数、有限浮点、UTF-8 文本和 Base64 BLOB 映射到 `scap-sql` 的类型；所有 SQL 与结果共享有界限制。

真实 `@libsql/client` **0.18.0** 的 execute 和 batch 在单次 pipeline 中关闭 stream；对应薄封装与真实 SDK 测试见 [Node 客户端](../../sdk/node/README.md)。支持该子集不等于完整 Hrana 或 ORM 兼容。

## 资源与故障

`Limits` 对 body、响应、pipeline 数、SQL cache、凭据、在途请求、deadline 及 SQL 参数/结果分别设上限。HTTP admission 使用有界 semaphore；读取 body、等待 backend 和最终返回共用原 deadline。取消 guard 在 future 退出或被丢弃时设置取消标志，Backend 不能因此推断已经进入 Raft 的命令被撤销。

UNKNOWN 不重放；响应预算或结果格式在 backend 成功后出错时不能声称事务回滚。结果没有形成完整成功响应之前不会向 SDK 流式释放 `RETURNING` 行。`lookup` 的 unknown 与有序取消的 cancelled 分别编码。结果与凭据不进入日志，响应禁止缓存。

`Backend::execute` 的 `NOT_LEADER` 必须表示本次请求尚未进入可能提交窗口，因为客户端允许在这一明确拒绝后向另一配置节点发起同 ID 尝试。已经提案、超时或结果不明时必须返回 COMMIT_UNKNOWN 等保守结果。

## 验证

生产源码为 `lib.rs`、`http.rs`、`protocol.rs`，unit 源分别为同级或子目录的 `tests.rs`。正式 unit 调用真实 Axum Router、真实 body/headers 与时间边界，覆盖超时、abort、准入拒绝、完整程序预检和结果错误；Backend 使用窄端口模拟。真实三副本 SDK 请求另行运行，不用于补齐 unit coverage。
