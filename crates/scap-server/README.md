# 有界三节点 SQLite daemon

`scap-server` 是正式运行入口，连接 HTTP/Hrana、Node SDK、当前权限、SQLite writer、三 voter Raft、RocksDB 和可选 S3 归档。它为一个静态 cell 服务最多 32 个配置数据库，支持在预注册可信 peer 池内通过 learner 追赶与 joint consensus 替换 voter，当前仍有明确容量边界，不提供生产 SLO 承诺。

## 启动

从仓库根目录构建。需要 Rust 1.90.0、C/C++17、make、libclang 18；Node SDK 使用 Node.js 24。

```bash
cargo +1.90.0 build --release -p scap-server --locked
npm --prefix sdk/node ci --ignore-scripts
npm --prefix sdk/node run build
```

每个节点使用不同的私有 data_dir、node ID、peer 地址、HTTP 地址与证书私钥。所有节点的 cluster/cell 身份、bootstrap voters、可信 peer 池、数据库与令牌配置一致。完整基础 JSON、临时证书生成和节点配置方式见[工程说明](../../docs/engineering/sqlite-service.md)。

新部署明确 Initialize；目标 data_dir 必须尚不存在：

```bash
./target/release/scap-server --initialize /absolute/path/node-1.json
```

原节点重启使用 OpenExisting，不加 flag：

```bash
./target/release/scap-server /absolute/path/node-1.json
```

首次加入的非 bootstrap 节点使用明确的 Join；目标目录也必须不存在：

```bash
./target/release/scap-server --join /absolute/path/node-4.json
```

Join 还必须提供 `SCAP_JOIN_MANAGEMENT_URL`（健康 leader 的 loopback 管理 URL，可经 SSH 转发）和 `SCAP_MANAGEMENT_TOKEN`。启动会先进行新的 Safe ReadIndex 管理 GET，校验 cluster/cell/incarnation、规范化的原 bootstrap voters 和完整确定性 genesis 摘要，并要求新 node ID 严格大于当前全部 voters、learners、outgoing 与 next learners 的最大 ID；存在未应用配置变更时拒绝加入。genesis 摘要与初始化复用同一构造函数，包含原始 administrator、状态限额、term/index 1/1、三 voter 配置和完整初始应用字节。URL 仅接受字面 loopback HTTP，没有代理、重定向、userinfo、query 或 fragment。这个授权只有原 5 秒启动预算内有效，不接受离线授权文件。远端或输入预检失败不会创建 data_dir 或打开服务端口；预检成功后，在建目录前、打开监听前和开始服务前仍复核原截止时间。后续阶段失败会保留已创建的目录供诊断，不能通过换新目录复用旧 ID 再次 Join。

正常顺序是先成功 Join，再由现有 leader 执行 add learner。曾经使用的节点丢盘不能换一个空目录后重新 Join 同 ID；必须使用新的单调 ID。已有合法数据的原节点仍按 OpenExisting 重开。该协议依赖受控运维和节点凭据，不能宣称防止恶意克隆相同身份与私钥的部署。

Initialize 只允许本机 ID 属于三个 bootstrap voters，Join 只允许本机 ID 不属于它们。Join 保存相同的 genesis 和初始三 voter 配置，本机尚无投票权；它不是单节点新集群。重启仍使用 OpenExisting，采用磁盘上的实际 ConfState，绝不把配置中的 bootstrap voters 重新写回。OpenExisting 同时解码绑定 durable application，校验不可变的 bootstrap administrator 与配置一致；拒绝缺失、损坏或身份不匹配的数据，不创建同名空库。原 bootstrap voters 仍是必须保留的可信部署输入，不能在替换成员后把它改成当前 voters；本轮没有另加可独立证明历史 genesis 的磁盘字段。启动先取得 RocksDB 独占锁，再检查 disposable writer namespace。Peer mTLS 同时校验 CA、作用域 DNS 身份和配置中的 leaf DER pin；本机 HTTP 可监听 loopback，非 loopback 地址需要明确的外部 TLS 代理配置。

## 受限成员管理

`peers` 是 3–16 个预注册通信身份，不等于当前 voters。可选 `bootstrap_voters` 必须是其中恰好三个不同 ID。旧的三 peer 配置省略该字段时沿用这三个 ID；更大的池必须显式填写。三个 peer 且管理缺省/关闭时仍使用原固定成员通信策略。启用管理或显式扩大可信池才允许配置条目；是否有投票权仍由已应用的 ConfState 判定。

变更前必须把候选节点的 ID、endpoint 与证书 pin 部署到所有继续服务及参与追赶的节点。只在 leader 增加配置不够。可信池在进程生命期内固定；移除 voter 不自动撤销其通信证书，也不从池中删掉历史配置可能引用的 ID。需要撤销通信时另行撤销 pin，不能把更改目录误当成成员变更完成。

管理通过独立 loopback listener 开启；`management` 缺省或 `false` 表示关闭。配置对象包含 `listen`（例如 `127.0.0.1:9091`）与 `token_sha256`（64 位十六进制 SHA-256）。管理 token 必须独立于全部租户 token，禁止零摘要或复用租户摘要；租户拥有数据库 ADMIN 也不能使用此入口。它没有公共 SQL listener 上的管理路由。

`GET /v1/admin/membership` 使用 Safe ReadIndex，返回 `scope`（cluster_id、cell_id、cell_incarnation、bootstrap_voters、genesis_sha256）和 `membership`，其中 `conf_state` 包含 `voters`、`learners`、`voters_outgoing`、`learners_next`、`auto_leave`。同时返回 term、applied、commit、snapshot_index、leader_id、pending_conf_index 和每节点 matched/is_learner 进度。

`POST /v1/admin/membership` 接收以下形状。每次都应把新鲜 GET 返回的完整 `conf_state` 原样放入 `expected_conf_state`：

```json
{
  "action": "add_learner",
  "node_id": 4,
  "expected_conf_state": {
    "voters": [1, 2, 3],
    "learners": [],
    "voters_outgoing": [],
    "learners_next": [],
    "auto_leave": false
  },
  "deadline_ms": 5000
}
```

先 `add_learner`，待其追赶后再提交 `replace_voter`（`node_id` 为 learner，`remove_id` 为被替换 voter），最后以当前 joint 配置提交 `leave_joint`（不携带 `node_id` 或 `remove_id`）。请求与完整 ConfState 都拒绝未知字段。运行时拒绝未追赶的晋升、CAS 不符和并发未完成变更。只有精确的本次配置条目已持久应用，才返回 `outcome: "applied"`；排队或成功发送不算完成。超时和结果不确定返回 `MEMBERSHIP_UNKNOWN`，必须 GET 核对当前权威配置，不自动重发 POST。deadline 缺省 5000 ms，允许 1–30000 ms；读取 body、排队、共识等待共用原截止时间。

`GET /v1/admin/status` 使用同一独立管理 token，返回 `{authoritative:false,node_id,status:{role,term,leader_id,commit,applied,snapshot_index,is_voter}}`。它仅是本节点观测，用于验证 learner 安装快照和移除后的本地状态，不能替代强读配置或证明变更完成。`role` 为小写字符串；上游 Raft 的被移除 leader 可能短暂保留 role 名称，`is_voter=false` 时服务仍拒绝 SQL leadership。

所有管理请求使用 `Authorization: Bearer ...`。CLI 从 `SCAP_MANAGEMENT_TOKEN` 环境变量读取秘密，不接受命令行 token，不使用环境代理、不跟随重定向，也不自动重试：

```bash
./target/release/scap-server --membership /absolute/path/node-1.json
./target/release/scap-server --membership /absolute/path/node-1.json /absolute/path/change.json
```

CLI 输出完整 JSON；非成功 HTTP、超时或不确定结果都以非零状态退出。管理最多 4 个在途调用，body 上限 16 KiB，CLI 响应上限 64 KiB。关闭服务同时停止管理 listener 并 drain 请求；本轮没有远程公共管理入口、自动成员重建或自动缩容。

## 应用入口

[Node SDK](../../sdk/node/README.md)提供 `execute`、`batch`、强读 `query`、`lookup`、`resolveOrCancel` 和不唤醒数据库的 `status`。裸 `@libsql/client/http` 可访问 `/db/{database}/` 下已经验证的自包含 Hrana 子集；不承诺同步本地文件驱动、全部 Hrana 或 ORM 无修改兼容。

受鉴权的 `GET /db/{database}/v1/status` 在原 `revision`、休眠、Cold、owner 和归档水位之外，返回 `base_revision`、`tail_entries`、`tail_bytes` 及 `request_epoch`、`retained_requests`、`unacknowledged_requests`、`retired_revision`。这些 u64 计数均为十进制字符串，来自同一新鲜权威视图；Cold 时尾部计数为零，基座 revision 仍表示保留的恢复锚点，不能据此假定镜像字节在本机可用。该入口不执行 SQL，也不为查询状态而唤醒冷库。

公开路径与错误合同见 [`scap-service`](../scap-service/README.md)。Bearer token 只存摘要，外部请求不能指定 owner/cell/S3 key。每次实际读写与结果查证均重新使用复制状态中的当前权限。`/readyz` 仅供选择候选节点，不能授权本地写或陈旧读。

## 运行时职责

| 文件 | 职责 |
| --- | --- |
| `config.rs` / `auth.rs` | 显式静态作用域、限额、token digest 与 principal 映射 |
| `cli.rs` / `node.rs` | Initialize/Join/OpenExisting、启动装配、mTLS/HTTP、信号和完整资源监督 |
| `management.rs` / `management_cli.rs` | 独立管理鉴权、强读配置、本地进度、CAS 变更、原 deadline 和显式 CLI |
| `mailbox.rs` / `listener.rs` | 全局及每库有界 SQL 准入、请求字节计量、原 deadline 与连接生命周期 |
| `lanes.rs` | 按需创建每库串行执行线程、固定 lane 预算、排队与退休同步、取消和 join |
| `worker.rs` / `local.rs` | 目录轮询、每库 leader owner 恢复、当前状态、SQL 执行、休眠、正式 checkpoint |
| `cache.rs` | 新 writer 目录生命周期与关闭后清理；旧缓存不充当权威 |
| `archive.rs` / `archive_jobs.rs` | 显式 S3 配置、有界后台归档、前景 hydrate、完成通知和线程回收 |

只有当前有投票权的 Raft leader 恢复 SQL owner；term 改变或本节点不再是 voter 时退休旧 writers。learner 和已移除节点不能宣告 SQL leadership；readiness 的目录轮询也必须满足这一条件。恢复依次 Claim、校验物理历史、新目录构造、Activate 和最终确认。正常超时选举使用 PreVote/check_quorum；独立强读使用 Safe ReadIndex，不采用 lease read。

SQL dispatcher 将请求交给按需创建的每库串行 lane；SQLite connection 在所属 lane 线程内创建、使用和关闭。不同库可分别执行 SQL 或等待前景 hydrate，同库仍按队列顺序执行。最多 32 个活动或退出中的 lane；休眠库关闭 writer 且队列为空后退出，冷库不保留专用 SQL 线程。退休与入队使用同一锁，旧线程 join 完成前不创建替代 writer；再次启动使用新的 boot/worker 身份并重新取得 owner 权限。

SQL 准入同时计量排队和执行中的请求：全局最多 32 个请求、8 MiB，每库最多 8 个请求、2 MiB，单请求最多 1 MiB。额度用尽返回 `OVERLOADED`。目标 lane 已退休但尚未完成 join 时，已经准入的请求保留原 reservation，按 FIFO 等待成功 join 后交给新 lane；等待期间继续检查取消和原 deadline，失败退出不会自动重放旧请求。

`/readyz` 的公开提示只由目录维护更新，每库 lane 使用私有就绪状态，单库请求的超时或恢复失败不会覆盖其他库的节点选择提示；关闭期间始终返回未就绪。实际请求仍独立检查当前权限、领导状态和 ReadIndex。

S3 归档采用 `Suspend → upload/verify → Publish → Prune`，唤醒为当前发布根的 `Hydrate → Claim/Activate`。后台任务固定原身份、owner、head 和 deadline，I/O 后由 cell 再检查；任务和完成队列各 8 槽，每库一个 pending，失败退避到原 deadline 加 5 秒。单库 Prune 不截共享日志，成功通知与周期维护只请求正式全 cell checkpoint。

目录与各 lane 仅在短临界区共享后台任务队列；前景 hydrate 使用各自的 Controller，对象 I/O 不持有共享队列锁。dispatcher 的轮询目录维护仍包含同步 ReadIndex 和 checkpoint 请求，活动 lane 也定期维护，因此共享元数据延迟仍可能推迟分发。每库额度不能代替加权公平调度，也不隔离共享 CPU、磁盘或 cell quorum 的全部尾延迟。

若后台 Prune 刚好先于前景 Claim，控制序号会拒绝原恢复身份；本次请求在 SQL 执行前失败，不在调用内部刷新序号。后续独立请求或维护任务可捕获新鲜视图建立新的恢复工作，UNKNOWN 的原身份和结论保持不变。归档、SQL、Raft、peer 或 HTTP 线程退出会交给 supervisor；关闭先取消再 drain/join，无法强制中断的 native I/O 仍需要外部进程管理。

## 当前边界

- 一个 cell、bootstrap 恰好三个 voter、最多 32 个库；成员替换限于 3–16 个预注册 peer，不能动态信任陌生证书，也不提供迁移或多 cell 路由。
- 每库逻辑镜像最多 64×4096 bytes，即 256 KiB；每库未退休窗口最多 128 条 accepted/cancel 记录，显式确认并推进世代后可释放；旧 cell 管理回执最多 4096 条，v5 激活后冻结旧表；新管理操作使用每库独立序号和一个最近回执，不再累计消耗该额度。
- Store 逻辑镜像采用内容块增量持久化，同一 WriteBatch 原子发布；cell 在 Commit 候选状态中折叠物理前缀，强读与恢复核验完整恢复基座和有界物理尾部。物理折叠不删除请求结果或取消记录，它们仅在显式确认及有序世代退休后释放；不能由此推断大库吞吐或延迟。
- 按库 lazy lane 隔离 SQL 与前景 hydrate；全局线程/准入预算固定，尚无加权公平调度、独立恢复容量预留或跨库性能保证。
- 归档正文必须装入一次有界 hydrate command；state/command 分别为 8 MiB/4 MiB，尚无分块恢复。
- 永久保留对象；原结果和取消记录只能经显式应用确认及有序世代退休释放，旧世代永久 fenced。无自动对象 GC、对象删除或 S3-only 灾难恢复。恢复所需总体容量没有跨库预留协议。
- 无 quorum、损坏、未知 outcome 或当前权限失败时保持拒绝；不会改用旧文件、较旧对象或本地成功。

Cell state 在持久激活后使用 v5，物理归档继续使用 v4；旧 epoch 1 操作使用原业务 v2 envelope，新请求世代/确认/退休使用 v3，新管理控制命令与结果使用 v4。OpenExisting 读取合法 v1/v2/v3/v4 状态并保留原阶段语义；catalogue 在同一个原 deadline 内依次完成 history、retention、control 三次独立有序激活。只有精确持久结果及 fresh ReadIndex 确认 v5 后才置 ready，普通 lane 拒绝未激活状态，tenant 不能触发升级。正式 peer envelope 为 4，与旧 1/2/3 隔离；整组停机后原盘升级。控制序号、最近回执、旧表封闭与容量预留见 [ADR-0020](../../docs/adr/0020-bounded-administrative-control.md)。

Initialize、Join 和规范 genesis 摘要统一使用与旧二进制逐字节相同的 v2 初始应用，再由有序 activation 开启新语义；新 learner 从旧日志前缀追赶时也必须先看到原预算和格式。epoch 1 且未退休前缀的 v2/v3 已发布对象继续按原精确摘要读取，原管理 receipt、鉴权、未退休结果及取消 fence 均保留；Hydrate 不覆盖之后的显式确认。升级必须先停止写入和全部原 voter，再统一用新二进制 OpenExisting；新旧 wire 版本隔离，不支持旧二进制降级或混合版本滚动协商。新节点只能在已升级的健康集群完成新鲜预检后加入。详细限额、升级和故障矩阵见[工程说明](../../docs/engineering/sqlite-service.md)，服务合同见 [ADR-0014](../../docs/adr/0014-sqlite-service-and-cold-lifecycle.md)，增量持久化、按库执行与连接复用见 [ADR-0015](../../docs/adr/0015-incremental-blocks-and-isolated-execution.md)。

## 验证

```bash
cargo +1.90.0 test -p scap-server --lib --bins --locked
cargo +1.90.0 clippy -p scap-server --all-targets --locked -- -D warnings
npm --prefix sdk/node test
```

单元覆盖率按[仓库规范](../../docs/engineering/testability-and-coverage.md)单独采集精确计数。真实三 daemon/SDK/分区/重启/S3/测量脚本位于 [service-network](../../experiments/service-network/README.md)，真实 S3 条件写与后端重启另见 [archive-s3](../../experiments/archive-s3/README.md)；这些实验不进入单元覆盖率。

生产性能判定使用[性能与恢复规范](../../docs/engineering/performance-slo.md)。实际完成的场景、二进制摘要、样本分母及故障时刻由本次证据记录；本文不把配置参数或历史测试次数当成当前性能结果。

## 请求结果退休管理员配置

轮转是显式管理动作。普通数据库 token 仍只接受 permissions 1–3，不能指定 bootstrap administrator 身份。要管理一个数据库的结果保留，在该数据库 `tokens` 内添加独立条目：`retention_admin:true`，`principal_id` 等于配置的 `administrator_id`，`permissions:5`（READ|ADMIN），独立非零 `credential_id` 且不同于 `service_credential_id`，以及该 token 的 SHA-256 与当前 auth_epoch。缺省/false 继续使用原租户规则；错误类型、非管理员主体、额外 WRITE 位或内部 service credential 都拒绝启动。该凭证也不能复用成员管理 token。

这只显式把既有管理员权限暴露给指定数据库的退休入口，不改变旧库复制 policy。旧库已有 bootstrap administrator 的 ADMIN 权限，因此无需在升级中伪造 AuthFence。普通调用者通过自己的原身份确认结果；管理员凭证不能替其他主体确认，不能通过此配置执行 SQL 写。确认全部完成后，管理员调用 SDK `rotateRequests(expectedEpoch)`；status 可观察 requestEpoch、retainedRequests、unacknowledgedRequests、retiredRevision。

Cold 可确认已知结果但拒绝轮转，先恢复精确归档再推进。旧请求身份不得换成新世代重发。完整步骤和失败边界见 [API 合同](../../docs/architecture/api-contracts.md)、[SDK](../../sdk/node/README.md)和 [真实退休实验](../../experiments/retention-network/README.md)。
