# 有界三节点 SQLite daemon

`scap-server` 是正式运行入口，连接 HTTP/Hrana、Node SDK、当前权限、SQLite writer、固定三副本 Raft、RocksDB 和可选 S3 归档。它为一个静态 cell 服务最多 32 个配置数据库，当前属于有明确容量边界的实现，不提供生产 SLO 承诺。

## 启动

从仓库根目录构建。需要 Rust 1.90.0、C/C++17、make、libclang 18；Node SDK 使用 Node.js 24。

```bash
cargo +1.90.0 build --release -p scap-server --locked
npm --prefix sdk/node ci --ignore-scripts
npm --prefix sdk/node run build
```

每个节点使用不同的私有 data_dir、node ID、peer 地址、HTTP 地址与证书私钥。三个节点的 cluster/cell 身份、静态 membership、数据库与令牌配置一致。完整可解析 JSON、临时证书生成和三个节点的配置方式见[工程说明](../../docs/engineering/sqlite-service.md)。

新部署明确 Initialize；目标 data_dir 必须尚不存在：

```bash
./target/release/scap-server --initialize /absolute/path/node-1.json
```

原节点重启使用 OpenExisting，不加 flag：

```bash
./target/release/scap-server /absolute/path/node-1.json
```

CLI 只接受上述两种形式。OpenExisting 拒绝缺失、损坏或身份不匹配的数据，不创建同名空库。启动先取得 RocksDB 独占锁，再检查 disposable writer namespace。Peer mTLS 同时校验 CA、作用域 DNS 身份和配置中的 leaf DER pin；本机 HTTP 可监听 loopback，非 loopback 地址需要明确的外部 TLS 代理配置。

## 应用入口

[Node SDK](../../sdk/node/README.md)提供 `execute`、`batch`、强读 `query`、`lookup`、`resolveOrCancel` 和不唤醒数据库的 `status`。裸 `@libsql/client/http` 可访问 `/db/{database}/` 下已经验证的自包含 Hrana 子集；不承诺同步本地文件驱动、全部 Hrana 或 ORM 无修改兼容。

公开路径与错误合同见 [`scap-service`](../scap-service/README.md)。Bearer token 只存摘要，外部请求不能指定 owner/cell/S3 key。每次实际读写与结果查证均重新使用复制状态中的当前权限。`/readyz` 仅供选择候选节点，不能授权本地写或陈旧读。

## 运行时职责

| 文件 | 职责 |
| --- | --- |
| `config.rs` / `auth.rs` | 显式静态作用域、限额、token digest 与 principal 映射 |
| `cli.rs` / `node.rs` | Initialize/OpenExisting、启动装配、mTLS/HTTP、信号和完整资源监督 |
| `mailbox.rs` / `listener.rs` | 有界 SQL 准入、请求字节计量、原 deadline 与连接生命周期 |
| `worker.rs` / `local.rs` | leader owner 恢复、当前状态、SQL 执行、休眠、正式 checkpoint |
| `cache.rs` | 新 writer 目录生命周期与关闭后清理；旧缓存不充当权威 |
| `archive.rs` / `archive_jobs.rs` | 显式 S3 配置、有界后台归档、前景 hydrate、完成通知和线程回收 |

只有当前 Raft leader 恢复 SQL owner；term 改变立即退休旧 writers。恢复依次 Claim、校验物理历史、新目录构造、Activate 和最终确认。正常超时选举使用 PreVote/check_quorum；独立强读使用 Safe ReadIndex，不采用 lease read。

S3 归档采用 `Suspend → upload/verify → Publish → Prune`，唤醒为当前发布根的 `Hydrate → Claim/Activate`。后台任务固定原身份、owner、head 和 deadline，I/O 后由 cell 再检查；任务和完成队列各 8 槽，每库一个 pending，失败退避到原 deadline 加 5 秒。单库 Prune 不截共享日志，成功通知与周期维护只请求正式全 cell checkpoint。

若后台 Prune 刚好先于前景 Claim，只有明确 `Rejected(Cold)` 可以在 SQL 执行前刷新一次；原 deadline 不变，Unknown 不自动重试。归档、SQL、Raft、peer 或 HTTP 线程退出会交给 supervisor；关闭先取消再 drain/join，无法强制中断的 native I/O 仍需要外部进程管理。

## 当前边界

- 一个 cell、三个静态 voter、最多 32 个库；不提供动态成员、迁移或多 cell 路由。
- 每库逻辑镜像最多 64×4096 bytes，即 256 KiB；每库最多 128 条 accepted/cancel 记录，cell 最多 4096 条管理记录。
- 完整 Store 镜像同步替换，强读与恢复核验保留的完整物理历史；不能由此推断大库吞吐或延迟。
- 单 SQL actor；后台 S3 已解耦，前景 cold hydrate 仍可能推迟其他库请求。
- 归档正文必须装入一次有界 hydrate command；state/command 分别为 8 MiB/4 MiB，尚无分块恢复。
- 永久保留对象、原结果和取消 fence，无自动 GC、对象删除或 S3-only 灾难恢复。恢复所需总体容量没有跨库预留协议。
- 无 quorum、损坏、未知 outcome 或当前权限失败时保持拒绝；不会改用旧文件、较旧对象或本地成功。

格式为 cell state/command/outcome v2，支持绑定相同身份/限额的合法 v1 热历史及原管理 receipt 重试；旧二进制直接降级和混合版本滚动协商不受支持。详细限额、升级和故障矩阵见[工程说明](../../docs/engineering/sqlite-service.md)，决策见 [ADR-0014](../../docs/adr/0014-sqlite-service-and-cold-lifecycle.md)。

## 验证

```bash
cargo +1.90.0 test -p scap-server --lib --bins --locked
cargo +1.90.0 clippy -p scap-server --all-targets --locked -- -D warnings
npm --prefix sdk/node test
```

单元覆盖率按[仓库规范](../../docs/engineering/testability-and-coverage.md)单独采集精确计数。真实三 daemon/SDK/分区/重启/S3/测量脚本位于 [service-network](../../experiments/service-network/README.md)，真实 S3 条件写与后端重启另见 [archive-s3](../../experiments/archive-s3/README.md)；这些实验不进入单元覆盖率。

生产性能判定使用[性能与恢复规范](../../docs/engineering/performance-slo.md)。实际完成的场景、二进制摘要、样本分母及故障时刻由本次证据记录；本文不把配置参数或历史测试次数当成当前性能结果。
