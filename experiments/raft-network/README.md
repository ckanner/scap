# 三进程 mTLS Raft 网络契约

记录日期：2026-11-01。状态：**8 项真实三进程 mTLS 契约已执行通过**。本目录将正式的 `scap-raft-wire`、`scap-raft-transport`、`scap-raft-runtime` 与已有持久 driver、RocksDB 和 cell 状态机装配起来，验证真实 socket 故障下的合同。它只有独立 integration test target，没有产品 library 或可部署服务 binary；生产 crate 不依赖本目录。

## 验证对象与信任边界

每个 voter 是独立 OS 子进程，拥有自己的真实 RocksDB 目录、mTLS server、有限 outgoing workers 和专用 runtime 线程。三个进程按固定成员 `{1, 2, 3}` 从 genesis `(term=1, index=1)` 启动；重新启动严格打开原目录，保留节点身份并分配新的非零 boot ID。

所有 Raft 消息均经过正式 `NetworkWorkers → PeerClient → TCP/mTLS → PeerServer → Handle::admit → Runtime → Driver`。父进程通过 stdin/stdout 发控制命令、业务提案并读取观察结果；**这个控制通道不负责投递 Raft 消息、推进 tick、写磁盘或安装 snapshot**。运行中的节点由正式 `Runtime::run` 按单调时钟自动 tick，使用真实 raft-rs 的 PreVote、Vote、check_quorum 和 Safe ReadIndex。

六条有方向的透明 TCP 代理只处理字节流，TLS 从正式客户端到正式 server 端到端完成。代理不解密、不解析 Raft，也不伪造 ACK。它们可以关闭连接、拒绝新连接，或者接受真实 TCP 后不转发字节形成黑洞；两个方向可以分别控制。代理两端显式设置 TCP_NODELAY，避免把未定义的 Nagle 延迟混入故障模型。旧进程重启时代理原监听地址不变，实际目标切换到新进程的端口，原连接关闭，由正式网络组件恢复通信。

测试 CA、节点私钥和叶证书在每次用例运行时生成，只存在于临时目录。客户端检查私有 CA 与由 cluster/node ID 生成的服务端 DNS 名，服务端要求客户端证书；正式 policy 进一步绑定真实 TLS 叶证书的 SHA-256 指纹、node、cluster、cell 和 incarnation。证书有效期、pin revision 在请求准入和队列消费前分别检查。测试不提交私钥或长期有效的固定凭据，也不在证据中打印 PEM、DER 或密钥。

## 成功的具体含义

`Received` 只表示对端经过验证并接收进有限内存队列；它不表示 Raft 持久化、quorum commit、cell 接受或 SQLite 发布。`Answer::Admitted` 也只是本地提案准入。

本实验只有在新的 Safe ReadIndex 完成后读取正式持久 application，并通过 `CellState::decode_bound` 核对 cell、applied term/index，才检查业务结果。每张 read ticket 必须属于当前 boot，且 `applied >= barrier.index`。业务成功通过有序状态机的 `Lookup::Committed`、原始 result、receipt request ID 和 sequence 共同确认；重复请求还要求新的日志位置实际应用出 `AlreadyCommitted`，不能仅看提案准入或旧结果仍存在。

应用使用正式 `CellApplication` 的创建、owner claim/activate、幂等提交和 ResolveOrCancel；`physical_changes` 是有限的合成 opaque payload。**这里不执行 SQLite SQL，不将合成 payload 当成 SQLite 页面、session changeset 或 WAL。** 已有原生 SQLite 事务和发布验证仍由对应实验负责；本目录的通过不能直接当作 mTLS + SQL 入口 + SDK 的完整组合验收。

## 八项场景

| 测试 | 必须观察到的合同 |
| --- | --- |
| `automatic_runtime_commits_and_reads_across_real_mtls_reconnects` | 真实自动选举、业务提交和新 ReadIndex；同一请求再次应用仍返回原结果且 revision 不增加；拒绝一个 follower 的真实 TCP 后多数派继续，恢复连接后该副本追赶 |
| `tcp_blackhole_minority_cannot_commit_or_finish_a_new_read` | 旧 leader 被双向黑洞隔离，在降级前准入的提案不能增加 commit，新读不能完成；另外两副本形成多数派并继续提交；UNKNOWN 由后续有序 ResolveOrCancel 明确解决；连接恢复后收敛 |
| `killed_leader_and_full_cluster_restart_retain_cell_history` | 对真实 leader 注入 SIGKILL，剩余 quorum 选主并保留已确认请求；旧节点重开追赶；随后全组三进程 SIGKILL 后在原目录重开，保留全部接受结果并能继续提交和创建新 boot 的读屏障 |
| `lagging_replica_installs_a_snapshot_over_real_mtls` | 关闭落后副本，leader 的 checkpoint/compact 越过其旧日志尾部；该副本重开后必须通过实际网络安装 snapshot，durable snapshot/applied 前进；再次 SIGKILL/重开仍保留该快照 |
| `mtls_and_node_authorization_reject_untrusted_inputs_before_raft` | 无客户端证书、错误 CA、过期证书、同 CA 的未授权叶证书、伪造 node、错误 cell incarnation、来自网络的本地 Raft 消息均被拒绝；合法连接作正向对照，注入的 term=900 不得到达状态机 |
| `pin_rotation_revokes_existing_connection_and_queued_messages` | 先通过同一真实连接准入两条尚未消费的消息，再更换 pin；旧队列消息必须在尚未过期时被复核丢弃；原连接的新请求被拒绝，新的授权证书可以使用；恢复原 pin 后原连接重新可准入 |
| `inbox_bytes_deadlines_and_receipts_do_not_claim_durability` | 独立验证 inbox 数量上限与累计内存计费上限；已过 deadline 的发送不占准入槽；仅收到 `Received` 的节点在 actor 尚未启动时退出，实际重开磁盘后的 term、commit 和 application 仍为 genesis |
| `one_way_partition_cannot_turn_rpc_receipts_into_safe_reads` | 旧 leader 到 follower 及该连接内 gRPC receipt 的路径保持 Open，只阻断 follower 到旧 leader 的 Raft 回复路径；向旧 leader 发起的新读请求不得返回成功；多数派恢复选主并继续业务，连接修复后收敛 |

少数派用例只在多数派已经提交另一条相同 predecessor 的操作这一特定历史中检查被隔离请求仍为 UNKNOWN，随后通过有序取消形成确定终态。请求超时本身从不等于回滚，也不触发隐式 SQL 重放。单向分区用例发起新的读请求并断言不返回成功；失败可能来自未完成的读或已经降级，未导出失败请求的 ticket，也未逐条记录分区后正向 gRPC receipt。所有已成功读的 ticket、boot 和 barrier 均明确检查。旧 ACK 的捕获重放、精确 ReadIndex 消息调度、PreVote 与 Vote 释放前的持久 term/vote 对照，仍由 [三进程受控消息实验](../raft-cluster/README.md) 承担，本实验不虚报这些证据。

## 实验结构

| 文件 | 职责 |
| --- | --- |
| `src/certs.rs` | 生成只用于本次运行的 CA、正常/过期/轮换证书与私钥 |
| `src/common.rs` | 固定身份、成员、资源上限、正式 cell 命令和组件配置 |
| `src/protocol.rs` | 有界父子控制帧；不承载 Raft 传输 |
| `src/child.rs` | 子进程装配正式 RocksDB、driver、runtime、server 和 workers |
| `src/proxy.rs` | 有限连接的透明 TCP 故障注入，保持端到端 TLS |
| `src/harness.rs` | 有界等待、进程生命周期、观察与断言所需的业务操作 |
| `tests/network.rs` | 八项集成合同及所需的客户端攻击输入 |

子进程复用相同 test executable，以精确测试名称进入服务循环。没有额外的默认空跑 helper test，也没有为了通过集成测试而替换正式网络 sender、Ready driver 或持久后端。

## 固定依赖与资源预算

完整依赖由实际生成的 [Cargo.lock](Cargo.lock) 固定。Rust 使用 1.90.0；raft-rs 固定 `ad13f3d90780f53aea2488c6a4b76c0d334bf136`、protobuf 2.28.0；Tokio 1.50.0、Tonic 0.14.6、prost 0.14.3；证书夹具使用 rcgen 0.13.2。存储采用正式 scap-raft-rocks 所锁定的 rust-rocksdb 0.24.0 / RocksDB 10.4.2，保持同步 WAL 与严格恢复策略。

| 资源 | 实验配置 |
| --- | --- |
| 成员 / OS 进程 | 3 个固定 voter，各自独立 RocksDB；父进程仅编排 |
| 时钟与选举 | wall tick 20ms；heartbeat=2、election=20；node 1/2/3 的选举范围依次为 `[30,31)`、`[40,41)`、`[50,51)` tick |
| Raft / driver | 单消息目标 24KiB、16 inflight、256KiB 未提交预算；输入 600KiB、每轮输出最多 64 条 / 2MiB、16 个 pending read、32 个 Ready round |
| Store / application | store image 4MiB、单条 32KiB、512 entries；cell application 与 read view 各 512KiB |
| Runtime inbox | 正常节点最多 64 条 / 64MiB **解析和持有成本**；计费包括 raw、解析对象及 fields/entries 的保守预算，不等于 wire 长度；背压用例使用更小明确上限 |
| Runtime 请求与发送 | 最多 32 个本地请求 / 1MiB，包括读结果预留；128 个 pending delivery / 4MiB；每个 peer 的 ordinary / snapshot 独立固定 worker，队列容量 32 |
| 消息时间 | 发送绝对 deadline 750ms；inbound 最大年龄 30s；本地读/提案的调用 deadline 显式指定，超时不返回成功 |
| TLS / RPC | wire 700KiB、32 个连接、全局 16 个请求、每连接 4 个 stream；握手、连接、请求预算各 2s；连接最大年龄 30s、关闭宽限 2s |
| 代理 | 六个方向各最多 64 个实际连接；无无界 accept task 或离线消息队列 |
| 控制与证据 | 请求 96KiB、响应 1100KiB；控制写入/响应共用 10s deadline；事件最多 20,000 条 / 8MiB |
| 工作与清理 | 协议工作预算 120s；选主/追赶 15s；worker、server 和 proxy 的关闭分别有明确截止时间；进程退出最多 15s |

这些是可重复故障夹具的参数与终止预算，**不是生产性能目标或 RTO 实测**。事件毫秒数包含父进程轮询、进程调度、证书握手和本机文件系统；没有故障发生到稳定窗口的完整业务统计，不能据此报告服务 p99、跨 AZ 恢复时间或容量上限。

## 复现与证据

需要 Linux、固定 Rust 工具链、C/C++17 和 libclang 18。建议原生编译使用 `CARGO_BUILD_JOBS=2`；常规 CI 应按锁文件从源码构建 native 依赖，不下载未知 RocksDB 二进制。

```bash
cargo +1.90.0 fmt --manifest-path experiments/raft-network/Cargo.toml --all -- --check
cargo +1.90.0 clippy --manifest-path experiments/raft-network/Cargo.toml --all-targets --locked -- -D warnings
cargo +1.90.0 test --manifest-path experiments/raft-network/Cargo.toml --locked -- --test-threads=1
```

每个成功用例写一份 `.log`，含事件顺序、各节点 term/commit/applied/last/snapshot、proposal 准入、业务接受结果、read ticket 的 boot/sequence/barrier、故障模式和代理连接计数。`completed_copy_bytes` 只统计正常结束的复制连接，不作为完整网络流量。默认目录是 `target/evidence/raft-network`，可用 `SCAP_NETWORK_EVIDENCE_DIR` 指定 CI artifact 路径。失败会打印已经观测的有界历史，并清理子进程；失败日志不能当成通过证据，存在旧成功日志也不能替代本次测试的退出状态。

本目录属于真实组件、网络、进程和磁盘的集成层，**不计入生产源码 100% 单元覆盖率**。正式 wire / transport / runtime 分别接受自己的独立单元覆盖率门禁。

## 本次执行结果

2026-11-01，Linux x86_64、Rust 1.90.0、GCC 13.3.0、libclang 18.1.1 环境，在正式源码冻结后使用本目录实际生成的锁文件和 `--locked --offline`：**8 passed、0 failed、0 ignored**，测试执行 13.22 秒，八份日志均到达 `verification passed`。本次包含 genesis application 的逐字节断言，格式和 Clippy `-D warnings` 同时通过。该时长只是测试运行成本，不是服务延迟或故障恢复指标。

本地通过独立 target 复用从同一锁定 RocksDB 源码与 features 构建的静态库；缓存 SHA-256 为 `9459aa3f59f4cca32af9f0e6549e043069c0d48131ab3d63b25396a17ccc9fd3`。未替换 native 实现、存储参数或正式 Rust 模块，常规 CI 仍从源码构建。

真实网络组合还发现了一个只看正常准入单测不容易暴露的问题：[Tonic 0.14.6 的 `serve_with_incoming`](https://docs.rs/tonic/0.14.6/tonic/transport/struct.Server.html#method.tcp_nodelay) 不应用 builder 的 TCP_NODELAY 设置，原先的自供 accepted socket 因而造成健康流量的延迟积累（文档与锁定源码核对日期：2026-11-01）。正式 transport 现对每个 accepted socket 显式设置 NODELAY，失败就拒绝该连接，并以真实 socket 与失败注入单元验证。修复后在原有读 deadline 下全部契约通过，没有通过延长超时来绕过问题。这仍不是吞吐或 p99 基准，当前每次发送的连接策略必须另外做生产容量验收。

## 尚不由此证明的范围

本实验不证明完整 SQL/SDK 网络入口、SQLite writer 自动接管、任意成员变更、生产证书签发与吊销控制面、多 cell 公平调度、S3 归档恢复、跨 AZ、介质掉电或丢盘，以及大快照流式传输或生产吞吐。真实进程 SIGKILL 证明进程崩溃恢复，不能替代设备断电测试；同一台主机上的三进程也不是三个故障域。

相关正式合同见 [runtime 与 RPC](../../docs/engineering/runtime-and-rpc.md)、[Raft 接合](../../docs/engineering/raft-rs-integration.md)、[持久存储](../../docs/engineering/durable-store.md) 和 [性能与恢复口径](../../docs/engineering/performance-slo.md)。
