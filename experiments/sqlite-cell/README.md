# 真实 SQLite 提交门与 durable cell 的组合合同

状态：**独立研究与集成测试 workspace**，不是可部署的数据库服务，也不是生产 SQLite adapter。这里把真实 libSQL virtual WAL、正式 `scap-core` 提交协调器、`scap-cell` 业务状态机、`scap-raft-driver` 和 `scap-raft-rocks` 接起来，检查“业务接受、原生可见、对外完成”之间的顺序。业务状态机没有在实验目录重写。

本包 `publish=false`，没有 library target。`sqlite-cell-writer` 是 `test=false` 的测试辅助进程，产品 crate 不得依赖本实验。六项集成合同独立于第一方产品的 100% 单元行 / 函数 / region / 分支覆盖率，不能用它们补产品覆盖率。

## 实际进程与持久化边界

父测试进程创建三个正式 `Driver<RocksBackend, CellApplication>`，每个 driver 使用独立 RocksDB 目录、节点身份和启动身份。三个真实 Raft 状态机通过父进程有界消息队列传递原始 `raft::eraftpb::Message`；没有用假 quorum 或手工制造 `Accepted`。应用命令必须真实复制、持久化、提交并应用；返回的 `last_outcome.position` 必须严格等于本次 proposal 的 `(term, index)`，且至少两个正式节点的 durable 状态已经达到该位置。

**这三个 Raft driver 位于同一个 OS 进程。** 本实验没有声称三个 Raft 进程、TCP 分区或跨主机故障。三 OS 进程的 Raft 分区 / 选举 / ReadIndex / 快照验证在相邻的 [`raft-cluster`](../raft-cluster/README.md) 实验中独立执行。

SQL writer 则是真实独立 OS 子进程，使用真实 libSQL 连接、真实文件与 WAL。父进程持有另一只只读 SQLite 连接，直接观察提交前后的数据库内容。故障合同确实调用 `kill` 并验证退出信号为 `SIGKILL` / 9；不是返回一个模拟错误。Raft 目录重开合同正常关闭三个 driver 后打开同一目录，不能把这个动作称为 Raft 进程崩溃。

## 版本与组成

| 组成 | 本实验使用方式 |
| --- | --- |
| Rust | 1.90.0；独立 `Cargo.lock`，固定依赖解析 |
| libSQL | 固定 [`d8bc862d20bedc72945a1da27c8b7045414c0261`](https://github.com/tursodatabase/libsql/commit/d8bc862d20bedc72945a1da27c8b7045414c0261)，`libsql-sys` 的 `rusqlite` feature，bundled SQLite 3.47.0 |
| virtual WAL gate | 直接复用 [`wal-gate/src/probe.rs`](../wal-gate/src/probe.rs) 的真实 `WrapWal::insert_frames` wrapper；没有普通提交后 `sqlite3_wal_hook` |
| raft-rs | 固定 TiKV [`ad13f3d90780f53aea2488c6a4b76c0d334bf136`](https://github.com/tikv/raft-rs/commit/ad13f3d90780f53aea2488c6a4b76c0d334bf136)，使用正式 driver 的 PreVote、CheckQuorum、Safe ReadIndex 策略 |
| RocksDB | 正式 `scap-raft-rocks`，锁定 `rocksdb 0.24.0` / `librocksdb-sys 0.17.3+10.4.2`，保留其 strict WAL 与持久化语义 |
| 业务规则 | 正式 `scap-cell`：owner / auth fencing、请求去重、持久取消、有界物理 base/tail 和完整逻辑结果保留 |
| 物理编码与恢复 | 正式 `scap-engine::Image` / `scap_core::physical`；实验仅将真实 native 捕获页转成正式 PageBatch，不再自行实现恢复算法 |
| 提交屏障 | 正式 `scap-core::CommitCoordinator` 和窄 `ConsensusPort` / `VisibilityPort`；重新执行 SQL 的业务去重另有明确边界，见下文 |
| 测试 IPC | 私有有界二进制 stdin/stdout 帧；没有 Hrana、HTTP、RPC 服务或 Node SDK |

源接口与版本核对日期：2026-10-31。virtual WAL 的上游入口是固定版本的 [`wal/wrapper.rs`](https://github.com/tursodatabase/libsql/blob/d8bc862d20bedc72945a1da27c8b7045414c0261/libsql-sys/src/wal/wrapper.rs) 与 [`wal/mod.rs`](https://github.com/tursodatabase/libsql/blob/d8bc862d20bedc72945a1da27c8b7045414c0261/libsql-sys/src/wal/mod.rs)。有关页大小、spill 与底层发布顺序的独立引擎探针，见 [`wal-gate` 说明](../wal-gate/README.md)。

## 六项合同

| 测试 | 真实动作与断言 |
| --- | --- |
| `returning_is_buffered_until_real_quorum_acceptance_and_native_publication` | 独立 writer 执行 `UPDATE ... randomblob(32) ... RETURNING`，先把暂定行留在私有缓冲，再进入真实 WAL gate。父进程外部 SQLite 连接仍见旧内容、没有完成 ACK，cell 查询为 `Unknown`。只有真实 quorum 和本次业务 `Accepted` 后才调用 native publish；最终 `sqlite3_step` 成功后才发 ACK，并核对结果、业务 sequence 与实际 SQLite revision。 |
| `newly_claimed_owner_fences_a_staged_old_writer_without_publishing` | 旧 writer 已产生真实页面但尚未 publish。另一个 `ClaimOwner` 提升 owner epoch；旧物理提交仍能进入 Raft 日志，但正式 cell 返回 `Rejected(Fenced)`。协调器不调用 publish，writer 回滚，外部 SQLite 内容和 revision 不变。 |
| `auth_fence_rejects_old_admission_after_raft_commit_without_sql_visibility` | 提交并应用 `AuthFence`，令 auth epoch 从 1 变为 2。已暂存的旧 admission 得到业务 `Rejected(Unauthorized)`；即使 Raft 已提交该尝试，也不发布 SQLite 页面。 |
| `killed_sql_writer_recovers_random_result_from_cell_pages_without_sql_replay` | cell 已经 durable quorum 接受页面和暂定结果，native publish 尚未发生时 SIGKILL SQL writer。旧文件仍见旧内容；从空文件应用 cell 保留的物理页，恢复出完全相同的随机结果和提交序号，`integrity_check=ok`。恢复不执行原 SQL。 |
| `duplicate_business_request_discards_new_random_pages_and_returns_original_result` | 首次成功后，用相同业务 request ID / fingerprint 重跑随机 SQL，确认产生不同结果、页面摘要及 predecessor。正式 cell 返回原始 `AlreadyCommitted` receipt；新页面被回滚，不 publish，通过当前授权下的 Lookup 取回原结果。 |
| `cancellation_owner_auth_results_and_pages_survive_snapshot_install_and_reopen` | 暂停第三个副本，另两个持久节点接受随机写、auth / owner 更新及 `ResolveOrCancel`。晚到同 ID 写得到 `Rejected(Cancelled)`。leader checkpoint 后真实发送 `MsgSnapshot` 安装到落后副本，再重开三个 RocksDB 目录并重新选举；验证 owner、auth、去重原结果、取消记录、完整原 Admission 和物理页均保留，且可从空文件重建。 |

这些合同有意区分三个事件：**Raft 日志提交**、**业务状态机接受**、**SQLite 原生发布**。owner / auth / cancel 被拒绝的命令可以作为 Raft 日志持久化，仍然不能触发页面发布。普通 `Outcome::Rejected` 只拒绝该 `(term, index)` 的这次尝试；它不自动永久取消 request ID。持久禁止迟到写依赖有序的 `ResolveOrCancel`。

## 初始化与物理恢复的证明范围

每个场景先创建零长度 SQLite 文件。建表、建立测试 revision 触发器、插入初始 `base` 数据放在一个显式事务中，其真实 gate 页面也经正式 cell 接受，之后才准许原生提交。当前实测初始化产生一个被接受的物理 batch；代码也对打开阶段的额外 gate 做有界处理，并逐次提交真实决策。

初始化完成后，测试立即只用 cell 保留的事务重建另一份空文件，检查初始内容。这一步防止后续恢复不自觉依赖未登记的本地 baseline。后续 SIGKILL 和快照场景继续使用同一个恢复过程：

1. 获取新的 Safe ReadIndex 完成结果，确认应用位置不落后，再读取正式 cell 状态。
2. 用 `CellState::decode_bound` 校验 cell 身份和真实 durable applied 位置；term 来自 applied entry 或 snapshot boundary，不能使用可能更大的当前选举 term。
3. 由可信 fixture 内部恢复角色，在当前授权下调用正式 `Image::recover`；它绑定该 fresh view 的身份、position、revision 和 commit hash，从 `recovery_source` 提供的 base 和连续 tail 恢复，正式共享物理算法校验格式、页面和摘要。
4. 把正式 Image 返回的完整字节写到新建零长度文件。实验不再独立循环重放页，也不把私有 IPC 格式当成生产恢复格式。
5. 同步恢复文件及父目录，再用只读 SQLite 检查 `PRAGMA integrity_check`、实际 revision 和原始随机结果。

恢复路径只写 cell 中的真实物理页，不重新执行 `CREATE`、`INSERT`、`UPDATE` 或 `randomblob`。DDL 也在已经持久化的页面里。此早期组合夹具仍不提供数据库迁移、删除或真实 S3 网络合同；有界 base/tail 与跨版本服务恢复分别由相邻正式引擎、[网络 SQL](../sqlite-network/README.md) 和 [旧盘升级](../history-network/README.md) 合同覆盖，不能据此宣称大数据库的通用恢复已完成。

## 提交协调器和业务请求去重的边界

一般接受 / 拒绝路径使用真实 `CommitCoordinator::complete`。它取得本次正式 cell outcome，检查原生 SQLite 仍处于 predecessor，收到真实 Accepted receipt 后才调用 `VisibilityPort::publish`。测试用同一原生事务内更新的 `cache_meta.revision` 观察实际文件前序；这是测试 schema，不能冒充已实现的生产引擎元数据协议。

`CommitCoordinator` 的重试合同针对**同一个不可变物理提案**。再次执行同一条非确定性 SQL，会生成新页面、新摘要和新 predecessor；业务去重返回的原 receipt 属于首次提交，不能把它的 ticket 修改成新提案以绕过校验。

因此第 5 项合同在本次真实 cell 返回 `AlreadyCommitted` 后，直接中止并回滚新 SQL 事务，取回原结果。它不把新页面送入 publication port，也不伪造新的 Accepted。这条实验路径验证业务去重与原生引擎的接合语义，尚不是 Node SDK 的完整重试实现。`Lookup::Unknown` 也不等于确定未提交；需要确定终止迟到请求时，使用有序取消操作。

## 显式资源与等待上限

| 资源 | 上限与行为 |
| --- | --- |
| 页格式 | 4096 字节；其他页大小在遍历上游 `PageHeaders` 之前拒绝 |
| spill | `cache_spill=OFF`；任何 non-commit `insert_frames` 仍明确拒绝，不声称支持通用 spill |
| gate 捕获 | 复用 probe 在复制时最多 1024 页；此 fixture 在编码 / 发 IPC 前进一步要求 batch 与文件均最多 64 页 |
| IPC 页捕获帧 | `16 + 64 * (4 + 4096)` 字节；`SCAPPG01`、`size_after`、数量、页号及整页字节，仅为实验父子进程私有格式；父进程用正式 Image::prepare 编成 `SCAPIMG!` 后才提交 cell |
| 结果 | 最大 1024 字节；本实验 UPDATE 恰为 32 字节，初始化为空 |
| IPC | 总帧在读取分配前检查上限；输入、输出 channel 容量均为 1；send 使用 `try_send`，父子往返共享最多 20 秒的绝对 deadline |
| 收敛工作 | 消息队列最多 4096 条；每轮最多处理 4096 条；driver drain 最多 64 轮，预算耗尽即失败 |
| 场景 | 最多 120 秒；事件历史最多 2000 条 / 2 MiB |
| 进程清理 | 等待退出最多 10 秒；失败 / panic 路径也 kill、reap，先关闭 channel 再有限等待 I/O 线程结束 |
| 持久状态 | cell state 最多 2 MiB，命令 400 KiB，单事务 300 KiB；其余 database / request / policy / Store / driver 上限在测试配置中显式设置 |

这些是实验拒绝和超时边界，不是服务吞吐、尾延迟或自动故障恢复 SLO。同步 RocksDB / OS 文件调用仍依赖正常工作的本地内核与文件系统；外层 CI job 有整体超时。

## 运行与证据

需要 Linux / Unix 的进程退出信号 API、Rust 1.90.0、C/C++17 编译工具链，以及 libclang 18 动态库和 headers 供固定 RocksDB bindings 构建。Ubuntu 24.04 可使用 `libclang-18-dev`。本次本地实际使用 GCC/G++ 13.3.0、libclang 18.1.3。使用默认源码编译 RocksDB 时建议设置 `CARGO_BUILD_JOBS=2`、`CXXFLAGS=-g0`；不需要预装 RocksDB 服务。

从仓库根目录执行：

```bash
cargo +1.90.0 fmt --manifest-path experiments/sqlite-cell/Cargo.toml --all -- --check
cargo +1.90.0 clippy --manifest-path experiments/sqlite-cell/Cargo.toml --all-targets --locked -- -D warnings
SCAP_SQLITE_CELL_EVIDENCE_DIR="$PWD/target/evidence/sqlite-cell" \
  cargo +1.90.0 test --manifest-path experiments/sqlite-cell/Cargo.toml --locked -- --test-threads=1
```

依赖已下载时可加 `--offline`。独立锁文件包含固定上游 git commit，产品根 workspace 不链接此 helper；CI 单独构建、执行并保留 `sqlite-cell-evidence` artifact。本地若使用已从相同锁定源码构建的 RocksDB 静态缓存，必须记录其来源与哈希，并保留 C++ runtime 链接；CI 仍从源码构建。

2026-10-31 的本地实际结果：**6 passed，0 failed，0 ignored**，stable fmt 和全部 targets Clippy `-D warnings` 通过。本次依赖已备齐后的首次测试执行为 2.40 秒；这个数字仅是六场景执行记录，不是数据库延迟、RTO 或压测结果。

每个通过的场景写一份有界 `.log`，含版本、进程几何、真实 applied `(term, index)`、业务 outcome、达到提交位置的持久副本数，以及相关的 native publication、SIGKILL 或 snapshot install 事件。初始化和恢复记录区分空文件重建与对原文件的只读观察。日志只含生成的测试数据；不应提交进 Git。未通过的场景会打印有界历史，不能留下成功结尾冒充通过。

## 尚未交付的生产能力

本实验验证了这些受限路径之间的真实组合，不声明整个 G0 已完成。尚缺生产 engine adapter、通用 SQL / 事务 / spill 支持、任意页大小、Node SQLite 驱动兼容、Hrana 返回屏障、远程认证与凭据解析、端到端 SQL 读屏障、worker 自动接管、S3 归档和冷恢复、资源隔离及线上运维接口。这里的 Safe ReadIndex 用于读取 cell 决策和恢复状态，外部 SQLite 读用于检验原生可见性，两者尚未形成生产 SQL 读取协议。

本地三份 RocksDB 的真实持久化和 SQL 子进程 SIGKILL 不能证明跨故障域高可用、真实掉电或硬件持久性，也不能替代正式的故障矩阵和性能验收。下一阶段生产化时应把 adapter 迁入受控产品 crate，继续满足严格单元覆盖门禁，并补上相应真实端到端故障验证。
