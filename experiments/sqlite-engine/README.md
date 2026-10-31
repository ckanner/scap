# 正式 SQLite adapter 与真实 cell 的契约验证

本目录是独立测试资产，`publish = false`，没有 library target。产品代码来自正式 `scap-sqlite`、`scap-engine`、`scap-sql`、`scap-cell`、`scap-raft-driver` 和 `scap-raft-rocks`，不从旧 WAL 实验复用执行逻辑。这里的私有 IPC、路由器和集群装配不是生产 RPC、SDK 或鉴权服务。

## 执行

```bash
SCAP_ENGINE_EVIDENCE_DIR=/tmp/scap-engine-evidence \
cargo +1.90.0 test --manifest-path experiments/sqlite-engine/Cargo.toml \
  --locked -- --test-threads=1
```

必须使用独立证据目录，避免并行执行覆盖同名记录。测试先写入 `verification in progress`，仅在全部断言完成后写入 `verification passed`。CI 收集这些文本记录，但不将数据库文件、日志目录或本地构建产物提交到 Git。

套件共 11 个契约场景。2026-10-31 最终完整候选源码本地执行：11 个契约测试全部通过，格式检查与 Clippy `-D warnings` 通过；11 份独立记录均出现最终通过标记，并在后续读取中保持 SHA-256 不变。测试运行时间仅表示这组夹具的执行耗时，不作为 RTO 或延迟分位数证据。

## 真实组件与约束

- 同一测试进程内有三个真实 `raft-rs` Driver、三个独立磁盘 RocksDB 后端、真实 cell 业务状态机。路由队列最多 4096 条，场景 deadline 120 秒，历史最多 2000 条 / 2 MiB。
- 每次 Lookup 都通过真实 Safe ReadIndex，并对当前持久应用状态执行 `decode_bound`；每次新 Accepted 都匹配该 proposal 的 term/index，并检查至少两个节点的 durable applied/commit 已推进。
- SQL 使用正式 `SqliteWriter`，全部连接私有，4096 字节页。事务结果通过正式类型和结果格式编码；物理变更通过正式 engine 格式，恢复不执行原 SQL。
- 夹具为合成主体授予 `READ | WRITE | ADMIN`。这是已授权内部测试身份，不覆盖生产凭据验证、多主体权限组合或 mTLS。当前 cell Lookup 要求 READ，测试不将 WRITE-only 语义视为已经验证。
- 数据库最多 64 页；物理事务最多 300 KiB；单次 SQL 最多 16 条、64 行、16 KiB 结果、200,000 VM 步。这些是夹具限制，不能据此声称产品容量或延迟目标已达到。
- 独立子进程只用于 SQL writer 的 SIGKILL 场景。父进程保有真实三副本集群，子进程使用正式 adapter，通过有界私有 IPC 将 proposal 交给父进程。父进程观察实际 durable quorum 和业务 Accepted 后才发回接受；子进程在返回 native publish 前阻塞，父进程确认外部读仍看不到新表、没有 SQL ACK，再发送真实 SIGKILL。IPC 帧最多约 316 KiB，通道容量 1，等待 20 秒，退出 deadline 10 秒。

## 场景

| 测试 | 断言 |
| --- | --- |
| `typed_sql_results_are_buffered_before_real_cell_acceptance` | 整数、实数、UTF-8、BLOB、NULL 参数及结果保留；WAL gate 内已能读取完整结果，同一 writer 文件的另一个连接仍读取旧数据；接受后才发布 |
| `ddl_retry_returns_original_receipt_without_reexecuting_sql` | 相同 CREATE TABLE 请求通过 preflight 返回原始 receipt/result，没有重新执行 SQL、增加物理 proposal 或伪造新 ticket |
| `read_only_and_zero_row_writes_require_durable_noop_records` | 无 WAL callback 的纯读和零行 UPDATE 仍须写入真实 cell 结果记录；数据库镜像可保持不变，数据库 revision 连续递增 |
| `failed_batch_rolls_back_all_changes_before_any_proposal` | 批次中后续唯一约束失败会撤销前面的 UPDATE，暂存 RETURNING 不发布、不提案，writer 停用 |
| `owner_fence_between_lookup_and_proposal_blocks_native_publish` | 成功 preflight 后、物理 proposal 前插入 ClaimOwner，旧 writer 被真实有序状态机拒绝 |
| `auth_fence_between_lookup_and_proposal_blocks_native_publish` | 成功 preflight 后插入 AuthFence，原 admission 被拒绝，旧数据仍可见 |
| `partition_returns_unknown_and_later_commit_is_recovered_without_sql_replay` | preflight 后隔离 leader，物理 proposal 无 quorum 时返回 UNKNOWN，无 SQL 发布；隔离期间新的 Safe ReadIndex 也无法完成；恢复连接后原 proposal 可提交并从物理历史恢复，不自动重执行 SQL |
| `snapshot_reopen_preserves_results_cancellation_and_physical_recovery` | 落后第三副本通过真实 MsgSnapshot 安装完整状态，随后正常关闭并重新打开三个 RocksDB 后端；原结果、取消记录和完整物理镜像保留 |
| `recovery_preserves_connection_dependent_checks_and_enforces_future_writes` | 原 writer 在 `last_insert_rowid()=7` 时合法提交 CHECK 约束行；全新连接从权威物理历史恢复后保留原数据与镜像，恢复检查不重新裁决当时的业务表达式；新连接随后违反 CHECK 的 INSERT 仍被拒绝，无 native 发布或新增 cell proposal |
| `unsafe_sql_limits_and_existing_worker_directories_fail_closed` | ATTACH、关键 PRAGMA、事务控制、临时表、扩展加载、虚表和越限结果拒绝；已有目录即使只有陈旧 WAL sidecar 也不能作为新 worker 缓存 |
| `sigkill_after_durable_acceptance_rebuilds_the_exact_original_result` | 真实接受后、native 发布前 SIGKILL；从全新目录恢复精确 randomblob 结果，integrity_check 通过，重试返回原 receipt/result |

## 证据边界

本套测试验证正式 adapter 与真实磁盘共识组件的组合行为，不补入单元覆盖率 profile。它与单元精确 100% 门禁、独立三进程 Raft 故障套件分别执行。

三个 Raft 节点仍在同一个测试进程内，网络由有界内存路由器模拟。因此没有证明 TCP/mTLS、跨 AZ、独立 Raft 进程崩溃、物理断电、宿主文件系统故障、设备诚实执行 fsync、生产调度或性能 SLO。正常关闭并重新打开后端也不等于三个节点遭遇 SIGKILL。

正式 adapter 的读请求当前走持久结果记录路径。这些测试不宣称已经交付高吞吐 ReadIndex-only SQL 读服务、Node.js/Hrana 入口、自动 owner 故障转移、S3 归档或无限历史保留。
