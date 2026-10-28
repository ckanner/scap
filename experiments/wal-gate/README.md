# libSQL virtual WAL 的 G0 实验探针

状态：研究与测试 harness，**不是可发布的运行时 adapter，也不是数据库服务**。本包只有测试和子进程辅助 binary，没有 library target；产品 crate 不得依赖它。它使用真实 libSQL 引擎，不使用普通 `sqlite3_wal_hook`，不把测试信号解释为真实 quorum。

## 锁定的底座与源码位置

- libSQL commit：[`d8bc862d20bedc72945a1da27c8b7045414c0261`](https://github.com/tursodatabase/libsql/commit/d8bc862d20bedc72945a1da27c8b7045414c0261)，workspace 版本 `0.10.0`，bundled SQLite 版本 `3.47.0`。
- [`libsql-sys/src/wal/mod.rs`](https://github.com/tursodatabase/libsql/blob/d8bc862d20bedc72945a1da27c8b7045414c0261/libsql-sys/src/wal/mod.rs)：`Wal::insert_frames`、`PageHeaders`，后者迭代器在该版本固定为 4096 字节。
- [`libsql-sys/src/wal/wrapper.rs`](https://github.com/tursodatabase/libsql/blob/d8bc862d20bedc72945a1da27c8b7045414c0261/libsql-sys/src/wal/wrapper.rs)：`WrapWal` 与默认透传实现。
- [`libsql-sys/src/connection.rs`](https://github.com/tursodatabase/libsql/blob/d8bc862d20bedc72945a1da27c8b7045414c0261/libsql-sys/src/connection.rs)：`Connection::open(path, flags, manager, auto_checkpoint, encryption)`；本探针启用 `rusqlite` feature，复用其 RAII 连接生命周期。
- [`libsql-ffi/bundled/src/sqlite3.c`](https://github.com/tursodatabase/libsql/blob/d8bc862d20bedc72945a1da27c8b7045414c0261/libsql-ffi/bundled/src/sqlite3.c)：`walFrames` 在提交路径中写 commit marker、同步 WAL，再在 `isCommit` 分支调用 `walIndexWriteHdr` 发布共享 header；先返回错误或阻塞的 wrapper 尚未调用该提交路径。

核查日期：2026-10-27。上游工具链文件指定 Rust 1.85.0；本实验是独立 Cargo workspace，保留独立锁文件，不污染产品 workspace。

## 实验范围

`GateWal` 在真实 `WrapWal::insert_frames` 中复制本次提交页面，然后等待同步测试决策。明确拒绝时返回 SQLite 错误，不调用底层提交；接受后才调用真实 `wrapped.insert_frames`。其他 WAL 方法按上游 wrapper 默认实现透传，包括 rollback、savepoint 和 checkpoint。

实验固定 4096 字节页面、`synchronous=FULL`、`cache_spill=OFF`，关闭自动 checkpoint，并限制一次捕获最多 1024 页。任何 non-commit `insert_frames`（spill）明确报错，**不宣称只捕获最终 callback 就能支持含早期 spill 的事务**。后续支持 spill 必须另行实现完整事务暂存、savepoint 回退和恢复协议。

测试分成两个层次：

| 层次 | 检查内容 | 证据边界 |
| --- | --- | --- |
| 探针合同检查 | 页大小、spill、边界、复制字节所有权、拒绝不调用 publish、publish 错误透传 | 仅检查探针本身，不作为引擎可靠性证据 |
| 真实引擎集成 | 成功提交、另一连接可见性、阻塞/拒绝、后续回滚与继续使用、savepoint、原始 RETURNING、两种进程退出恢复 | 使用固定上游 libSQL 构建和真实临时数据库 |

原始 `RETURNING` 实验特意验证：`sqlite3_step` 可能先返回暂定行，最终提交才经过 gate。服务层仍必须缓冲这些结果；本探针没有实现 Hrana 或 Node SDK 的返回屏障。

两种恢复实验必须分别解释：

1. **native commit 后进程退出**：已完成 `insert_frames`，子进程直接退出、不执行连接析构；重新打开真实 WAL 验证已提交记录。
2. **测试接受后、native publish 前退出**：把从真实引擎取得的页面写入独立测试 fixture，`sync_all` 文件及父目录，再直接退出。原工作库仍是旧状态；测试把完整页增量应用到隔离的干净基线，恢复新文件并检查 SQL 内容及 `integrity_check`，不重新执行 SQL。

第二项 fixture 是单机故障注入夹具，没有 Raft、身份、幂等、checksum 或生产日志格式。它只验证这个受限引擎路径导出的页面能恢复提交结果，**不证明 durable quorum、掉电安全、RPO 0、生产恢复、精确读屏障或自动 failover**。子进程退出也不等于真实掉电。

## 运行

需要 Rust、Cargo、C 编译器、构建依赖下载能力；固定版本默认使用预生成 bindings，不设置 `LIBSQL_DEV`。依赖升级或开启重新生成 bindings / 加密等 feature 时须重新核对 clang、cmake 等要求。

```bash
cargo test --manifest-path experiments/wal-gate/Cargo.toml --locked -- --test-threads=1
```

从本目录运行时使用 `cargo test --locked -- --test-threads=1`。所有测试数据位于独立临时目录。CI 应将这个 engine probe 作为独立 tier，保留工具链、依赖、命令与完整结果；不得将它并入核心产品的单元覆盖率分母或用它凑 100%。若未来复用探针逻辑为产品代码，必须迁移到受控产品 crate，并通过产品的 100% 单元行 / 函数 / 分支覆盖门禁及对应集成验证。

## 当前执行状态

2026-10-27 已在 Linux 环境用 Rust 1.85.0、GCC 13.3.0 和本目录锁文件完成编译，并执行：

```bash
cargo test --manifest-path experiments/wal-gate/Cargo.toml --locked --offline -- --test-threads=1 --nocapture
```

结果为 **13 passed，0 failed，0 ignored**：8 项真实引擎 / 子进程实验，5 项探针合同检查。forced-spill 实验通过实际 SQLite 小页缓存触发 non-commit callback，验证明确拒绝后外部连接仍只见旧数据。同一锁文件也已在 Rust 1.90.0 下重新编译并通过全部 13 项检查；CI 将在锁定环境独立重跑并保留结果。

这不是 G0 全部通过声明。尚未验证真实 quorum、掉电、精确读屏障、Hrana / Node SDK 返回边界、一般 spill 事务、加密或其他页大小；没有把测试套件运行时间当作数据库性能指标，也没有把本探针纳入产品 100% 单元覆盖率成绩。
