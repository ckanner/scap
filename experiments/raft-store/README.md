# 真实 RawNode / RocksDB 持久化与恢复契约实验

记录日期：2026-10-29。状态：**12 项真实依赖契约测试实际通过**，包含 5 项子进程退出恢复实验。本目录是 **G0 研究/集成测试**，没有产品 library 或服务 binary，不提供可部署节点。

## 验证对象与职责

本实验直接依赖正式的 [`scap-raft-store`](../../crates/scap-raft-store/src/lib.rs)，使用它的完整生产实现：身份、版本化编码、恢复校验、`raft::Storage`、持久化状态转换与错误后停止策略。它们按独立的第一方单元覆盖率门禁测试；本实验不补充单元覆盖率分子。

本目录中的 RocksDB wiring、RawNode 运行循环和合成计数器只服务契约测试。backend 以一个 RocksDB `WriteBatch` 替换单个完整 store image，明确开启 WAL 并设置 `WriteOptions::set_sync(true)`。`AtomicBackend::load` 检查整个专有 key namespace，缺少 image 但存在其他 key 时返回 `Unrecognized`；创建与打开既有数据库分开，不能自动把旧目录初始化为新组。

RawNode 由真实固定版本 raft-rs 提供。fixture 不使用 `MemStorage`、不另写一份 Raft 算法，也不通过 `max(commit, applied)` 修复损坏。它按照经过验证的 durable applied 配置新 RawNode，直接使用正式 store 的 `Storage` 实现。

## 固定构建组合

| 项目 | 本实验选择 |
| --- | --- |
| Rust | `1.90.0` |
| raft / raft-proto | git `ad13f3d90780f53aea2488c6a4b76c0d334bf136`，`protobuf-codec` |
| protobuf | crates.io `2.28.0`，不同于 TiKV 的 PingCAP fork |
| RocksDB Rust wrapper | `rocksdb 0.24.0`，`default-features = false`，仅启用 `bindgen-runtime` |
| native binding / engine | `librocksdb-sys 0.17.3+10.4.2`，bundled RocksDB `10.4.2`，静态构建 |
| native 源码 | 上游子模块 `410c5623195ecbe4699b9b5a5f622c7325cec6fe` |
| 其他直接依赖 | `slog 2.8.2`、`tempfile 3.27.0` |
| 完整版本与 registry checksum | 实际生成的 [Cargo.lock](Cargo.lock) |
| 本地 native 构建 | Linux x86_64，GCC 13.3 / C++17，libclang 18.1.3 |
| 测试构建选项 | `profile.dev.debug = 0`；本地 native 构建额外使用 `CXXFLAGS=-g0`、2 个构建 jobs |

Rust wrapper 声明 MSRV 1.85；native 构建需要 C/C++ 编译器、`make` 和可加载的 libclang，不能因为只用 Rust API 就省略这些依赖。此配置不启用 snappy/lz4/zstd/zlib/bzip2、jemalloc 或 io-uring。本次使用的是 rust-rocksdb 项目的发布包，**并非 TiKV 定制的 RocksDB binding/native 组合**。

构建版本来源是固定 [wrapper manifest][wrapper]、[sys manifest][sys]、[native 子模块][native]与本实验锁文件。关闭 debug 信息用于控制研究构建的资源占用，不改变持久化顺序，也不修改产品覆盖率采集配置。

## 实验数据与边界

每个数据库使用临时目录和合成身份。genesis 的 snapshot index / term 为 1，初始 commit / applied 同为 1，配置显式给出。应用状态是一个空值或 8 字节大端整数；每个非空普通日志条目携带一个整数增量。它不模拟 SQL、事务请求身份、fencing、权限或幂等去重协议。

实验固定以下有限范围，**不作为生产容量或性能默认值**：image 最多 8 MiB；单 entry 和 application 最多 1 MiB；最多 4096 个日志 entry。完整 image 原子替换使本轮恢复状态容易审查，但每次更新需要复制和重写整个有限 image，不能据此宣称实现了可扩展的日志存储。

fixture 的处理次序：

1. 获取一个 Ready 后保持串行，不穿插 `step/propose/campaign`。
2. 通过正式 store 同步持久化 snapshot、entries 与 HardState。
3. 持久成功后释放 `persisted_messages`，再调用 `advance_append`；普通 messages 也保守延后发送。
4. 保留原 Ready 的 committed entries，并追加 LightReady 的 committed entries；按序处理完整条目。
5. 将合法 commit、完整 ConfState、计数器结果与 applied 原子持久化，再调用 `advance_apply_to`。
6. 对 snapshot-only Ready，仍使用持久安装后的 applied 推进 RawNode。

commit-only 更新专门用于测试“commit 已持久、业务尚未应用”的崩溃窗口。配置条目通过真实 `apply_conf_change` 计算完整配置后持久保存。任何 store 错误立即结束该 fixture 的运行循环；错误后不继续 advance 或释放本批持久依赖响应。

## 测试清单

| 测试 | 需要观察到的结果 |
| --- | --- |
| 单 voter / LightReady / ReadIndex | 真实选举与提案产生提交；LightReady 的新 commit 不遗漏，应用后取得匹配 context 的 ReadState |
| 已持久投票 | 先 sync 再释放投票响应；重启后拒绝同 term 的另一候选 |
| 写入前失败、sync 后歧义失败 | 当前 store 永久停止，不释放持久依赖响应；重开接受经过校验的完整旧/新 image |
| 冲突日志替换 | 重启保留但不应用未提交后缀；更高 term 的合法 append 覆盖后缀并移除旧尾部 |
| snapshot-only Ready | 真实 MsgSnapshot 安装更高 index 的状态；推进 applied；完整 joint ConfState 重启保持 |
| ConfChangeV2 | 经提交进入显式 joint 配置，重启恢复，然后通过提交退出 joint |
| Ready sync 前退出 | 新提案不出现在恢复后的持久 image |
| Ready sync 后退出 | 新日志仍未提交，不直接应用；新 term 后可能合法提交，不能当作确定回滚 |
| commit sync 后、apply 前退出 | 恢复后仅应用已提交的缺失前缀一次 |
| apply sync 后、advance 前退出 | 新进程从 durable applied 启动，计数器效果不重复 |
| checkpoint sync 后退出 | snapshot、应用、配置与压缩边界一起恢复，边界 term 可用于日志匹配 |
| 非法恢复输入 | 错误节点身份、损坏 image、超出 owned-copy 大小上限、带外来 key 的 namespace 明确拒绝 |

### 进程退出测试的含义

5 个退出用例在独立子进程运行同一测试 binary，用精确测试名称和专用环境变量选择故障边界。子进程在该位置直接 `process::exit(73)`，不会正常析构数据库对象；父进程检查确切退出码、30 秒上限，然后重新打开真实磁盘上的 RocksDB。没有用重新创建一份内存镜像代替磁盘恢复，也没有依靠 sleep 猜测写入完成。

这些实验验证**明确软件边界的进程退出恢复**。它们没有切断机器电源、制造 torn write、修改磁盘控制器缓存或在 native fsync 中途注入故障。一次同步写返回后的进程退出证据不等于完成断电持久性或云盘 SLA 验证。

## 实际执行结果

在上述 Linux x86_64 / Rust 1.90.0 组合上，使用实际生成的锁文件及 `--locked --offline` 执行：**12 passed，0 failed，0 ignored**。其中 5 个测试实际创建子进程并在指定边界退出；没有以默认空跑或 ignored helper 增加通过数量。

Rustfmt 检查通过；`cargo clippy --all-targets --locked --offline -- -D warnings` 通过。首次 Clippy 指出了两个 fixture 的默认值后字段赋值写法，已改为明确结构初始化并重新通过，没有添加 lint 豁免。

本次结果验证了正式 store 与上述真实依赖的受限接合。它不包含三个持久副本的 quorum，也不包含 SQL ACK；生产单元覆盖率仍由根 workspace 的独立报告给出。

## 复现

安装固定 Rust 工具链，并确保系统具备 C++17、`make` 和 libclang；有多个 LLVM 版本时明确配置 `LIBCLANG_PATH`。在仓库根目录执行：

```bash
cargo +1.90.0 fmt --manifest-path experiments/raft-store/Cargo.toml --all -- --check
cargo +1.90.0 clippy --manifest-path experiments/raft-store/Cargo.toml --all-targets --locked -- -D warnings
cargo +1.90.0 test --manifest-path experiments/raft-store/Cargo.toml --locked -- --test-threads=1
```

首次运行需要下载固定公共依赖并编译 bundled RocksDB。依赖已下载时可加 `--offline`；低内存环境可用 `CARGO_BUILD_JOBS=2` 控制并行编译。本实验无需网络 listener，但需要真实临时文件、同步写和创建子进程权限。

## 尚未覆盖

- 没有三个独立节点、网络分区、多进程 quorum、TCP/gRPC 或 mTLS。
- 没有完整 SQL 状态机、owner/auth fence、请求去重、SQL 可见性发布、SDK 返回屏障或 S3。
- 节点重启与单节点 ReadIndex 不构成 SQL 强读或自动 writer 接管的完整证明。
- snapshot 与 image 都是有限内联字节；没有大快照外部文件发布、流式安装或增量回收。
- 没有真实文件系统断电、native 磁盘满/短写注入、长期压力或跨 AZ 测量。
- 不将运行耗时解释为生产吞吐、尾延迟、RTO 或 RPO。

正式 store 的单元覆盖率与这里的真实依赖证据分别报告。未来任何 RocksDB wiring 或 RawNode driver 被产品复用，都必须迁入正式源码清单并通过 100% 第一方单元覆盖率；本目录不是覆盖率例外的运行模块。

## 官方源码

[wrapper]: https://github.com/rust-rocksdb/rust-rocksdb/blob/v0.24.0/Cargo.toml
[sys]: https://github.com/rust-rocksdb/rust-rocksdb/blob/v0.24.0/librocksdb-sys/Cargo.toml
[native]: https://github.com/facebook/rocksdb/tree/410c5623195ecbe4699b9b5a5f622c7325cec6fe

- [固定 RawNode / Ready / LightReady 源码](https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/raw_node.rs)
- [固定 Storage 接口](https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/storage.rs)
- [commit 与 applied 的恢复说明](https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/lib.rs)
- [固定 RocksDB WriteOptions](https://github.com/rust-rocksdb/rust-rocksdb/blob/v0.24.0/src/db_options.rs)
