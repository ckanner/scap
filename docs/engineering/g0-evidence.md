# G0 原型执行证据与剩余门禁

初始记录日期：2026-10-27；RPC 与持久存储实验追加日期：2026-10-29。状态：**部分 G0 证据已经实际执行，整个 G0 尚未通过；没有可部署 HA 服务。** 性能、RTO 和三 AZ RPO 目标均未测量，不能从单机测试运行时间推导生产指标。

## 1. 本次实际交付

| 资产 | 实现与证据 | 不包含的能力 |
| --- | --- | --- |
| `crates/scap-core` | 提交完成顺序；两个窄 port；完整回执身份、前序序号、重复结果、未知结果与本地发布失败处理 | SQLite adapter、真实 quorum、授权校验服务、Raft 状态机 |
| `crates/scap-raft-store` | 正式 `raft::Storage`、有界持久镜像、身份/投票/日志/应用校验、原子 checkpoint 与恢复策略 | 生产 native 后端、网络 driver、SCAP SQL/owner/auth/dedup 状态机 |
| `experiments/wal-gate` | 固定 libSQL 的真实提交前 gate、另一连接可见性、拒绝/回滚、页面捕获与进程退出恢复 | 产品运行时 adapter、分布式日志、一般 spill 事务、SDK 返回屏障 |
| `experiments/raft-rpc` | 固定 raft-rs 的真实消息经过 Tonic loopback 往返，验证原始字节、字段、拒绝和两层限额 | RawNode、持久化、quorum、mTLS、TiKV 协议互通 |
| `experiments/raft-store` | 真实 RawNode 与同步 RocksDB，Ready/LightReady、投票、joint ConfState、快照及 5 个进程退出边界 | 三进程 quorum、真实断电、生产服务、SQL 接合、性能/RTO |
| 仓库工具 | 文档/合同检查；覆盖率源码清单与原始计数核对 | 证明报告来源可信或取代人工架构审查 |
| CI | 分开执行 Rust 单元覆盖、Python 工具单元覆盖、引擎探针、RPC 探针和持久恢复探针，保留覆盖率 JSON | 云环境性能、三 AZ 演练、生产 SLA |

`CommitCoordinator` 只有在新接受回执绑定完整请求、序号正确且本地发布成功后才返回 ACK。`AlreadyCommitted` 是单独的历史结果路径：停止当前上下文，交外部丢弃新暂存、对齐状态和取得原结果，绝不再次发布旧页面。`UNKNOWN`、非法回执、拒绝、发布失败与被捕获的 adapter panic 均不能让同一上下文继续提交。

端口合同依然需要真实 adapter 兑现。一个 fake 返回 `Accepted` 只能验证调用顺序，不能证明 fsync、quorum、授权或掉电持久性。`VisibilityPort` 还要求真实实现核对本地 applied head，避免旧页覆盖新状态。

## 2. 初始核心与引擎执行结果（2026-10-27）

环境：Linux x86_64，GCC 13.3.0；核心编译/Clippy 使用 Rust 1.90.0；覆盖率使用 `nightly-2025-09-18`（Rust 1.92.0-nightly）及其匹配 `llvm-tools-preview`；`cargo-llvm-cov 0.6.21`；Python 3.12 与 `coverage.py 7.10.6`。

| 测试层 | 本次结果 |
| --- | --- |
| Rust 产品核心单元测试 | **10 passed，0 failed** |
| 核心行覆盖 | **40 / 40，100%** |
| 核心函数覆盖 | **2 / 2，100%** |
| 核心 LLVM region 覆盖 | **38 / 38，100%** |
| 核心 LLVM 分支覆盖 | **10 / 10，100%** |
| Python 工具单元测试 | **47 passed，0 failed** |
| Python 工具语句覆盖 | **241 / 241，100%** |
| Python 工具分支覆盖 | **116 / 116，100%** |
| 真实 libSQL 实验 | **13 passed，0 failed，0 ignored**：8 项引擎/子进程实验与 5 项探针合同检查 |
| Rust 格式与 Clippy | 通过；Clippy 以 `-D warnings` 执行 |

这些百分比描述初始核心范围：当时只有一个生产 Rust 源文件、两个有函数体的生产函数。最新两个正式模块的覆盖计数见第 7 节。测试代码、编译器生成的实现、第三方依赖和测试探针不被包装成产品逻辑的覆盖成绩；所有第一方产品源码由门禁清单核对。LLVM 的已计数分支不等于所有 `match` 模式、派生比较的每个条件、MC/DC 或全部执行交错。10 项核心行为测试同时检查完整身份字段、错误结果及未发生的发布效果。

引擎实验先在上游指定 Rust 1.85.0 下完成，再用相同锁文件在 Rust 1.90.0 重新编译运行，均通过。它固定 4096 字节页面、关闭 spill、限制最多 1024 页，并使用同步测试决策。独立 fsync 页 fixture 只证明受限页面捕获/重建路径；进程退出不等于断电，也没有同步复制。

### 2.1 已验证的真实引擎行为

1. 提交 gate 等待时，另一真实 SQLite 连接只能读取旧数据；接受之后才看到新数据。
2. 明确拒绝 gate 后，外部连接看不到本次写入，回滚后可以继续正常事务。
3. 显式回滚与 savepoint 回退不会把已撤销内容带入最终提交页面。
4. 原始 `RETURNING` 会先给出暂定行，最终提交才经过 gate；服务层仍需缓冲，实验没有实现 SDK 屏障。
5. 真实 forced-spill 被明确拒绝，不出现部分可见；一般 spill 暂存协议仍未实现。
6. native commit 后子进程直接退出，重开 native WAL 可恢复提交。
7. gate 接受后、native publish 前写入测试页 fixture 并 fsync，再退出；隔离新文件可以用干净基线和真实页恢复并通过 `integrity_check`，没有重放 SQL。

精确底座、源码链接与实验解释见 [探针 README](../../experiments/wal-gate/README.md)。

## 3. 复现正式模块单元覆盖

首次准备工具：

```bash
rustup toolchain install 1.90.0 --profile minimal --component rustfmt,clippy
rustup toolchain install nightly-2025-09-18 --profile minimal --component llvm-tools-preview
cargo +1.90.0 install cargo-llvm-cov --version 0.6.21 --locked
```

在仓库根目录执行：

```bash
cargo +1.90.0 fmt --all -- --check
cargo +1.90.0 clippy --workspace --all-targets --all-features --locked -- -D warnings
mkdir -p target/coverage
cargo +nightly-2025-09-18 llvm-cov clean --workspace
cargo +nightly-2025-09-18 llvm-cov --workspace --lib --bins --all-features --locked --branch --no-cfg-coverage --no-cfg-coverage-nightly --json --output-path target/coverage/unit.json
python3 scripts/check_unit_coverage.py target/coverage/unit.json
```

只运行正式 workspace 的 library/binary unit harness，不运行独立实验 workspace 或 integration tests；采集前清理旧 profile。`scap-raft-store` 的单元测试使用可控 AtomicBackend，不链接 RocksDB 后端。禁止因 `cfg(coverage)` 改变产品代码，脚本同时拒绝相关源码排除。新增 bin、feature 或生成代码时必须扩展真实编译/执行矩阵，不能认为当前命令自动覆盖所有未来配置。

报告文件为 `target/coverage/unit.json`。CI 对每个生产源文件核对精确整数计数；缺源码、重复文件、非法计数、分支缺失或未达 100% 都失败。核心报告中若出现研究探针等未批准的生产来源也失败，不能通过从实验路径引入代码绕过分母。

## 4. 复现工具脚本覆盖

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
mkdir -p target/coverage
COVERAGE_FILE=target/coverage/tooling.coverage .venv/bin/python -m coverage erase
COVERAGE_FILE=target/coverage/tooling.coverage .venv/bin/python -m coverage run --branch --source=scripts -m unittest discover -s tests/tooling
COVERAGE_FILE=target/coverage/tooling.coverage .venv/bin/python -m coverage report --show-missing --fail-under=100
COVERAGE_FILE=target/coverage/tooling.coverage .venv/bin/python -m coverage json -o target/coverage/tooling.json
```

47 项 unittest 包括错误文件、非法链接、设计合同、真实 CLI 入口、近 100% 的舍入陷阱、空分母、遗漏源码、嵌套 coverage cfg、实验代码混入单元 target 等反例。工具脚本没有使用 `no cover` / `no branch` 隐藏路径。

## 5. 独立引擎实验

```bash
cargo +1.90.0 fmt --manifest-path experiments/wal-gate/Cargo.toml --all -- --check
cargo +1.90.0 test --manifest-path experiments/wal-gate/Cargo.toml --locked -- --test-threads=1
```

初次构建需访问固定的公共上游与 crates registry，并需要 C 编译器。下载已完成时可加 `--offline`。本目录没有可供产品依赖的 library target，实验结果不进入核心 unit profile。

## 6. 真实 RPC 编码与传输实验（2026-10-29）

固定 raft-rs `ad13f3d90780f53aea2488c6a4b76c0d334bf136` 的 `protobuf-codec`，在 Tonic 0.14.6 / Prost 0.14.3 外层 envelope 中携带原始 bytes；Tokio 1.50.0，Rust 1.90.0，完整解析版本由独立 Cargo.lock 固定。真实 TCP/HTTP2/gRPC 往返 **8 passed，0 failed，0 ignored**；格式与 Clippy `-D warnings` 通过。

测试覆盖 Append、snapshot 完整配置字段、ReadIndex context、未知字段/非规范 varint 字节保持、版本/codec 错误、路由错误、畸形内层及 from/to 冲突、内层 2048 字节与 gRPC 4096 字节的独立限额。snapshot 仅传输，没有安装；ReadIndex 仅传输，没有形成读屏障。测试不通过 sleep 猜测端口就绪，使用真实本机 listener，且有有限连接/请求/退出超时。

结果仅证明该受限编解码边界可工作。没有 RawNode、fsync、quorum、mTLS 或 SQL 提交；`Observed` 不等于 Accepted。protobuf 2.28.0 也不是 TiKV 的 PingCAP fork。详细用例、构建要求和明文 loopback 限制见 [实验 README](../../experiments/raft-rpc/README.md)。

```bash
cargo +1.90.0 fmt --manifest-path experiments/raft-rpc/Cargo.toml --all -- --check
cargo +1.90.0 clippy --manifest-path experiments/raft-rpc/Cargo.toml --all-targets --locked -- -D warnings
cargo +1.90.0 test --manifest-path experiments/raft-rpc/Cargo.toml --locked -- --test-threads=1
```

这组测试在独立 workspace 和 CI job 运行，属于研究/集成证据，不混入核心 unit profile，也不改变第 2 节覆盖率分母。未来复用其中的第一方运行逻辑，须先迁入生产范围并满足 100% 单元门禁。

## 7. 持久存储、RawNode 与进程恢复（2026-10-29）

正式 `scap-raft-store` 实现固定 raft-rs 的 `Storage`，通过 `AtomicBackend` 隔离原子同步 I/O。真实契约夹具直接使用该正式实现，并以 RocksDB 单个同步 WriteBatch 保存完整状态；没有用 MemStorage 代替持久策略。代码职责与完整格式见 [持久存储契约](durable-store.md)，布局取舍见 [ADR-0008](../adr/0008-bounded-durable-store-g0.md)。

### 7.1 正式单元与精确覆盖率

同第 3 节的固定工具链与命令重新采集整个正式 workspace，**29 项单元测试通过，0 failed**：`scap-core` 10 项，`scap-raft-store` 19 项。

| 正式源文件 | 行 | 函数 | LLVM region | LLVM 分支 |
| --- | --- | --- | --- | --- |
| `crates/scap-core/src/lib.rs` | **40 / 40** | **2 / 2** | **38 / 38** | **10 / 10** |
| `crates/scap-raft-store/src/lib.rs` | **524 / 524** | **44 / 44** | **790 / 790** | **174 / 174** |

每个文件、每种指标都是 100%，由未放宽的精确整数门禁检查。所有正式第一方源码仍进入分母；只登记新增的单元测试文件与独立研究目录，没有通过忽略产品源码、改变 coverage cfg、舍入或降低阈值补齐覆盖。

第一次采集暴露 4 个未覆盖 region。补充测试验证了 persist、apply、checkpoint 在各字段分别合法时仍可能超过总镜像预算，以及更严格恢复限额和累计日志数量的拒绝路径。内部 checkpoint 对已经验证的 applied 范围改用窄的确定性 term 查询，避免重复制造不可达的错误分支；外部 `Storage::term` 的 Compacted/Unavailable 检查保留。覆盖率用来驱动真实错误路径和职责边界，不把“覆盖所有计数”当成所有执行交错已经验证。

### 7.2 真实依赖与恢复证据

环境：Linux x86_64、Rust 1.90.0、GCC 13.3.0、libclang 18.1.3。固定 raft-rs `ad13f3d90780f53aea2488c6a4b76c0d334bf136` / protobuf 2.28.0；RocksDB Rust binding 0.24.0、`librocksdb-sys 0.17.3+10.4.2`，native RocksDB 10.4.2。完整解析版本由独立 Cargo.lock 固定；该 binding 不是 TiKV 的 fork。原生构建关闭默认压缩等特性，采用静态库；夹具显式开启 WAL 并对 WriteBatch 设置 sync。

**12 项真实契约测试通过，0 failed，0 ignored**；格式检查与 Clippy `-D warnings` 通过。

| 证据 | 实际检查 |
| --- | --- |
| Ready / LightReady | 单投票节点真实选举、提案、持久提交及应用；ReadIndex context 传播；重开后继续运行 |
| 投票 | 投票先同步再发响应；重开后拒绝同 term 的第二个候选者 |
| 不确定存储结果 | 写入前报错与实际同步后报错都停止实例，不提前发 persisted response 或 advance；重开分别得到旧或新状态 |
| 日志与配置 | 未提交后缀不被当成业务应用，可由合法新后缀替换；ConfChangeV2 显式进入 joint、重开及退出 joint |
| Snapshot | 真实 snapshot-only Ready 安装完整 joint ConfState，保留 boundary term；不把日志匹配后的 commit 快进当成安装证据 |
| 恢复输入 | 身份不符、完整性破坏、超过读取上限、外来或残留 key 均拒绝 |

其中 **5 项测试使用独立子进程在明确位置直接退出**，父进程检查约定退出码、限时等待并重新打开真实数据库：

| 退出位置 | 重开后的期望结果 |
| --- | --- |
| Ready 同步前 | 本次新提案未持久存在 |
| Ready 同步后 | 持久后缀存在，但不能擅自视为已提交或已应用；后续合法共识可以提交结果未知的提案 |
| commit 同步后、apply 前 | 恢复已提交范围并仅应用一次 |
| apply 同步后、advance 前 | 从持久 applied 恢复，不重复业务效果，并能继续提案 |
| checkpoint 同步后 | 恢复 checkpoint、应用和 boundary term，并能继续运行 |

子进程退出不调用 RocksDB 的正常析构；这验证的是进程崩溃路径，不是物理掉电、native fsync 内部 torn write 或设备丢失。注入错误分别发生在真实写调用之前和成功同步之后，不冒称已经注入底层 ENOSPC 或 I/O 故障。合成应用是计数器，单节点 ReadIndex 也不等于产品 SQL 读屏障。

复现需 C/C++17 编译器、libclang 18 和相应开发文件；Ubuntu 24.04 可安装 `libclang-18-dev`，并按安装位置设置 `LIBCLANG_PATH`。CI 单独执行下列合同测试，不把结果混入单元覆盖：

```bash
cargo +1.90.0 fmt --manifest-path experiments/raft-store/Cargo.toml --all -- --check
cargo +1.90.0 clippy --manifest-path experiments/raft-store/Cargo.toml --all-targets --locked -- -D warnings
cargo +1.90.0 test --manifest-path experiments/raft-store/Cargo.toml --locked -- --test-threads=1
```

### 7.3 本阶段的适用边界

完整镜像是有明确限额的 G0 布局，每次修改重写整个状态。checkpoint 会把当前应用复制进 snapshot，同时保留当前应用与必要的日志后缀，所以它也可能增大镜像并超过总上限；拒绝时磁盘保留旧镜像。不能据此推断大 cell 容量、长尾成本或生产吞吐。

正式模块已有 raft-rs 依赖与 Storage 实现；生产 RawNode driver、native 后端装配和 SCAP 业务状态机尚未实现。实验包含真实依赖与恢复行为，但没有完成三进程 quorum、RPC 接合、SQLite 原子发布或 HA 服务。上述计数不改变原有性能、RTO 和 RPO 合同。

## 8. 仍然阻断完整 G0 / HA 上线的工作

- 完整、可恢复的事务暂存协议：spill、更多 page size、大事务、checkpoint 交互、错误恢复与所有可见性边界。
- 生产 `raft-rs` driver、native backend 及增量存储布局；把已有单节点 Ready/LightReady、应用、快照和成员变更证据扩展到真实三进程 quorum、网络分区与物理存储故障。
- 与提交完成策略连接的真实引擎与共识 adapter，以及其独立 100% 单元覆盖和真实契约测试。
- Hrana / Node.js SDK 的请求身份、返回值缓冲、交互事务、UNKNOWN 和重试语义。
- 固定 sqld 与现代平台依赖树的实际接合边界；RPC mTLS 身份、成员权限、重连/取消、全局背压与多 cell 调度验证。
- 跨三个 AZ 的失败检测、owner 仲裁、重建、路由恢复和 R0/R1/R2 接管实现。
- [性能目标](performance-slo.md)的真实延迟、吞吐、安全容量、RTO、RPO 与长期可用性证据。

这些工作不能用本页测试计数代替。后续每次修改代码或工具链，应保留新的精确报告并更新本页；性能不达标不得更改已确认写入的持久性合同。

2026-10-28 的 [ADR 0006](../adr/0006-raft-rs-consensus-library.md) 将共识库首选候选由 OpenRaft 调整为 `raft-rs`。本页既有测试结果保持原有范围：此前没有接入任何真实 Raft adapter，不能把引擎探针或提交策略的通过记录记作 `raft-rs` 验证。新增工作的出口见 [集成门禁](raft-rs-integration.md)。

2026-10-29 的 [ADR 0007](../adr/0007-tikv-stack-and-rpc-boundaries.md)补充 TiKV 技术栈参考、运行与 RPC 约束及上述 codec/transport 实验。当时尚无正式 Raft 依赖或持久 adapter。

同日后续 [ADR 0008](../adr/0008-bounded-durable-store-g0.md)落实有界持久策略和真实 RawNode/RocksDB 恢复实验，新增第 7 节证据。正式 Storage 已接入；生产 driver 与 native runtime 仍待实现，整个 G0 尚未通过。
