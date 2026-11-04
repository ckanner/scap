# G0 原型执行证据与剩余门禁

初始记录日期：2026-10-27；后续 Raft/存储、cell/引擎、mTLS 和可信 SQL 接合记录分别保留其当时范围。**2026-11-02 的有界 SQL/SDK、owner 恢复、强读与 S3 闭环见第 13 节；2026-11-04 的增量持久化、隔离、本地授权合并和受控成员替换见第 14 节，最新单元与成员故障结果见 14.8。** 生产规模、三 AZ RPO、R0/R1/R2 性能和长期可用性仍未验收，完整 G0 / 生产上线门禁仍未通过，剩余工作见第 15 节。早期章节中的“尚未实现”是相应阶段的历史状态，不覆盖后续 ADR 的实现。

## 1. 历次交付的原始组件范围（新增服务集成见第 13 节）

| 资产 | 实现与证据 | 不包含的能力 |
| --- | --- | --- |
| `crates/scap-core` | 提交完成顺序；两个窄 port；完整回执身份、前序序号、重复结果、未知结果与本地发布失败处理 | SQLite adapter、真实 quorum、授权校验服务、Raft 状态机 |
| `crates/scap-raft-store` | 正式 `raft::Storage`、有界持久镜像、身份/投票/日志/应用校验、原子 checkpoint 与恢复策略 | 增量布局、SCAP SQL/owner/auth/dedup 状态机 |
| `crates/scap-raft-driver` | 正式单 RawNode 串行 driver、Ready/LightReady 持久顺序、应用、读票据、限额和停止语义 | 生产传输、调度、业务 ACK、完整成员管理 |
| `crates/scap-raft-rocks` | 正式同步 RocksDB 后端、独占目录、严格 WAL 恢复、私有持久选项与 namespace 校验 | 副本自动重建、设备故障证明、增量布局 |
| `crates/scap-cell` | 确定性 owner/auth、物理事务接受、业务去重、原结果、持久取消与版本化 codec；绑定应用位置和复制限额 | 真实凭证认证、完整 lifecycle、引擎格式校验、S3、历史 GC、生产服务 |
| `crates/scap-sql`、`scap-engine`、`scap-sqlite` | 有界 SQL/结果类型、物理镜像与历史恢复、真实提交前 gate、私有 native 连接与新目录物化 | 外部 SQL/SDK 服务、通用 spill、自动 writer 恢复编排 |
| `crates/scap-raft-wire` | 固定版本 envelope、有限 protobuf 预扫描、节点 pin 与 cell 权限、消费前身份复核 | 动态成员、证书控制面、传输 I/O |
| `crates/scap-raft-transport` | Tonic/rustls ring mTLS、实际 leaf DER、连接/请求/消息限额、绝对 deadline | Raft 提交判断、SQL 成功、证书自动签发 |
| `crates/scap-raft-runtime` | 单 cell 串行 owner、自动 tick、Safe ReadIndex、请求与物理发送预算、反馈关联、有限网络关闭 | 多 cell 调度、SQL writer、同步磁盘强制中断、完整服务入口 |
| `experiments/wal-gate` | 固定 libSQL 的真实提交前 gate、另一连接可见性、拒绝/回滚、页面捕获与进程退出恢复 | 产品运行时 adapter、分布式日志、一般 spill 事务、SDK 返回屏障 |
| `experiments/raft-rpc` | 固定 raft-rs 的真实消息经过 Tonic loopback 往返，验证原始字节、字段、拒绝和两层限额 | RawNode、持久化、quorum、mTLS、TiKV 协议互通 |
| `experiments/raft-store` | 真实 RawNode 与同步 RocksDB，Ready/LightReady、投票、joint ConfState、快照及 5 个进程退出边界 | 三进程 quorum、真实断电、生产服务、SQL 接合、性能/RTO |
| `experiments/raft-cluster` | 直接组合正式模块；三个真实 OS 进程和独立磁盘目录；leader/整组 SIGKILL、分区、后缀、快照失败重试、WAL 损坏、tick PreVote 和请求绑定读 | 生产 RPC/mTLS、SQL 接合、物理断电、自动修复、性能/RTO |
| `experiments/sqlite-cell` | 固定真实 libSQL、3 个正式持久 Raft 实例及 cell；真实 SQL 子进程的提交 gate、业务拒绝、发布、SIGKILL 后从空文件恢复、snapshot/reopen | 三个独立 Raft OS 进程、生产 RPC/SDK、通用 spill、生产引擎 adapter 和自动接管 |
| `experiments/sqlite-engine` | 正式 SQLite adapter 与真实 cell 的十一项独立故障合同 | 三个独立 Raft OS 进程、mTLS 网络、自动 owner 接管 |
| `experiments/raft-network` | 正式 wire/transport/runtime/cell，三个独立 OS 进程与 RocksDB，真实 mTLS、方向性网络故障、重启与快照 | SQLite SQL/SDK 网络组合、跨 AZ、设备断电、性能/RTO |
| `crates/scap-cell-client` | 完整固定 scope、原请求上下文、Safe ReadIndex/view 绑定、tracked 业务结果与正式 CommitGate | 外部凭证验证、业务网络 RPC、SQL 调度 |
| `crates/scap-sql-worker` | 明确的 ClaimOwner/物理恢复/新目录 native 创建/ActivateOwner 入口与每次执行生命周期 | 自动故障检测、跨节点调度、SDK 服务 |
| `experiments/sqlite-network` | 正式 SQLite writer 与三个持久 mTLS 进程的七项真实故障组合；物理数据/结果、fence、UNKNOWN、发布前 SIGKILL、snapshot/restart | 三 AZ、设备断电、生产凭证、自动控制面和性能 |
| 仓库工具 | 文档/合同检查；覆盖率源码清单与原始计数核对 | 证明报告来源可信或取代人工架构审查 |
| CI | 十个独立质量 job：Rust 单元覆盖、Python 工具单元覆盖、引擎、RPC、持久恢复、三进程受控故障、SQLite/cell、正式 SQLite adapter、真实 mTLS 网络、真实 SQLite/mTLS 组合；另有文档 job | 云环境性能、三 AZ 演练、生产 SLA |

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

这些百分比描述初始核心范围：当时只有一个生产 Rust 源文件、两个有函数体的生产函数。第 9 节保留当时五个正式模块、六份生产源码的计数，第 10 节保留八个模块、十三份源码的计数；第 11 节保留十一个模块、二十三份源码的计数；本轮十三个模块、二十六份源码见第 12 节。测试代码、编译器生成的实现、第三方依赖和测试探针不被包装成产品逻辑的覆盖成绩；所有第一方产品源码由门禁清单核对。LLVM 的已计数分支不等于所有 `match` 模式、派生比较的每个条件、MC/DC 或全部执行交错。10 项核心行为测试同时检查完整身份字段、错误结果及未发生的发布效果。

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

首次准备 C/C++17、libclang 18 开发文件和固定 Rust 工具；Ubuntu 24.04 可安装 `libclang-18-dev`，并将 `LIBCLANG_PATH` 指向 `/usr/lib/llvm-18/lib`。正式 workspace 现在包含 native 后端，单元构建也需要这些工具：

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

只运行正式 workspace 的 library/binary unit harness，不运行独立实验 workspace 或 integration tests；采集前清理旧 profile。store/driver 使用可控 AtomicBackend，driver 内部仍为真实 RawNode；native adapter 的单元调用使用私有 RocksDB memory Env，只有隔离目录元数据操作接触临时文件系统，不声称完成真实磁盘恢复。正式 SQLite adapter 另以私有 native connection、临时目录与可控配置/文件效果验证单元行为，不把集群或进程故障混入 profile。详细分类见[单元边界](testability-and-coverage.md)。禁止因 `cfg(coverage)` 改变产品代码，脚本同时拒绝相关源码排除。新增 bin、feature 或生成代码时必须扩展真实编译/执行矩阵，不能认为当前命令自动覆盖所有未来配置。

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

## 7. 首轮持久存储、RawNode 与进程恢复（2026-10-29）

正式 `scap-raft-store` 实现固定 raft-rs 的 `Storage`，通过 `AtomicBackend` 隔离原子同步 I/O。真实契约夹具直接使用该正式实现，并以 RocksDB 单个同步 WriteBatch 保存完整状态；没有用 MemStorage 代替持久策略。代码职责与完整格式见 [持久存储契约](durable-store.md)，布局取舍见 [ADR-0008](../adr/0008-bounded-durable-store-g0.md)。

### 7.1 正式单元与精确覆盖率

该轮按第 3 节的固定工具链采集当时的正式 workspace，**29 项单元测试通过，0 failed**：`scap-core` 10 项，`scap-raft-store` 19 项。以下是该轮历史计数，后续四模块报告见第 8 节，最新报告见第 10 节。

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

该轮结束时已有正式 raft-rs 依赖与 Storage 实现，RawNode driver 和 native 后端仍在实验中。第 8 节随后补齐正式 driver/native 模块及三进程 quorum 证据；RPC 接合、SQLite 原子发布和 HA 服务仍未完成。以上历史计数不改变原有性能、RTO 和 RPO 合同。

## 8. 正式 driver/native backend 与三进程故障（2026-10-29）

正式 `scap-raft-driver` 直接持有 `RawNode<Store<B>>`，正式 `scap-raft-rocks` 实现 `AtomicBackend`。独立三进程实验直接依赖这些模块，没有复制实验版运行循环。模块合同见[串行 driver](serial-driver.md)，决策见 [ADR-0009](../adr/0009-serial-driver-and-native-backend.md)。

### 8.1 该轮完整单元报告

清理旧 profile 后，使用第 3 节固定命令采集全部正式 workspace：**64 passed，0 failed，0 ignored**。其中 core 10 项、store 19 项、driver 23 项、native adapter 12 项。

| 正式源文件 | 行 | 函数 | LLVM region | LLVM 分支 |
| --- | --- | --- | --- | --- |
| `crates/scap-core/src/lib.rs` | **40 / 40** | **2 / 2** | **38 / 38** | **10 / 10** |
| `crates/scap-raft-store/src/lib.rs` | **524 / 524** | **44 / 44** | **790 / 790** | **174 / 174** |
| `crates/scap-raft-driver/src/lib.rs` | **331 / 331** | **29 / 29** | **501 / 501** | **68 / 68** |
| `crates/scap-raft-rocks/src/lib.rs` | **90 / 90** | **15 / 15** | **147 / 147** | **8 / 8** |
| 合计 | **985 / 985** | **90 / 90** | **1476 / 1476** | **260 / 260** |

所有文件、所有列精确达到 100%，门禁输出 `PASS: every production Rust source is present; unit counters are 100%.`。没有降低阈值、隐藏产品源码或把多进程实验计入 unit profile。native 最后一个未覆盖 region 来自泛型 opener 的不同测试实例；同一受控 opener 类型现在验证准备成功和失败，并断言失败不会创建 native 内存库。

driver 单元测试覆盖真实 Ready/LightReady 顺序、快照与成员状态、应用/存储失败和 panic 后停止、各输入输出预算、跨 boot 读票据、取消和内部读队列上限。native 单元测试覆盖原子目录预留、缺失/外来路径、namespace、借用长度检查、实际 memory Env 读写/错误委托与严格打开选项。测试替身只控制依赖边界，不替代 Raft 协议。

### 8.2 五项真实故障合同

Linux x86_64、Rust 1.90.0、GCC 13.3.0、libclang 18.1.3；与第 7 节相同的固定 Raft/native 版本。该轮正式源码下 **5 passed，0 failed，0 ignored**，格式与 Clippy `-D warnings` 通过。

| 场景 | 实际观察与断言 |
| --- | --- |
| leader 故障与整组重启 | 先隔离 node3，仅在 leader1 + node2 的多数派持久应用后 SIGKILL leader1；拥有历史的 node2 与落后的 node3 恢复 quorum 并继续应用；旧 leader 重开追赶，再全组 SIGKILL/重开，已提交历史完整且不重复 |
| 1 对 2 分区 | 旧 leader 仍自认为 leader 时准入新提案和读票据；少数派 commit 不前进、该读不完成；多数派继续提交；连接恢复后收敛 |
| 未提交后缀 | 实际持久但未提交的后缀在 SIGKILL 重开后仍存在，却未被擅自应用；多数派提交新 term 冲突前缀后才能断言该特定 UNKNOWN 提案被覆盖 |
| snapshot 失败与重试 | checkpoint 超过落后节点日志末尾；第一次真实 MsgSnapshot 投递被拒并反馈 Failure，随后真实重试、持久安装及 Finish；重开仍保留快照与应用 |
| 损坏 WAL | SIGKILL 后定位包含已同步操作的真实 WAL，核对物理 record header，翻转一个 checksum bit 并同步；正式打开明确返回 `Corruption: checksum mismatch`，目录、IDENTITY、CURRENT 指向与坏 WAL 保留；其他两副本继续提交并完成读屏障 |

每个响应验证 `snapshot <= applied <= commit <= last`；合成应用保存完整 token/delta 历史且不去重，能够观察重复应用。读完成以 node/boot/ticket 唯一性检查，不能因 index 不同漏过同一请求的重复完成。五份有界事件日志分别记录参数、请求、故障、持久水位、应用序列和读/快照结果，由 CI artifact 保留。

本层是三个真实 OS 进程、各自真实 RocksDB 目录和父进程控制的有界 IPC 消息路由。分区是消息投递控制；选举使用逻辑 tick 和显式 campaign。SIGKILL 保留宿主机内核缓存，WAL 修改是明确的损坏注入。它们不等于生产 Tonic/mTLS、真实 TCP 故障、物理断电、自动 writer 路由或端到端 RTO。

```bash
cargo +1.90.0 fmt --manifest-path experiments/raft-cluster/Cargo.toml --all -- --check
cargo +1.90.0 clippy --manifest-path experiments/raft-cluster/Cargo.toml --all-targets --locked -- -D warnings
cargo +1.90.0 test --manifest-path experiments/raft-cluster/Cargo.toml --locked -- --test-threads=1
```

本地先按锁文件从源码构建 native 静态库，最终隔离 target 复用同一源码和 features 的该第三方 C++ 缓存，使用 `ROCKSDB_LIB_DIR`、`ROCKSDB_STATIC=1` 与显式 `RUSTFLAGS='-C link-arg=-lstdc++'`。第一方 Rust、插桩和 profile 仍重新生成；未用其他系统版本替换 RocksDB。CI 不设置这组缓存快捷参数，按锁文件从 native 源码构建。

### 8.3 审查发现与实现约束

1. 读序号必须绑定 boot；取消旧票据不能取消重启后的同序号新读。取消也不能只释放外层计数后绕过真实 Raft 内部 pending read 上限。
2. 已完成但尚未交出的读结果也阻止新输入，调用方先 drain，避免输出持续积压或饥饿。
3. native 打开可能在检查 `create_if_missing` 前创建目录；正式 `open_existing` 因此先验证路径，失败不能自动走初始化。
4. RocksDB 默认 PointInTimeRecovery 可能退到较早的合法状态；正式后端固定 `AbsoluteConsistency` 和 paranoid checks，检测到坏 WAL 时拒绝恢复。严格模式也可能拒绝损坏的尾部，需上层从健康副本受控重建，当前尚未实现自动重建。它不检测整份有效旧镜像的外部回滚。

这些行为与固定上游源码依据见[模块合同](serial-driver.md)和 [ADR-0009](../adr/0009-serial-driver-and-native-backend.md)。完整镜像仍是有界 G0 布局，不能外推规模化成本；driver 的 propose 准入、Raft 消息或 ReadBarrier 也不是业务 SQL ACK。

## 9. 有界业务状态机、选举与读、SQLite 接合（2026-10-31）

本轮新增正式 `scap-cell`，复用 `scap-core` 提交身份和 driver 的纯 `Application`；Store 增加非空业务 genesis 的原子初始化，driver 修复新 leader 的 ReadIndex 准入。决策见 [ADR-0010](../adr/0010-cell-acceptance-and-raft-safety.md)，接口见 [cell 合同](cell-state-machine.md)和 [Raft 安全边界](raft-safety.md)。

### 9.1 该阶段完整单元报告

在新的隔离 coverage target 中，用第 3 节固定工具链和原有严格门禁重新采集全部正式 workspace：**92 passed，0 failed，0 ignored**。其中 core 10 项、store 21 项、driver 24 项、native adapter 12 项、cell 25 项。只使用单元 harness；下述三进程和真实 SQL 运行不进入这个 profile。

| 正式源文件 | 行 | 函数 | LLVM region | LLVM 分支 |
| --- | --- | --- | --- | --- |
| `crates/scap-core/src/lib.rs` | **40 / 40** | **2 / 2** | **38 / 38** | **10 / 10** |
| `crates/scap-raft-store/src/lib.rs` | **539 / 539** | **45 / 45** | **806 / 806** | **176 / 176** |
| `crates/scap-raft-driver/src/lib.rs` | **334 / 334** | **29 / 29** | **504 / 504** | **70 / 70** |
| `crates/scap-raft-rocks/src/lib.rs` | **90 / 90** | **15 / 15** | **147 / 147** | **8 / 8** |
| `crates/scap-cell/src/lib.rs` | **685 / 685** | **36 / 36** | **817 / 817** | **286 / 286** |
| `crates/scap-cell/src/codec.rs` | **566 / 566** | **50 / 50** | **1114 / 1114** | **38 / 38** |
| 合计 | **2254 / 2254** | **177 / 177** | **3426 / 3426** | **588 / 588** |

六份生产源文件均出现在 coverage map，每列精确 100%；门禁输出 `PASS: every production Rust source is present; unit counters are 100%.`。阈值未降低，没有新增生产源码排除或 coverage 条件编译。Python 工具再次执行 **47 passed**，语句 **241/241**、分支 **116/116**，均为 100%。

cell 单元分别覆盖当前权限优先于历史命中、owner Claim/Activate、前序 revision、物理摘要、业务 fingerprint、原 Admission/receipt/result、UNKNOWN、取消、管理去重、容量拒绝、严格解码、截断/损坏和内外应用位置。跨模块的不可能状态通过边界设计避免，不用无法执行的分支或忽略规则充当防御。

### 9.2 本轮修复与恢复约束

1. 固定 raft-rs 在新 leader 尚无本 term 已提交条目时忽略 MsgReadIndex；原 driver 会分配一张不能正常完成的票据。现在返回非致命 `ReadNotReady`，不分配、不消耗序号；当前 term 提交后重新准入。这一行为同时有单元和真实三进程证据。
2. `Store::create_new_with_application` 在一次原子镜像中保存相同的非空业务 application 与 genesis snapshot data；超限先于 backend I/O 拒绝，写前/写后错误保留相应 UNKNOWN 恢复边界。
3. `CellState::decode_bound` 绑定同一个 Store 视图中的 cell 身份、durable applied 对应的 entry term/index 和复制限额。不能用当前 HardState.term 代替 applied entry 的 term；snapshot-only 安装后同样必须验证。
4. 普通 `Rejected` 正常推进 applied，只说明该 term/index 的尝试被拒；永久请求取消必须使用有序持久 `ResolveOrCancel`。不存在的 Lookup 仍为 UNKNOWN。
5. 历史业务命中返回原 receipt、原位置与原结果，不能为了匹配重新执行产生的新物理 digest 而改写历史 ticket。当前 `scap-core` 仍以不可变物理提案为边界，SDK 的语义去重需要在发布前单独处理。

### 9.3 三进程合同扩展到八个场景

第 8 节原有 5 个场景全部保留，本轮总计 **8 passed，0 failed，0 ignored**，fmt 与 Clippy `-D warnings` 通过。新增：

| 场景 | 必须实际观察到的行为 |
| --- | --- |
| tick 驱动 PreVote → Vote | 不调用 campaign；预投票阶段持久 term/vote 不变，获得多数预投票后才正式改变；Vote/响应释放前持久状态已保存。新 leader 的 no-op 未提交时读被 `ReadNotReady` 拒绝，提交后首张 seq=1 票据成功 |
| 孤立 follower 三次选举超时 | 健康多数派持续交换真实心跳并提交；孤立节点只发 PreVote，不膨胀持久 term；恢复连接不扰动原 leader，历史收敛并在再次重开后保留 |
| 单向分区与旧读 ACK | follower → leader 回复被阻断；重放之前真实捕获的旧 ACK，不能完成分区后的新 ticket；check_quorum 最终降级，恢复选举后继续提交与新读 |

八份 v2 有界历史记录持久 term/vote、真实消息、读上下文和结果，CI artifact 为 `three-process-raft-evidence`。仍是三个独立 Raft OS 进程、各自真实磁盘与受控 IPC，不是生产 Tonic/mTLS 或跨 AZ 实验。PreVote 不代替多数派安全规则；没有启用租约读，主动 leader transfer 尚未专项验收。

### 9.4 六项真实 SQLite/cell 合同

独立 `experiments/sqlite-cell` 固定 libSQL `d8bc862d20bedc72945a1da27c8b7045414c0261`，复用同一正式 core、cell、driver、Store、RocksBackend 和固定 Raft 版本。**6 passed，0 failed，0 ignored**，fmt 与 Clippy `-D warnings` 通过。新 helper 的 `test=false` 避免将复用的旧 WAL 探针 5 项检查重复计入本层。

| 场景 | 真实引擎与持久状态的断言 |
| --- | --- |
| RETURNING 与正常接受 | 暂定结果只进入内部缓冲；提交 gate 等待时另一连接仍见旧值；实际 quorum 及业务 Accepted 后才允许 native publish，再交出测试 ACK |
| owner 更换 | 已暂存旧 writer 的事务成为 Raft 已提交条目，但业务结果为 Fenced；没有 native publish、没有成功 ACK |
| 权限变更 | AuthFence 先提交，旧准入版本的写随后被 Unauthorized 拒绝；另一 SQL 连接看不到该变更 |
| 接受后、发布前 SIGKILL | 真实杀死 SQL writer，已接受的随机结果尚未发布；从 cell 保留的物理事务重建空文件，得到同一随机值和 revision，integrity_check 通过，没有重执行 SQL |
| 业务重复请求 | 相同业务 ID/fingerprint 再执行会生成新的随机值和物理页；命中原 AlreadyCommitted 后丢弃新页，返回原结果，revision 不增加 |
| 取消、快照与重开 | 取消 fence 阻止迟到接受；owner/auth、原结果与完整物理事务经过实际 MsgSnapshot 安装到落后副本，再重开三个 RocksDB 目录后保留；从保留事务重建 SQL 状态 |

初始化 DDL 和初始数据也实际经过 gate、quorum 与业务 Accepted。恢复从 **0 字节文件**开始，按序应用保留的真实页面，逐页核对最终页覆盖，并比较 `integrity_check`、事务内 `cache_meta` revision 和 cell revision；没有另行提供未记录的 baseline。

本层的三个 Raft 实例位于**同一个父测试进程**，各自独立真实 RocksDB 目录；SQL writer 是独立 OS 子进程，SIGKILL 案例实际核对 signal 9。三独立 Raft OS 进程故障由前一层验证，不能将两个夹具组合描述成已部署完整服务。

fixture 固定 4096 字节 page、最多 64 页的事务/恢复数据库以及无 spill 路径；它复用受限 WAL 探针，只作为 helper 测试代码。普通 native 提交、消息投递、Raft commit 与业务接受分别观察。初始化后的请求通过真实 `CommitCoordinator` 验证新接受/拒绝的发布顺序；重新执行产生不同物理 ticket 的语义重复请求在发布前单独处理，绝不伪造原 receipt 的 digest。

复现命令：

```bash
cargo +1.90.0 fmt --manifest-path experiments/sqlite-cell/Cargo.toml --all -- --check
cargo +1.90.0 clippy --manifest-path experiments/sqlite-cell/Cargo.toml --all-targets --locked -- -D warnings
cargo +1.90.0 test --manifest-path experiments/sqlite-cell/Cargo.toml --locked -- --test-threads=1
```

`SCAP_SQLITE_CELL_EVIDENCE_DIR` 控制六份有界历史的输出位置；CI artifact 为 `sqlite-cell-evidence`。本地再次按锁文件从源码构建 native RocksDB，隔离 Rust/coverage target 只复用相同源码与 features 的 C++ 静态缓存；CI 仍自行从 native 源码构建。这些测试耗时只记录执行成本，不是 SQL 服务 p99、writer RTO、掉电 RPO 或三 AZ 可用性测量。

## 10. 正式 SQLite adapter、结果与物理恢复（2026-10-31）

本轮新增正式 `scap-sql`、`scap-engine`、`scap-sqlite`；固定 libSQL 从研究探针进入根 workspace，旧第三方依赖的版本、来源与 checksum 均保留。具体设计见 [ADR-0011](../adr/0011-bounded-native-sqlite-adapter.md)与[引擎合同](sqlite-engine.md)。研究 IPC、三节点测试路由和故障编排没有进入产品运行时。

### 10.1 最终完整单元门禁

以第 3 节固定工具链，在独立且清理 profile 的 target 采集整个正式 workspace：**142 passed，0 failed，0 ignored**。其中 core 10、store 21、driver 24、RocksDB adapter 12、cell 25、engine 11、SQL codec 9、native SQLite/config/file adapter 30。单元报告没有混入下面的真实集群/进程测试。

| 正式源文件 | 行 | 函数 | LLVM region | LLVM 分支 |
| --- | --- | --- | --- | --- |
| `crates/scap-cell/src/codec.rs` | **566 / 566** | **50 / 50** | **1114 / 1114** | **38 / 38** |
| `crates/scap-cell/src/lib.rs` | **688 / 688** | **37 / 37** | **820 / 820** | **286 / 286** |
| `crates/scap-core/src/lib.rs` | **40 / 40** | **2 / 2** | **38 / 38** | **10 / 10** |
| `crates/scap-engine/src/lib.rs` | **217 / 217** | **14 / 14** | **318 / 318** | **120 / 120** |
| `crates/scap-raft-driver/src/lib.rs` | **334 / 334** | **29 / 29** | **504 / 504** | **70 / 70** |
| `crates/scap-raft-rocks/src/lib.rs` | **90 / 90** | **15 / 15** | **147 / 147** | **8 / 8** |
| `crates/scap-raft-store/src/lib.rs` | **539 / 539** | **45 / 45** | **806 / 806** | **176 / 176** |
| `crates/scap-sql/src/lib.rs` | **208 / 208** | **18 / 18** | **408 / 408** | **60 / 60** |
| `crates/scap-sqlite/src/config.rs` | **87 / 87** | **12 / 12** | **143 / 143** | **10 / 10** |
| `crates/scap-sqlite/src/file.rs` | **44 / 44** | **8 / 8** | **76 / 76** | **2 / 2** |
| `crates/scap-sqlite/src/gate.rs` | **157 / 157** | **17 / 17** | **192 / 192** | **40 / 40** |
| `crates/scap-sqlite/src/lib.rs` | **124 / 124** | **7 / 7** | **160 / 160** | **10 / 10** |
| `crates/scap-sqlite/src/sql.rs` | **282 / 282** | **14 / 14** | **288 / 288** | **24 / 24** |
| 合计 | **3376 / 3376** | **268 / 268** | **5014 / 5014** | **854 / 854** |

13 份第一方生产源码均在 coverage map 中，所有计数精确相等；仓库脚本输出 `PASS: every production Rust source is present; unit counters are 100%.`。没有排除异常处理、adapter、native 配置或文件效果，也没有使用覆盖率条件编译。新增 `ConfigOps` 与文件效果端口让真实配置/物化流程的每一步失败都能被单位注入，同一正式策略在真实 native 调用中使用。

全 workspace Rust 1.90 格式与 Clippy `--all-targets --all-features --locked -- -D warnings` 通过。Python 工具重新执行 **47 passed**，语句 **241/241**、分支 **116/116**；门禁本身的阈值与检查逻辑没有改低。

SQLite adapter 单元包含隔离 native connection/临时目录调用；共识裁决由可控端口驱动，文件失败由同一效果边界注入。它们验证小范围 adapter 行为，不声称证明真实 quorum、设备断电或生产恢复；这些证明与独立实验分层。

### 10.2 十一项独立真实 adapter/cell 合同

`experiments/sqlite-engine` 在最终候选源码上独立完整运行 **11 passed，0 failed，0 ignored**，格式与 Clippy 通过。使用三个真实 RawNode/Driver、三个独立磁盘 RocksDB、实际 CellApplication 和正式 SqliteWriter。十一份有界证据记录均包含最终 `verification passed`，独立复读 SHA-256 一致。

| 场景 | 已验证行为 |
| --- | --- |
| 类型化参数与 RETURNING | gate 前已完整缓冲 NULL/i64/有限实数/UTF-8/BLOB；同一 writer 文件的其他读连接只见旧值；实际业务接受后才发布 |
| DDL 业务重试 | 先经过带 ReadIndex 的 Lookup，返回原 receipt/result，不重新执行 CREATE TABLE，不新增 proposal |
| SELECT 与零行 UPDATE | 不触发 WAL 回调也必须记录 quorum 结果；revision 连续推进，镜像可保持不变 |
| 同批后续 SQL 失败 | 前面的写和暂定结果全部回滚，无新 proposal，writer 停止 |
| owner fence | 成功 preflight 后先提交 ClaimOwner，原 writer 的实际物理 proposal 被 Fenced 拒绝 |
| auth fence | preflight 后先提交 AuthFence，旧 admission 被拒绝，不发布 |
| 分区 UNKNOWN | preflight 后隔离 leader，proposal 无 quorum、无 native 发布；新的 Safe ReadIndex 也不能完成。连通恢复后原 proposal 可以迟到提交，并从原物理历史恢复，无 SQL 自动重试 |
| snapshot 与后端重开 | 实际 MsgSnapshot 安装到落后第三副本；正常关闭并重开三后端后，原结果、取消 fence 与完整物理数据保留 |
| SQL/资源/目录限制 | PRAGMA、ATTACH、事务控制、临时库、虚表、扩展及越限结果被拒；旧目录/sidecar 不能复用 |
| Accepted 后 SIGKILL | 真实 SQL 子进程被 signal 9 终止；cell 已持久接受而原生页未发布，客户端无 ACK；新目录物理恢复保留准确 randomblob 与原结果 |
| 非确定 CHECK 的恢复 | 已合法接受的连接状态相关 CHECK 不在新连接中被重新裁决；物理 image/head 和原行保留，恢复后的违规 INSERT 仍被 `SQLITE_CONSTRAINT_CHECK` 拒绝 |

初始化 DDL 也进入相同共识历史，恢复从空 Image 开始；不再借助测试 schema 的 cache_meta 表或旧 `SCAPPG01` 页格式。正式 `SCAPIMG!` v1、结果 `SCAPRES1` 和请求 fingerprint 均由生产模块生成和校验。

三个 Raft 实例仍在同一父测试进程内，SQL SIGKILL 使用独立子进程；不能把本套说成生产网络、三独立 Raft OS 进程、跨 AZ 或断电测试。第 9 节与更早实验的历史记录保留其当时范围。CI 为本层新增独立 job 与 `sqlite-engine-evidence` artifact，unit artifact 仍单独采集。

```bash
cargo +1.90.0 fmt --manifest-path experiments/sqlite-engine/Cargo.toml --all -- --check
cargo +1.90.0 clippy --manifest-path experiments/sqlite-engine/Cargo.toml --all-targets --locked -- -D warnings
SCAP_ENGINE_EVIDENCE_DIR=/tmp/scap-engine-evidence \
cargo +1.90.0 test --manifest-path experiments/sqlite-engine/Cargo.toml --locked -- --test-threads=1
```

本地隔离构建继续只复用同一已锁定源码/features 的 native RocksDB 静态缓存，Rust 与 LLVM profile 重新生成；CI 从固定 native 源码构建。测试执行时间不作为性能或 RTO 证据。

### 10.3 审查中关闭的具体问题

- DDL/唯一键重试可能在进入 WAL gate 前报错；新增前置线性化 Lookup，提交时仍二次裁决。
- 无 dirty pages 不调用 gate；新增同镜像空页事务，不能绕过 quorum 返回结果。
- 合法历史 receipt 对应的结果过大或损坏，必须保留 `CommittedButUnavailable`，不能报成未提交的 SQL 错误。
- 默认 integrity_check 重新执行连接状态相关 CHECK 会误拒合法恢复；现在先安装安全与资源限制，仅在结构检查期间忽略 CHECK，结束必恢复，恢复失败不发布连接。新增真实回归确保业务约束并未关闭。
- 已有目录中的旧 WAL/SHM 可污染基线；新 worker 必须独占新目录，且文件、目录和父目录的同步失败均阻断构造。

该轮结束时，正式 adapter 仍是有界完整镜像实现。每次提交的镜像复制/摘要和每次重启的全历史恢复尚未通过大库、长期容量或尾延迟验证；独立 SQL 强读、SDK、生产 transport 与自动 owner 接管当时仍未交付。后续正式网络实现见第 11 节。

## 11. 正式 mTLS 网络与单 cell 运行时（2026-11-01）

新增正式 `scap-raft-wire`、`scap-raft-transport`、`scap-raft-runtime`。三个真实独立 voter 进程直接组合这些正式模块、已有持久 driver/RocksDB 与 CellApplication；父进程只进行控制和观测，不通过 IPC 投递 Raft 消息。设计见 [ADR-0012](../adr/0012-bounded-raft-network-runtime.md)与[运行时合同](raft-network-runtime.md)。

### 11.1 最终单元门禁

以第 3 节固定工具链清空原始 profile，重新采集最终整个 workspace：**198 passed，0 failed，0 ignored**。其中既有八个 crate 142 项，wire 13 项、transport 12 项、runtime 31 项。包括最终 fatal read view 回归；网络多进程实验没有进入本报告。

| 正式源文件 | 行 | 函数 | LLVM region | LLVM 分支 |
| --- | --- | --- | --- | --- |
| `crates/scap-cell/src/codec.rs` | **566 / 566** | **50 / 50** | **1114 / 1114** | **38 / 38** |
| `crates/scap-cell/src/lib.rs` | **688 / 688** | **37 / 37** | **820 / 820** | **286 / 286** |
| `crates/scap-core/src/lib.rs` | **40 / 40** | **2 / 2** | **38 / 38** | **10 / 10** |
| `crates/scap-engine/src/lib.rs` | **217 / 217** | **14 / 14** | **318 / 318** | **120 / 120** |
| `crates/scap-raft-driver/src/lib.rs` | **334 / 334** | **29 / 29** | **504 / 504** | **70 / 70** |
| `crates/scap-raft-rocks/src/lib.rs` | **90 / 90** | **15 / 15** | **147 / 147** | **8 / 8** |
| `crates/scap-raft-runtime/src/driver.rs` | **36 / 36** | **12 / 12** | **55 / 55** | **0 / 0** |
| `crates/scap-raft-runtime/src/lib.rs` | **652 / 652** | **44 / 44** | **937 / 937** | **154 / 154** |
| `crates/scap-raft-runtime/src/workers.rs` | **154 / 154** | **16 / 16** | **243 / 243** | **30 / 30** |
| `crates/scap-raft-store/src/lib.rs` | **539 / 539** | **45 / 45** | **806 / 806** | **176 / 176** |
| `crates/scap-raft-transport/src/client.rs` | **128 / 128** | **16 / 16** | **168 / 168** | **18 / 18** |
| `crates/scap-raft-transport/src/incoming.rs` | **50 / 50** | **9 / 9** | **67 / 67** | **4 / 4** |
| `crates/scap-raft-transport/src/lib.rs` | **49 / 49** | **6 / 6** | **59 / 59** | **14 / 14** |
| `crates/scap-raft-transport/src/server.rs` | **146 / 146** | **17 / 17** | **174 / 174** | **4 / 4** |
| `crates/scap-raft-wire/src/certificate.rs` | **21 / 21** | **1 / 1** | **32 / 32** | **8 / 8** |
| `crates/scap-raft-wire/src/codec.rs` | **128 / 128** | **8 / 8** | **246 / 246** | **34 / 34** |
| `crates/scap-raft-wire/src/lib.rs` | **208 / 208** | **22 / 22** | **249 / 249** | **84 / 84** |
| `crates/scap-sql/src/lib.rs` | **208 / 208** | **18 / 18** | **408 / 408** | **60 / 60** |
| `crates/scap-sqlite/src/config.rs` | **87 / 87** | **12 / 12** | **143 / 143** | **10 / 10** |
| `crates/scap-sqlite/src/file.rs` | **44 / 44** | **8 / 8** | **76 / 76** | **2 / 2** |
| `crates/scap-sqlite/src/gate.rs` | **157 / 157** | **17 / 17** | **192 / 192** | **40 / 40** |
| `crates/scap-sqlite/src/lib.rs` | **124 / 124** | **7 / 7** | **160 / 160** | **10 / 10** |
| `crates/scap-sqlite/src/sql.rs` | **282 / 282** | **14 / 14** | **288 / 288** | **24 / 24** |
| 合计 | **4948 / 4948** | **419 / 419** | **7244 / 7244** | **1204 / 1204** |

23 份第一方生产源码全部进入 coverage map，所有可计数指标精确相等。`runtime/driver.rs` 为 12 项无条件委托，没有条件分支；其行、函数和 region 均实际执行，整体分支分母为 1204。检查器输出 `PASS: every production Rust source is present; unit counters are 100%.`。没有生产源码排除、coverage(off)、覆盖率条件编译或以故障实验填充分母。

完整 workspace 的 Rust 1.90.0 格式与 Clippy `--all-targets --all-features --locked -- -D warnings` 通过。Python 工具 **47 passed**，语句 **241/241**、分支 **116/116**。根锁文件增加 88 项第三方解析结果；原有第三方版本、来源与 checksum 没有改变。

新单元涵盖纯 wire/授权策略、隔离真实 native TLS/连接调用、运行时正常调度与窄边界故障；单元测试中的 driver decorator 对非注入调用仍执行正式 `RaftDriver` 委托与真实 RawNode。预扫描、异步收发、错误分支和正式委托均保留在生产分母。

### 11.2 八项独立真实网络合同

最终 fatal-read 修复后的候选源码下，`experiments/raft-network` 完整执行 **8 passed，0 failed，0 ignored，0 filtered**，格式与严格 Clippy 通过。64 个源码/构建输入在执行前后 SHA-256 一致，八份日志各自以 `verification passed` 结束。

实验使用正式 `Runtime::run` 自动 tick 和 `NetworkWorkers → PeerClient → TCP/mTLS → PeerServer → Handle → Runtime → Driver` 链路。透明代理仅转发加密 TCP 字节并注入方向性连接故障。成功日志各自保留实际提交/应用水位、请求结果和最终验证记录；独立 artifact 为 `raft-network-evidence`。

| 场景 | 直接观察和断言 |
| --- | --- |
| 健康组与重连 | 自动 PreVote 选举、正式 cell 操作、Safe ReadIndex、实际应用产生的 AlreadyCommitted 原结果、TCP 拒绝后的恢复 |
| 双向分区 | 少数派实际存在 `last > commit` 的未提交后缀且 commit 不推进；多数派继续；UNKNOWN 请求经有序取消确定终态 |
| 进程被杀与整组重启 | Leader SIGKILL 后其余副本继续；旧节点追赶；全组三进程 SIGKILL 后从原目录恢复历史 |
| 持久 snapshot | 落后副本通过实际 MsgSnapshot 安装；第二次 SIGKILL 后严格重开接收方磁盘，解码 snapshot 并核对八个原业务结果 |
| 认证与作用域 | 无证书、错误 CA、过期/未绑定证书、伪造 from、旧 cell incarnation 和网络注入本地 Raft 消息均被拒绝 |
| 轮换与已有连接 | pin 轮换使两条已准入但未消费的消息失效；同一旧连接上的新请求被拒，重新授权后可恢复 |
| 背压与 receipt | 数量及保守解析内存预算生效；过期发送不成功；收到 Received 后停机重开，term/commit/applied 仍为 1，application 字节仍等于 genesis |
| 单向分区 | 切断 follower 到旧 leader 的方向，新强读请求不能成功；多数派继续；网络恢复后收敛 |

最后一个场景没有导出失败读的 ticket，也没有逐条观测分区后的正向 RPC receipt；只声称其直接观测结果。成功读的 boot/ticket/barrier 会被检查。精确旧 ACK 重放的证据仍归第 9 节受控消息实验。

本层业务提交的 `physical_changes` 是合成 opaque payload，没有调用正式 SQLite SQL writer。真实 SQL adapter/cell 的第 10 节合同和本节网络合同分别成立；不能把二者拼成已经执行过的 SQL/SDK 网络验收。正常 fixture 退出也不证明永久卡住的同步设备 I/O 能在固定时间内优雅退出。

```bash
cargo +1.90.0 fmt --manifest-path experiments/raft-network/Cargo.toml --all -- --check
cargo +1.90.0 clippy --manifest-path experiments/raft-network/Cargo.toml --all-targets --locked -- -D warnings
SCAP_NETWORK_EVIDENCE_DIR=/tmp/scap-network-evidence \
cargo +1.90.0 test --manifest-path experiments/raft-network/Cargo.toml --locked -- --test-threads=1
```

工具链为 Rust 1.90.0、nightly-2025-09-18、cargo-llvm-cov 0.6.21、coverage.py 7.10.6、GCC 13.3.0；本轮本地 libclang 为 18.1.1。本地 native RocksDB 静态缓存仍由同一锁定源码/features 构建，SHA-256 为 `9459aa3f59f4cca32af9f0e6549e043069c0d48131ab3d63b25396a17ccc9fd3`。CI 从源码编译，不引用本机缓存路径；新采集的 unit profile 不混入任何多节点实验。

### 11.3 验证中修复的具体问题

- 使用 Tonic 自供 incoming 时，builder 的 TCP_NODELAY 设置没有应用到接入 socket。小消息延迟积累导致健康组 ReadIndex 超时；正式接入层现在显式设置 NODELAY，配置失败拒绝连接。在保持原读 deadline 的情况下，真实八场景通过。
- 反馈消费与活跃 attempt ID 撤销合为同一个 mailbox 临界区，避免重复 callback 在二者之间重新入队。超时消费遵守同一规则，迟到、旧 term 或旧 snapshot attempt 不能修改新尝试。
- runtime 的逻辑 delivery 和 worker 实际持有的 payload 使用不同预算。物理 reservation 一直到真正释放消息/future 时才归还；超时或收到回执不会提前释放仍占内存的数据预算。
- 完成但尚未被调用方取走的读结果继续持有请求 reservation；取消也不提前释放仍排队的请求。持久化错误或 panic 关闭入口与等待读；读屏障完成后的 fatal view 错误也在同一次 poll 关闭入口，阻止已失效 owner 继续准入。
- 串行调度通过窄 `RaftDriver` port 调用正式持久 driver。单元故障 decorator 只替换指定的一次操作结果，其余调用执行真实 driver；时钟、native codec 结果、网络和磁盘失败分别注入，不另写模拟 Raft 协议。

## 12. 正式 SQLite 网络提交与 owner 恢复（2026-11-02 UTC）

[ADR-0013](../adr/0013-tracked-sqlite-network-commit.md)及 [SQLite 网络合同](sqlite-network.md)把正式 native writer 与已有固定成员 mTLS cell 接通。新增 `scap-cell-client`、`scap-sql-worker`，扩展 driver/runtime 的 tracked proposal 和 cell 的逐 Entry outcome；没有通过 `Admitted`、最后一次 outcome 或猜测日志 index 判断业务成功。

### 12.1 新的全工作区单元报告

最终正式 Rust 源码下采集 fresh unit-only LLVM profile，**245 passed，0 failed**。十三个 crate、二十六个生产源码文件全部进入 coverage map，`check_unit_coverage.py` 对每个文件核对精确整数并通过：

| 维度 | 全部正式源码 |
| --- | --- |
| Lines | **5802 / 5802，100%** |
| Functions | **474 / 474，100%** |
| Regions | **8346 / 8346，100%** |
| Branches | **1402 / 1402，100%** |

| 本轮直接变化的组件 | Lines | Functions | Regions | Branches |
| --- | --- | --- | --- | --- |
| `scap-raft-driver` | 510/510 | 37/37 | 743/743 | 120/120 |
| `scap-cell` | 1320/1320 | 93/93 | 2037/2037 | 338/338 |
| `scap-raft-runtime` | 951/951 | 80/80 | 1396/1396 | 210/210 |
| `scap-cell-client` | 294/294 | 21/21 | 348/348 | 74/74 |
| `scap-sql-worker` | 209/209 | 12/12 | 251/251 | 34/34 |
| 其余八个既有组件 | 2518/2518 | 231/231 | 3571/3571 | 626/626 |

各 crate 单元数为：cell 28、cell-client 18、core 10、engine 11、driver 33、rocks 12、runtime 37、store 21、transport 12、wire 13、sql 9、sql-worker 11、sqlite 30。Python 工具仍为 **47 passed**，241/241 statements 与 116/116 branches。单元收集不执行任何独立 experiment；没有源码 exclusion、coverage(off)、缺失 map 或集成记录补缺。

真实 RuntimePort 和 NativeFactory/Engine 委托也由 unit 调用；policy 使用窄端口控制时钟、存储、请求结果和 native 创建。owner 恢复中原 deadline 在恢复前、native 构造后和交付前都重新检查，激活竞争和部分资源退出各自有测试。

### 12.2 七项独立真实 SQL/mTLS 合同

`experiments/sqlite-network` 使用三个独立 OS 进程、三个 RocksDB 目录、正式 Runtime/NetworkWorkers/PeerServer 和实际 mTLS，SQL 仅在独立 SQL 线程使用正式 Writer。透明代理只调度加密 TCP，CellPort decorator 只暂停精确效果边界；生产接受、恢复和发布算法没有复制到 fixture。

| 场景 | 直接证明 |
| --- | --- |
| SQL、DDL 与 RETURNING 去重 | 唯一键和随机 blob 的原 receipt/result 保留，重复 DDL 不重执行 |
| preflight 后 owner fence | 最终有序提交拒绝，独立 SQLite 读连接看不到新页面 |
| preflight 后 auth fence | 旧 auth epoch 拒绝，同样没有新 native 可见性 |
| TCP 黑洞造成 quorum 丢失 | 请求 UNKNOWN 且不发布；新多数派有序取消，网络恢复后 fence 仍有效 |
| 已接受回执超过原 deadline | 仍返回 UNKNOWN；显式解析与新目录物理恢复得到同一随机结果 |
| Accepted 后、native publish 前 SIGKILL | 另一个真实进程成为 leader，正式恢复入口取得新 owner/new directory，物理恢复原事务与结果 |
| snapshot 和整组重启 | 实际 mTLS MsgSnapshot 持久安装；接收者 snapshot 检查与全组三进程 SIGKILL/reopen 后仍可恢复数据和取消记录 |

完整运行 **7 passed，0 failed，0 ignored**，每份逐事件日志均以 `verification passed` 结束。最终冻结源码的格式/严格 Clippy 与复跑另由同一 quality workflow 验证；源码/构建输入在本地运行前后以 SHA-256 核对。实验 artifact 为 `sqlite-network-evidence`，不混入 Rust unit artifact。

旧 `raft-cluster`、`sqlite-cell`、`sqlite-engine`、`raft-network` 分别回归 **8、6、11、8 passed**，合计 33 项，0 failed/ignored；33 份日志均完成最终验证。新增 Answer 枚举要求旧普通提案 fixture 显式拒绝意外 `Applied`，不会把它映成 `Admitted`；fixture 配置仍需满足实际请求/视图预算。这些兼容修复不改变正式持久性或 deadline 合同。

### 12.3 本次证据不扩大的结论

恢复入口由可信调用方显式触发。Claim 后失败可能留下 inactive 新 epoch；Activate 已生效而后续读失败可能留下 active owner，但不交付 writer。后续恢复必须先读取权威状态，使用新 worker ID 和新目录；调用失败不证明 owner 变更回滚。

尚未实现外部 SQL/Hrana/Node SDK、凭证验证和 worker admission 服务、自动故障检测/调度/路由、动态成员、多 cell、S3 归档/GC、增量布局与大事务。测试同机 loopback 和 SIGKILL 不证明三 AZ、设备断电、生产 RTO 或目标 p99；性能目标保持原值且待测。

## 13. 正式 SQL 服务、Node SDK 与冷生命周期（2026-11-02）

对应 [ADR-0014](../adr/0014-sqlite-service-and-cold-lifecycle.md)、[正式服务方案](sqlite-service.md)和 [可运行配置](../../crates/scap-server/README.md)。新增 `scap-service`、`scap-server`、`scap-archive` 与 TypeScript SDK，保留既有提交、CP 和原结果合同。所有核心算法在正式 crate 中；实验仅创建进程、透明代理、故障控制和断言。

### 13.1 全工作区 fresh unit-only 门禁

16 个正式 Rust crate、45 个生产源文件，**364 个单元测试全部通过**。固定 nightly 采集的单一新 profile 与源码清单逐文件核对；没有混入任何独立 experiment 或网络部署 profile。

| 精确整数维度 | 覆盖 / 分母 |
| --- | --- |
| Lines | **9359 / 9359** |
| Functions | **863 / 863** |
| Regions | **13745 / 13745** |
| Branches | **2074 / 2074** |

SDK 的 **11 个单元测试**使用真实固定 `@libsql/client`，依赖端口控制网络、时钟和请求 ID；`c8` 的行/语句/函数/分支均为 100%。源码清单门禁另外核对唯一生产源 `src/client.ts` 的 **318 个 statement、30 个 function、225 个 branch counter** 全部为正整数，不用四舍五入的百分比或遗漏源码过关。

三个 Python 工具的 **58 个单元测试**全部通过，**321/321 statements、160/160 branches**。新增 SDK 门禁拒绝遗漏源码、重复路径、空分母、非法 hit、branch arity 错误、忽略标记和未覆盖 counter。Rust gate 保持完整 map、四维整数和无排除检查。

固定工具链为 Rust 1.90.0、nightly-2025-09-18、cargo-llvm-cov 0.6.21、Node.js 24.22.1、TypeScript 5.9.3、c8 12.0.0、coverage.py 7.10.6。SDK 包和 Cargo 依赖都有锁文件。CI 的 native 依赖从锁定源码构建；本机复用的 native 静态库只属于本次环境，不是 CI 下载依赖。

### 13.2 关键行为及单元反例

- SQL 入口先完整解析并验证自包含 Hrana pipeline，再准入有界 SQL mailbox；Bearer 映射为不可变数据库/principal/credential 身份，执行时仍检查复制状态中的权限和 auth epoch。
- owner 调度只允许 Raft leader 操作；term 变化退休全部本地 writer。空闲计时必须同时匹配当前 owner、active 状态和 revision，不能让旧 writer 的空闲时间休眠一个新 owner。
- 强读使用自己的 Safe ReadIndex，并核对当前授权、物理镜像与已接受 head；不写 quorum 结果记录、不增加 revision。读事务拒绝变更、事务控制和未授权函数，并有原 deadline、VM、行数和字节限额。
- 冷流程按 Suspend / 上传核验 / Publish / Prune / Hydrate 排序。物理内容只有在可恢复对象已经有序发布后才可裁剪；原 receipt、结果、权限和 fence 保留。新格式兼容合法 v1 状态与旧行政操作重试，但没有混版本或降级协议。
- 后台归档每库最多一个 pending，总队列 8，失败有界退避；任务携带原 owner/head/generation 和 deadline。fresh read 后到最终 apply 前换 owner 仍会被 cell 拒绝，不能用旧任务裁剪新历史。
- 对后台 Prune 与前景 Claim 的竞争，仅明确 `Rejected(Cold)` 可在原 deadline 下刷新一次并 hydrate；SQL 尚未运行，UNKNOWN 不进入该重试。实际 Controller / CellApplication 注入测试验证一次成功和第二次拒绝。
- 启动与部分失败拥有完整资源归属；缓存 namespace 的根和子项都拒绝 symlink。SIGINT/SIGTERM、运行 future 取消、线程启动失败或 panic 都触发停止和 join；慢 HTTP body 在停止时被显式唤醒关闭。
- 所有自包含 HTTP/1 响应明确 `Connection: close`，避免客户端复用接近 30 秒绝对寿命的连接而在最后核对时被断开；30 秒慢连接硬限和连接数限额仍保留。
- 行政 ID 整数耗尽、每个读/写时钟检查点失败、native 恢复目录错误、旧权限、损坏原结果、丢失裁决和状态读取失败都有禁止 ACK/重放的单元断言。

### 13.3 独立真实合同

冻结后的全部 9 套 Rust experiment 已重新执行格式、严格 Clippy 与锁定依赖测试：共 **27 个检查步骤、76 个测试全部通过，0 failed / ignored**。各套测试数为 WAL 13、RPC 8、Store 12、Raft cluster 8、SQLite cell 6、SQLite engine 11、Raft network 8、SQLite network 8、S3 2。43 份历史均有最终 `verification passed`，回归前后源码无漂移，未使用 unit profile。

| 独立实验 | 本次验收内容 |
| --- | --- |
| `sqlite-network` | 原七项 durable SQL/mTLS 合同加独立强读，共 8 项；ReadIndex 与 SQL snapshot 绑定，少数派不能强读 |
| `archive-s3` | 固定真实 SeaweedFS 4.51 的两个对象合同；签名、错误凭据、条件 PUT 不覆盖、HEAD 超限、SIGKILL/同目录重开 |
| `service-network` | 8 项真实三 daemon 合同；含真实 Node SDK 五组调用、租户/只读权限、leader SIGKILL、双向 TCP 黑洞、全组重启、冷库与 S3 故障、双库持续测量 |

服务实验启动三个独立 RocksDB 目录、实际 `scap-server` release 二进制、实际 HTTP/Hrana SDK 和实际双向 TLS。S3 黑洞时，新的 beta revision 已 suspended 但没有 prune；alpha 继续在原 1.5 秒 deadline 内完成五组写与强读。网络恢复后 beta 自动发布/裁剪到新 revision，再精确恢复数据与原随机结果。

服务 harness 每次运行保存构建 hash、环境和逐请求原始结果；本机最终验收另外保存生产源码清单、源码包及运行前后摘要核验。CI 绑定实际 checkout commit 与自行构建的 binary，不声称自动产出这份本机源码包。服务历史只有所有断言通过才写末行 `verification passed`；`completed.json` 必须含完整 8 项及 S3 requested。测量另核对全部 ACK 的行与内容，而非仅检查响应次数。源码或 binary 变化时不复用此前结果冒充最终构建。

### 13.4 性能结果的适用范围与失败记录

本次诊断负载为 **同一宿主机 loopback、两个小库、4 请求/秒、8 秒固定原 deadline、30 秒热基线和故障后 60 秒观察**。这与生产目标的三 AZ、500 请求/秒、2 秒 deadline、GiB 库和长期故障分位不是同一 profile。所有 360 个 scheduled/invoked/result/deadline 样本保留；每库每秒一个强读和一个稳定 ID 小写，恢复必须满足两库完整 30 秒稳定窗口，最后重新核对所有 ACK。

较早两轮 debug 测量没有满足稳定窗口：首轮热基线 120 次只有 49 成功，另有 61 COMMIT_UNKNOWN、4 OVERLOADED、6 NO_LEADER；透明代理修正 NODELAY 后另一轮为 68 成功、40 UNKNOWN、12 NO_LEADER。它们仍是失败，不能删除、改写为事后成功或混进 release 的成功分位数。

优化热请求时去掉了两次重复的 ReadIndex，保留正式 Writer 自己的新鲜权威检查；后台 S3 归档移出了 SQL 线程。release 与热路径同时变化，因此不作单因素性能归因。第一轮 release 虽收齐 360 样本并形成恢复窗口，但末尾 ACK 核对遇到 HTTP 连接断开，整项仍记失败；随后补了明确关闭响应的连接协议及原生 EOF/停止回归。

最终格式冻结后的 release binary SHA-256 为 `6012c2366632ecad0de381c6382d4b6000f98bd6f14f9ca1a9f03dab26f43150`，68 个生产输入的 source ID 为 `0681df93b2539a45bcaab2c952fa828a89b002db43378fc6a09b2a665991485e`，运行前后无源码漂移。该二进制完整 8 项通过，末尾全部 ACK 核对无缺失。环境为 Linux x64、Node 24.22.1、可见 9 个 CPU、约 9.7 GiB 内存、同机临时磁盘；没有证明 CPU/磁盘隔离。

| 最终诊断结果 | 实际观测 |
| --- | --- |
| 热基线 | 120/120 成功；每库每操作 30 个样本 |
| 故障观察 | 240 次中 228 成功、12 次 NO_LEADER，集中在故障后最初三个探测轮次 |
| UNKNOWN / OVERLOADED / ACK 缺失 | 本轮均为 0；此前失败轮仍保留 |
| 首次成功 | 故障后 3.050 s；alpha 3.050 s、beta 3.338 s |
| 双库 30 秒窗口起点 | 故障后 **3.009 s**；于 **33.009 s** 确认完整窗口，探测分辨率 1 s |
| 热 alpha 强读 p95 / p99 | 151.252 / 190.762 ms |
| 热 alpha 写 p95 / p99 | 164.286 / 164.479 ms |
| 热 beta 强读 p95 / p99 | 161.575 / 188.405 ms |
| 热 beta 写 p95 / p99 | 189.106 / 201.415 ms |

这些分位数仅描述各 30 个成功热样本；故障阶段各分组为 57 成功/3 失败，完整分母和成功分位单独保存在 [可复核摘要](../evidence/sqlite-service-local-2026-11-02.json)。摘要包含全部生产文件摘要、二进制标识、环境、指标与原始样本文件 hash；原始过程日志作为测试 artifact 保存，不提交生成的凭据或数据库。CI 会针对其实际 commit 重新构建并保留独立结果，不把本机数字复制成 CI 或生产结果。

单次窗口只是一条观测；不转写成生产 RTO p95/p99 或 SLA。当前热请求实测尾延迟仍高于原先 50/100 ms 目标，后续增量存储、复用安全 peer 连接和恢复调度优化不能绕过持久性门禁。

### 13.5 CI 与原始计数

首次 GitHub quality run 在调度前拒绝了两处 job 级 `runner.temp` 表达式；本机 YAML 语法解析未发现该平台规则。已将临时目录变量改为 step 写入 `GITHUB_ENV`，并在文档 workflow 增加固定 actionlint 1.7.12 及官方 SHA-256 校验，检查 GitHub 上下文与 workflow schema。该失败保留，不计为数据库测试通过。

合入前同时检查 PR 与 push 两轮 CI 时，发现同一源码的 push unit 在取消测试中出现 `ConnectionRefused`，而 PR 轮全部通过。根因是测试固定等待 120 ms 后连接，未等待 RocksDB/TLS 初始化和 listener bind 的真实完成。测试改为在正式资源装配后首次轮询 shutdown future 时发送 oneshot 启动信号；受控 release gate 验证启动前信号未发生。保留严格单次连接，不对启动错误静默重试。取消后只对 `AddrInUse` 在单个 1 秒测试预算内观察端口最终释放，其他错误立即失败；RocksDB 独占锁仍要求父任务取消完成后立即重新打开。生产源码与最终服务构建输入不变，失败历史保留。修正后的 11 个 node tests 先通过，再按预先固定的 20 轮完整运行得到 220 passed、0 failed/ignored；任一失败立即停止，没有重试失败轮。全 workspace 单元与完整 CI 重新执行。

质量 workflow 增加 SDK unit、独立 S3、正式服务部署三个 job，共 13 个质量 job，另有文档 job。Rust profile、Python profile、SDK profile、各类故障历史分别保存 artifact，完整性检查与执行退出码分开。正式服务 job 在 release 构建上运行完整 8 项及全部 360 样本，但输出明确 `production_slo_passed=false`。

## 14. 增量磁盘块、按库隔离与连接复用（2026-11-04）

对应 [ADR-0015](../adr/0015-incremental-blocks-and-isolated-execution.md)。本轮从 main `466973d1a9516426ccb27519b17f93a420255b60` 的树 `bcc465b9ecb05fc138a140d54979d1d51f710783` 开始，分别处理完整 native 镜像重复落盘、冷唤醒阻塞全局 SQL 线程，以及每个 peer 消息重复建立 TLS 连接的问题。三个改动共用正式实现；实验没有替代存储、SQLite 或共识算法。

### 14.1 单元与静态门禁

修正本节记录的集成缺陷、冻结正式源码并清理旧 profile 后，使用原固定 nightly、完整 workspace、`--lib --bins --all-features --locked --branch` 重新采集。**396 个 Rust 单元测试全部通过，0 failed / ignored**；47 个生产源文件全部进入 coverage map，逐文件四项精确计数均相等。

| 精确整数维度 | 覆盖 / 分母 |
| --- | --- |
| Lines | **10151 / 10151** |
| Functions | **932 / 932** |
| Regions | **14890 / 14890** |
| Branches | **2214 / 2214** |

没有加入生产排除、修改阈值或合并故障测试 profile。新加入清单的两个测试文件分别属于 block layout 与 SQL lanes。全工作区格式与严格 Clippy（all targets / all features / `-D warnings`）通过。SDK **11 passed**，318 statements / 30 functions / 225 branches 全命中；Python 工具 **58 passed**，321 statements / 160 branches 精确 100%。

覆盖反例包括：清单截断、块长与数量上限、缺块/坏摘要/多余 key、未知 namespace、旧格式迁移、写结果不确定后的停止；同库 FIFO、不同库独立推进、退出与入队竞争、全局/单库配额、原 deadline/取消、spawn/build/panic/join；实际 TLS 链/DNS/时间、同 socket 复用、在现存连接上撤销当前 pin、恢复权限后重连，以及同步授权检查超过绝对 deadline。

### 14.2 真实磁盘与故障回归

新增 native blocks 实验直接使用正式 `RocksBackend`。验证新布局更新、磁盘重开和 checkpoint；旧格式读取不迁移，第一次同步更新后通过子进程退出（不运行 Rust 析构）再恢复；缺块、损坏和外来 key 均拒绝打开或初始化。该文件 **4 passed**，其中一个是子进程入口，不把入口本身另计为一类故障证明。

原三进程 WAL 破坏 fixture 初次失败：它仍寻找 `scap/g0/atomic-image`，因此在注入前就退出。更新为同时寻找实际 G1 manifest、chunk key 与原操作字节后，完整 **8 项 Raft cluster 合同通过**。CRC32C 单比特破坏、native `Corruption` 拒绝、保留 IDENTITY/CURRENT/损坏 WAL 和健康多数派继续推进的断言都没有放宽。该失败是旧格式 fixture 假设失效，不计为持久性测试通过。

本机随后完成 9 套独立 Rust 回归，共 **80 passed，0 failed / ignored**：WAL 13、RPC 8、Store 16、Raft cluster 8、SQLite cell 6、SQLite engine 11、Raft network 8、SQLite network 8、S3 2。网络合同包含现存连接撤销 pin、真实 mTLS 快照、TCP 黑洞、少数派拒绝强读、ACK 后进程故障、原结果恢复与全组重开。单元报告不含这些样本。全部 9 套独立实验均通过各自 manifest 的格式检查与严格 Clippy（all targets / locked / `-D warnings`）。

独立 S3 fixture 新增与完整服务相同的可选四进程 TCP 模式，使用固定 SeaweedFS 4.51；默认仍为 `mini`。两项合同在 **46.69 s** 内通过，包含签名条件 PUT、不同内容不覆盖、HEAD 大小限制、错误凭据拒绝、停机期间已过期 PUT 不创建对象，以及原目录重启后的精确字节核验。故障前确认四个组件仍在运行，逐个 SIGKILL 并核对信号 9；重启后同时核对 `published/older` 与 `orphan/newer` 的原始完整字节。两个历史文件均以 `verification passed` 结束。测试输入在执行前后相同；该补充只修改实验夹具和说明，71 个生产输入的摘要仍与最终完整服务运行一致。

### 14.3 冷唤醒隔离的负对照与证据约束

固定同一台机器、原 main release 和新增合同做负对照。先确认 cold beta 已连接并阻塞在真实 S3 TCP 黑洞中，再发起其余 beta 请求与 alpha 热库请求。原 main 的 **17/17** 计划尝试均有记录；13 个 beta 请求未触发单库拒绝，4 个 alpha 请求中 3 个 `COMMIT_UNKNOWN`，最后一次读在原 beta 请求结束后才成功。因此旧实现按预期不通过隔离合同。

新合同固定保留 beta 13 次强读和 alpha 两组写/强读，17 个请求 ID 与 ordinal 均唯一；单库 8 槽上限要求至少 5 次 `OVERLOADED`。所有 alpha 请求必须成功、实际观测完成时刻早于自己的原 1500 ms deadline，也早于第一条 beta 请求结束。不能删除超时、把晚到成功当作按时成功，或只用 S3 connection refused 的快速失败证明隔离。CI 同时检查请求种类、时间戳有限性/顺序与完整分母。

本机不允许创建 Unix socket，固定 SeaweedFS `mini` 的启动尝试失败。随后采用同一 **4.51 / 153ab668c99731a6d29492bf6c61d0b4fa701101** 二进制的正式 master/volume/filer/s3 四进程模式，通过显式 loopback HTTP/gRPC TCP 地址启动，并以实际签名对象请求检查就绪。没有修改上游源码、系统权限或用内存替身代替对象存储。默认 CI 仍使用原 mini 模式；运行 artifact 记录实际后端拓扑。

### 14.4 真实服务发现的调度问题

最初的新实现虽已通过完整 100% 单元门禁，真实服务仍发现两处问题；这些失败保留，不能用随后成功的样本覆盖。

1. 冷唤醒隔离的首次正向运行中，4 次 alpha 请求全部按时完成且早于原 beta 结束，13 次 beta 产生 5 次限额拒绝；但之后的 `cold.status()` 返回 `NO_LEADER`，整项失败。排查发现各库 Worker 与 catalogue 共用公开 readiness 标志：一个库的请求期限失败或新线程初次观察 term 都可能清掉节点提示；反过来，单库读成功也能覆盖 catalogue 的 false。现在仅 catalogue 发布公开提示，每库使用私有观察状态，停止信号始终优先；SQL 的逐请求权威检查保持不变。
2. 编译全部结束后的完整服务运行通过第 01 项，但 SDK 第 02 项五组用例有四组出现非预期 `OVERLOADED`，第 03–08 项未执行。三个进程均仍存活。正常错误、去重成功后 stopped writer、以及只查询元数据的 lane 都可能进入退休；旧队列关闭到线程 join 之间的请求被错误拒绝。现在 dispatcher 在原额度内保留尚未执行请求，旧线程成功 join 后一次性向新 lane 交接 FIFO；退出未完成时仍处理取消和过期，真实满额保持拒绝。

新增确定性测试在旧 executor 析构中设置阻塞栅栏，核对其他库进展、原请求不重复执行、无重叠 writer、新 boot 与顺序交接，并覆盖等待期取消/超时和异常退出。readiness 的装配边界测试验证公共 true/false 均不被单库操作覆盖，停止不能被晚到提示撤销。完整故障实验继续独立于单元分母。

### 14.5 最终冻结构建与同机对照

修正后的 release 二进制 SHA-256 为 `f7b150027e365e69f0722930a81aabf4f4fed3280704ef7bfa77aa5c5c92e488`。71 个生产构建输入的摘要为 `750892e547d34a355668592056f6cb6fe7f962f583e0127f631272d3a47127c2`，构建前后与完整运行前后均匹配；服务 fixture 未再修改。原 main release 摘要为 `e48686f164a32a799d53392048c19960d9f94ca7c7a212e0f8091045a6da5786`，以相同清单规则记录 69 个输入。两者复用同一固定源码生成的 O3 native RocksDB 库，SHA-256 为 `4998da12e679834d39b191009ae67fcd6e1377853bed855d29dd0ad0a8f657b5`；正式 Rust 分别重建。原、新构建都在无并行编译的窗口测量。

最终完整服务运行 **8/8 合同通过**，实际 Node SDK **5/5 用例通过**。前景 cold 隔离记录完整 17 次：beta 的 13 次中 5 次 `OVERLOADED`、2 次 `ARCHIVE_UNAVAILABLE`、6 次 `COMMIT_UNKNOWN`；alpha 的四次成功依次为 **51.524、11.971、18.012、9.114 ms**，均早于各自 1500 ms deadline 和原 beta 的 **2050.560 ms** 完成时刻。后续状态查询、真实 S3 SIGKILL/重启、精确 hydrate、后台黑洞、归档恢复到 revision 3 与原随机结果均通过；后台黑洞期间另五组热写/读也按原预算完成。

测量函数在基线和最终 fixture 中字节相同。每次均固定两个小库、4 请求/秒、8 秒请求 deadline、30 秒热基线及一次 leader SIGKILL 后 60 秒观察；原、新各 **360** 次尝试均保留。两者热态均 **120/120 成功**，恢复阶段均 **228/240 成功、12 次 NO_LEADER**，最后核对的已 ACK 写无丢失。新版本双库完整 30 秒稳定窗口从故障后 **3.005 s** 开始、于 **33.005 s** 确认；原版本为 **3.009 s / 33.009 s**。这些是一秒探测分辨率下的单次观测，不能推断恢复分位数。

| 成功热样本 p99，ms | 原 main | 最终版本 | 每次分母 |
| --- | --- | --- | --- |
| alpha 强读 | 143.292 | 232.295 | 30/30 成功 |
| alpha 写 | 198.445 | 177.311 | 30/30 成功 |
| beta 强读 | 155.903 | 241.075 | 30/30 成功 |
| beta 写 | 157.911 | 226.373 | 30/30 成功 |

热尾延迟结果有升有降，三组 p99 更高；不能把本次改动描述为整体延迟优化成功。恢复阶段各组成功 p99 从 **372.527/387.537/396.091/509.087 ms** 变为 **253.219/281.618/322.185/281.181 ms**，但每组仍保留 3/60 的失败分母，也不构成生产性能验收。调度器 timer 在少数计划点提前约毫秒唤醒，原始 scheduled/invoked 值及偏差统计完整保留，没有改写样本。

精确来源清单、环境、全部分组分母/分位、失败尝试、17 条隔离样本与原始 artifact 摘要在 [2026-11-04 可复核证据](../evidence/sqlite-service-local-2026-11-04.json)。该摘要明确 `production_slo_passed=false`。native 减少重复块写入和冷库隔离已有实现/反例证据；热读 50 ms、热写 100 ms、GiB 恢复与三 AZ/500 请求每秒 profile 仍未通过。

### 14.6 首次远端检查未执行

[PR #11](https://github.com/ckanner/scap/pull/11) 的首次提交 `512467a9e91c729eed35b8c29807cd1a369c6958` 同时触发 push 和 pull request workflows，均很快结束为 failure。逐项读取 PR 的 [quality run](https://github.com/ckanner/scap/actions/runs/41826281700) 与 [documentation run](https://github.com/ckanner/scap/actions/runs/41826281801) 后，13 项质量 job 与 1 项文档 job 的步骤列表全部为空，Rust 单元 job 的日志读取返回 BlobNotFound。因此当前没有远端测试执行结果，不能把它记为代码测试失败或 CI 通过。

当时检查元数据表明每个 check 有一条 annotation，但连接器尚未读取正文，因此首次调查没有推定原因或宣称 CI 通过。后续本地复验与维护者决定见下一节；这条历史记录不代替后续实际执行结果。

### 14.7 本地完整复验与维护者授权合并

2026-11-04，维护者明确要求以完整本地测试为准，在远端执行额度不可用期间无需等待 CI；本地验证通过即可合并并继续目标。没有降低覆盖率阈值、删除远端测试或修改分支保护。远端 job 未执行仍不记为通过。

对 [PR #11](https://github.com/ckanner/scap/pull/11) 的精确 head `b1ace698048dca12ade51aa66ee33405cac252c0` 重新执行本地门禁：396 个 Rust 单元与 47 个生产源文件的四维精确 100%、11 个 SDK 单元及其四维 100%、58 个 Python 工具单元、9 套独立 Rust 实验共 80 项、8 项完整服务合同与 5 项真实 SDK 子测试均通过。真实故障与 unit profile 分开，固定 release 二进制和源码前后校验一致；未把功能通过改写为生产 SLO。

合并前核对远端 head/base 与本地已验证 tree，使用 expected-head 保护执行 merge，随后读取 PR 与 main 确认结果：merge commit `bd5d97eb4335268941f2523b1f46ab76ee604b11`，tree `b8d772b63f041a9f8922134ffd23fc38a74b7d57`。本轮成员替换从该精确合入版本继续，不依赖早期本地合成历史。

本地完整证据归档 SHA-256 为 `79cba95ef8b3761f9c83c74e265db39f794fc770b0b0227340f27d8f4020ed44`。先前失败尝试和原始分母保持保留；该归档仅证明本节指明的旧 head，不作为后续成员变更新代码的测试结果。

### 14.8 受控成员替换的完整本地验证

[ADR-0016](../adr/0016-durable-membership-replacement.md)增加三 voter 的受控替换：预注册通信身份与真实 ConfState 分离；Join 核对健康 leader 的新鲜视图及完整 genesis；唯一 learner 追赶后进入显式 joint，再显式退出。完整配置 CAS、新 ID 单调增加、精确条目持久完成与管理 UNKNOWN 均进入正式 driver/runtime。管理服务使用独立 loopback listener 和 token，CLI 禁代理、重定向与自动重发；现有三 peer 固定模式保持可用。

**452 个 Rust 单元测试全部通过，17 个测试二进制，0 failed / ignored / filtered。** 51 个生产源文件逐文件全部进入精确分母，新增四个生产模块没有进入测试排除表。

| 指标 | 本轮实际覆盖 / 总数 |
| --- | --- |
| Lines | **11424 / 11424** |
| Functions | **1075 / 1075** |
| Regions | **16778 / 16778** |
| Branches | **2486 / 2486** |

固定 nightly 采集前递归确认 0 profraw / 0 profdata；285 个唯一 `membership-full-1-` 前缀 raw profiles 与实际 LLVM merge-list 的文件集合完全相等，没有重复、旧前缀或遗漏。原始计数器、合并结果和列表归档后逐文件校验 SHA。全工作区格式及 all-targets/all-features 严格 Clippy 通过，运行前后和最终汇总时的源码输入一致，旧报告未被覆盖。

SDK 本轮独立执行 **11/11**，lines/statements **318/318**、functions **30/30**、branches **225/225**。Python 工具本轮独立执行 **58/58**，statements **321/321**、branches **160/160**，没有 missing/excluded。Rust、SDK、Python 和真实故障分别计量，真实 daemon 没有写入 unit profile。

固定 release 二进制 SHA-256 为 `9a9df3656d99e5275ca4cee74ceb7e8c85ba37156d5e24e605011728c7064dbb`，75 项生产输入聚合 SHA-256 为 `5d9c2d210970e0c9363e187c15ddefd7397708fd1560623174b703f5d4b8bd17`。构建前后与实际成员、服务测试前后保持一致；完整输入清单、覆盖计数与原始收据哈希见[机器可读证据](../evidence/membership-local-2026-11-04.json)。

[成员真实实验](../../experiments/membership-network/README.md)首次执行完成 **8/8**。原三个 voter 的 snapshot 为 **129/138/138** 后才解除隔离；node 4 从 applied **1** 安装 snapshot **129** 并应用至 **144**。替换 node 2 的 joint 在全组 SIGKILL 后保留，再稳定到 `[1,3,4]`。新 ACK 只存在于 `[3,4]` 时，杀死二者后仅重开 `[1,4]`，保留 node 3 停止，仍逐行恢复原数据。最终 **alpha 68 + beta 67 = 135** 条成功 witness 全部保留。

少数派最后一次 AddLearner(5) 返回原始 **503 / MEMBERSHIP_UNKNOWN**；恢复 quorum 后权威配置出现 `learners:[5]`。这个真实样本证明未知响应后变更仍可能生效，记录没有被改成原请求成功，也没有盲重发 POST。旧节点重现不能恢复服务，现有 node 4 换空目录 Join 在建目录前被拒绝。

原有九套独立 Rust 实验本轮共 **80/80**，0 failed/ignored/filtered，43 份公开历史匹配实际测试名和完成标记。所有九条 test 命令各执行一次。完整执行账本保留 30 次 Cargo 调用：28 次 exit 0，以及一次并行编辑期间的格式检查失败、一次新 Answer 枚举引起的旧网络 fixture 编译失败。两处 fixture 只新增显式拒绝不应收到的成员响应，原断言/超时不变；诊断后仅继续尚未执行的场景，没有把失败记录删除或把已通过测试反复重跑。

其他准备与局部失败也保留：第一次 release 编译成功但期间三处生产文件改变，一致性 guard 拒绝冻结，未用于真实测试；最终 build-2 才通过前后输入核对。两次磁盘预检未启动任何编译或测试，安全回收停用缓存后才执行一次完整 Rust 采集。局部 coverage 曾有未覆盖的真实错误路径，补齐测试后进入上述完整四维门禁；未调低阈值或隐藏生产代码。

原有完整服务回归也首次执行完成 **8/8**，含 **5/5** 真实 SDK 子测试。冷唤醒黑洞期间保留全部 **17** 次计划请求：13 次冷库请求受有界准入控制，其中 5 次被限额拒绝；热库 4/4 在各自 1,500 ms deadline 内、且早于原冷请求完成。实际 S3 停止时热库继续读写，重开后精确恢复，revision 3 后台归档恢复且原结果保留。

独立测量保留全部 **360** 个计划样本：热基线 **120/120** 成功；故障观察 **228/240** 成功，12 次 `NO_LEADER` 仍在分母中。故障后连续 30 秒窗口的起点为 **3,004.219 ms**，于 **33,004.219 ms** 完成确认；首次成功为 **3,115.532 ms**。174 条已确认测量写入逐条核对，丢失 **0**。成功样本分位与每次原始结果分别记录在 `measurement.json` 和 `latency.samples.jsonl`，不能把这些分位改写为包含失败的生产延迟保障。

本轮证据仍是同机、loopback、有界小库、每秒四次测量请求与进程 SIGKILL。`production_slo_passed=false`；三 AZ、介质断电、规模化负载与长期可用性不能由这些测试计数推导。

## 15. 仍然阻断生产规模和完整平台目标的工作

- 当前单 cell 上限 32 个配置数据库、每库 256 KiB；128 个请求/库和 4096 个行政记录/cell 到限即拒绝。native 增量块已实现，逻辑状态仍整体编码、复制与校验；分段物理历史和可证明的保留策略尚缺，万级冷库与 GiB 级库不能只靠调大常数验收。
- 前景 cold hydrate 已按库隔离，线程与请求有独立有界额度；dispatcher 元数据扫描仍可能等待 cell，任意数量租户的加权公平性未实现。R1 预置文件、R2 热备执行与跨 AZ 路由恢复尚未实现。
- 当前 S3 实现具备 suspend/publish/prune/hydrate，没有对象 GC、删除/跨 cell 迁移、PITR、完整目录与权限恢复、S3-only DR。对象与原结果一直保留，长尾成本未全部解决。
- 已有受控 learner/joint 成员替换和故障证据；自动发现/采购/调度损坏副本、证书/管理员轮换控制面、多 cell 与混版本 rolling upgrade 尚待实现与故障验证。原始 bootstrap 配置仍须由部署者保留，可信通信目录不提供拜占庭防护。
- 支持闭合 Hrana pipeline、显式事务 batch 和强读；跨请求交互事务、cursor、同步文件驱动兼容、更多 page size、spill 与大事务不在当前服务范围。
- 三 AZ、设备断电/慢盘/丢盘、生产参考负载、故障分位、长期可用性与成本需要独立环境和样本。单机进程 SIGKILL、100% 单元覆盖率以及这 8 项成功不能替代上述证据。

这些限制不取消已实现的请求闭环，也不降低原有持久性合同。阶段结果、缺失能力和性能未达标分别报告；不能用测试计数代替完整目标的验收。

2026-10-28 的 [ADR 0006](../adr/0006-raft-rs-consensus-library.md) 将共识库首选候选由 OpenRaft 调整为 `raft-rs`。本页既有测试结果保持原有范围：此前没有接入任何真实 Raft adapter，不能把引擎探针或提交策略的通过记录记作 `raft-rs` 验证。新增工作的出口见 [集成门禁](raft-rs-integration.md)。

2026-10-29 的 [ADR 0007](../adr/0007-tikv-stack-and-rpc-boundaries.md)补充 TiKV 技术栈参考、运行与 RPC 约束及上述 codec/transport 实验。当时尚无正式 Raft 依赖或持久 adapter。

同日后续 [ADR 0008](../adr/0008-bounded-durable-store-g0.md)落实有界持久策略和真实 RawNode/RocksDB 恢复实验，新增第 7 节证据；当时正式 driver/native 尚待实现。

[ADR 0009](../adr/0009-serial-driver-and-native-backend.md)落实正式 driver/native 和第 8 节三进程故障合同。2026-10-31 的 [ADR 0010](../adr/0010-cell-acceptance-and-raft-safety.md)继续增加第 9 节业务接受、选举/读和 SQLite 接合证据；ADR 0011 与 0012 分别落实第 10、11 节。整个 G0 尚未通过，剩余工作以上述第 15 节为准。
