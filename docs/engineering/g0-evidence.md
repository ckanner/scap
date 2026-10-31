# G0 原型执行证据与剩余门禁

初始记录日期：2026-10-27；RPC、持久存储、正式 driver/native backend 与三进程故障实验追加日期：2026-10-29；cell 业务状态机、选举/读合同和 SQLite 接合追加日期：2026-10-31。状态：**部分 G0 证据已经实际执行，整个 G0 尚未通过；没有可部署 HA 服务。** 性能、RTO 和三 AZ RPO 目标均未测量，不能从单机测试运行时间推导生产指标。最新正式 workspace 与组合结果见第 9 节；前面的分阶段记录保留其当时范围。

## 1. 本次实际交付

| 资产 | 实现与证据 | 不包含的能力 |
| --- | --- | --- |
| `crates/scap-core` | 提交完成顺序；两个窄 port；完整回执身份、前序序号、重复结果、未知结果与本地发布失败处理 | SQLite adapter、真实 quorum、授权校验服务、Raft 状态机 |
| `crates/scap-raft-store` | 正式 `raft::Storage`、有界持久镜像、身份/投票/日志/应用校验、原子 checkpoint 与恢复策略 | 增量布局、SCAP SQL/owner/auth/dedup 状态机 |
| `crates/scap-raft-driver` | 正式单 RawNode 串行 driver、Ready/LightReady 持久顺序、应用、读票据、限额和停止语义 | 生产传输、调度、业务 ACK、完整成员管理 |
| `crates/scap-raft-rocks` | 正式同步 RocksDB 后端、独占目录、严格 WAL 恢复、私有持久选项与 namespace 校验 | 副本自动重建、设备故障证明、增量布局 |
| `crates/scap-cell` | 确定性 owner/auth、物理事务接受、业务去重、原结果、持久取消与版本化 codec；绑定应用位置和复制限额 | 真实凭证认证、完整 lifecycle、引擎格式校验、S3、历史 GC、生产服务 |
| `experiments/wal-gate` | 固定 libSQL 的真实提交前 gate、另一连接可见性、拒绝/回滚、页面捕获与进程退出恢复 | 产品运行时 adapter、分布式日志、一般 spill 事务、SDK 返回屏障 |
| `experiments/raft-rpc` | 固定 raft-rs 的真实消息经过 Tonic loopback 往返，验证原始字节、字段、拒绝和两层限额 | RawNode、持久化、quorum、mTLS、TiKV 协议互通 |
| `experiments/raft-store` | 真实 RawNode 与同步 RocksDB，Ready/LightReady、投票、joint ConfState、快照及 5 个进程退出边界 | 三进程 quorum、真实断电、生产服务、SQL 接合、性能/RTO |
| `experiments/raft-cluster` | 直接组合正式模块；三个真实 OS 进程和独立磁盘目录；leader/整组 SIGKILL、分区、后缀、快照失败重试、WAL 损坏、tick PreVote 和请求绑定读 | 生产 RPC/mTLS、SQL 接合、物理断电、自动修复、性能/RTO |
| `experiments/sqlite-cell` | 固定真实 libSQL、3 个正式持久 Raft 实例及 cell；真实 SQL 子进程的提交 gate、业务拒绝、发布、SIGKILL 后从空文件恢复、snapshot/reopen | 三个独立 Raft OS 进程、生产 RPC/SDK、通用 spill、生产引擎 adapter 和自动接管 |
| 仓库工具 | 文档/合同检查；覆盖率源码清单与原始计数核对 | 证明报告来源可信或取代人工架构审查 |
| CI | 七个独立质量 job：Rust 单元覆盖、Python 工具单元覆盖、引擎、RPC、持久恢复、三进程故障、SQLite/cell；保留覆盖率 JSON 和故障历史，另有文档 job | 云环境性能、三 AZ 演练、生产 SLA |

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

这些百分比描述初始核心范围：当时只有一个生产 Rust 源文件、两个有函数体的生产函数。最新五个正式模块、六份生产源码的覆盖计数见第 9 节。测试代码、编译器生成的实现、第三方依赖和测试探针不被包装成产品逻辑的覆盖成绩；所有第一方产品源码由门禁清单核对。LLVM 的已计数分支不等于所有 `match` 模式、派生比较的每个条件、MC/DC 或全部执行交错。10 项核心行为测试同时检查完整身份字段、错误结果及未发生的发布效果。

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

只运行正式 workspace 的 library/binary unit harness，不运行独立实验 workspace 或 integration tests；采集前清理旧 profile。store/driver 使用可控 AtomicBackend，driver 内部仍为真实 RawNode；native adapter 的单元调用使用私有 RocksDB memory Env，只有隔离目录元数据操作接触临时文件系统，不声称完成真实磁盘恢复。详细分类见[单元边界](testability-and-coverage.md)。禁止因 `cfg(coverage)` 改变产品代码，脚本同时拒绝相关源码排除。新增 bin、feature 或生成代码时必须扩展真实编译/执行矩阵，不能认为当前命令自动覆盖所有未来配置。

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

该轮按第 3 节的固定工具链采集当时的正式 workspace，**29 项单元测试通过，0 failed**：`scap-core` 10 项，`scap-raft-store` 19 项。以下是该轮历史计数，后续四模块报告见第 8 节，最新报告见第 9 节。

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

### 9.1 最新完整单元报告

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

## 10. 仍然阻断完整 G0 / HA 上线的工作

- 完整、可恢复的事务暂存协议：spill、更多 page size、大事务、checkpoint 交互、错误恢复与所有可见性边界。
- 增量存储布局、物理存储故障与安全副本重建；把正式串行 driver 接入真实生产传输、多 cell 调度与完整成员管理。
- 将受限 SQLite/cell 装配实现为正式引擎与共识 adapter，纳入独立 100% 单元覆盖与通用真实契约；当前研究 helper 不能作为产品运行时依赖。
- 在已有有界接受子集上补全 lifecycle、迁移、删除、管理员轮换、归档引用和安全历史回收；完成 S3/manifest/GC 的独立恢复证明。
- Hrana / Node.js SDK 的请求身份、返回值缓冲、交互事务、UNKNOWN 和重试语义。
- 固定 sqld 与现代平台依赖树的实际接合边界；RPC mTLS 身份、成员权限、重连/取消、全局背压与多 cell 调度验证。
- 跨三个 AZ 的失败检测、owner 仲裁、重建、路由恢复和 R0/R1/R2 接管实现。
- [性能目标](performance-slo.md)的真实延迟、吞吐、安全容量、RTO、RPO 与长期可用性证据。

这些工作不能用本页测试计数代替。后续每次修改代码或工具链，应保留新的精确报告并更新本页；性能不达标不得更改已确认写入的持久性合同。

2026-10-28 的 [ADR 0006](../adr/0006-raft-rs-consensus-library.md) 将共识库首选候选由 OpenRaft 调整为 `raft-rs`。本页既有测试结果保持原有范围：此前没有接入任何真实 Raft adapter，不能把引擎探针或提交策略的通过记录记作 `raft-rs` 验证。新增工作的出口见 [集成门禁](raft-rs-integration.md)。

2026-10-29 的 [ADR 0007](../adr/0007-tikv-stack-and-rpc-boundaries.md)补充 TiKV 技术栈参考、运行与 RPC 约束及上述 codec/transport 实验。当时尚无正式 Raft 依赖或持久 adapter。

同日后续 [ADR 0008](../adr/0008-bounded-durable-store-g0.md)落实有界持久策略和真实 RawNode/RocksDB 恢复实验，新增第 7 节证据；当时正式 driver/native 尚待实现。

[ADR 0009](../adr/0009-serial-driver-and-native-backend.md)落实正式 driver/native 和第 8 节三进程故障合同。2026-10-31 的 [ADR 0010](../adr/0010-cell-acceptance-and-raft-safety.md)继续增加第 9 节业务接受、选举/读和 SQLite 接合证据。整个 G0 尚未通过，剩余工作以上述第 10 节为准。
