# G0 原型执行证据与剩余门禁

初始记录日期：2026-10-27；RPC 实验追加日期：2026-10-29。状态：**部分 G0 证据已经实际执行，整个 G0 尚未通过；没有可部署 HA 服务。** 性能、RTO 和三 AZ RPO 目标均未测量，不能从单机测试运行时间推导生产指标。

## 1. 本次实际交付

| 资产 | 实现与证据 | 不包含的能力 |
| --- | --- | --- |
| `crates/scap-core` | 提交完成顺序；两个窄 port；完整回执身份、前序序号、重复结果、未知结果与本地发布失败处理 | SQLite adapter、真实 quorum、授权校验服务、Raft 状态机 |
| `experiments/wal-gate` | 固定 libSQL 的真实提交前 gate、另一连接可见性、拒绝/回滚、页面捕获与进程退出恢复 | 产品运行时 adapter、分布式日志、一般 spill 事务、SDK 返回屏障 |
| `experiments/raft-rpc` | 固定 raft-rs 的真实消息经过 Tonic loopback 往返，验证原始字节、字段、拒绝和两层限额 | RawNode、持久化、quorum、mTLS、TiKV 协议互通 |
| 仓库工具 | 文档/合同检查；覆盖率源码清单与原始计数核对 | 证明报告来源可信或取代人工架构审查 |
| CI | 分开执行 Rust 单元覆盖、Python 工具单元覆盖、引擎探针和 RPC 探针，保留覆盖率 JSON | 云环境性能、三 AZ 演练、生产 SLA |

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

这些百分比只描述当前范围。核心目前只有一个生产 Rust 源文件、两个有函数体的生产函数。测试代码、编译器生成的实现、第三方依赖和测试探针不被包装成产品逻辑的覆盖成绩；所有第一方产品源码由门禁清单核对。LLVM 的已计数分支不等于所有 `match` 模式、派生比较的每个条件、MC/DC 或全部执行交错。10 项核心行为测试同时检查完整身份字段、错误结果及未发生的发布效果。

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

## 3. 复现核心单元覆盖

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

只运行 library/binary 的 unit harness，不运行独立引擎 workspace 或 integration tests；采集前清理旧 profile。禁止因 `cfg(coverage)` 改变产品代码，脚本同时拒绝相关源码排除。新增 bin、feature 或生成代码时必须扩展真实编译/执行矩阵，不能认为当前命令自动覆盖所有未来配置。

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

## 7. 仍然阻断完整 G0 / HA 上线的工作

- 完整、可恢复的事务暂存协议：spill、更多 page size、大事务、checkpoint 交互、错误恢复与所有可见性边界。
- `raft-rs` driver / 存储 adapter 的真实 durable flush、`Ready` / `LightReady` 次序、状态机原子落盘、snapshot/purge 与成员变更验证。
- 与提交完成策略连接的真实引擎与共识 adapter，以及其独立 100% 单元覆盖和真实契约测试。
- Hrana / Node.js SDK 的请求身份、返回值缓冲、交互事务、UNKNOWN 和重试语义。
- 固定 sqld 与现代平台依赖树的实际接合边界；RPC mTLS 身份、成员权限、重连/取消、全局背压与多 cell 调度验证。
- 跨三个 AZ 的失败检测、owner 仲裁、重建、路由恢复和 R0/R1/R2 接管实现。
- [性能目标](performance-slo.md)的真实延迟、吞吐、安全容量、RTO、RPO 与长期可用性证据。

这些工作不能用本页测试计数代替。后续每次修改代码或工具链，应保留新的精确报告并更新本页；性能不达标不得更改已确认写入的持久性合同。

2026-10-28 的 [ADR 0006](../adr/0006-raft-rs-consensus-library.md) 将共识库首选候选由 OpenRaft 调整为 `raft-rs`。本页既有测试结果保持原有范围：此前没有接入任何真实 Raft adapter，不能把引擎探针或提交策略的通过记录记作 `raft-rs` 验证。新增工作的出口见 [集成门禁](raft-rs-integration.md)。

2026-10-29 的 [ADR 0007](../adr/0007-tikv-stack-and-rpc-boundaries.md)补充 TiKV 技术栈参考、运行与 RPC 约束及上述 codec/transport 实验。Raft 的生产 runtime dependency 和持久 adapter 仍未接入，不把测试依赖或网络往返算作完整 G0 通过。
