# SCAP

面向多租户 SaaS 与 Agent 的 SQLite 数据库平台。多个独立数据库共享一个三副本存储 cell；活跃库使用私有 SQLite 连接，休眠库把可恢复的物理历史归档到 S3 兼容对象存储。

**当前已经有可运行的三节点数据库服务、Node.js 客户端、自动 writer 接管、独立强读，以及休眠、归档、裁剪和唤醒。** 正式实现与真实故障测试使用同一套引擎、状态机和网络代码。当前发布范围仍是有明确容量上限的 G0 实现，生产规模、三 AZ 性能、动态成员、多 cell 调度、GC/PITR/区域灾备尚未验收；不是通用 SQLite 文件挂载服务，也没有对外 SLA。

## 已实现的完整请求路径

| 能力 | 当前行为 |
| --- | --- |
| SQL 服务 | `scap-server`，Rust / Axum；闭合 Hrana HTTP v2 pipeline，真实 `@libsql/client` 兼容测试 |
| Node.js 入口 | TypeScript `sdk/node`；标准 execute/batch，显式强读、原结果查询和有序取消 |
| 本地引擎 | 固定 libSQL 的 SQLite C 内核及提交前 WAL gate；私有连接，不向用户暴露可绕过复制的文件路径 |
| 共识 | 固定 TiKV `raft-rs`，三个 voter；PreVote、check_quorum、Safe ReadIndex；关闭租约读 |
| 成功写 | 同一个 cell 的 durable quorum、状态机接受、native SQLite publication 均完成后才 ACK |
| 自动接管 | 仅当前 leader 恢复 writer；新 owner epoch、新 worker ID、新目录；从权威物理历史恢复并激活 |
| 分区 | CP；少数派拒绝新的强读和写，没有本地成功或陈旧读降级 |
| 原结果 | 请求 ID、SQL/参数指纹、原 receipt 和结果持久保留；UNKNOWN 不盲重放，Lookup 缺失不代表取消 |
| 强读 | 新鲜 Safe ReadIndex、当前 READ 权限、owner 与物理 head 绑定；不增加数据库 revision 或写结果记录 |
| 冷生命周期 | 有序 Suspend → 不可变对象上传/核验 → PublishArchive → PruneArchive；唤醒先核验精确归档再恢复 owner |
| S3 不可用 | 热库仍可在 quorum 正常时服务；未完成归档的历史不裁剪，冷库唤醒明确失败 |
| 重启与关闭 | 默认严格 OpenExisting，显式初始化；损坏不自动建空库；SIGINT/SIGTERM 停准入、取消、排空并 join 所有 owner |
| 工程门禁 | 第一方 Rust 行/函数/region/分支全部 100%；SDK 行/语句/函数/分支 100%；单元与真实故障 profile 分离 |

架构、精确上限、启动配置和故障语义见 [正式 SQLite 服务](docs/engineering/sqlite-service.md)、[server 操作入口](crates/scap-server/README.md)和 [ADR-0014](docs/adr/0014-sqlite-service-and-cold-lifecycle.md)。

## 当前上限与适用范围

当前一个进程只承载一个固定成员 cell，每个节点按需创建独占数据库的 SQL 线程，活动与退出中的线程合计最多 32 条，休眠且无排队请求后释放。每个 cell 最多 **32 个配置数据库**；每库最多 **64 个 4 KiB 页面，即 256 KiB**；状态镜像上限 8 MiB，单条 cell command 上限 4 MiB。数据库最多保留 128 个请求身份记录，cell 最多保留 4096 个行政操作记录。达到容量时拒绝新工作，不驱逐幂等记录或取消 fence。

这些限额用于验证完整协议。它们没有满足最初规划的 10,000 个冷库、100 个热库、500 req/s 或 GiB 级库；也不能仅通过调大常数就变成该规模的系统。native 持久化已改为同一同步 WriteBatch 内的内容块增量更新；逻辑状态的完整编码、全历史恢复、全量归档以及强读的历史校验仍有放大成本。下一步需要逻辑分段日志与快照、可证明的保留策略、多 cell 公平调度，并保持全部故障门禁。

后台 S3 归档使用独立、有界、可停止并显式 join 的线程，不占用 SQL 执行线程等待对象 I/O。前景冷库 hydration 在该库独占 lane 中等待，受原请求 deadline 限制；其他库可独立处理请求。全局 32 请求/8 MiB、单库 8 请求/2 MiB 的在途与排队配额同时生效。当前不删除任何 S3 对象，因此没有未经证明的 GC，但对象与幂等元数据成本也不会自动归零。

## Node.js 使用方式

在仓库构建 SDK 后，可以从工作区直接引用它。当前包未发布到 npm。

```bash
npm --prefix sdk/node ci --ignore-scripts
npm --prefix sdk/node run build
```

```javascript
import { createClient } from "./sdk/node/dist/client.js";

const db = createClient({
  endpoints: [
    "https://node-1.example.invalid",
    "https://node-2.example.invalid",
    "https://node-3.example.invalid",
  ],
  database: "alpha",
  authToken: process.env.SCAP_TOKEN,
  timeoutMs: 2000,
});

await db.execute("CREATE TABLE IF NOT EXISTS items(id INTEGER PRIMARY KEY, value TEXT)");
await db.execute({ sql: "INSERT INTO items(value) VALUES (?)", args: ["hello"] });
const rows = await db.query("SELECT id, value FROM items");
console.log(rows.rows);
db.close();
```

`execute` 和 `batch` 复用已有 libSQL SDK 语义；只读热点使用 `query` 才走独立 ReadIndex 强读。直接使用标准 `@libsql/client/http` 也可访问 `/db/{name}` 的 Hrana 路由，但客户端自身的请求身份、未知结果处理和多节点路由必须遵守 [API 契约](docs/architecture/api-contracts.md)。

现有 `better-sqlite3` 的同步文件 API 不能直接把文件名换成 S3 URL。网络访问需要异步 SDK；跨请求交互事务、持久 baton、cursor、扩展加载和跨库事务不在当前兼容范围。完整错误与迁移示例见 [Node SDK](sdk/node/README.md)。

## 构建与验证

固定 Rust 1.90.0；native 构建需要 Linux、C/C++17、make、libclang 18。Node 单元与部署合同固定 Node.js 24.22.1。服务配置、证书 scope、显式初始化和同目录重开命令见 [server README](crates/scap-server/README.md)。

```bash
cargo build --release -p scap-server --locked
cargo test --workspace --lib --bins --all-features --locked -- --test-threads=1
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
npm --prefix sdk/node test
python3 scripts/check_sdk_coverage.py sdk/node/coverage/coverage-final.json
python3 scripts/check_repo.py
```

100% Rust 门禁使用固定 nightly 和 cargo-llvm-cov，核对每个正式源文件的精确分母，见 [覆盖率规范](docs/engineering/testability-and-coverage.md)。运行测试不会把 coverage、数据库、生成的证书或进程日志提交到仓库。

独立验证分三层：

- [真实 SQLite/mTLS 合同](experiments/sqlite-network/README.md)：native 发布边界、owner/auth fence、UNKNOWN、snapshot 与完整重启，另含独立强读合同。
- [真实 S3 对象合同](experiments/archive-s3/README.md)：签名、不可变条件写、大小校验、故障和同目录重启。
- [三节点服务/SDK/冷生命周期](experiments/service-network/README.md)：真实 daemon、真实 Node SDK、leader SIGKILL、网络黑洞、全组重启、S3 黑洞、热库继续服务及冷库恢复；另保留完整 360 个本机负载样本和 30 秒恢复窗口。

正式源码最新全工作区报告为 **396 个 Rust 单元测试，47 个生产源文件，10151 行 / 932 函数 / 14890 regions / 2214 branches 全部覆盖**。SDK 有 11 个单元测试；仓库门禁有 58 个 Python 单元测试。故障合同独立执行，不计入这些单元覆盖率。完整证据、失败样本和适用边界见 [执行证据](docs/engineering/g0-evidence.md)。

## 性能和可靠性合同

单区域三个独立故障域、正确持久化、非拜占庭故障、仍有有效多数派或其可恢复数据时，设计目标是单进程、单节点、单存储副本或单 AZ 故障不丢已确认事务。永久丢失多数副本、区域灾难、应用误删使用不同的恢复合同。

原生产目标保持不变：SDK 热强读 p99 ≤50 ms、小写 p99 ≤100 ms；writer 恢复 R0/R1/R2 的 p99 目标分别 30/15/10 秒，并有库大小、尾部和预置副本条件。**本机小库、4 req/s、单次故障的观测不能证明这些 p99、三 AZ RPO 或 99.9% 可用性。** 恢复时间从真实故障发生计到随后验证完成的 30 秒稳定窗口起点；所有超时、UNKNOWN、拒绝和最慢数据库必须保留。见 [性能与恢复目标](docs/engineering/performance-slo.md)。

## 设计导航

| 主题 | 文档 |
| --- | --- |
| 总体架构、需求与一致性 | [总体架构](docs/architecture/overview.md)、[需求合同](docs/architecture/requirements.md)、[一致性协议](docs/architecture/consistency.md) |
| 当前服务与配置 | [SQLite 服务](docs/engineering/sqlite-service.md)、[server README](crates/scap-server/README.md) |
| 客户端与隔离 | [API 契约](docs/architecture/api-contracts.md)、[租户与安全](docs/architecture/tenancy-security.md) |
| 存储和故障 | [生命周期](docs/architecture/storage-lifecycle.md)、[故障矩阵](docs/operations/failure-matrix.md)、[恢复手册](docs/operations/runbooks.md) |
| Raft 与持久化 | [Raft 安全边界](docs/engineering/raft-safety.md)、[持久 Store](docs/engineering/durable-store.md)、[网络运行时](docs/engineering/raft-network-runtime.md) |
| SQLite 权威提交 | [cell 状态机](docs/engineering/cell-state-machine.md)、[native adapter](docs/engineering/sqlite-engine.md)、[网络提交](docs/engineering/sqlite-network.md) |
| 工程与验收 | [路线图](docs/engineering/roadmap.md)、[验证计划](docs/engineering/validation.md)、[性能规范](docs/engineering/performance-slo.md)、[测试架构](docs/engineering/testability-and-coverage.md) |
| 技术与证据 | [技术栈](docs/architecture/technology-stack.md)、[TiKV 参考审计](docs/research/tikv-rust-stack.md)、[ADR](docs/adr/README.md)、[全部执行证据](docs/engineering/g0-evidence.md) |

PostgreSQL 延后。Bottomless / Litestream 是备份机制的参考，不承担 SCAP 的同步提交与自动选主。SQL 引擎复用的 libSQL SQLite C 内核，与 Turso 的 Rust 重写引擎是不同实现。

开发与协作规则见 [CONTRIBUTING.md](CONTRIBUTING.md)、[AGENTS.md](AGENTS.md)；安全报告见 [SECURITY.md](SECURITY.md)。主文档中文，代码和协议标识符英文。仓库分发许可证仍由维护者决定，当前没有擅自添加开源授权；第三方组件沿用各自许可证。

最新实现更新：**2026-11-04**。历史阶段和当时未完成项保留在对应 ADR 与执行记录中；增量持久化、按库隔离与连接复用见 [ADR-0015](docs/adr/0015-incremental-blocks-and-isolated-execution.md)，精确验收结果以执行证据为准。
