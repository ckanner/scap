# 对象权威 SQLite 执行器

本模块只负责私有 SQLite 执行、最终物理页捕获和提交前可见性控制，不持有数据库提交权威。它没有 Raft、cell、term、index 或旧回执依赖。

## 调用合同

上层先读取新鲜 HEAD，验证当前权限、原请求身份、writer 和精确数据根，再将完整、已核验的 SQLite 镜像交给 `SqliteWriter::create_new`。空字节数组表示一个全新空数据库；恢复已有库时，上层不能用空数组替代缺失的数据。

执行器在调用方提供的私有父目录下，独占创建一个新目录及 `database.sqlite`。目录权限为 `0700`，数据库为 `0600`；已存在的目录、缓存和 WAL sidecar 一律不复用。本地同步写仅用于物化完整基线，不是事务确认依据。

每次 `execute` 是一个显式有界事务。SQL 结果先完整缓冲并编码；原生 `xFrames` 的提交回调将最终 `PageBatch` 和精确结果字节送交 `CommitGate::publish`，尚未调用底层 WAL 的发布操作。上层必须先持久化全部对象依赖、再以原 HEAD 条件发布，最后才能返回 `Accepted`。收到 `Accepted` 后才允许 SQLite 继续发布；两者均完成才返回结果。

没有脏页的事务不会触发原生 `xFrames`，但 `execute` 仍会显式调用权威 gate 记录原结果。独立只读请求应使用 `query`；它不调用 gate、不修改镜像，必须由上层以调用期间取得的新鲜授权快照准入。

## 失败语义

| 结果 | 含义 |
| --- | --- |
| `Rejected` | 当前候选没有得到接受；不证明同业务身份的其他在途候选没有提交 |
| `OutcomeUnknown` | 远端结果不能确定，包括回调 panic；上层保留原身份查证，不能重跑 SQL |
| `CommittedButUnavailable` | gate 已接受，但本地发布或结果物化失败；不能撤回远端提交或改报回滚 |
| SQL、预算、镜像或 I/O 错误 | 本次执行器停止；上层按发生边界决定请求结果，不复用缓存 |

任何失败后执行器永久停止，下一次操作需要依据权威重新恢复。所有回调 panic 在跨越 C 边界前捕获；未知状态在调用权威适配器之前安装。

## 资源与安全边界

固定引擎版本和 4096 字节页。SQL 语句、参数、列、返回行、值长度、完整结果、VM 步数、数据库页数和变页数分别限额。非法或缺失增长页、重复/乱序页、页大小变化、提交前 spill 均失败关闭。

执行器拒绝用户控制事务、PRAGMA、ATTACH、临时 schema、扩展加载、虚拟表以及未列入允许集合的函数。只读路径还校验 SQLite 完整 VM 的 `readonly` 属性。恢复时核对页结构和完整性；结构检查不会重新执行非确定的业务 CHECK 条件。

此 crate 不实现凭据认证、HEAD/ETag、对象完整性摘要、请求去重、请求退休或 S3 请求期限。它们由对象权威层完成；`CommitGate` 是受信组件接口，不能开放给租户。

## 验证

```bash
cargo test -p scap-object-sqlite --lib --locked -- --test-threads=1
cargo clippy -p scap-object-sqlite --all-targets --locked -- -D warnings
```

单元测试包含真实固定 SQLite 引擎与可控 authority/filesystem/configuration 效果边界。对象端点、进程崩溃、全部计算丢失和端到端恢复属于独立集成验收，不计入单元覆盖率。
