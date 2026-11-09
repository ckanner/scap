# SQLite WAL-reset：b00d67e 只读核查

核查日期：2026-11-09。SCAP 源码精确提交为 `b00d67e879c923012e89923829c0e39959b79848`；未修改源码、依赖或构建缓存，未执行新的 Cargo/native workload。

## 结论

当前固定的 libSQL **没有包含这次 SQLite 官方 WAL-reset 修复**。SCAP 目前的正常服务调用路径，通过“每个本地数据库文件只有一个受控 native 连接，操作串行、checkpoint 在同一连接同步完成”的架构约束排除了官方描述的触发拓扑。这是对当前调用图和私有文件生命周期的源代码判断，**不是 native 已修补，也不是对任意嵌入方式或外部程序的保证**。

将 libSQL 升级到核查时的官方 main `a1d031cb602fedefbcf55c568e98e998a2274400` 不会解决该问题：其 `wal.c` 与当前 pin 逐字节相同，bundled `sqlite3.c` 的 Git 内容对象也完全相同。所需 WAL publication hooks 保留，但修复仍缺失。本次没有建立新依赖 fork，也没有做升级。

## 官方问题与精确 native 身份

[SQLite WAL 文档 §11](https://www.sqlite.org/wal.html#walreset) 指出：该问题影响 WAL 模式、同一文件上不同线程或进程中的两个以上连接，在写入和 checkpoint 特定交错下可导致损坏；影响范围为 3.7.0 至 3.51.2，3.51.3 修复，并提供 3.44.6、3.50.7 回移。其过程是已完成 checkpoint 的 WAL 被另一个提交重置，而新 checkpoint 错把旧进度用于新 WAL，后续可能遗漏已提交页面。该官方页面已更新至 2026-08-25，不能沿用早期“没有自然复现”的说法作为保证。[3.51.3 发布说明](https://www.sqlite.org/releaselog/3_51_3.html) 单独确认修复。

| 项目 | 实际值 |
| --- | --- |
| SCAP 固定 libSQL commit | `d8bc862d20bedc72945a1da27c8b7045414c0261` |
| libSQL crate 版本 / commit 日期 | `0.10.0` / `2026-10-13` |
| native `SQLITE_VERSION` | `3.47.0` |
| native `SQLITE_VERSION_NUMBER` | `3047000` |
| native `SQLITE_SOURCE_ID` | `2024-10-21 16:30:22 03a9703e27c44437c39363d0baf82db4ebc94538a0f28411c85dda156f82alt1` |
| bundled `sqlite3.c` SHA-256 | `0eb52e017a09ddb955a7fbaa5c2e5c39ed238f7480ec485e45f64fbb624ee7fb` |
| bundled `sqlite3.c` Git blob | `62a917fb9bef09786a753a0a92fd590f80a62421` |
| source `wal.c` SHA-256 | `705931f95dfc18705943b779c5079cfb828f0799d9ae149808bf27d3855153a3` |
| source `wal.c` Git blob | `984f87c5f7451aa508991f0e04265ef97ac5c5ca` |

pin 由 [SCAP Cargo.toml](https://github.com/ckanner/scap/blob/b00d67e879c923012e89923829c0e39959b79848/crates/scap-object-sqlite/Cargo.toml) 与 Cargo.lock 一致指定。按仓库依赖配置，native 构建入口是 [libsql-ffi/build.rs](https://github.com/tursodatabase/libsql/blob/d8bc862d20bedc72945a1da27c8b7045414c0261/libsql-ffi/build.rs) 的 bundled C 分支；不是宿主机安装的 SQLite。当前依赖未启用 encryption/其他自选 WAL 后端。源码文件均与本地 pin 的 Git 对象逐字节一致。

## 当前 SCAP 如何排除触发拓扑

| 约束 | 精确源码位置与含义 |
| --- | --- |
| 文件必须新建 | `scap-object-sqlite/src/file.rs`：`ImageBuilder::create_new` 先创建新的 0700 目录，再以 `create_new(true)`、0600 创建 `database.sqlite`；已有目录/旧 sidecar 不会被接纳为新 image。 |
| 不能复制 image 能力重开同一文件 | `PreparedImage` 没有 Clone 或公开路径/裸连接接口，`SqliteWriter::open` 消费它。构造第二个 writer 必须另建 image；再次使用同目录会失败。注意调用者本来知道目录，所以这不是阻止可信 host 或同 UID 程序直接访问路径的安全沙箱。 |
| 单连接且受线程约束 | `scap-object-sqlite/src/lib.rs` 的 writer 内只有一个 `NativeConnection`，并持有 `Rc<RefCell<...>>`，因此不能以安全 Rust 跨线程共享；execute/query 都需要 `&mut self`。不会从现有连接派生读池。 |
| 辅助探测不是同文件第二连接 | `sql.rs::open` 的全局 temp 目录探测只打开独立 in-memory 连接，检查结束即销毁，之后才建立唯一 file-backed 连接。libSQL `Connection::open` 本身只创建一个 raw 连接。 |
| checkpoint 串行 | 打开时传 `NO_AUTOCHECKPOINT=0`，配置也设置 `wal_autocheckpoint=0`。接受提交后，`finish` 同步在原连接执行 `PRAGMA main.wal_checkpoint(TRUNCATE)`，返回后才允许下一个操作；不创建后台 checkpointer。忙或不完整会停止缓存并返回 `CommittedButUnavailable`，不能据此撤销已接受提交。 |
| 用户 SQL 无法再开连接或触发维护 | `sql.rs::authorize` 默认拒绝未列出的动作，包含 PRAGMA、ATTACH、事务控制和扩展入口；query.rs 进一步只允许读。`FULL_MUTEX` 是额外单连接保护，不能被当作多连接问题的修复。 |
| 多 worker 不共享物理文件 | `scap-service/src/engine.rs` 为每个 Engine 建独立随机 TempDir；session 路径使用 checked、单调递增序号。出错/重新打开/激活/接管均丢弃旧 session，新恢复另用新路径。`scheduler.rs` 对 actor 工作串行执行，但排除 WAL-reset 的关键仍是文件隔离，即使两个 owner 候选同时存在也各用自己的文件。 |
| 退出不与同文件业务操作并行 | writer 字段顺序先销毁 native 连接，后删除 image 目录与 sidecar。Engine 也先销毁 session，再销毁父目录。旧 orphan 目录不会作为正常恢复输入重新打开。 |

相应核心调用链为 [Database::restore / Session](https://github.com/ckanner/scap/blob/b00d67e879c923012e89923829c0e39959b79848/crates/scap-object/src/lib.rs)、[native writer](https://github.com/ckanner/scap/blob/b00d67e879c923012e89923829c0e39959b79848/crates/scap-object-sqlite/src/lib.rs)、[private image](https://github.com/ckanner/scap/blob/b00d67e879c923012e89923829c0e39959b79848/crates/scap-object-sqlite/src/file.rs)、[engine](https://github.com/ckanner/scap/blob/b00d67e879c923012e89923829c0e39959b79848/crates/scap-service/src/engine.rs)。完整源文件核查记录 SHA-256 为 `a6a06eafa05d5a15a6659584862b0e1005c3f7cbf7885346c4c9030fcc201f2d`；上述固定提交链接也可独立复核。

测试中确实有额外同文件 reader：例如 `capacity_tests.rs::busy_native_checkpoint_reports_committed_but_unavailable_and_stops`、`alter_tests.rs::accepted_alter_with_a_blocked_checkpoint_recovers_the_committed_schema`，以及门钩子内的独立可见性观察。它们是刻意的测试接缝，reader 只读、调用按单线程顺序推进；它们不是生产连接池，也不是 WAL-reset deterministic reproducer。不同单测使用不同临时目录。不能拿这些测试通过来声称引擎漏洞已修复。

## 约束边界与剩余风险

私有目录仍处于可信 operator/embedding host 的控制下。直接用 sqlite CLI、备份 sidecar 或同 UID 代码重开活动缓存，改变 VFS、目录或 mount，或者未来把 read pool / background checkpoint 引入同一个文件，都可能打破上述排除条件。文件系统 allowlist、S3 单 owner 和 HEAD CAS 不是 native WAL-reset 修复；单进程也不意味着只有一个连接。

若本地 native 计算已错误，内容哈希不能识别业务上“错误但字节一致”的页面；S3 持久权威也不能自动修正这种输出。因此必须把“每活动 SQLite 文件只有一个连接”写入运维/嵌入合同，并在解除约束前完成 native 修补与独立验证。架构排除也不替代普通的 native 依赖维护。

## 官方 libSQL main 与可行集成选择

核查的官方 main 是 [a1d031cb602fedefbcf55c568e98e998a2274400](https://github.com/tursodatabase/libsql/commit/a1d031cb602fedefbcf55c568e98e998a2274400)，日期 2026-11-07。与 pin 逐字节比较的文件有 `wal.c`、`VERSION`、`libsql-sys/src/connection.rs`、`wal/{mod,wrapper,ffi,sqlite3_wal}.rs`、bundled `sqlite3.h`、`build.rs`，全部相同。大型 `sqlite3.c` 远端接口未返回完整正文，返回的 Git blob 与本地 exact pin 相同；本记录明确区分这两种证据。

官方仓库 [issue #2271](https://github.com/tursodatabase/libsql/issues/2271) 在此次检索时仍 OPEN、0 comments。读取当前 main 并检索相关 commits / PRs 后，未找到可直接改 pin 即获得该修复的官方版本；这不是对所有分支和私有版本的穷尽证明。

官方 SQLite 修复是 [72a14a575e72b44d6401107039f387f944d7b647](https://github.com/sqlite/sqlite/commit/72a14a575e72b44d6401107039f387f944d7b647)，对应 Fossil `7168988acbec2d8d51106a263e553f8942b8b23d983dbbe5028e0f9be68cbb83`。最小语义变化是：拿到 `WAL_READ_LOCK(0)` 后比较实时 wal-index 与本 checkpoint 缓存头的 `aSalt`；仅在仍相同的情况下更新 `nBackfillAttempted`、复制/同步页面和写 `nBackfill`；无论是否匹配都释放 reader lock。它另加 fault point 660 和 `walrestart.test` 以确定性重现交错。当前 pin 在该锁之后立即写 `nBackfillAttempted`，缺少该检查；该固定上游提交的 diff 同时保留了修复前后的精确代码与回归测试。

可选后续路径按改动范围排列：

1. 优先采用官方 libSQL 发布的精确回移提交，在保持 `WrapWal::insert_frames` / `libsql_wal_methods.xFrames` 的情况下更新 pin、lock 与构建来源记录。
2. 若官方尚无修复，可单独审查一个受控依赖回移候选。必须保留 libSQL 自己的 reverse iterator 和 checkpoint callbacks，在原 `wal.c` 与生成的 amalgamation 中一致落地；不能只改版本号或把上游整个 wal.c 替换过来。是否建立 fork/供应源是另一个明确决策，本次没有实施。
3. 直接替换为普通 SQLite 3.51.3+ 不是 drop-in：SCAP 依赖的前置 WAL publication hooks 不属于普通 SQLite 相同接口。常规提交后的 WAL 通知不能替代当前“先远端权威接受、再 native publication”的门。保留这些门需要独立适配项目，不应混入本次 raw-frame 改动。

## native 升级验收门

- 保存修复来源、生成方式、整个 native C/headers/构建参数哈希与最终 `.a`、ELF 身份，区分 crate release 号和真实 SQLite version/source ID。
- 先让 deterministic WAL-reset 反例在原始 native 构建上真实失败、修复构建上通过，使用上游 fault hook/测试或等价受控交错；普通随机压力测试未复现不能当作修复证据。
- 重新验证 SCAP pre-publication gate 的原页/原结果、拒绝与中断、S3 接受而 native 失败、UNKNOWN、不重放、checkpoint 忙与缓存废弃、独立恢复与 retained receipt。
- 重跑受影响 first-party units、严格 Clippy/精确四维覆盖及 native/真实 HTTP-S3 的分层验收，尤其提交前可见性、冷恢复、结果账本、边界容量和运行时来源。保持原始失败与新成功独立记录。

本次新 native 执行、漏洞复现、修复验证均为 **NOT_RUN**。它是源码与官方来源评估，不改变已有 b00d67e 的 507-unit 正式结果，也不借那些结果声明 native 已修补。
