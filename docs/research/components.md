# 开源组件调研与采用边界

初始查询日期：2026-10-27；Raft 选型复核：2026-10-28。状态：架构候选与源码核实记录，尚未完成端到端实现、故障注入或生产验证。

本文件回答三个问题：已有项目提供了什么、SCAP 准备复用什么、哪些保证必须由 SCAP 自己建立。技术栈的模块分工见 [技术栈与集成契约](../architecture/technology-stack.md)。这里的“已存在”仅表示在官方文档或公开源码中找到了相应能力，不表示不同组件拼接后已经满足本项目的可靠性目标。

## 1. 选型结论

推荐以 **libSQL 的 SQLite C 分支和远程 SQL 生态作为执行与兼容基础，以 raft-rs 驱动的共享 cell 和本地持久存储建立提交权威，以 S3 保存冷数据**。每个 cell 是一个复制组，初期由三个 voting members 组成，承载多个数据库；不为每个租户创建独立的三节点复制组。

| 层次 | 候选组件 | 已存在的能力 | SCAP 必须承担的部分 | 当前决策 |
| --- | --- | --- | --- | --- |
| SQLite 执行 | libSQL C 分支、`libsql-sys` | SQLite 执行、文件格式兼容基础、virtual WAL 接口 | 提交前的持久确认、可见性控制、恢复后重放、资源限制 | 首选验证 |
| 远程 SQL | `sqld`、Hrana | 协议、远程查询、namespace 管理、认证接入基础 | 路由、唤醒、会话归属、租户授权、迁移期间行为 | 尽量复用，锁定实现版本 |
| Node.js 异步客户端 | `@libsql/client` | 远程 libSQL、Promise API、ORM 适配生态 | 错误契约、兼容测试、明确可重试范围 | 默认入口 |
| Node.js 同步兼容 | `libsql` npm 包 | 接近 `better-sqlite3` 的 API，支持远程连接 | 缺失 API 处理、阻塞影响评估、事务兼容验证 | 存量应用的可选入口 |
| 共识 | TiKV raft-rs / crate `raft` | 选举、日志复制、成员变更、ReadIndex 与显式 Ready 接口 | driver、网络与持久存储、状态机、fencing、幂等、快照、调度 | 首选候选；OpenRaft 保留对照 |
| cell 本地持久化 | RocksDB | 有序 KV、原子 WriteBatch、WAL、同步写选项 | 按 Raft 契约实现落盘顺序、回调、恢复与截断 | 首选候选，需测量写放大 |
| 冷存储 | S3 / 经验证的 S3-compatible 服务 | 对象存储与对象 API | 不可变对象布局、manifest 发布、恢复验证、引用与回收 | 采用，供应商能力逐项验证 |
| 控制面 | etcd | 一致性 KV、事务、watch、lease | 数据库目录、配置与调度流程、目录和 cell 状态收敛 | 采用；不作为 WAL 提交 fencing 权威 |
| 连续备份参考 | Bottomless、Litestream | 异步上传、快照与恢复等现成实现 | 同步提交和自动 failover 仍未被替代 | 参考或独立备份用途 |

上述组合降低每个闲置数据库必须常驻的计算资源，但平台仍有复制组、控制面和监控的固定成本。“SQLite 是进程内数据库”不能推出“分布式平台没有运维成本”。节省幅度需要用活跃库数量、缓存规模、复制流量、S3 请求和恢复时间实测。

## 2. libSQL、Turso rewrite 与 Turso Cloud 要分开看

[libSQL 官方 README][libsql-readme]明确区分两个引擎：libSQL 是 SQLite 的分支；Turso Database 是以 Rust 重写的另一个实现。Rust 服务端、Rust binding、Rust 重写 SQL 引擎不是同一件事。SCAP 首期采用的是 **SQLite C 分支 + Rust 服务和存储适配层**。

[当前 TypeScript SDK 文档][turso-ts]也分别列出 `@libsql/client` 与 `@tursodatabase/database`、`@tursodatabase/sync`、`@tursodatabase/serverless`。后者属于新的 Turso 引擎生态。SCAP 不把引擎重写、离线双向同步、托管云的调度和 HA 混为一个可直接自托管的软件包。

libSQL 仓库公开了 `sqld`、复制与 Bottomless 等组件，但公开源码的范围和托管产品的完整能力不能画等号。首期不依赖“下载仓库即可获得 Turso Cloud 同等 SLA”这一假设。Rust Turso 可以作为后续引擎候选；切换前仍须重跑 SQL、文件导入、事务、SDK 和故障恢复验证。

### 2.1 Virtual WAL 是真实可复用的接口，但不是现成的 HA 实现

[libSQL 扩展说明][libsql-extensions]公开了 virtual WAL 的注册与选择机制。[当前 Rust 接口源码][libsql-wal]包含 `WalManager` 和 `Wal`，后者涵盖读写事务、页读取、撤销、savepoint、checkpoint；`insert_frames` 接收页大小、事务提交标志 `is_commit` 和同步标志 `sync_flags`。

这使 SCAP 可以在 WAL 提交路径中接入共享日志，优先复用引擎的页级事务结果，避免在多个副本重复执行可能包含时间、随机数或其他非确定性行为的 SQL。**如何暂存未提交页、确认 quorum、发布可见状态，以及网络超时后的事务归属，仍是 SCAP 的实现工作。**

普通 [`sqlite3_wal_hook`][sqlite-wal-hook]不满足这一集成需求：官方说明该回调发生在提交完成并释放写锁之后；回调返回错误也不会撤销已经发生的提交。因此不能把“hook 中上传 S3 或等待 Raft”当作安全的提交前持久化屏障。

实现前必须核对锁定版本的 Rust trait、C `wal.h` 和实际调用顺序。当前 `PageHeaders::iter()` 源码还可见固定页大小的假设，说明不能仅凭接口参数就承诺所有 SQLite 页大小均可用。首期支持的 page size、编译选项、扩展和导入格式必须由验证结果确定。

### 2.2 `sqld` 可以复用到哪一层

[Admin API 文档][libsql-admin]提供 namespace 创建、删除与 fork 接口；[Docker 文档][libsql-docker]提供 primary / replica 及认证配置；[Hrana 规范][hrana]定义远程客户端交互。

SCAP 可以复用协议与执行层，但以下能力不是“namespace 存在”就自然具备的：租户资源配额、可信的数据库身份映射、按需唤醒、单 writer 调度、故障隔离、持久提交确认与自动恢复。多个 namespace 共处一个进程仍共享内存、CPU 和崩溃故障域。

源码核实时发现 `storage_server_address` / `LIBSQL_STORAGE_SERVER_ADDR` 配置痕迹，但在本次查看的 [main.rs][libsql-main]、[lib.rs][libsql-server-lib] 与依赖中，没有确认到可直接部署的完整共享存储服务及其仲裁、ACK 契约。该配置不作为现成 HA 能力的证据。部分历史设计文档还描述旧的 PostgreSQL wire protocol / mvSQLite 路径，不能替代当前协议和构建验证。

## 3. Node.js 接入：兼容目标要具体

### 3.1 默认异步入口

`@libsql/client` 是 SCAP 的默认候选入口；已有 Drizzle SQLite 项目可评估 `drizzle-orm/libsql`，Prisma SQLite 项目可评估 `@prisma/adapter-libsql`。官方均有对应接入文档：[Drizzle][drizzle]、[Prisma][prisma]。这不表示 PostgreSQL 项目切换到 SQLite 也只需改 adapter。

“业务少改”以实际调用方式为条件：已有异步 repository 层通常比直接使用同步驱动更容易迁移。`@libsql/client` 返回 Promise 与 ResultSet，不能直接替换所有同步 `get()` / `all()` / `run()` 的返回值。事务、整数精度、BLOB、错误类型、连接级设置、扩展和 `ATTACH` 都须纳入兼容范围。

### 3.2 `better-sqlite3` 的兼容候选

[官方 libsql-js][libsql-js]的 npm 包名为 `libsql`，目标是接近 `better-sqlite3` 的 API，支持本地文件和远程 libSQL；另有 `libsql/promise`。基础 CRUD 可以保留较多调用形态，但不承诺 100% drop-in。

[compat.js][libsql-js-compat]中仍有未实现的 UDF、aggregate、table、backup、serialize 接口；普通事务包装也需要单独验证嵌套 savepoint 语义。[Rust binding 源码][libsql-js-native]使用阻塞等待完成同步调用，所以远程读写会占用调用线程。对 Node.js 主线程而言，少改代码与网络等待对事件循环的影响需要一起评估。把数据库放到 worker thread 可以隔离主线程，但线程间接口又会引入新的异步边界。

原生 SQLite + 自定义 VFS 暂列后续兼容路线。`better-sqlite3` 官方允许[定制 SQLite 构建][better-sqlite-build]；这也意味着不能假设替换操作系统的 `libsqlite3` 就能改变所有 Node native addon 的行为。VFS 分发、注册、ABI 和同步 I/O 阻塞都需要额外工程。

## 4. raft-rs：复用 TiKV 共识核心，承担明确的外围职责

根据 [ADR-0006](../adr/0006-raft-rs-consensus-library.md)，首选由 OpenRaft 调整为 [raft-rs][raft-repo]。它采用 Apache-2.0，在 TiKV 中用于共识；库本身只提供共识核心，不能自动带来 TiKV raftstore 的日志、快照、传输和多 Group 调度。

OpenRaft 的异步框架和高层接口能减少初期集成工作，也有 Databend meta-service 等真实采用。SCAP 现在更重视 TiKV 数据复制路径的使用经验，接受额外 driver 工作。详细对照、正式 TiKV v8.5.8 锁文件及 G0 源码候选见 [Raft 选型调查](raft-library-selection.md)。当前不声明候选依赖已在本项目验证。

三组关键集成契约如下：

| 契约 | 官方接口能证明什么 | SCAP 的集成要求 |
| --- | --- | --- |
| 日志与投票持久化 | [RawNode / Ready][raft-raw]区分普通与持久依赖消息，要求按序完成 entries、HardState 与 snapshot | 自研同步 Ready driver 和 RocksDB store；真实落盘后才能 advance_append 或发送对应 persisted_messages |
| 已提交状态应用 | [集成说明][raft-lib]提示 commit index 与 applied 的持久关系；LightReady 仍可能产生提交进度 | 完整处理两批 committed entries；commit 先于或同批覆盖业务、ConfState、dedup、applied，再 advance_apply_to |
| 强一致读与写响应 | [Safe ReadIndex][raft-read]提供请求 context 与读取水位；提案成功不等于业务提交 | 等待持久 apply，绑定远程 SQL 快照；owner fencing、权限与幂等由状态机裁决 |

SCAP 的数据库身份为 `db_id + incarnation + epoch + db_seq` 的组合。`incarnation` 区分删除后重建的数据库实例；`epoch` 区分 writer 归属；`db_seq` 标识该数据库实例中的提交顺序。它们与 cell 的 Raft term / log index 不是同一套编号。状态机必须在应用提交时校验身份、epoch 与前置水位，不能只在请求进入时查一次 etcd lease。

三个副本只能在所声明的故障模型下形成多数派保护；不能承诺同时丢失多数磁盘、区域灾难或实现错误也不丢数据。S3 归档、灾难恢复与单节点切换应分别定义验收范围。

## 5. RocksDB：适合做本地持久层，但要显式配置耐久性

[RocksDB][rocksdb-repo]是嵌入式有序 KV，可选择 Apache-2.0 或 GPLv2 授权路径；SCAP 候选采用 Apache-2.0 路径，Rust binding 及其传递依赖另行锁定核验。

2026-10-29 的正式 native 后端固定 [rust-rocksdb 0.24.0 manifest](https://github.com/rust-rocksdb/rust-rocksdb/blob/v0.24.0/Cargo.toml)，其许可元数据为 Apache-2.0；[librocksdb-sys manifest](https://github.com/rust-rocksdb/rust-rocksdb/blob/v0.24.0/librocksdb-sys/Cargo.toml)固定 `0.17.3+10.4.2`，许可元数据为 `MIT/Apache-2.0/BSD-3-Clause`。完整依赖由根 Cargo.lock 记录，关闭默认特性，仅开启 bindgen-runtime，并使用 bundled static native；这不是 TiKV 定制的 binding/native 组合。实际职责与测试分层见 [ADR-0009](../adr/0009-serial-driver-and-native-backend.md)，不据此替本仓库选择自身许可证。

[官方基础操作文档][rocksdb-basic]给出 WriteBatch 的原子更新语义；[WAL 文档][rocksdb-wal]说明默认 `WriteOptions.sync = false`，`sync = true` 才在 WAL 同步到持久介质后返回。**原子性与持久性是两项不同条件。**

SCAP 首版要求启用 RocksDB WAL，并对 Raft 所需的持久写使用明确的同步完成边界。未来可增加跨 cell group commit，但在对应有序前缀真实落盘前不得报告 Ready 持久完成。不能先关闭 RocksDB WAL，再用“上层已经是 Raft”解释本地恢复缺口。

RocksDB 中的 log、状态机、去重记录、manifest 指针与回收水位需要明确的 key/column family 设计。更新相关状态时使用同一个数据库实例内的原子批次；跨实例的独立写入不具有这种原子性。主要待测风险是多租户写放大、compaction 尾延迟、磁盘满、后台恢复以及大事务造成的复制阻塞，而不只是平均写入吞吐。

## 6. Bottomless 与 Litestream：备份组件，不是默认 HA 提交路径

| 项目 | 正常模式 | 适合借鉴 / 复用 | 不能直接推导的保证 |
| --- | --- | --- | --- |
| [Bottomless][bottomless] | libSQL virtual WAL；已提交页面异步上传到 S3，可恢复 | libSQL 集成方式、快照/WAL 增量与恢复代码 | 每次 COMMIT 都等待远端 quorum、writer fencing、无损自动 failover |
| [Litestream][litestream-how] | 独立进程读取原生 SQLite WAL，转成 LTX 并异步复制 | 连续备份、对象布局、压缩合并、恢复工具和运维体验 | 本地提交已同步到远端、选主与旧 writer 隔离 |
| [Litestream writable VFS][litestream-vfs] | 本地写 buffer 加周期上传，单 writer，远端最终一致 | 按需页读取与远端数据库访问实验 | 分布式锁、强一致生产 HA |

[Litestream 官方 caveats][litestream-tips]明确其普通复制存在数据丢失窗口。较短周期只是缩短正常条件下的滞后，不构成严格 RPO 上限。

新版 [`litestream sync -wait`][litestream-sync]能等待某次远端复制完成，可作为计划停机前的显式上传屏障，但不会自动改变 SQLite COMMIT，也没有补齐 failover。SCAP 的严格提交路径使用共享 cell；这些备份机制不能同时充当另一套独立提交权威。

## 7. S3 与 etcd 的边界

[AWS S3 文档][s3-consistency]说明单对象更新与读后写一致性；跨对象原子更新需要应用自行设计。SCAP 因而采用不可变对象与显式 manifest 发布协议。其他 S3-compatible 服务不能只凭 API 名称继承 AWS 的一致性、条件写或耐久保证，必须验证所用操作。

[etcd API 保证][etcd-guarantees]支持一致性 KV 与协调，但 watch 本身不提供线性一致读，并可能延迟。SCAP 将 etcd 用作意图、配置和目录：路由缓存可以暂时落后，cell 必须拒绝旧 incarnation / epoch 的提交。数据库可提交的 owner 与最新提交头以 cell 状态机为权威；etcd 的 revision 不能直接冒充该数据库的提交 fencing token。

## 8. 进入实现前的关闭条件

以下是整体验证门槛；当前仅有 [G0 记录](../engineering/g0-evidence.md)中的局部实现证据，不能视为整体验收通过：

1. 锁定 libSQL、Hrana、SDK 与 raft-rs 版本，建立可复现构建；通过目标 Node.js、ORM 和 SQLite 特性兼容样例。
2. 用最小 virtual WAL 原型证明：quorum 确认前，其他连接不可观察到新提交；提交失败、savepoint、rollback 与 checkpoint 不破坏状态。
3. 对 RocksDB adapter 验证 crash、磁盘同步错误、投票持久化、日志截断与 snapshot 安装，确认不会报告虚假的持久完成。
4. 对旧 writer、drop/recreate、超时后重试和读屏障做故障注入；检查数据库身份与去重记录。
5. 验证对象已上传但 manifest 未发布、manifest 已提交但响应丢失、S3 暂时不可用等情况下的恢复与回收。
6. 实测共享 cell 的隔离、恢复时间、RocksDB 放大和对象请求成本，再决定扩容单元与生产目标。

## 官方资料索引

非 Raft 资料沿用 2026-10-27 查询；Raft 资料于 2026-10-28 复核。`main` 与 `latest` 链接用于追溯来源，实际实现必须换成锁定的 release / commit，不将这些浮动链接当成依赖锁文件。

- [libSQL README][libsql-readme]；[virtual WAL 扩展说明][libsql-extensions]；[Rust Wal/WalManager 源码][libsql-wal]。
- [sqld Admin API][libsql-admin]；[Docker 部署][libsql-docker]；[Hrana 3 规范][hrana]；[main.rs][libsql-main]；[lib.rs][libsql-server-lib]。
- [Turso TS SDK 对照][turso-ts]；[libsql-js README][libsql-js]；[compat.js][libsql-js-compat]；[Rust binding][libsql-js-native]；[Drizzle SQLite][drizzle]；[Prisma SQLite][prisma]。
- [SQLite WAL hook][sqlite-wal-hook]；[better-sqlite3 定制构建][better-sqlite-build]。
- [raft-rs 仓库][raft-repo]；[RawNode][raft-raw]；[集成说明][raft-lib]；[读取模式][raft-read]；OpenRaft 对照来源见 [专项调查](raft-library-selection.md)。
- [RocksDB 仓库及许可说明][rocksdb-repo]；[WriteBatch 与同步写][rocksdb-basic]；[WAL 同步][rocksdb-wal]。
- [Bottomless][bottomless]；[Litestream 工作原理][litestream-how]；[复制窗口][litestream-tips]；[sync -wait][litestream-sync]；[可写 VFS][litestream-vfs]。
- [S3 一致性][s3-consistency]；[etcd API 保证][etcd-guarantees]。

[libsql-readme]: https://github.com/tursodatabase/libsql/blob/main/README.md
[libsql-extensions]: https://github.com/tursodatabase/libsql/blob/main/libsql-sqlite3/doc/libsql_extensions.md
[libsql-wal]: https://github.com/tursodatabase/libsql/blob/main/libsql-sys/src/wal/mod.rs
[libsql-admin]: https://github.com/tursodatabase/libsql/blob/main/docs/ADMIN_API.md
[libsql-docker]: https://github.com/tursodatabase/libsql/blob/main/docs/DOCKER.md
[hrana]: https://github.com/tursodatabase/libsql/blob/main/docs/HRANA_3_SPEC.md
[libsql-main]: https://github.com/tursodatabase/libsql/blob/main/libsql-server/src/main.rs
[libsql-server-lib]: https://github.com/tursodatabase/libsql/blob/main/libsql-server/src/lib.rs
[turso-ts]: https://docs.turso.tech/sdk/ts/reference
[libsql-js]: https://github.com/tursodatabase/libsql-js
[libsql-js-compat]: https://github.com/tursodatabase/libsql-js/blob/main/compat.js
[libsql-js-native]: https://github.com/tursodatabase/libsql-js/blob/main/src/lib.rs
[drizzle]: https://orm.drizzle.team/docs/sqlite/get-started-sqlite
[prisma]: https://www.prisma.io/docs/orm/v7/core-concepts/supported-databases/sqlite
[sqlite-wal-hook]: https://sqlite.org/c3ref/wal_hook.html
[better-sqlite-build]: https://github.com/WiseLibs/better-sqlite3/blob/master/docs/compilation.md
[raft-repo]: https://github.com/tikv/raft-rs
[raft-raw]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/raw_node.rs
[raft-lib]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/lib.rs
[raft-read]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/read_only.rs
[rocksdb-repo]: https://github.com/facebook/rocksdb
[rocksdb-basic]: https://github.com/facebook/rocksdb/wiki/Basic-Operations
[rocksdb-wal]: https://github.com/facebook/rocksdb/wiki/WAL-Performance
[bottomless]: https://github.com/tursodatabase/libsql/blob/main/bottomless/README.md
[litestream-how]: https://litestream.io/how-it-works/
[litestream-tips]: https://litestream.io/tips/#data-loss-window
[litestream-sync]: https://litestream.io/reference/sync/
[litestream-vfs]: https://litestream.io/guides/vfs-write-mode/
[s3-consistency]: https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html#ConsistencyModel
[etcd-guarantees]: https://etcd.io/docs/v3.6/learning/api_guarantees/
