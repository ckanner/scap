# 技术栈与集成契约

初始查询日期：2026-10-27；Raft 选型复核：2026-10-28；TiKV 技术栈复核：2026-10-29；正式 mTLS 运行层更新：2026-11-01；SQL/SDK/强读及冷生命周期装配：2026-11-02。状态：正式有界服务已可部署，完整平台与生产性能仍有未通过门禁。当前模块、固定依赖和启动方式见 [SQLite 服务实现](../engineering/sqlite-service.md)。

SCAP 首期只实现 SQLite 平台。目标是让 Node.js 应用通过现有 libSQL SDK 或兼容入口访问独立数据库，并将执行计算、提交日志与冷数据分离。详细的开源证据与替代方案见 [组件调研](../research/components.md)。

## 1. 栈总览

| 模块 | 技术选择或方向 | 主要职责 | 采用方式与状态 |
| --- | --- | --- | --- |
| 外部 SQL 入口 | Rust 1.90.0、Tokio 1.50.0、Axum 0.8.9、Hrana HTTP v2 子集 | 凭据、数据库映射、限额、绝对 deadline 与完整响应 | 正式 scap-service/scap-server；默认 loopback，非 loopback 需显式外部 TLS 代理配置；没有完整 sqld 会话 |
| SQL worker | Rust、libSQL SQLite C 分支、`libsql-sys` | 执行 SQL、事务管理、本地页缓存、恢复与重放 | 锁定引擎分支，集成自定义 virtual WAL |
| durable cell | Rust、TiKV raft-rs、Tonic、RocksDB | 三副本共识、提交权威、writer fencing、每库提交头和幂等结果 | 正式 driver/store/runtime；已含有界 Suspend/Publish/Prune/Hydrate，迁移/删除/GC planned |
| Raft peer RPC | Tokio 1.50.0、Tonic 0.14.6、Prost 0.14.3、raft protobuf-codec、mTLS/tls-ring | 固定成员复制、节点/cell 授权、有界准入与反馈 | 正式 wire/transport/runtime；真实三进程网络契约独立验证 |
| 内部业务调用 | Mailbox、CellPort、EngineFactory、Objects 窄端口 | SQL gate、同 cell 访问、owner 恢复与 S3 | 正式同进程装配；跨进程业务 gRPC 和独立 controller planned |
| archive / restore | Rust、object_store 0.14.2、reqwest 0.13.2、rustls/ring | 条件 PUT、HEAD/GET、完整 manifest、发布/Prune/hydrate | 正式 scap-archive 与有界后台 Jobs；不使用 GC 或 bucket listing 恢复 |
| control plane | 当前 JSON 静态配置；后续 Rust、Axum/Tonic、etcd | 数据库目录、容量调度、配置与生命周期协调 | 固定三节点、最多 32 库；leader 自动 owner 恢复和 idle 维护已实现；动态目录/etcd planned |
| Node.js SDK | TypeScript、Node.js 24、`@libsql/client` 0.18.0 | execute/batch、独立 query、请求身份与结果查证 | 正式 sdk/node；完整 ORM、同步 libsql 与原生 SQLite driver 兼容仍待验证 |
| 可观测性 | 当前 ready/live 和受鉴权有限 status；后续 tracing/Prometheus/OTLP | 服务与单库状态、指标、链路及故障定位 | 基本入口已实现，生产观测与可靠审计平台 planned |
| 配置与故障验证 | 显式版本 JSON、固定依赖锁、真实进程/TCP/S3 故障夹具 | 输入范围校验、准入和独立故障验证 | 正式配置校验与独立实验；TOML/fail-rs 为后续候选，不是当前依赖 |

一个 cell 是一个 Raft 复制组，不等于一台机器，也不等于一个客户数据库。初期一个 cell 有三个持久 voting members，多个租户的小数据库共享它。计算 worker 数量随活跃库和负载变化，不为每库保留独立数据库进程或独立 Raft 集群。`Suspended` 先释放 SQL 执行资源与无引用的执行缓存，cell 仍可靠保存必要的 committed tail；达到 `Cold` 还须完成归档并满足持久热数据回收条件。二者对应同一权威 lifecycle `SUSPENDED`，不能把计算休眠等同于所有持久数据已卸载。具体规则见 [存储生命周期](storage-lifecycle.md)。

表中同时列出正式模块与待实现方向。模块之间的可靠性契约必须分别实现并验证，不能由选用了 Rust、Raft 或 S3 自动获得。

依据 [ADR-0006](../adr/0006-raft-rs-consensus-library.md)，共识采用 `tikv/raft-rs`（crate `raft`），重视其在 TiKV 数据复制中的使用经验；OpenRaft 保留为研究对照，没有集成运行时。正式 `scap-raft-store` 实现 `Storage`，`scap-raft-driver` 管理真实 RawNode，`scap-raft-rocks` 提供同步 native 后端；wire/transport/runtime 提供固定成员 mTLS、有限队列和自动 tick，见 [ADR-0012](../adr/0012-bounded-raft-network-runtime.md)。[ADR-0014](../adr/0014-sqlite-service-and-cold-lifecycle.md)进一步装配 SQL/SDK、Safe ReadIndex、自动 writer 接管及有限冷生命周期；动态平台和规模验证仍待完成。

[ADR-0007](../adr/0007-tikv-stack-and-rpc-boundaries.md)基于 TiKV 正式版本的 manifest、lock 与调用路径核对，保留本项目 Tokio/Axum/Tonic 方向。TiKV 主 RPC 实际使用 grpcio、状态 HTTP 使用 Hyper；其云 SDK 中出现 Tonic 不等于主服务采用 Tonic。具体组件、fork、native 版本与取舍见 [技术栈审计](../research/tikv-rust-stack.md)和[机器可读决策](../../contracts/technology-decisions.json)，不整体复制 TiKV 依赖树。

## 2. Runtime 与进程模型

[Tokio][tokio-blocking]处理异步 I/O，[Axum][axum]提供 HTTP 路由与 Tower 中间件，[Tonic][tonic]提供 gRPC。选型目的是复用同一 Rust 异步生态，同时把真正的数据库阻塞工作隔离出来。

SQLite C 调用、RocksDB 同步写、压缩和大对象处理不得长时间占用负责心跳、选举和网络的 runtime worker。SQL 连接放在有界执行池或专用 worker 线程中，由队列控制并发；同一数据库的写入按单 writer 规则调度。RocksDB 同步 I/O 也要通过有序、有限并发的存储执行路径完成。

当前每个 daemon 按需为需要执行/恢复的数据库创建独占 SQL lane，活动与退出中的 lane 合计不超过 32；休眠且无排队请求后释放。Raft owner 和 catalogue dispatcher 独立，S3 启用时还有一个受监督的归档线程。前景 cold hydrate 只占用自己的数据库 lane；全局和每库请求/字节配额共同限制资源。节点 supervisor 监视关键线程/任务的异常退出并停止整体准入，停止时取消和 join，不留下 detached owner。native 同步 I/O 不能被异步取消强制中断。

`spawn_blocking` 只是可用机制，不是取消或资源隔离方案。Tokio 官方说明已开始的 blocking task 不能通过普通 abort 停止。SQL 超时应配合引擎 interrupt/progress 控制，RPC 取消必须区分“尚未执行”“已执行但未确认”“已提交但响应丢失”；不得把请求连接断开解释成数据库事务必然回滚。

进程隔离按租户等级设计：共享进程适合平台受控 SQL，独立 worker/process 用于更强的资源和故障隔离。native SQL extension 与应用自定义代码不开放给普通租户任意加载。

队列同时按数量和字节限额；Raft 控制流、SQL、持久化、归档与管理接口有各自资源预算。独立线程或 HTTP/2 stream 不自动证明隔离，必须验证过载和大流量下的心跳、管理与租户尾延迟。编码、mTLS 身份、deadline、健康检查、日志桥接与配置的完整约束见 [运行与 RPC 契约](../engineering/runtime-and-rpc.md)。

当前 peer runtime 使用调用方提供的专用阻塞 owner 线程，每个 peer 的 ordinary/snapshot 各有一个异步 worker，所有发送共享有限实际 payload 预算。每个发送 lane 至多复用一个有龄期上限的 mTLS client；RPC 前后重新验证实际服务端证书链、DNS、日期和当前 pin 授权。排队、必要的握手和发送共享同一原绝对 deadline，失败/取消即丢弃缓存；生产吞吐和 p99 仍需测量。server 的自供 incoming 对 accepted socket 显式设置 NODELAY；全局连接预算在 accept 前预留，RPC 预算在解码前预留。`Received` 只表示进入有限 inbox，消息消费时还要复核权限，不能当作已经交给 driver 或已持久化。详细实现与限制见 [网络运行层](../engineering/raft-network-runtime.md)。

## 3. SQL 引擎、协议与客户端

### 3.1 引擎与协议边界

首期选 [libSQL SQLite C 分支][libsql]，不是 Rust Turso rewrite。引擎的页面格式、WAL 语义、编译选项和 extension 集合固定在经过验证的构建中；引擎升级作为存储兼容性变更管理。

当前复用固定 libSQL C 内核及 virtual WAL 接口；正式 `scap-service` 自行实现 [Hrana][hrana] 的有限 HTTP v2 解析和响应，不嵌入完整 `sqld`。单次 pipeline 只接受已验证的 execute 或原子 batch，支持位置参数、64 位整数、BLOB/NULL 等类型；跨请求会话、interactive transaction、cursor、WebSocket 与 named args 拒绝。

锁定 libSQL 的 sqld 声明旧一代 Axum/Tonic/Prost 和精确 Tokio 依赖，不能与平台依赖树直接等同。当前通过受限协议边界避开完整旧 sqld 合编，并用真实固定 SDK 验证；未来扩展协议仍须单独验证，不能因当前 execute/batch 通过便声称整个 sqld API 兼容。原始依赖证据见 [兼容性调查](../research/tikv-rust-stack.md)。

网关对外提供稳定数据库地址与凭据，对内映射当前 `db_id`、`incarnation`、cell 和 worker。Hrana 的会话不能在任意 worker 间逐语句轮转；故障切换可以使未完成事务失效，客户端需要按明确错误处理，不承诺跨节点延续原生 SQLite connection 内存状态。

### 3.2 Node.js 选择

当前 [`sdk/node`](../../sdk/node/README.md) 固定使用 `@libsql/client` 0.18.0 的远程异步模式，增加候选节点、稳定 request ID、query、lookup/resolveOrCancel 和 status。没有 UNKNOWN 写自动重放。Drizzle / Prisma 的真实查询兼容与 embedded replica 仍未纳入当前支持范围。

已有大量 `better-sqlite3` 同步调用的项目，可以单独验证 [`libsql`][libsql-js] npm 包。其 [兼容层][libsql-js-compat]与 [native 实现][libsql-js-native]说明它支持类似调用形态和远程连接，但同步接口会等待网络，部分 API 尚缺失。不能用“SQLite 兼容”替代应用的事务/UDF/扩展与事件循环测试。

薄 TypeScript 包已实现数据调用与结果查证，不自造 SQL 方言；通用管理 API、同步驱动和原生 SQLite VFS 路线仍为后续兼容工作。

## 4. Virtual WAL 与分布式提交的接合

[libSQL Rust virtual WAL 接口][libsql-wal]为首选集成点。SCAP 需要在 `insert_frames(..., is_commit, ...)` 所在的提交路径处理事务页，同时覆盖 rollback、savepoint、checkpoint 和恢复；它不是一个“发送网络请求”的附加 callback。

最低正确性要求如下。正式有界 adapter 已实现提交前 gate、结果缓冲、完整镜像恢复和独立 SQL 强读，并接入正式服务；并行连接、大事务与更大数据库 profile 仍按门禁推进，见 [引擎合同](../engineering/sqlite-engine.md)及 [服务实现](../engineering/sqlite-service.md)：

1. 未经 cell 接受并持久确认的事务页，只能作为暂存数据存在，不能对其他连接发布为已提交版本。
2. 每次提交包含数据库身份与前置水位，cell 应用时再次校验，拒绝旧 writer、旧数据库实例或不连续写入。
3. 提交确认返回前，满足 cell 的持久多数派条件；本地缓存随后按已确认结果发布。已提交但响应不确定的情况由提交身份查询解决，不能猜测为回滚。
4. checkpoint 只能推进已经确认的提交水位；本地文件不是能绕过 cell 的第二个写入权威。
5. 恢复与页面重放遵守数据库实例、页大小、页校验和以及提交顺序，不在 follower 上重新运行任意业务 SQL。

普通 [`sqlite3_wal_hook`][sqlite-wal-hook]发生在提交和释放写锁之后，不能用于实现第 1 项。集成 PoC 必须证明真实可见性边界；如果 virtual WAL 版本不能满足，就调整引擎适配或局部 fork，而不把缺口下放给 SDK。

页大小、数据库头、VACUUM、DDL、savepoint、大小扩张/截断及异常返回都是此适配层的输入契约。现有接口源码有固定页大小的实现假设，因此首版只支持验证通过的格式；导入其他格式时明确拒绝或走离线转换。

## 5. raft-rs 与 RocksDB 的职责拆分

### 5.1 Cell 的状态机

raft-rs 负责共识过程，SCAP 的 driver 负责驱动和持久化集成，SCAP 的状态机负责数据库规则。候选命令包括 owner 变更、事务提交、归档 manifest 发布、数据库删除与回收确认。它们在同一个 cell 的全序中生效。

正式 `scap-cell` 已实现 `Create / ClaimOwner / ActivateOwner / AuthFence / Commit / ResolveOrCancel` 及 `SuspendDb / PublishArchive / PruneArchive / HydrateArchive`，包含当前权限再检查、原准入记录、业务 fingerprint、物理 digest、原结果与取消 fence。纯 `Application` 不执行 I/O 或 SQL；codec 使用固定 sha2，v2 冷状态写入后不支持旧 binary 降级。当前保留结果和对象，迁移、删除与历史 GC 仍为后续工作，具体见 [cell 合同](../engineering/cell-state-machine.md)及 [ADR-0014](../adr/0014-sqlite-service-and-cold-lifecycle.md)。

数据库的提交身份至少包含：

| 字段 | 用途 | 不可混淆的概念 |
| --- | --- | --- |
| `db_id` | 平台数据库标识 | 客户可修改的显示名称或路径 |
| `incarnation` | 一次数据库生命周期的唯一实例身份 | drop/recreate 后复用旧目录或旧 WAL |
| `epoch` | 当前 writer 归属代次 | etcd lease ID、Raft term |
| `db_seq` | 此数据库实例的提交顺序 | cell 级共享 Raft log index |
| `request_id` / `txn_id` | 识别一次业务请求或事务，关联重试结果 | 不能仅凭相同 SQL 文本去重 |

状态机校验完整身份与期望前序水位后，才改变该库的提交头。控制面分配了 worker 或 etcd lease 尚未过期，都不能替代这个校验。删除后的旧请求和旧缓存不得命中新建实例。

首期不建立跨 cell 分布式事务，也不把多个独立数据库的 COMMIT 包装成一个原生 SQLite 事务。大事务必须有显式大小、缓冲与背压规则，防止一个租户阻塞整个 cell。

### 5.2 Raft 持久化适配必须自研

根据 [RawNode / Ready 契约][raft-raw]与 [Storage 接口][raft-storage]：

- 一个 cell 的 `RawNode` 由串行 driver 驱动。`Storage` 是读取日志和状态的接口，持久写入与完成事件仍由应用组织。
- entries、snapshot 与 `HardState` 按序进入持久存储后，才能发送相应 `persisted_messages` 或推进持久完成。普通 messages 与这些持久依赖消息分开处理。
- 首版采用同步持久 Ready，调用 `advance_append` 后完整处理 `LightReady`，有序持久应用，再调用 `advance_apply_to(durable_applied)`；不提前引入异步 Ready 流水线。
- 空条目、拒绝、去重命中和成员变更均推进真实 applied。vote、日志替换、snapshot 安装与压缩不得形成不可恢复视图。

SCAP 已自行实现正式 RocksDB adapter 与有界 Tonic peer transport；不能把内存 store 或网络入队当作持久副本。cell/node 身份、连接限额、deadline 和消息大小由正式模块承担，不由共识库自动提供。外部 SQL 使用静态数据库 token 绑定并由 cell 每次复核 auth_epoch；动态成员、外部身份源和控制面仍按后续门禁推进。

首版采用 **持久状态机**。业务变更、完整 `ConfState`、最后应用位置与请求去重记录原子保存；durable commit 必须先于或同批覆盖 durable applied。[上游集成说明][raft-lib]特别指出，条目已持久并 committed，不代表 commit index 已在应用前落盘。禁止重启时用 `max(commit, applied)` 掩盖不一致。完整实现顺序与门禁见 [raft-rs 集成契约](../engineering/raft-rs-integration.md)。

### 5.3 RocksDB 的初始约束

[RocksDB WriteBatch][rocksdb-basic]提供同一实例内的原子多键更新；[同步 WAL 写][rocksdb-wal]决定何时可声称落盘。初始实现保持 WAL 开启，持久写明确使用同步完成语义。group commit 可以优化多个请求，但相关 Raft 回调必须等该批次完成真实同步。

RocksDB 按 cell 副本或有界存储分片组织，不为每个租户创建一个 RocksDB 实例，也不为每个数据库创建无限增长的 column family。具体采用“每 cell 独立实例”还是“一个节点合并有限 cell”，由故障隔离、compaction 和原子性验证决定；跨实例写入不得被当成单个原子 batch。

至少需要区分日志记录、投票/日志元数据、每库状态、幂等结果、归档发布与 GC 水位。恢复时校验 checksum、last-applied、日志范围、实例身份和快照清单。磁盘满、WAL 写错误或同步错误必须使相应副本停止报告成功，不能静默退化成内存存储。

RocksDB 的 WAL 与 SCAP 复制的数据库事务日志是两层不同日志。前者保护一个副本的本地数据，后者负责跨副本共识；不能因为后者存在就省略前者的恢复设计。

TiKV 使用自己的 rust-rocksdb fork 和固定 native 子模块，不等于任意 crates.io 同名 binding。本项目在真实 sync、WriteBatch、checkpoint、恢复与构建验证后锁定 binding/native/features；暂不同时引入独立 Raft Engine，以免未经验证地增加跨引擎恢复组合。对应上游事实见 [技术栈审计](../research/tikv-rust-stack.md)。

G0 已固定 rust-rocksdb `0.24.0` / native RocksDB `10.4.2`。正式 `scap-raft-rocks` 以 WAL 开启、sync WriteBatch 原子替换完整有界镜像，`scap-raft-driver` 管理真实 RawNode 的串行顺序；这不是 TiKV 的 fork 组合。格式、资源限制和写放大见 [持久 store 契约](../engineering/durable-store.md)，运行与恢复边界见 [driver 合同](../engineering/serial-driver.md)、[受控三进程实验](../../experiments/raft-cluster/README.md)和[真实 mTLS 网络实验](../../experiments/raft-network/README.md)。当前服务 OpenExisting 对坏/丢 RocksDB 拒绝启动，不自动建空；自动坏盘副本重建、增量持久布局与规模化调度仍需实现。

### 5.4 读屏障与 SDK 重试

首版采用 [Safe ReadIndex][raft-read]：`read_index` 使用唯一请求 context，driver 匹配 Ready 返回的 `ReadState`，等待持久状态机应用到该水位。SQL 查询发生在独立 worker，故仍需从同一状态机视图得到数据库的有效身份、权限、owner 与提交头，再让 worker 固定精确 revision 的 SQL 快照。只检查“我是 leader”、check_quorum 或 etcd 缓存不够。

这些检查已用于 `query` / read batch；正常选举启用 PreVote 和 check_quorum，没有启用租约读。当前强读还会核验保留的完整物理历史，复杂度和尾延迟不能仅凭协议名字推导。

标准 SDK 的网络重试不能变成无条件重放 SQL。共识日志不自动提供业务请求幂等；SCAP 状态机记录请求身份和原始结果，区分明确未执行、明确已提交和结果未知。没有可靠请求标识时，不自动重试结果未知的非幂等写入。

## 6. S3 冷存储与 etcd 控制面

### 6.1 S3

当前对象存储保存不可变完整单库历史和 manifest，`scap-archive` 固定 object_store 0.14.2 与 reqwest 0.13.2，并使用 rustls/ring。显式 endpoint/bucket/region 和指定凭据变量，不采用环境中的隐式云身份链；条件 PUT 后执行 HEAD/GET，验证精确长度和 SHA-256。范围读取、分块 hydrate 和增量对象属于后续扩展。AWS 的[单对象一致性][s3]不等于跨对象事务，也不能自动推广到所有兼容服务。

归档流程先使引用的数据对象完整可读，再通过 cell 状态机发布归档水位和 manifest 身份；只有满足恢复与保留策略后才回收已覆盖日志。不能把“上传任务已经排队”或“PUT 请求已发送”当成可回收条件。S3 暂时不可用时，应保留未归档的持久日志并施加背压。

有界后台 Jobs 保留原始 owner/head/auth/deadline，发布和 Prune 最后仍由状态机 fence。Prune 清物理历史而保留全部结果和权限；全 cell Checkpoint 独立完成共享日志压缩。已发布引用是恢复根，所有对象永久保留，没有 GC。SeaweedFS 的实际接口/重启实验与三 daemon 冷恢复证据分别见 [archive-s3](../../experiments/archive-s3/README.md)和 [service-network](../../experiments/service-network/README.md)。

数据库对象按 `db_id/incarnation` 等不可混淆的身份组织。fork、备份保留、删除标记和引用回收由显式元数据管理，不能靠 bucket listing 猜测活跃数据库。对象版本和保留策略服从运维文档；本文件不规定具体生命周期参数。

### 6.2 etcd

本节为 planned。当前 daemon 不连接 etcd，目录、三个 peer 和凭据绑定由版本化 JSON 配置，owner 的自动接管及闲置维护直接依据 cell 状态。动态配置传播、租户目录与跨 cell 调度尚未实现。

etcd 保存数据库目录、客户配置、容量与调度意图、节点注册和服务发现等控制面状态。[etcd watch][etcd]可以延迟且不是线性一致读，因此路由缓存仅为查询加速，不能决定一个旧 writer 是否还能提交。

有效 owner epoch、数据库提交头和影响日志安全的归档发布由 cell 状态机管理。控制器发起变更后，以 cell 的确认状态更新目录；中间失败靠幂等 reconciliation 收敛。不能将两个独立共识系统的写入当作一个原子事务。

路由缓存与权限缓存分别管理。权限正向缓存必须受运维文档规定的固定上限以及 token 到期时间中较早者约束，不通过命中滑动续期；目录命中也不能免除授权校验。数据提交 fencing 仍由 cell 完成。

## 7. 可观测性与诊断

当前已提供基本 live/ready 和受鉴权有限数据库 status；ready 只用于候选路由，不是 quorum 或单次提交证明。Prometheus 指标、Rust tracing 和 OpenTelemetry/OTLP 链路仍是后续生产观测方案。下面列出目标要求，不能当作已安装的 dashboard 或告警。

| 范围 | 必须能够回答的问题 |
| --- | --- |
| 客户请求 | 请求在哪个阶段等待，冷启动耗时多少，是否为结果未知，是否被限流 |
| 提交路径 | quorum 确认耗时、磁盘同步耗时、等待队列、未完成提交与过期 epoch 拒绝数 |
| 读取路径 | cell 屏障耗时、worker 追赶距离、缓存命中与页读取耗时 |
| 归档与恢复 | 已提交与已归档的距离、S3 失败、manifest 验证、恢复失败与对象缺口 |
| 本地存储 | 磁盘空间、WAL 大小、compaction 积压、stall、写放大和同步错误 |
| 控制面 | 目录与 cell 状态不一致时间、唤醒队列、迁移失败、权限缓存过期 |

遵循 [Prometheus 标签建议][prometheus]，不将无界 `db_id`、用户 ID 或 SQL 文本放进全部指标标签。集群、cell、角色和有限错误类别用于聚合；单库诊断采用受控日志、采样 trace 或按需查询。token、SQL 参数及客户数据不默认写入 telemetry。

[OpenTelemetry Rust][otel-rust]不同信号的稳定状态并不相同，选定 exporter 后锁定版本并测试开销、背压和降级。遥测出口失败不能阻塞数据库提交。

## 8. 依赖、许可证与升级策略

本文件不指定未经验证的最新版本。进入实现时建立依赖清单，记录 upstream commit/tag、Rust toolchain、libSQL/SQLite 编译选项、目标架构、SDK/ORM 版本和数据库格式版本；使用锁文件与可复现构建产物。

需要单独管理四种兼容性：外部 SQL/SDK 契约、内部 RPC、复制日志和磁盘状态格式、S3 对象与 manifest 格式。库能编译不代表这四种格式可以滚动升级。SCAP 的日志位置采用 cell 身份加 term/index，不暴露某个库的内部类型作为长期协议；这种接口隔离不意味着不同 Raft 实现能混群、共享磁盘或热切换。

libSQL 仓库采用 MIT；[raft-rs][raft-repo]采用 Apache-2.0；RocksDB 官方允许在 Apache-2.0 与 GPLv2 中选择。项目初期按拟采用版本逐项记录许可，保留 notices，并单独核验 Rust binding、native 库与传递依赖。引擎或服务的 fork 修改集中在适配层，避免将大范围分叉成本隐藏在普通依赖升级中。

## 9. 候选变成已选定组件的条件

所有正式模块及其 codec、native/async adapter、runtime driver 委托均纳入精确 100% 单元覆盖门禁，Node SDK 也独立检查精确覆盖率。底层合成 payload 的网络实验与真实 SQLite/SDK/S3 服务实验分开，完整计数和构建条件见 [G0 证据](../engineering/g0-evidence.md)。当前有界服务闭环已实现，完整生命周期、规模、跨 AZ 与生产 SLO 仍未整体通过。以下结果决定相关能力是否可进入生产：

- libSQL virtual WAL：提交可见性、事务撤销与恢复都满足要求，目标 SDK 和导入格式验证通过。
- raft-rs/RocksDB：真实 Ready/LightReady 契约、持久 commit/applied、掉电/进程崩溃/磁盘故障和快照恢复通过，未出现虚假持久 ACK。
- cell：旧 writer、drop/recreate、结果未知重试、只读屏障和成员变更的安全性得到故障注入证据。
- S3：manifest 与数据对象的发布/回收顺序可恢复，兼容服务通过所需操作验证。
- 运行时：长查询、冷启动和 compaction 不造成无界线程、内存或跨租户饥饿。
- RPC/依赖接合：保留固定成员 mTLS、SQL gate、HTTP/SDK、版本、准入和取消证据；继续验证证书控制面、扩展 Hrana/ORM 范围及生产部署边界。

Bottomless、Litestream 的常规异步备份不能替代以上测试。若首期无法完成同步提交、fencing 或其他正确性门禁，必须停止 HA 上线，相关产物只作为实验原型；不能用现有架构文档授权降低产品保障。产品范围或可靠性合同的变更需要新的 ADR 和维护者明确决定，再同步修改需求、接口及验收条件。

## 官方来源

初始组件来源于 2026-10-27，Raft 来源于 2026-10-28 复核；2026-10-29 的 TiKV/平台依赖核对采用固定源码。组件细节与完整源码链接见 [组件调研](../research/components.md)和 [TiKV 技术栈审计](../research/tikv-rust-stack.md)。

[tokio-blocking]: https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html
[axum]: https://docs.rs/axum/latest/axum/
[tonic]: https://docs.rs/tonic/latest/tonic/
[libsql]: https://github.com/tursodatabase/libsql/blob/main/README.md
[hrana]: https://github.com/tursodatabase/libsql/blob/main/docs/HRANA_3_SPEC.md
[libsql-wal]: https://github.com/tursodatabase/libsql/blob/main/libsql-sys/src/wal/mod.rs
[sqlite-wal-hook]: https://sqlite.org/c3ref/wal_hook.html
[turso-ts]: https://docs.turso.tech/sdk/ts/reference
[libsql-js]: https://github.com/tursodatabase/libsql-js
[libsql-js-compat]: https://github.com/tursodatabase/libsql-js/blob/main/compat.js
[libsql-js-native]: https://github.com/tursodatabase/libsql-js/blob/main/src/lib.rs
[raft-repo]: https://github.com/tikv/raft-rs
[raft-raw]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/raw_node.rs
[raft-storage]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/storage.rs
[raft-lib]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/lib.rs
[raft-read]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/read_only.rs
[rocksdb-basic]: https://github.com/facebook/rocksdb/wiki/Basic-Operations
[rocksdb-wal]: https://github.com/facebook/rocksdb/wiki/WAL-Performance
[s3]: https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html#ConsistencyModel
[etcd]: https://etcd.io/docs/v3.6/learning/api_guarantees/
[prometheus]: https://prometheus.io/docs/practices/naming/
[otel-rust]: https://opentelemetry.io/docs/languages/rust/

当前新增依赖和集成边界以各正式 Cargo.toml、根 Cargo.lock、[Node 锁文件](../../sdk/node/package-lock.json)及 [ADR-0014](../adr/0014-sqlite-service-and-cold-lifecycle.md)为准；研究中的候选清单不自动成为运行依赖。
