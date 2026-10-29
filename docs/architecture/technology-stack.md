# 技术栈与集成契约

初始查询日期：2026-10-27；Raft 选型复核：2026-10-28；TiKV 技术栈复核：2026-10-29。状态：首期候选方案；本文件定义拟实现的职责与正确性边界，不代表组件已集成或完成生产验证。

SCAP 首期只实现 SQLite 平台。目标是让 Node.js 应用通过现有 libSQL SDK 或兼容入口访问独立数据库，并将执行计算、提交日志与冷数据分离。详细的开源证据与替代方案见 [组件调研](../research/components.md)。

## 1. 栈总览

| 模块 | 技术候选 | 主要职责 | 采用方式 |
| --- | --- | --- | --- |
| 外部 SQL 入口 | Rust、Tokio、Axum/Tower、Hrana | TLS、认证、授权、路由、限额、会话与超时 | 复用 sqld/Hrana 实现，补平台入口 |
| SQL worker | Rust、libSQL SQLite C 分支、`libsql-sys` | 执行 SQL、事务管理、本地页缓存、恢复与重放 | 锁定引擎分支，集成自定义 virtual WAL |
| durable cell | Rust、TiKV raft-rs、Tonic、RocksDB | 三副本共识、提交权威、writer fencing、每库提交头和幂等结果 | 自研 driver、持久 store 与状态机 |
| 内部 RPC | Tonic、外层 Prost、内层 Raft protobuf-codec、mTLS/rustls 候选 | worker/cell、复制、恢复、控制面交互 | 自研版本化服务定义、编码边界与错误模型 |
| archive / restore | Rust、S3 客户端 SDK | 生成不可变对象、发布 manifest、验证恢复、回收对象 | 自研流程；复用成熟对象 SDK |
| control plane | Rust、Axum/Tonic、etcd | 数据库目录、配置、调度意图、服务发现、生命周期协调 | 自研控制器；etcd 提供一致性元数据 |
| Node.js SDK | TypeScript、`@libsql/client`；可选 `libsql` | 异步 SQL 默认入口、存量同步 API 兼容 | 优先采用已有客户端，薄封装必要平台能力 |
| 可观测性 | `tracing`、Prometheus、OpenTelemetry/OTLP；raft-rs slog 边界适配 | 服务指标、请求链路与故障定位 | 采用生态组件；可靠审计另立持久合同 |
| 配置与故障验证 | Serde/TOML、fail-rs 候选 | 类型化配置、生效记录、确定性注入 | 自研范围校验；真实故障证据独立报告 |

一个 cell 是一个 Raft 复制组，不等于一台机器，也不等于一个客户数据库。初期一个 cell 有三个持久 voting members，多个租户的小数据库共享它。计算 worker 数量随活跃库和负载变化，不为每库保留独立数据库进程或独立 Raft 集群。`Suspended` 先释放 SQL 执行资源与无引用的执行缓存，cell 仍可靠保存必要的 committed tail；达到 `Cold` 还须完成归档并满足持久热数据回收条件。二者对应同一权威 lifecycle `SUSPENDED`，不能把计算休眠等同于所有持久数据已卸载。具体规则见 [存储生命周期](storage-lifecycle.md)。

这些都是本项目的设计选择。模块之间的可靠性契约必须实现并验证，不能由选用了 Rust、Raft 或 S3 自动获得。

依据 [ADR-0006](../adr/0006-raft-rs-consensus-library.md)，共识首选由 OpenRaft 调整为 `tikv/raft-rs`（crate `raft`），重视其在 TiKV 数据复制中的使用经验。OpenRaft 的高层异步接口仍有工程价值，作为替代候选保留；比较和正式 TiKV 发布对应的源码候选见 [选型调查](../research/raft-library-selection.md)。正式 `scap-raft-store` 实现 `Storage`，`scap-raft-driver` 管理真实 RawNode，`scap-raft-rocks` 提供同步 native 后端；三者已在独立三进程故障合同中组合验证。RPC 目前是单独的 codec/transport 实验，生产传输接合、完整业务 cell 与 SQL 服务尚未完成。

[ADR-0007](../adr/0007-tikv-stack-and-rpc-boundaries.md)基于 TiKV 正式版本的 manifest、lock 与调用路径核对，保留本项目 Tokio/Axum/Tonic 方向。TiKV 主 RPC 实际使用 grpcio、状态 HTTP 使用 Hyper；其云 SDK 中出现 Tonic 不等于主服务采用 Tonic。具体组件、fork、native 版本与取舍见 [技术栈审计](../research/tikv-rust-stack.md)和[机器可读决策](../../contracts/technology-decisions.json)，不整体复制 TiKV 依赖树。

## 2. Runtime 与进程模型

[Tokio][tokio-blocking]处理异步 I/O，[Axum][axum]提供 HTTP 路由与 Tower 中间件，[Tonic][tonic]提供 gRPC。选型目的是复用同一 Rust 异步生态，同时把真正的数据库阻塞工作隔离出来。

SQLite C 调用、RocksDB 同步写、压缩和大对象处理不得长时间占用负责心跳、选举和网络的 runtime worker。SQL 连接放在有界执行池或专用 worker 线程中，由队列控制并发；同一数据库的写入按单 writer 规则调度。RocksDB 同步 I/O 也要通过有序、有限并发的存储执行路径完成。

`spawn_blocking` 只是可用机制，不是取消或资源隔离方案。Tokio 官方说明已开始的 blocking task 不能通过普通 abort 停止。SQL 超时应配合引擎 interrupt/progress 控制，RPC 取消必须区分“尚未执行”“已执行但未确认”“已提交但响应丢失”；不得把请求连接断开解释成数据库事务必然回滚。

进程隔离按租户等级设计：共享进程适合平台受控 SQL，独立 worker/process 用于更强的资源和故障隔离。native SQL extension 与应用自定义代码不开放给普通租户任意加载。

队列同时按数量和字节限额；Raft 控制流、SQL、持久化、归档与管理接口有各自资源预算。独立线程或 HTTP/2 stream 不自动证明隔离，必须验证过载和大流量下的心跳、管理与租户尾延迟。编码、mTLS 身份、deadline、健康检查、日志桥接与配置的完整约束见 [运行与 RPC 契约](../engineering/runtime-and-rpc.md)。

## 3. SQL 引擎、协议与客户端

### 3.1 引擎与协议边界

首期选 [libSQL SQLite C 分支][libsql]，不是 Rust Turso rewrite。引擎的页面格式、WAL 语义、编译选项和 extension 集合固定在经过验证的构建中；引擎升级作为存储兼容性变更管理。

优先复用 `sqld` 中 [Hrana][hrana] 的请求/响应与事务会话处理。可以先 fork 并隔离平台修改，也可以在完成接口验证后抽取模块；不假设所有 server 内部模块都是稳定的公共库 API。首期只声明兼容已经通过测试的协议特性，尤其是 interactive transaction、batch、statement 参数、整数和 BLOB 返回值。

锁定 libSQL 的 sqld 声明旧一代 Axum/Tonic/Prost 和精确 Tokio 依赖，与平台候选并非已统一的依赖树。G0 必须验证集中 fork、必要的协议抽取或独立构建/进程边界，并重跑 Hrana/SDK 契约；新 RPC 实验通过不等于完整 server 已能合编。固定源码和版本证据见 [兼容性调查](../research/tikv-rust-stack.md)。

网关对外提供稳定数据库地址与凭据，对内映射当前 `db_id`、`incarnation`、cell 和 worker。Hrana 的会话不能在任意 worker 间逐语句轮转；故障切换可以使未完成事务失效，客户端需要按明确错误处理，不承诺跨节点延续原生 SQLite connection 内存状态。

### 3.2 Node.js 选择

默认使用 [`@libsql/client`][turso-ts] 的远程异步模式。Drizzle / Prisma 应通过相应官方 adapter 接入。首期不默认启用 embedded replica，避免把客户端本地库、同步时机和陈旧读控制引入云服务的基本契约。

已有大量 `better-sqlite3` 同步调用的项目，可以单独验证 [`libsql`][libsql-js] npm 包。其 [兼容层][libsql-js-compat]与 [native 实现][libsql-js-native]说明它支持类似调用形态和远程连接，但同步接口会等待网络，部分 API 尚缺失。不能用“SQLite 兼容”替代应用的事务/UDF/扩展与事件循环测试。

SCAP 可增加薄 TypeScript 包提供配置、错误分类、显式请求标识和管理 API，但不自造 SQL 方言。原生 SQLite driver 的 VFS 路线留作后续兼容工作，不列入第一版默认交付范围。

## 4. Virtual WAL 与分布式提交的接合

[libSQL Rust virtual WAL 接口][libsql-wal]为首选集成点。SCAP 需要在 `insert_frames(..., is_commit, ...)` 所在的提交路径处理事务页，同时覆盖 rollback、savepoint、checkpoint 和恢复；它不是一个“发送网络请求”的附加 callback。

最低正确性要求如下，均属于待实现契约：

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

SCAP 的 RocksDB adapter 与 Tonic transport 必须自行实现，不能把内存 store 或网络入队当作持久副本。鉴权、cell/node 身份、连接限额、重试与消息大小也不由共识库自动提供。

首版采用 **持久状态机**。业务变更、完整 `ConfState`、最后应用位置与请求去重记录原子保存；durable commit 必须先于或同批覆盖 durable applied。[上游集成说明][raft-lib]特别指出，条目已持久并 committed，不代表 commit index 已在应用前落盘。禁止重启时用 `max(commit, applied)` 掩盖不一致。完整实现顺序与门禁见 [raft-rs 集成契约](../engineering/raft-rs-integration.md)。

### 5.3 RocksDB 的初始约束

[RocksDB WriteBatch][rocksdb-basic]提供同一实例内的原子多键更新；[同步 WAL 写][rocksdb-wal]决定何时可声称落盘。初始实现保持 WAL 开启，持久写明确使用同步完成语义。group commit 可以优化多个请求，但相关 Raft 回调必须等该批次完成真实同步。

RocksDB 按 cell 副本或有界存储分片组织，不为每个租户创建一个 RocksDB 实例，也不为每个数据库创建无限增长的 column family。具体采用“每 cell 独立实例”还是“一个节点合并有限 cell”，由故障隔离、compaction 和原子性验证决定；跨实例写入不得被当成单个原子 batch。

至少需要区分日志记录、投票/日志元数据、每库状态、幂等结果、归档发布与 GC 水位。恢复时校验 checksum、last-applied、日志范围、实例身份和快照清单。磁盘满、WAL 写错误或同步错误必须使相应副本停止报告成功，不能静默退化成内存存储。

RocksDB 的 WAL 与 SCAP 复制的数据库事务日志是两层不同日志。前者保护一个副本的本地数据，后者负责跨副本共识；不能因为后者存在就省略前者的恢复设计。

TiKV 使用自己的 rust-rocksdb fork 和固定 native 子模块，不等于任意 crates.io 同名 binding。本项目在真实 sync、WriteBatch、checkpoint、恢复与构建验证后锁定 binding/native/features；暂不同时引入独立 Raft Engine，以免未经验证地增加跨引擎恢复组合。对应上游事实见 [技术栈审计](../research/tikv-rust-stack.md)。

G0 已固定 rust-rocksdb `0.24.0` / native RocksDB `10.4.2`。正式 `scap-raft-rocks` 以 WAL 开启、sync WriteBatch 原子替换完整有界镜像，`scap-raft-driver` 管理真实 RawNode 的串行顺序；这不是 TiKV 的 fork 组合。格式、资源限制和写放大见 [持久 store 契约](../engineering/durable-store.md)，运行与恢复边界见 [driver 合同](../engineering/serial-driver.md)和[三进程实验](../../experiments/raft-cluster/README.md)。生产传输与完整业务状态机仍需实现。

### 5.4 读屏障与 SDK 重试

首版采用 [Safe ReadIndex][raft-read]：`read_index` 使用唯一请求 context，driver 匹配 Ready 返回的 `ReadState`，等待持久状态机应用到该水位。SQL 查询发生在独立 worker，故仍需从同一状态机视图得到数据库的有效身份、权限、owner 与提交头，再让 worker 固定精确 revision 的 SQL 快照。只检查“我是 leader”、check_quorum 或 etcd 缓存不够。

标准 SDK 的网络重试不能变成无条件重放 SQL。共识日志不自动提供业务请求幂等；SCAP 状态机记录请求身份和原始结果，区分明确未执行、明确已提交和结果未知。没有可靠请求标识时，不自动重试结果未知的非幂等写入。

## 6. S3 冷存储与 etcd 控制面

### 6.1 S3

对象存储用于不可变快照、增量段及 manifest。采用标准 S3 客户端，验证 checksum、范围读取、条件写、对象可见性、超时和重试语义。AWS 的[单对象一致性][s3]不等于跨对象事务，也不能自动推广到所有兼容服务。

归档流程先使引用的数据对象完整可读，再通过 cell 状态机发布归档水位和 manifest 身份；只有满足恢复与保留策略后才回收已覆盖日志。不能把“上传任务已经排队”或“PUT 请求已发送”当成可回收条件。S3 暂时不可用时，应保留未归档的持久日志并施加背压。

数据库对象按 `db_id/incarnation` 等不可混淆的身份组织。fork、备份保留、删除标记和引用回收由显式元数据管理，不能靠 bucket listing 猜测活跃数据库。对象版本和保留策略服从运维文档；本文件不规定具体生命周期参数。

### 6.2 etcd

etcd 保存数据库目录、客户配置、容量与调度意图、节点注册和服务发现等控制面状态。[etcd watch][etcd]可以延迟且不是线性一致读，因此路由缓存仅为查询加速，不能决定一个旧 writer 是否还能提交。

有效 owner epoch、数据库提交头和影响日志安全的归档发布由 cell 状态机管理。控制器发起变更后，以 cell 的确认状态更新目录；中间失败靠幂等 reconciliation 收敛。不能将两个独立共识系统的写入当作一个原子事务。

路由缓存与权限缓存分别管理。权限正向缓存必须受运维文档规定的固定上限以及 token 到期时间中较早者约束，不通过命中滑动续期；目录命中也不能免除授权校验。数据提交 fencing 仍由 cell 完成。

## 7. 可观测性与诊断

候选采用 Prometheus 指标、Rust `tracing` 结构化日志和 OpenTelemetry/OTLP 链路。重点观察用户体验与持久性边界，而不只观察容器是否存活。

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

当前四个正式模块均达到精确 100% 单元覆盖，独立 WAL、RPC、RawNode/RocksDB 恢复和三进程故障合同已运行，见 [G0 证据](../engineering/g0-evidence.md)。完整业务 cell、SQL/RPC 接合和规模化验证尚未完成。以下结果决定是否继续使用候选：

- libSQL virtual WAL：提交可见性、事务撤销与恢复都满足要求，目标 SDK 和导入格式验证通过。
- raft-rs/RocksDB：真实 Ready/LightReady 契约、持久 commit/applied、掉电/进程崩溃/磁盘故障和快照恢复通过，未出现虚假持久 ACK。
- cell：旧 writer、drop/recreate、结果未知重试、只读屏障和成员变更的安全性得到故障注入证据。
- S3：manifest 与数据对象的发布/回收顺序可恢复，兼容服务通过所需操作验证。
- 运行时：长查询、冷启动和 compaction 不造成无界线程、内存或跨租户饥饿。
- RPC/依赖接合：原始消息与版本边界、生产 mTLS、背压/取消，以及所选 sqld/平台组合的真实 SDK 行为通过验证。

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
