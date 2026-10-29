# TiKV Rust 技术栈审计与 SCAP 采用边界

查询日期：2026-10-29。状态：官方源码审计与候选决策；**引用 TiKV 的生产使用不表示 SCAP 已集成、通过压力测试或取得相同可靠性**。决策见 [ADR-0007](../adr/0007-tikv-stack-and-rpc-boundaries.md)，具体约束见 [运行时与 RPC 契约](../engineering/runtime-and-rpc.md)。

## 1. 基线与结论

本次以 TiKV 正式发布 `v8.5.8` 对应 commit `a1fdd6a59bb9c8a282c15677e1894501a52425cf` 为基线，同时核对 [Cargo.toml][tikv-cargo]、[Cargo.lock][tikv-lock]与实际调用路径。清单中的声明版本、最终解析版本、Git fork 和运行用途分开记录；不能从 lock 中出现一个库就推断主服务使用它。

SCAP 优先复用 raft-rs 共识核心，平台继续验证 **Tokio / Axum / Tower / Tonic / rustls** 组合；对 TiKV 的资源隔离、流控、配置和故障验证方式做针对性借鉴。Prometheus、Serde/TOML、fail-rs 是可直接评估的候选。yatp、专用日志引擎、定制 RocksDB binding 和 allocator 逐项验证后决定，不一起加入依赖树。

这是面向 SCAP 工作负载和维护成本的工程选择，尚无同负载性能比较。TiKV 是长期演进的混合技术栈；成熟的产品经验不能自动覆盖本项目新写的 SQLite 提交、日志发布与恢复路径。

## 2. 实际依赖及处理方式

以下版本为上述 TiKV lock 的核查结果，**不是 SCAP 的新增生产依赖锁**。三类决定分别为“直接候选”“借鉴设计”“暂不引入”；候选只有通过对应 G0 门禁才成为实际采用版本。

| 范围 | TiKV 已核实实现 | SCAP 处理方式 | 理由与待验事项 |
| --- | --- | --- | --- |
| 共识 | raft-rs `ad13f3d…`，crate 标记 0.7.0 | 直接候选 | 已由 ADR-0006 决定；driver、持久 store 与恢复仍待验证 |
| 主 gRPC | grpcio 0.10.4，基于 gRPC C-core | 借鉴设计，暂不引入 grpcio | 平台保留 Tonic；验证流控、取消、背压、TLS 和错误语义 |
| HTTP 运维端口 | Hyper 0.14.28，独立 Tokio runtime | 借鉴设计 | 平台采用 Axum/Tower 候选，借鉴与数据面隔离，不能把存活响应当强读可用 |
| Protobuf | 主路径使用 rust-protobuf 2.8.0 的 PingCAP fork；lock 还含其他版本 | 显式编码边界 | 外层 Prost envelope，内层 raft-rs protobuf-codec 原始字节；不同生成类型不能直接互换 |
| 异步执行 | Tokio 1.50.0，另有历史 timer/executor fork | Tokio 直接候选 | 独立验证所选版本；不复制历史兼容分支 |
| 执行池 | yatp `9fcf102b…`，有自有 FuturePool 包装 | 借鉴设计，暂不引入 yatp | 先实现有界队列、专用阻塞池与公平准入，调度瓶颈出现后比较 |
| 日志 | slog 2.5.2、slog-async 2.6.0、slog-global fork | 借鉴设计 | 平台保留 tracing；raft-rs 的 slog Logger 在适配边界统一输出 |
| 指标 | prometheus 0.13.0、prometheus-static-metric 0.5.1 | Prometheus 直接候选 | 指标与桶边界按 SCAP SLO 定义；不照搬 nightly feature 和无界标签 |
| 配置 | Serde 1.0.228、TOML 0.5.7、自有在线配置模块 | Serde/TOML 直接候选 | 采用类型校验与生效配置记录；不复制巨型配置控制器 |
| 故障注入 | fail 0.5.1、专用 failpoint runner、传输 filters | fail-rs 直接候选 | 用例隔离与真实磁盘/网络证据独立；不继承上游覆盖率结论 |
| KV 持久层 | TiKV rust-rocksdb fork `64a092fd…` | RocksDB 候选，binding 待验 | 同名 crate 不等于相同 native 引擎；需核验 sync、snapshot、构建与恢复 |
| Raft 日志引擎 | raft-engine 0.4.2，`tikv-8.5` 分支 `3d844051…` | 暂不引入 | 先明确单后端恢复，再用日志吞吐、放大与恢复测量决定 |
| AWS S3 | aws-sdk-s3 1.126.0、aws-config 1.8.15 | 官方 SDK 家族直接候选 | 实际 Rust/MSRV、TLS、endpoint、条件写与重试仍须独立验证，不照搬旧 connector |
| 分配器 | tikv-jemallocator 0.6.1，可选其他 allocator | 暂不改变基线 | 根据 Rust/native 内存、碎片与尾延迟测量决定 |
| 工具链 | nightly-2026-01-30 | 保持 SCAP 自己的固定工具链 | 不因参考 TiKV 而整体迁移 nightly 或复制其测试 runner |

完整的候选状态与落地决定记录在 [技术选型清单](../../contracts/technology-decisions.json)。任何“直接候选”都不等于已经完成包版本、编译特性与传递依赖审查。

## 3. RPC / HTTP：读取调用路径，避免误判主服务

### 3.1 TiKV 主服务是 grpcio

[server.rs][tikv-server]使用 `grpcio::ServerBuilder`，注册 `create_tikv` 与 health service；这是真实的主服务构建路径。对应 workspace 选择 grpcio 的 `openssl`、`protobuf-codec` 等 feature，具有 C-core / native 构建边界。gRPC 协议相同不意味着 grpcio 和 Tonic 的 Rust 服务类型、生成代码、运行时或完成语义可以互换。

TiKV lock 同时包含 Tonic 0.14.5、Prost 0.14.3 和 Hyper 1.9.0；[gcp_v2/Cargo.toml][gcp-cargo]的 Google Cloud SDK 引入了另一条依赖链。不能据此写“TiKV 主 RPC 已换成 Tonic”。SCAP 保留 Tonic 是自身平台集成选择，不冒称 TiKV 主路径已经证明此组合。

[raft_client.rs][raft-client]包含有界 `ArrayQueue`、Raft 消息批处理与 flush、连接状态及发送错误处理。值得借鉴的是有限队列、批次/时间边界、对端失败反馈与拥塞下控制消息进度，不是照抄默认大小。RPC 返回、发送入队、Raft durable quorum 与 SQL 成功必须继续区分。

### 3.2 HTTP status server 与数据库就绪不同

[status_server/mod.rs][status-server]单独构建名为 `status-server` 的 Tokio runtime，处理 `/metrics`、`/status`、`/config` 等路径。该提交的 GET `/status` 返回空成功响应，不能据此证明拥有 quorum、有效 owner 或最新 SQL 快照。

SCAP 应保留独立的管理端口/资源预算，区分进程存活、节点恢复完成、cell 可服务及数据库可服务。管理配置接口与 SQL 数据接口分别授权；快照、备份或长 SQL 不得无限占据网络与管理执行资源。Axum/Tower 候选用于组织路由与中间件，其限额、超时和错误转换需要真实验证。

### 3.3 TLS 与对端身份

TiKV 的 [security 模块][security]组织证书与安全连接，主 RPC 采用其 OpenSSL 配置。SCAP 平台优先验证 Tonic/rustls 的 mTLS；加密连接之外，还必须验证证书身份与当前 node/cell 授权匹配，拒绝错组、旧世代或已撤销对端。不能只接受“由同一个 CA 签发”就授予全部数据库能力。

证书轮换、长连接重认证/退出、过期、失败重试和身份到协议字段的绑定均为实现门禁。使用 rustls 不意味着整个产品没有 native 依赖；SQLite、RocksDB 和具体密码提供者分别核查。

## 4. 两个必须关闭的依赖兼容问题

### 4.1 raft-rs 与 Tonic 的消息生成类型

锁定 raft-rs 的 [proto/Cargo.toml][raft-proto]中，`prost-codec` 使用 Prost 0.11，`protobuf-codec` 使用 protobuf 2。Tonic 0.14 配套的 Prost 0.14 生成类型不因此自动兼容。不能把两个版本的 `Message` trait 当作同一个接口，也不能只改 feature 名就宣称接入完成。

G0 验证路线是：外层采用 SCAP 自定义、版本化的 Prost envelope，带 cell/node 身份与有界 `bytes` payload；内层保存 raft-rs protobuf-codec 编码的原始 Raft 消息。路由/转发保留原字节，不做未经定义的解码再编码，防止未知字段或字节身份在中间层改变。接收方仍须解析、检查消息身份与大小，再交给正确的 RawNode。

这种组合只定义 SCAP 内部传输，**不表示兼容 TiKV 的 kvproto 服务或可加入 TiKV 集群**。TiKV 还使用 rust-protobuf fork；SCAP 的具体 protobuf 2 版本和生成工具仍以自己的锁文件为准。loopback RPC 实验、实际测试结果与限制统一记录在 [raft-rpc 实验](../../experiments/raft-rpc/README.md)，本调查不预先标记通过。

### 4.2 复用 sqld 与现代平台栈不能假定已经统一

本项目引擎基线 libSQL `d8bc862d20bedc72945a1da27c8b7045414c0261` 的 [libsql-server/Cargo.toml][sqld-cargo]声明 Axum 0.6.18、Tonic 0.11、Prost 0.12，且固定 Tokio `=1.38`；其 [workspace][libsql-cargo]使用 Hyper 0.14。它与新的平台 RPC 候选属于不同的依赖组合。

G0 必须在以下路径中形成明确且经过测试的决定：维护集中的 sqld fork 并验证升级；抽取协议/会话逻辑并做必要适配；或采用独立构建/进程边界。独立 workspace 只能分开依赖解析，不能自动在同一进程解决 runtime、Rust 类型和 FFI 链接冲突。

不能为了 Cargo 能解析而强行提升 sqld 全部依赖，再沿用原来的 Hrana/Node 兼容结论。引擎提交 gate、interactive transaction、RETURNING、整数/BLOB 与错误行为仍需重新验证。RPC 实验成功也不关闭此项门禁。

## 5. 调度与资源隔离

[read_pool.rs][read-pool]确实使用 yatp，包含任务优先级、资源准入与满容量返回；[FuturePool 包装][future-pool]记录运行任务并限制任务数量。SCAP 应参考这些边界：Tokio 负责异步 I/O，SQLite FFI、同步持久化、压缩与大对象处理进入有界的专用执行路径，Raft 状态仍按 cell 串行驱动。

过载时明确拒绝或按有界期限等待，保留控制消息进度；区分执行中的任务与等待任务，度量队列时间、拒绝率和不同租户尾延迟。`spawn_blocking` 不等于完整取消、配额或公平性。yatp 是否比现有执行方式更合适，需要用真实负载与维护成本比较。

[yatp 固定 README][yatp-readme]描述自适应线程与多级反馈队列，也保留 work in progress 标记。不能仅因 TiKV 使用便把它的所有能力写成 SCAP 默认已验证配置。

## 6. 日志、指标与配置

### 6.1 日志输出采用单一清晰路径

TiKV 的 [logger][logger]实际采用 slog、slog-async、全局桥接与独立日志线程；Cargo.toml 明确其 tracing 主要用于 tracing-active-tree，不能说整个 TiKV 已转向 tracing/OTLP。SCAP 保持 tracing，raft-rs 的 slog Logger 在适配边界接入，避免双重输出、循环桥接和无限日志缓冲。

该 TiKV 源码中的旧注释提到 blocking 与避免丢日志，但实际常量为 `OverflowStrategy::Drop`。应以代码核对策略，不从旧注释推出“日志绝不丢失”。SCAP 必须定义队列满策略、丢弃指标与退出行为；诊断日志不充当数据库提交证明，需要可靠审计时另立合同。

### 6.2 Prometheus 适合直接评估

[metrics 模块][metrics]使用 Prometheus gather/TextEncoder，并监控进程、线程和 allocator。SCAP 采用该生态时按现有性能合同拆分 admission、Ready 等待、fsync、quorum、apply、SQL 发布及恢复阶段；标签基数、采样与直方图桶属于 SCAP 的设计。不能继承 TiKV 的数量、默认桶或 nightly 编译特性。

### 6.3 配置与生效状态可追溯

[config/mod.rs][config]使用 Serde/TOML、未识别键收集、类型验证、关键配置比较与 `last_tikv.toml` 生效记录。SCAP 借鉴明确优先级、范围校验、静态/热更新分类和启动对照；数据目录、身份、磁盘格式等变化不得静默生效。

本地配置不能替代 Raft 中的 owner、auth、membership 或回收权威。部署记录保留实际生效配置、构建标识和格式版本；不复制 TiKV 的整个在线配置框架来满足少量配置需求。

## 7. 持久存储、S3 与 allocator

TiKV 的 [engine_rocks/Cargo.toml][engine-rocks]引用自己的 rust-rocksdb fork；本次锁定 wrapper 为 `64a092fd3b4b1639b42fdc3c5f31edbd05528177`。其 [.gitmodules][rocks-submodules]指向 TiKV RocksDB / Titan，git tree 固定 native RocksDB `0da2397eeb4b40b534ed586c13fb0b795438b2ce`、Titan `b21afb5d7a50f960fbf47a19c103ebc6c43636a3`。README 的旧版本说明不能替代这些实际 pin。

SCAP 先列出 WriteBatch、同步 WAL、checkpoint/snapshot、错误传播与恢复接口，再选 binding。fork、native 子模块、加密/压缩 feature、目标架构与升级格式必须一起验证。当前保留 RocksDB 后端候选；Raft Engine 是独立日志引擎，不是共识库，也不自动解决跨引擎状态恢复。

TiKV 的 [AWS 模块][aws-cargo]固定官方 AWS SDK，实际 [s3.rs][aws-s3]构建 `aws_sdk_s3::Client`，使用 Smithy 的 Hyper 0.14 connector；其中关于 rusoto 的旧注释不代表仍以 rusoto 为 S3 实现。SCAP 可评估官方 SDK，但需独立核验 MSRV、TLS/connector、凭据、endpoint、范围读、checksum、条件写与超时结果。S3-compatible API 名称不能继承具体供应商的一致性保证。

[Makefile][makefile]默认构建路径选择 jemalloc，允许 system/tcmalloc/mimalloc/snmalloc；[tikv_alloc][allocator]还受平台与 feature 控制。不能说任何 Cargo 构建都必然使用 jemalloc。SCAP 依据 Rust 与 native 分配、RSS、碎片和尾延迟测量选择，并保持测试与部署的 allocator 一致。

## 8. 测试资产与 100% 单元覆盖率

TiKV 的 [异步 I/O 故障测试][async-io-test]实际暂停持久化并检查副本行为；[transport_simulate][transport-test]注入丢包、延迟和隔离。这些比只列出 fail-rs 包名更值得参考。其部分测试覆盖异步持久化/应用优化，SCAP 首版仍按已经确定的同步 Ready 契约实现，不能顺带开启这些优化。

[failpoint runner][failpoint-runner]使用 custom_test_frameworks 等 nightly 特性，TiKV [工具链][toolchain]也锁定 nightly。SCAP 可复用 fail-rs 能力而不移植整套 runner；用例间清理注入状态，实际代码路径与测试配置保持可审计。第一方注入封装和错误分支按本项目分类进入覆盖率，不能为了数字将产品逻辑放进研究目录。

第一方 driver、HTTP/RPC adapter、配置、鉴权、序列化、资源控制、持久完成与恢复继续遵守 [100% 单元覆盖率合同](../engineering/testability-and-coverage.md)。真实网络、进程、磁盘和断电测试单独报告；TiKV 的测试、上游覆盖率或 SCAP loopback 演示都不能替代分布式正确性和性能验收。

## 9. 候选采用与升级记录

每项进入实际实现的组件至少记录：上游仓库、release 与完整 commit、最终 lock 解析版本、fork/patch、native 子模块、features、工具链/MSRV、目标平台、codegen 与 protoc 版本、许可证及 notices、必要回归场景。生成代码也记录来源和生成命令；手写业务逻辑不能被“生成目录”排除覆盖率。

在升级时分别检查 Rust 类型兼容、RPC 消息兼容、日志/磁盘格式和对象格式；semver 或编译成功不能证明可以滚动升级。先确定内部服务/库边界，再控制版本数量；不同时保留两套生产 RPC 实现作为未经证明的“随时替换”能力。

本次调查的出口是明确候选与风险，并由 [运行时/RPC 门禁](../engineering/runtime-and-rpc.md)形成可复核证据。现有 RPO、RTO、容量和性能目标保持；实际结果以 [G0 记录](../engineering/g0-evidence.md)及具体实验 README 为准。

## 官方来源

除单独标明的项目外，链接均固定到本次 TiKV 正式发布源码；它们说明上游行为，不代表 SCAP 已具备该行为。

[tikv-cargo]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/Cargo.toml
[tikv-lock]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/Cargo.lock
[tikv-server]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/src/server/server.rs
[status-server]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/src/server/status_server/mod.rs
[raft-client]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/src/server/raft_client.rs
[security]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/components/security/src/lib.rs
[gcp-cargo]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/components/cloud/gcp_v2/Cargo.toml
[raft-proto]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/proto/Cargo.toml
[sqld-cargo]: https://github.com/tursodatabase/libsql/blob/d8bc862d20bedc72945a1da27c8b7045414c0261/libsql-server/Cargo.toml
[libsql-cargo]: https://github.com/tursodatabase/libsql/blob/d8bc862d20bedc72945a1da27c8b7045414c0261/Cargo.toml
[read-pool]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/src/read_pool.rs
[future-pool]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/components/tikv_util/src/yatp_pool/future_pool.rs
[yatp-readme]: https://github.com/tikv/yatp/blob/9fcf102bfcc3acaa0d992b018ada7593deb04d97/README.md
[logger]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/components/tikv_util/src/logger/mod.rs
[metrics]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/components/tikv_util/src/metrics/mod.rs
[config]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/src/config/mod.rs
[engine-rocks]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/components/engine_rocks/Cargo.toml
[rocks-submodules]: https://github.com/tikv/rust-rocksdb/blob/64a092fd3b4b1639b42fdc3c5f31edbd05528177/.gitmodules
[aws-cargo]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/components/cloud/aws/Cargo.toml
[aws-s3]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/components/cloud/aws/src/s3.rs
[makefile]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/Makefile
[allocator]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/components/tikv_alloc/src/lib.rs
[async-io-test]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/tests/failpoints/cases/test_async_io.rs
[transport-test]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/components/test_raftstore/src/transport_simulate.rs
[failpoint-runner]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/tests/failpoints/mod.rs
[toolchain]: https://github.com/tikv/tikv/blob/a1fdd6a59bb9c8a282c15677e1894501a52425cf/rust-toolchain.toml
