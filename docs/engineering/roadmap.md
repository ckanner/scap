# 实施路线与发布门禁

状态：G0 整体仍未关闭，已完成可部署的有界 SQLite 服务闭环。2026-11-02 的正式 `scap-server` 已连接三副本共识、HTTP/Node SDK、独立强读、自动 owner 恢复与 S3 冷生命周期；这不等于完整平台、规模或生产 SLO 已通过。2026-11-04 新增内容块增量持久化、按库惰性执行和重新授权的连接复用，见 [ADR-0015](../adr/0015-incremental-blocks-and-isolated-execution.md)。当前实现见 [服务说明](sqlite-service.md)和 [ADR-0014](../adr/0014-sqlite-service-and-cold-lifecycle.md)，执行证据见 [g0-evidence.md](g0-evidence.md)。

## 1. 原则

先验证最可能推翻架构的接口与故障边界，再扩展控制面和规模。客户端演示成功、容器能够重启、正常情况下三副本数据相同，都不足以证明高可用。

任一阶段未达到持久性门禁，产物只能标为实验或备份恢复原型，不能对外承诺本仓库的严格 HA。改变产品保障范围须记录新的 ADR 和维护者决定，不能在实现中静默降级。

共识库按照 [ADR 0006](../adr/0006-raft-rs-consensus-library.md) 采用 TiKV 的 `raft-rs`；[选型调研](../research/raft-library-selection.md) 记录取舍。正式 driver/Store/native/mTLS runtime 已集成并进入独立故障验证，没有 OpenRaft 运行时需要迁移。所选上游的成熟度不替代本项目的持久化、状态机及服务门禁。

TiKV 的运行、网络与工程组件已按固定版本完成 [技术栈审计](../research/tikv-rust-stack.md)。采用与暂缓项见 [ADR-0007](../adr/0007-tikv-stack-and-rpc-boundaries.md) 和 [技术决策清单](../../contracts/technology-decisions.json)，后续实现受 [运行与 RPC 契约](runtime-and-rpc.md)约束；参考项目的成熟度不能替代本项目门禁。

## 2. 阶段计划

| 阶段 | 交付 | 进入下一阶段的条件 |
| --- | --- | --- |
| G0：关键可行性 | 锁定依赖与引擎/协议接合边界、WAL 原型、真实 SDK 兼容、RPC/存储契约验证 | 能在提交可见前暂存/拒绝/确认；页恢复正确；所选有界 Hrana/SDK 与依赖组合验证；许可和版本明确 |
| G1：一个可靠 cell | 三副本日志、持久状态机、owner fencing、提交与读屏障 | 故障注入证明 ACK 保留、旧写者拒绝、未知结果不重复接受 |
| G2：多库与平台入口 | Gateway、权限、目录、调度、多库配额、会话与错误语义 | 跨租户权限与资源测试通过；控制面失效行为符合合同 |
| G3：对象与生命周期 | 快照、增量、发布、GC、冷唤醒、PITR、DR checkpoint | 在干净环境恢复成功；任意上传/发布/删除点崩溃不破坏恢复链 |
| G4：试运行与运营 | 跨 AZ、升级、成员变更、容量、告警、演练、成本报告 | 实际业务兼容和 SLO 测量完成，所有阻断缺陷关闭 |

这些门禁与 [验证计划](validation.md) 同名阶段对应。可以并行开发独立模块，但不能绕过依赖门禁进入生产。

### 2.1 当前已实现与尚未关闭的边界

| 范围 | 已有正式实现 | 仍待完成的目标 |
| --- | --- | --- |
| 共识与服务 | 三 voter 单 cell、持久 Ready/应用、PreVote/check_quorum、Safe ReadIndex、真实 daemon；本轮加入受控 learner/joint 替换，验收见 ADR-0016 | 跨 AZ/设备故障、自动坏盘运维、逻辑分段与保留、多 cell |
| SQL 与接入 | SQLite gate、独立强读、自包含 Hrana execute/batch、Node SDK、稳定请求结果查证 | 完整 ORM/同步驱动、交互式事务、生产规模的调度验收 |
| 多租户与恢复 | 静态最多 32 库、token/当前 auth_epoch、leader 自动接管、新目录恢复、按库惰性 lane/准入配额 | 动态目录、外部身份源、每租户公平性、坏盘成员自动重建 |
| 冷生命周期 | Suspend、不可变 S3 发布、受覆盖 Prune、精确 hydrate、全 cell Checkpoint | GC/结果退休、PITR/DR、分块归档、恢复空间预留和成本收敛 |
| 验证与运营 | 独立 unit 门禁、实际进程/TCP/S3/SDK 场景及可复现命令 | 生产规模分母、稳定恢复窗口、长期运行、SLO 与故障域认证 |

当前单库逻辑镜像 256 KiB、每库 128 条 accepted/cancel 和 cell 4096 条管理记录，不能用该 profile 宣称 1 GiB 恢复目标或无限 Agent 密度达标；达到预算必须拒绝增长。已实现后续阶段的有界子集也不自动关闭该阶段全部 gate。

## 3. G0 的具体工作

所有生产代码遵守 [100% 单元覆盖率与可测架构](testability-and-coverage.md)，每个阶段同时核查 [性能与恢复目标](performance-slo.md) 的适用部分。正式基础模块现已装配 SQL/SDK、leader 自动 writer 接管、强读和后台 S3 生命周期。单元覆盖与真实 WAL、磁盘、三进程网络、SQL/SDK/S3 实验分别计量，精确计数见 [执行证据](g0-evidence.md)。G0 仍保留集成边界、平台能力和生产 profile 的未完成验证，不能将有限功能通过解释为整体完成。

### 3.1 引擎适配

固定 libSQL commit、SQLite compile options、page size、目标平台和 WAL 接口。验证普通事务、DDL、savepoint、回滚、checkpoint、数据库增长/截断、取消、I/O 错误及模拟 quorum 失败。

最重要的验收是：在 cell 未接受前，另一个读连接绝不能观察到成功提交；cell 接受但 worker 退出后，恢复必须得到同一结果。普通 `wal_hook` 不能作为该证明。

### 3.2 持久化适配

保持已实现的串行 `raft-rs` driver 与持久存储 adapter 合同，继续执行锁定上游版本的适用测试及更多存储故障测试。`Storage` 的读取接口不能代替应用负责的持久写入；RocksDB WriteBatch / sync、`HardState`、`ConfState`、last-applied、snapshot 和 log purge 的恢复关系仍是发布门禁。

首版采用串行同步 `Ready`：完成必要持久化后调用 `advance_append(ready)`，处理 `LightReady`，有序持久化应用结果，再调用 `advance_apply_to(durable_applied)`；先验证这些工作、消息类别和应用进度，再考虑异步持久化流水线。持久化失败不得发送 `persisted_messages` 或虚报持久推进；应用完成边界不得超前于实际可恢复的业务状态，`commit_index` 也不能落后于已持久化的应用位置。具体接口、顺序和验证出口以 [raft-rs 集成门禁](raft-rs-integration.md) 为准。

[ADR-0008](../adr/0008-bounded-durable-store-g0.md)落实正式 `scap-raft-store` 和进程退出边界；[ADR-0009](../adr/0009-serial-driver-and-native-backend.md)落实 driver/native 后端与受控三进程；[ADR-0010](../adr/0010-cell-acceptance-and-raft-safety.md)落实 cell 接受规则与 PreVote/ReadIndex；[ADR-0011](../adr/0011-bounded-native-sqlite-adapter.md)落实正式 SQL adapter；[ADR-0012](../adr/0012-bounded-raft-network-runtime.md)落实 mTLS/runtime；[ADR-0013](../adr/0013-tracked-sqlite-network-commit.md)接通逐请求裁决与 owner 恢复入口；[ADR-0014](../adr/0014-sqlite-service-and-cold-lifecycle.md)完成三节点服务、独立强读、SDK、leader 自动接管与有限冷生命周期。下一步扩展持久布局、资源隔离、动态平台和可回收历史，不回退已有 fencing/ACK 合同。

### 3.3 运行、RPC 与依赖边界

当前已明确接合边界：固定 libSQL C/virtual WAL 引擎，由正式 scap-service 实现受限 Hrana HTTP v2，不合编完整旧 sqld。记录真实依赖、features、代码生成器和协议版本，并用固定 `@libsql/client` 0.18.0 验证该子集。扩展会话或 ORM 时继续独立验证，不能为统一依赖版本假设旧 sqld 全部行为已经兼容。

早期 `raft-rpc` 实验仅验证外层 Prost envelope 透传内层 raft-rs `protobuf-codec` 原始字节、字段/版本/大小拒绝与真实 loopback 往返。2026-11-01 的正式 wire/transport/runtime 已补齐固定成员的 mTLS、实际 leaf pin 与 node/cell 授权、有限消息解析、连接/RPC/inbox/发送预算和绝对 deadline。`Received` 只表示排队成功，尚未保证交给 driver，消费时还要复核授权和有效期。

[真实网络契约](../../experiments/raft-network/README.md)使用三个独立 RawNode/RocksDB 进程与合成 payload；[SQLite 网络](../../experiments/sqlite-network/README.md)和 [服务实验](../../experiments/service-network/README.md)进一步装配正式 SQL/SDK；[成员实验](../../experiments/membership-network/README.md)验证受控 learner/joint 替换。后续按 [运行与 RPC 契约](runtime-and-rpc.md)和 [Ready 门禁](raft-rs-integration.md)补证书控制面、慢盘/丢盘、自动坏盘运维及容量证据。当前每个发送 lane 有界复用一个 TLS 连接，每次 RPC 前后重新验证实际证书链和当前 pin；握手摊销、socket 和尾延迟仍需实测，不能把某次场景通过当成性能达标。禁止由 gRPC Received 推导 SQL 成功，也不能在超时后无条件重放未知结果的业务写入。

### 3.4 客户端与备选基线

正式 `sdk/node` 和真实 Node/三 daemon 实验已覆盖固定客户端的 execute/batch、强读、身份和结果查证。下一步选择实际应用及 ORM、可选同步 libsql 包，记录迁移改动、查询模式与故障行为，不能用基础 SDK 通过替代全部业务兼容。

对 dqlite 的现成同步复制、原生 SQLite + Litestream 的备份恢复分别做对照，验证自研存算分离带来的收益与复杂度。它们是技术对照，不改变正式 HA 合同。

### 3.5 Go / No-Go

如果 WAL 接口不能安全控制可见性，或持久存储契约无法证明，停止扩展产品功能，重新选择底座。可选择缩小兼容范围、集中维护引擎 patch，或重评已有复制引擎；不得在提交后上传数据来假装满足门禁。

当前同 cell、静态身份、外部 SQL/SDK、强读、自动 owner 接管、有限冷生命周期和受控成员替换已形成有界闭环。G0 整体仍未宣布通过：完整业务兼容、规模化持久布局、动态平台、租户公平性及生产故障/性能 profile 仍有门禁；当前 256 KiB profile 不等于 1 GiB 目标。功能证据不豁免自动坏盘运维、证书控制面、多 cell、设备故障或 SLO 验收，也不自动产生对外 SLA。

## 4. G1–G3 的实现顺序

1. 已实现不依赖 S3 的最小可靠 cell、提交/强读和 owner fencing；继续补设备故障和更大 profile 证据。
2. 已有有界每库元数据及静态目录；后续验证更大密度、增量持久布局和不依赖全历史扫描的恢复。
3. 已有 HTTP/SDK、静态鉴权、请求结果查询和错误边界；后续加入外部身份、动态目录、公平调度及经验证的事务会话。
4. 已有 idle 休眠、不可变归档、Publish/Prune/Hydrate 和全 cell Checkpoint；先永久保留对象与结果，继续扩展块级恢复和前景隔离。
5. 设计并实现可证明的 GC、结果退休、恢复容量预留和删除，之后才能评价持续运行的冷存成本与容量收敛。
6. 受控成员替换按 [ADR-0016](../adr/0016-durable-membership-replacement.md)先补齐同 cell 冗余修复；继续实现跨 cell 离线迁移、混版本升级及带来源证明的灾难恢复自动化。

禁止从一开始同时实现所有优化：按页远读、多写者、跨库事务、跨区同步、跨库对象打包、无限事务分块均留待后续 ADR。

## 5. 仓库开发顺序

核心已有 Rust workspace、固定 toolchain 与锁文件，正式 Node SDK 位于 `sdk/node`，提交独立 package-lock 和 Node 版本要求。后续按 [目录规划](repository-layout.md) 扩展模块并补齐新增依赖的许可证与构建记录。

独立 Rust 依赖/故障实验使用各自 workspace；S3 实验和 Node 编排的正式 daemon 实验同样与 unit profile 分开。实验只装配正式模块和故障控制，不保存另一套恢复算法。所有正式实现都须满足第一方 100% 精确单元覆盖门禁；其余模块按实际实现建立，不创建空服务、假 Docker Compose 或无实现 API stub。

## 6. 试运行标准

- 用非关键租户或可重放数据验证，但与生产使用同一持久化模式。
- 每次试运行产出构建标识、配置、原始指标、故障时间线和数据库不变量检查结果。
- 首次对外 SLA 来源于测量和演练，而不是设计文档中的期望。
- 回滚计划必须考虑磁盘 / 日志格式；不支持格式回退时采用恢复迁移，而非直接运行旧二进制。
- 关键正确性缺陷阻断发布；性能不达标先限额和缩小范围，不更改已确认写入保障。

当前可复现启动和支持范围以 [SQLite 服务文档](sqlite-service.md)为准，实测结果以实验 README 与 [G0 证据](g0-evidence.md)为准。后续推进时保留当前 ACK、权限、UNKNOWN、冷恢复和无 quorum 拒绝合同，不以扩大规模为由静默弱化。
