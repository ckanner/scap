# SCAP：S3 原生 SQLite

SCAP 面向大量独立租户／Agent 数据库：数据库页面、原请求结果、权限和写者身份由 S3 中的单库 HEAD 引用；本地 SQLite 文件用于执行和缓存，全部计算节点与缓存丢失后从对象存储重建。

本项目按 [PR #16](https://github.com/ckanner/scap/pull/16) 重建。旧 Raft、RocksDB、cell 服务和旧 SDK 只保留在 Git 历史；当前构建采用对象存储权威协议和 SQLite 提交前 WAL gate。

## 当前实现与验证状态

最新核查：2026-11-17。main 为 `fab8ca0`（HEAD7），已合入 #54 代际复制／GC 和
#55 Deleted 最后一代退休。当前产品路线仍是 S3 唯一持久权威、SQLite 私有本地执行。

| 代码 | 内容 | 当前状态 |
| --- | --- | --- |
| [PR #59](https://github.com/ckanner/scap/pull/59)，本轮代码 `b4c5236` | 汇集 #56 owner plan、#57 有限 controller、#58 保留快照 S1；修复锁内入队前的期限检查，过期请求不创建 actor | 隔离 stable/nightly 各 787 单位通过；两个调度文件四维精确覆盖；原有 7 文件的分支测量缺口仍阻断，继续 Draft |
| [PR #60](https://github.com/ckanner/scap/pull/60)，本轮代码 `9b5e9ae` | 保留 Manifest 证明全部绑定，取消内部 HEAD 十六进制摘要和部分根字符串分配 | 隔离 792 单位及严格 Clippy 通过；指纹微型分析不代表服务吞吐；历史两组四库写入回退 24.00%／24.52% 尚未定位，继续 Draft |
| [PR #61](https://github.com/ckanner/scap/pull/61)，本轮代码 `841da9c` | 同一 S3 后端永久登记每次启动的 worker ID，拒绝复用及不确定启动；基于 #59 `b4c5236` | 隔离 stable/nightly 各 797 单位、真实进程 10 个启动故障及 8 个 TCP 场景通过；自动分配由后续 #62 实现 |
| [PR #62](https://github.com/ckanner/scap/pull/62) | 永久 high-water counter、显式初始化、自动分配和永久占用；UNKNOWN 不收养、不复用身份 | 独立 stable/nightly 各 808 单位、实际自动分配 18 场景及显式 ID 兼容 10 场景通过；原 7 个 branch 零分母仍阻断，继续 Draft |
| [PR #63](https://github.com/ckanner/scap/pull/63) | S2 retained point 恢复到全新 Scope；核心、HTTP、Node SDK、取消、发现、GC 消费者与独立恢复资源 | 已实现并提交；原生故障与精确候选验证见恢复专项记录，保持 Draft |
| [PR #64](https://github.com/ckanner/scap/pull/64) | 实际服务 CPU／分配／对象等待／建连诊断；共享 S3 空闲连接从 2 调至有界 8 | 存储 45 单位与实际 TCP 负控通过；四库写建连 83→4；不宣布普遍 TPS 提升或历史 24% 回退已修复 |

各份结果对应各自的源码组合，测试数不能相加，也没有借用旧候选的实际合同认证新代码。
本轮 #59/#61 fresh unit-only 报告已发出的计数全部命中，**但原有 7 个文件 branch
仍为 0/0，完整逐文件四维门禁未满足**。其中 6 个含有 `match` 等决策路径，不能称为
结构无分支；没有改门槛、排除生产文件或用 region 冒充分支。代码、设计与证据见
[2026-11-17 审查和修复](docs/engineering/sqlite-s3-review-2026-11-17.md)，测量规则见
[分支测量说明](docs/engineering/branch-coverage-measurement-gap.md)。

2026-11-13 的历史补验：原 11–12 日部分 raw originals 未能恢复，当日重新构建正式
release，按原合同重新执行，分别保存原失败、新通过和未运行项。HEAD6、终态退休、
native／deployment discovery、owner-plan、isolation、controller 矩阵、S1、资源与
GC transport 已取得完整新结果；service discovery 在新 `642383c` 上也已完成，固定 b15
的 1 GiB 恢复、39 份原结果查证与 16,384 个 BLOB 全量审计通过。各自来源与边界见
[2026-11-13 交付与验收](docs/engineering/sqlite-s3-review-2026-11-13.md)。不能把只补
HEAD6 和终态两个尾项当作所有旧证据已恢复，也不以当前检查器的绿色文字代替严格门禁。

自动实例身份分配和 S2 已有独立实现；它们分别不等于动态 fleet 与任意时间 PITR。
动态 fleet、PITR、硬 RSS／磁盘隔离、持续过载与长期成本、真实 AWS 和生产 SLO
仍未交付。单库仍串行，冷恢复仍完整读取闭包；同环境请求账本与实际
吞吐分别报告。两组配对的完整正确性和原负控通过，但不能宣称减少一个 GET 已解决
热点吞吐。原计数、尾延迟、采样限制和下一步 profile 见
[Manifest 性能验收](docs/engineering/verified-manifest-load-validation.md)。

## SQLite 文件安全与吞吐边界

SCAP 不把 S3 挂载成 SQLite 文件，也不跨主机共享活动 `.db/WAL/SHM`。私有本地镜像和临时目录经过文件系统准入；对象存储中的原 ETag 条件发布负责跨节点排序与旧写者 fencing。SQLite WAL 的 wal-index 需要同机共享内存；SQLite 支持同机多进程，单库一个 writer 不等于整个服务只能单进程。EFS 支持 NFSv4 advisory byte-range locks，这不等于支持跨主机共享 SQLite WAL。官方依据和实现映射见[存储安全与吞吐分析](docs/architecture/sqlite-s3-safety-and-throughput.md)及[部署要求](docs/operations/sqlite-storage-safety.md)。

| 问题 | 当前处理 | 保留的边界 |
| --- | --- | --- |
| 共享网络文件的锁／同步风险 | 本地私有执行镜像，跨节点只通过对象 API 协调 | 本地 I/O、overlay 底层和挂载稳定性仍由部署保证；真实 NFS/EFS/FUSE 挂载验收不能用类型分类测试替代 |
| 旧实例迟到写入 | 同一 HEAD 上的 owner epoch 和原 ETag CAS；#61 永久登记，#62 可自动取得新 ID | 首次升级历史和目标 IAM 另验；自动编号不授予数据库 owner、不刷新静态路由 |
| 热点单库吞吐 | 同库 actor 串行，短事务和一个事务内多 SQL 语句 | 没有同库并行 reader pool、MVCC 或独立事务 group commit；增加 pod 不会自动提高该库吞吐 |
| 多库与冷恢复 | 不同库有界 actor，独立控制池与恢复准入，空闲 actor 回收 | CPU、网络、磁盘和 S3 仍共享；冷恢复仍读取完整数据及保留结果闭包，没有 lazy VFS |
| 长期存储 | HEAD6 代际复制／退休／持久 sweep，HEAD7 永久终态 seal；S1 候选保护 retained roots | GC 默认没有删除权限；需要重复 sweep，逻辑数据库配额不限制 bucket 总量 |

S3 Standard 是目标验证后端；S3 Express One Zone 的单 AZ 故障域不能包装成跨 AZ RPO=0。Turso 的开源 libSQL、Cloud 存储路径和新 Rust MVCC 引擎是不同层次；其基准不作为 SCAP 性能证据，详见[官方对照](docs/architecture/sqlite-s3-safety-and-throughput.md#6-turso-可以借鉴什么)。

本轮采纳与暂缓的具体实践见 [Turso 接续设计](docs/architecture/turso-adoption-next.md)。
当前保持 FULL 与受检 TRUNCATE；group commit、按需 VFS 和新引擎 MVCC 仍各需独立
提交／可见性／故障协议，不能通过把 SQLite 文件放到网络卷或关闭同步来代替。

## 实现入口

| 模块 | 职责 |
| --- | --- |
| [scap-object](crates/scap-object/src/lib.rs) | HEAD/对象格式、权限、精确请求身份、提交/取消/关闭窗口、接管/激活、独立强读及名称目录 |
| [scap-object-store](crates/scap-object-store/src/lib.rs) | 真实签名 S3 exact GET、同响应 ETag、条件创建/替换、截止时间和错误分类 |
| [scap-object-sqlite](crates/scap-object-sqlite/src/lib.rs) | 固定 libSQL SQLite 内核、私有连接、提交前物理页拦截、结果缓冲和只读快照 |
| [scap-sql](crates/scap-sql/src/lib.rs) | 有界 SQL 参数、精确指纹和完整类型化结果编码 |
| [scap-service / scapd](crates/scap-service/README.md) | 认证 HTTP、严格请求解析、独立控制与目录线程、租户／数据库排队与显式恢复 |
| [Node SDK](sdk/node/README.md) | 固定原 SQL／目录／owner 意图、无损 typed SQL、结果查证／取消、静态路由；候选增加 OwnerPlanClient、有限 OwnerController 与快照接口，均不自动重放 SQL |

成功写必须依次完成：暂存 SQL 与原结果 → 上传并回读校验不可变依赖 → 用原 ETag 条件发布 HEAD → 本地 native publication → 返回成功。HEAD 响应丢失时保留 UNKNOWN；查证和取消始终使用原请求身份，不重新执行随机 SQL。

每个新强读先读取新的 HEAD，并校验当前 READ 权限和固定数据根。S3 不可用时新强读和写入都失败关闭，没有热缓存成功降级。接管以 HEAD CAS 推进 owner epoch，恢复数据与保留结果后重新核对 HEAD，再激活。

## 容量与运行配置

**默认单库为 10 GiB，管理员可调大，也可设置 `quota.max_bytes = None` 取消 SCAP 业务容量配额。** 配额随 HEAD 持久化并以原 revision 的 CAS 修改；禁止缩到已有文件以下。SQLite 的 4 KiB 页号边界仍存在，约 16 TiB 理论文件空间不等于实测服务容量。

| 项目 | 默认或实现 |
| --- | --- |
| 单库逻辑文件 | 10 GiB；既有库遵守 HEAD 配额 |
| 持久数据布局 | 128 KiB 原始字节块，256 分支内容寻址树，仅更新变化块及路径 |
| 冷恢复与热执行 | 流式恢复到新私有文件；Session 复用连接，每次读写重新验证远端 HEAD |
| 事务变化页 / page cache | 各 64 MiB；cache 是软目标，不是进程 RSS 隔离 |
| SQL 结果 / 参数和返回值 | 每事务 50 MiB / 每个 Text-BLOB 2 MiB，可独立配置 |
| 聚合输入 / SQL 文本 | 64 MiB / 1 MiB，包含编码开销 |
| 操作 / 恢复预算 | 30 秒 / 30 分钟，受调用方更早 deadline 约束 |
| 请求留存 | 默认每世代 4,096 条、256 MiB 原结果，保留 current 与两代 closed |

这些执行和留存预算不随数据库大小增长。对象帧与原结果采用原始二进制字节，去掉整库内存复制与 JSON 字节数组膨胀。完整冷恢复仍需下载并检查整个数据库；没有实现 lazy VFS。

[真实容量实验](experiments/object-capacity/README.md)分别装载 1 GiB 独立随机数据及默认 10 GiB 实际 SQLite 文件边界，检查增量 I/O、全部计算丢失后的恢复、全部 ACK 原结果和每个 BLOB。不能仅凭配置或稀疏文件宣称实测通过；具体完成范围以候选绑定的验证记录为准。官方产品对照、配置 API 和证明边界见 [ADR-0022](docs/adr/0022-production-capacity.md)与[对象运行时](docs/engineering/object-runtime.md)。

关闭窗口只变更引用。**HEAD6 的显式管理员 compaction、退休世代 GC 和 HEAD7 的永久终态退休均已合入主线，默认仍未启用 GC 权限。** 协议与严格边界见 [HEAD6 设计](docs/architecture/head6-compaction-gc.md)和[管理接口](crates/scap-service/docs/reclamation.md)。旧块、索引和 orphan 只有在安全迁移、退休及公平重复 sweep 后才能回收；当前文件配额不限制 bucket 总量。HEAD7 通过显式 seal 退休 Deleted 最后一代；HEAD9 S1 候选还要求 live retained roots 为空才允许终态退休。内部 Rust API 的 principal 是可信准入输入；HTTP 服务从 token 摘要映射得到可信主体，再由最新 HEAD 检查数据库权限。发现分页不等于数据恢复或自动 owner 协调；这些接口和合同分别记录。

HTTP 服务用不可变五元组接入，`create` 后显式激活。HEAD6/7 使用 legacy `takeover`／`activate`；接受 owner plan 升级为 HEAD8/9 后，旧入口永久拒绝，必须使用固定计划的 prepare/claim/resume/abort。每次服务启动的 `worker_instance` 不得复用；#61 在 S3 永久登记，#62 支持 `"auto"` 和显式管理员初始化，首次升级仍须处理旧实例和历史发号。全部计算丢失后仍以原 Scope 查 HEAD，再按对应格式完成恢复。Node SDK 在发送前用 `prepare`／`save` 固定 SQL、参数、世代和请求 ID；超时或断线后用原身份 `lookup`／`cancel`。配置和启动命令见[服务说明](crates/scap-service/README.md)，完整恢复流程见[运行手册](docs/operations/http-service.md)。

`RoutedClient` 使用受信静态路由，fresh status 后最多派发一次原业务请求。legacy `OwnerClient`
保存的意图只能按[旧 owner 合同](docs/architecture/owner-reconciliation.md)显式协调和查证；
新 `OwnerPlanClient` 用持久描述与 HEAD phase 恢复已接受计划。
`OwnerController` / `OwnerControllerFleet` 候选在固定策略、期限和调用预算内推进计划，TLS/证书配置错误
不作为 owner 死亡证据。旧 CAS 不换 ETag，原 SQL 的 UNKNOWN 仍用 lookup/cancel；固定12场景
已覆盖多controller竞争、取消、拒绝与迟到操作，动态fleet与生产故障域仍有独立出口；自动编号见 #62，不能由原矩阵推导。协议与范围见[owner 计划](docs/architecture/accepted-owner-plan.md)、
[控制器方案](docs/architecture/owner-controller-plan.md)及 [SDK 合同](sdk/node/README.md)。

命名入口独立启用 `POST /v1/catalogue`。保存固定创建意图后显式推进到 Ready，再按相同 Scope 激活；目录 Ready 不等于 writer 已激活。取消只竞争未绑定的 Reserved，正常删除先保留永久 Deleted HEAD 再释放名称。名称重用产生新 Scope，已有 SQL 意图不会自动改目标。

S2 通过 `prepare_restore` 固定源 SnapshotRef 与新目标身份，沿原意图显式 inspect/resume/abort。
复制在新 Scope 下重封装全部对象，并通过一个私有 native 镜像校验；完成证明形成后才继续
绑定与 Ready。新库不继承源 ACL、writer、sequence 或请求结果空间，完成后独立于源数据。
配置、预算、权限屏障及 UNKNOWN 处理见[恢复合同](crates/scap-service/docs/restore.md)，
实际进程专项见[恢复实验](experiments/object-restore-runtime/README.md)。

## 构建与验证

Rust 固定 1.90.0。native 编译需要 C/C++ 编译器、make 和 libclang。依赖与引擎 Git revision 均由 Cargo.lock 锁定。

```bash
cargo build --workspace --locked
cargo test --workspace --lib --bins --all-features --locked -- --test-threads=1
cargo clippy --workspace --all-targets --locked -- -D warnings
npm --prefix sdk/node-codec test
npm --prefix sdk/node test
npm --prefix sdk/node run test:http
python3 scripts/check_repo.py
```

四维精确单元覆盖率、真实对象故障合同和执行身份按 [验证规范](docs/engineering/validation.md)独立执行。独立 [N0 模型](experiments/object-authority-model/README.md)保留自己的可执行历史判定器，不能替代真实 S3/SQLite 验证。

## 验证记录与历史证据

每份记录只认证其固定提交、依赖和实际二进制。原始失败、修正与新候选结果分别保留；模型、单元、
本地兼容 S3、真实 AWS 和部署故障域证据互不代替。下表集中保留早期进展入口，避免把历史完成时点当成当前状态。

| 范围 | 记录 |
| --- | --- |
| HEAD7 终态退休 | [验收](docs/engineering/head7-runtime-validation.md) |
| HEAD6 代际复制／GC | [验收](docs/engineering/head6-runtime-validation.md)、[当日实施状态](docs/engineering/status-2026-11-10.md) |
| HEAD5 组合与后续修复 | [组合设计](docs/architecture/head5-runtime-composition.md)、[组合验收](docs/engineering/runtime-completion-validation.md)、[六项 native/S3 记录](docs/evidence/head5-runtime-network-local-2026-11-09.json) |
| #35 发现与部署恢复 | [验收](docs/engineering/discovery-recovery-validation.md) |
| #31/#32 名称目录与 actor | [验收](docs/engineering/catalogue-actors-validation.md)、[机器记录](docs/evidence/catalogue-actors-local-2026-11-08.json) |
| #30 名称目录模型 | [模型与边界](docs/engineering/named-catalogue-model.md) |
| #29 生命周期 | [真实合同](docs/engineering/n1-lifecycle-validation.md) |
| #28 执行存储准入 | [验收](docs/engineering/local-storage-validation.md)、[当时环境与失败记录](docs/engineering/status-2026-11-07.md) |
| #27 HTTP／Node | [验收](docs/engineering/http-service-validation.md) |
| #26 ALTER／保留结果 | [验收](docs/engineering/native-integrity-validation.md)、[机器记录](docs/evidence/native-integrity-local-2026-11-06.json) |
| #21 原生故障扩展 | [故障记录](docs/evidence/s3-n1-fault-contracts-local-2026-11-06.json) |
| #20 容量基线 | [1 GiB／10 GiB 记录](docs/evidence/production-capacity-local-2026-11-06.json) |
| #19 首个原生本地验收 | [记录](docs/evidence/object-native-local-2026-11-06.json) |
| #58 保留快照 | [设计与模型精化](docs/architecture/retained-snapshot-restore.md)、[真实专项入口](experiments/object-snapshot-runtime/README.md)、[HTTP 合同](crates/scap-service/docs/snapshots.md) |

## 设计与后续阶段

当前状态、目标、#59 合入条件和后续实施顺序见[接续交付计划](docs/engineering/sqlite-s3-delivery-plan.md)。

- [已接受的完整方案](docs/architecture/object-storage-native-proposal.md)、[ADR-0020](docs/adr/0020-object-storage-native-authority.md)。
- [首个原生实现与格式选择](docs/adr/0021-object-native-runtime.md)、[可配置容量与 v2 恢复布局](docs/adr/0022-production-capacity.md)。
- [认证 HTTP 与新 SDK](docs/adr/0023-authenticated-http-and-node-sdk.md)、[真实服务恢复合同](experiments/object-service/README.md)。
- [名称目录与永久身份](docs/adr/0024-named-catalogue-and-permanent-identities.md)、[目录协议与范围](docs/architecture/name-catalogue-plan.md)。
- [全目录发现与恢复方案](docs/architecture/catalogue-discovery-plan.md)、[分段索引、pin/GC 与 PITR 方案](docs/architecture/storage-reclamation-plan.md)。
- [路线图](docs/engineering/roadmap.md)、[故障矩阵](docs/operations/failure-matrix.md)、[运行说明](docs/operations/runbooks.md)。
- [协作要求](AGENTS.md)、[本地验证身份](docs/engineering/local-validation.md)。

本仓库不承诺生产 SLA、跨 AZ 或长期低成本结论；GiB 恢复只按实际候选实验报告范围描述。完整阶段退出以路线图及对应证据为准。许可证仍由维护者决定，第三方组件保留各自许可证。
