# SCAP：S3 原生 SQLite

SCAP 面向大量独立租户／Agent 数据库：数据库页面、原请求结果、权限和写者身份由 S3 中的单库 HEAD 引用；本地 SQLite 文件用于执行和缓存，全部计算节点与缓存丢失后从对象存储重建。

本项目按 [PR #16](https://github.com/ckanner/scap/pull/16) 重建。旧 Raft、RocksDB、cell 服务和旧 SDK 只保留在 Git 历史；当前构建采用对象存储权威协议和 SQLite 提交前 WAL gate。

## 当前实现与验证状态

最新核查：2026-11-20（纽约）。[PR #65](https://github.com/ckanner/scap/pull/65) 和
[PR #66](https://github.com/ckanner/scap/pull/66) 均已合并，主线基准为
[`b9d736ba`](https://github.com/ckanner/scap/commit/b9d736ba563b615004d35204e970ca5895ad618c)。
owner/controller、S1/S2、永久实例身份、有界 S3 连接复用、同库并行强读池、受信动态
fleet 和 Linux 内核资源准入均已在主线。该合并提交的 6 个工作流、24 个 job 全部成功，
不是仍待合入的候选；本次逐项重新读取了远端结果，见[当前复核](docs/engineering/sqlite-s3-review-2026-11-20.md)。

#66 的冻结验收包含 stable/nightly 各 911 项单位、77 个 Rust 生产文件逐文件四维
精确 100%，以及读池、动态 fleet、内核资源、固定开环过载四项实际合同。
原件、失败及来源仍见[原交付记录](docs/engineering/sqlite-s3-scale-validation-2026-11-18.md)。
本轮参数绑定优化及文档修正有自己的验证记录，不能继承 #66 的测试计数或覆盖结论。
Manifest GET 省略候选按[正式决策](docs/engineering/manifest-get-elision-decision-2026-11-18.md)
退出本次交付；普通精确读取保留，历史约 24% 回退并未被宣称已解决。

| 已合入能力 | 实现范围与边界 |
| --- | --- |
| [同库强读池](crates/scap-service/docs/read-pool.md) | 固定 reader worker、私有完整镜像、租户／库活跃额度；每次读校验新 HEAD，SQL 前最多一次过期镜像重建；writer 仍按库串行 |
| [动态 owner fleet](docs/architecture/dynamic-owner-fleet.md) | 版本化受信快照、完整有限策略历史、不可逆退役、旧计划收敛；SIGHUP 等待旧 tick/socket/DNS 归还后切换；没有分布式配置共识或自动扩缩容 |
| [内核资源准入](docs/architecture/kernel-resource-envelope.md) | 可选检查实际 cgroup v2、普通 CPU 调度与有限 tmpfs；启动前拒绝不满足部署条件；不是每租户 RSS 隔离或任意磁盘配额认证 |
| [持续开环负载](experiments/object-overload/PLAN.md) | 预先冻结 30 秒、1,140 次到达与分窗进展；相同 64 条逻辑写比较 64 次单事务和 8 次 SQL batch；不是服务器 group commit 或生产 SLO |

以下是前一 #65 冻结组合的历史证据，不冒称新候选已重新通过：

| 范围 | 当前实现与验证 |
| --- | --- |
| 生产冻结组合 `aab8a22` | stable/nightly 各 887 项单位通过；76 个生产文件的行、函数、region、branch 均精确 100%，无缺失 map 或零分母；fmt、严格 Clippy 通过 |
| 恢复核心审查 | 保留原 READ 上下文与总期限，复制描述绑定源和容量，native 清理后再检查取消／期限；补真实 fsync/丢失 HEAD/非法子树/序列边界反例 |
| S2 实际专项 | 正式 release 的 7 个场景、126 个独立审计负控通过；删除源 payload 后新 Scope 仍独立恢复 |
| 永久 worker 身份 | 同一正式 release 的显式 ID 10 场景、自动分配 18 场景通过；启动 marker 的原始 PUT/GET、正文、ETag 与对应进程就绪严格绑定 |
| HTTP / SDK | Node 161 项单位与严格覆盖通过，HTTP 7 项、controller HTTP/进程 12 项通过；TCP 8 场景通过 |
| CI | owner/Missing/controller/固定矩阵/S1/S2/显式和自动身份实际合同、模型、SDK/codec 和固定 TypeScript 检查均接入每个 PR；保存原始证据与负控 |
| 性能 | 原四库约 24% 回退仍未归因；新 2×2 诊断保留全部正负样本与观察器成本，不宣称吞吐验收或生产 SLO 通过 |

#65 历史组合的详情、来源、CI 状态与当时边界见
[self-review 与 CI 收口](docs/engineering/sqlite-s3-self-review-2026-11-17.md)、
[恢复核心审查](docs/engineering/restore-core-review-2026-11-18.md)和
[历史性能因果诊断](docs/engineering/manifest-proof-causal-2026-11-18.md)。覆盖修复没有
改变 `AGENTS.md` 或检查器门槛，没有用集成 profile 补单位；LLVM 对某些 Rust 语法的
测量局限仍由[分支测量说明](docs/engineering/branch-coverage-measurement-gap.md)明确记录。

[前一组合验证](docs/engineering/sqlite-s3-followup-validation-2026-11-17.md)中的
877 项单位、4 个未命中文件和 8 个 branch 零分母是旧候选的真实失败，保留原样。最终普通读取路径的新 release 及实际见
[恢复与身份验收](docs/engineering/manifest-get-runtime-2026-11-17.md)。
[11 月 13 日补验](docs/engineering/sqlite-s3-review-2026-11-13.md)的各次实际也保持
各自源码与原件身份，不能合算为当前候选的认证。

自动实例身份分配、S2、读池、有限动态 fleet、资源准入与开环合同已经按上方范围合入。
任意时间 PITR、独立事务 group commit、跨库 WAL 聚合、lazy VFS、新 MVCC 引擎、跨进程
fleet 共识、长期 GC／成本和真实 AWS／生产 SLO 仍有独立出口。单库 writer 仍串行，
冷恢复仍完整读取闭包，热点写吞吐不会因增加 reader 或 pod 自动提高。

## SQLite 文件安全与吞吐边界

SCAP 不把 S3 挂载成 SQLite 文件，也不跨主机共享活动 `.db/WAL/SHM`。私有本地镜像和临时目录经过文件系统准入；对象存储中的原 ETag 条件发布负责跨节点排序与旧写者 fencing。SQLite WAL 的 wal-index 需要同机共享内存；SQLite 支持同机多进程，单库一个 writer 不等于整个服务只能单进程。EFS 支持 NFSv4 advisory byte-range locks，这不等于支持跨主机共享 SQLite WAL。官方依据和实现映射见[存储安全与吞吐分析](docs/architecture/sqlite-s3-safety-and-throughput.md)及[部署要求](docs/operations/sqlite-storage-safety.md)。

| 问题 | 当前处理 | 保留的边界 |
| --- | --- | --- |
| 共享网络文件的锁／同步风险 | 本地私有执行镜像，跨节点只通过对象 API 协调 | 本地 I/O、overlay 底层和挂载稳定性仍由部署保证；真实 NFS/EFS/FUSE 挂载验收不能用类型分类测试替代 |
| 旧实例迟到写入 | 同一 HEAD 上的 owner epoch 和原 ETag CAS；#61 永久登记，#62 可自动取得新 ID | 首次升级历史和目标 IAM 另验；自动编号不授予数据库 owner、不刷新静态路由 |
| 热点单库吞吐 | 单库 writer actor 串行，可选私有镜像强读池；短事务和一个事务内多 SQL 语句 | 读池增加读执行并发，未实现新 MVCC 引擎或独立事务 group commit；增加 pod 不会自动提高该库写吞吐 |
| 多库与冷恢复 | 不同库有界 actor，独立控制池与恢复准入，空闲 actor 回收 | CPU、网络、磁盘和 S3 仍共享；冷恢复仍读取完整数据及保留结果闭包，没有 lazy VFS |
| 长期存储 | HEAD6 代际复制／退休／持久 sweep，HEAD7 永久终态 seal；已合入的 S1 保护 retained roots，S2 恢复到独立新库 | GC 默认没有删除权限；需要重复 sweep，逻辑数据库配额不限制 bucket 总量 |

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
| [Node SDK](sdk/node/README.md) | 固定原 SQL／目录／owner 意图、无损 typed SQL、结果查证／取消、显式业务路由；OwnerPlanClient、有限动态 OwnerControllerFleet 与快照接口均不自动重放 SQL |

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

关闭窗口只变更引用。**HEAD6 的显式管理员 compaction、退休世代 GC 和 HEAD7 的永久终态退休均已合入主线，默认仍未启用 GC 权限。** 协议与严格边界见 [HEAD6 设计](docs/architecture/head6-compaction-gc.md)和[管理接口](crates/scap-service/docs/reclamation.md)。旧块、索引和 orphan 只有在安全迁移、退休及公平重复 sweep 后才能回收；当前文件配额不限制 bucket 总量。HEAD7 通过显式 seal 退休 Deleted 最后一代；HEAD9 S1 还要求 live retained roots 为空才允许终态退休。内部 Rust API 的 principal 是可信准入输入；HTTP 服务从 token 摘要映射得到可信主体，再由最新 HEAD 检查数据库权限。发现分页不等于数据恢复或自动 owner 协调；这些接口和合同分别记录。

HTTP 服务用不可变五元组接入，`create` 后显式激活。HEAD6/7 使用 legacy `takeover`／`activate`；接受 owner plan 升级为 HEAD8/9 后，旧入口永久拒绝，必须使用固定计划的 prepare/claim/resume/abort。每次服务启动的 `worker_instance` 不得复用；#61 在 S3 永久登记，#62 支持 `"auto"` 和显式管理员初始化，首次升级仍须处理旧实例和历史发号。全部计算丢失后仍以原 Scope 查 HEAD，再按对应格式完成恢复。Node SDK 在发送前用 `prepare`／`save` 固定 SQL、参数、世代和请求 ID；超时或断线后用原身份 `lookup`／`cancel`。配置和启动命令见[服务说明](crates/scap-service/README.md)，完整恢复流程见[运行手册](docs/operations/http-service.md)。

`RoutedClient` 使用受信静态路由，fresh status 后最多派发一次原业务请求。legacy `OwnerClient`
保存的意图只能按[旧 owner 合同](docs/architecture/owner-reconciliation.md)显式协调和查证；
新 `OwnerPlanClient` 用持久描述与 HEAD phase 恢复已接受计划。
`OwnerController` / `OwnerControllerFleet` 在固定策略、期限和调用预算内推进计划，TLS/证书配置错误
不作为 owner 死亡证据。旧 CAS 不换 ETag，原 SQL 的 UNKNOWN 仍用 lookup/cancel；固定12场景
已覆盖多controller竞争、取消、拒绝与迟到操作；动态配置、旧历史和退役已随 #66 按
[动态 fleet 合同](docs/architecture/dynamic-owner-fleet.md)验收合入。自动编号见 #62，不能由原矩阵推导。协议与范围见[owner 计划](docs/architecture/accepted-owner-plan.md)、
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

当前状态、目标与后续实施顺序见[接续交付计划](docs/engineering/sqlite-s3-delivery-plan.md)。

- [已接受的完整方案](docs/architecture/object-storage-native-proposal.md)、[ADR-0020](docs/adr/0020-object-storage-native-authority.md)。
- [首个原生实现与格式选择](docs/adr/0021-object-native-runtime.md)、[可配置容量与 v2 恢复布局](docs/adr/0022-production-capacity.md)。
- [认证 HTTP 与新 SDK](docs/adr/0023-authenticated-http-and-node-sdk.md)、[真实服务恢复合同](experiments/object-service/README.md)。
- [名称目录与永久身份](docs/adr/0024-named-catalogue-and-permanent-identities.md)、[目录协议与范围](docs/architecture/name-catalogue-plan.md)。
- [全目录发现与恢复方案](docs/architecture/catalogue-discovery-plan.md)、[分段索引、pin/GC 与 PITR 方案](docs/architecture/storage-reclamation-plan.md)。
- [路线图](docs/engineering/roadmap.md)、[故障矩阵](docs/operations/failure-matrix.md)、[运行说明](docs/operations/runbooks.md)。
- [协作要求](AGENTS.md)、[本地验证身份](docs/engineering/local-validation.md)。

本仓库不承诺生产 SLA、跨 AZ 或长期低成本结论；GiB 恢复只按实际候选实验报告范围描述。完整阶段退出以路线图及对应证据为准。许可证仍由维护者决定，第三方组件保留各自许可证。
