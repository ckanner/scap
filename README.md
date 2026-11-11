# SCAP：S3 原生 SQLite

按 [PR #16](https://github.com/ckanner/scap/pull/16) 重建的对象存储权威数据库。数据库页面、原请求结果、权限和写者身份由 S3 中的单库 HEAD 引用；本地 SQLite 文件仅用于执行和缓存，可全部丢弃后重建。

当前构建已经移除旧 Raft、RocksDB、cell 服务和旧 SDK，没有双后端、旧盘迁移或格式兼容路径。旧代码保留在 Git 历史。选择性复用纯 SQL 编解码和 SQLite 原生提交前 WAL gate，不复用旧 cell 回执或提交协议。

**当前实现包括 S3 权威运行时、认证 HTTP/Node SDK、名称目录、有界多数据库 actor、全目录发现、部署恢复、分段请求索引，以及租户 intake、结果输出池、HTTP 绝对期限和显式 owner 协调。** [PR #54](https://github.com/ckanner/scap/pull/54) 的 HEAD6 生产候选 `66f452e` 另加入完整代际复制与持久 GC checkpoint，并修复 retained-result/cancelled 的请求 nonce 绑定缺口。新候选已完成 stable/nightly 各 **632 项单元、59 个生产文件四维逐文件精确覆盖**；原生故障、保留结果、生命周期、目录、新的 1 GiB 全量恢复，以及整栈 HTTP/资源/回收/负载和全部独立判定/负对照均通过，已合入 main。最新准确状态见[HEAD6 验收](docs/engineering/head6-runtime-validation.md)与[实施状态](docs/engineering/status-2026-11-10.md)。[PR #55](https://github.com/ckanner/scap/pull/55) 继续实现 Deleted 最后一代的显式永久退休，按新源码独立验收。自动 owner controller、PITR、完整资源预算、真实 AWS 和生产 SLO 尚未完成；历史 HEAD5 的结果单独保存在[上一批组合验收](docs/engineering/runtime-completion-validation.md)。

**最新增量：HEAD7 的冻结产品 `7b757` 已完成整批必需本地验收：stable/nightly 各 652 项单元、60 个生产文件四维精确覆盖，terminal retirement 的真实合同与 25 负/1 正对照，多代 GC 与 23 负/1 正对照，以及新的 native、HTTP、发现/部署恢复、资源、1 GiB 恢复和固定负载合同全部通过。** [PR #55](https://github.com/ckanner/scap/pull/55) 已合入 main `fab8ca0`；来源、原失败和分母见 [HEAD7 验收](docs/engineering/head7-runtime-validation.md)。

[PR #56](https://github.com/ckanner/scap/pull/56) 的 HEAD8 冻结产品 `3e85035` 已通过 stable/nightly 各700项单元、63个生产文件四维精确覆盖，SDK 92项单位及独立模型989正向/48负/3正对照；真实原生、1 GiB恢复、资源、终态回收和负载已通过。发现接口一次外部时限失败原样保留，同条件重验、owner V2专项和GC最终审计仍在执行，见[HEAD8验收](docs/engineering/head8-owner-plan-validation.md)。[PR #57](https://github.com/ckanner/scap/pull/57) 另行实现有限自动controller，其开发结果不替代HEAD8验收。

**2026-11-11 增量（均仍为草稿）：** HEAD8 `e3bdf7b` 修复真实 Missing 与新 HEAD 拼接造成的误 Corrupt；703 项 stable/nightly 单元、63 个生产文件四维精确覆盖通过，真实接管专项正在以 `dbd181c` 重验，原夹具失败保留。PR #57 修复 TLS/证书错误被当作 owner 失联的问题；Node 22.16.0 的150单元、20文件精确V8覆盖和19项loopback通过，独立控制器模型402正向/40负/3正对照正式通过（`76f5633`）。这些证据不代替多进程 controller/S3 联合验收。

PR #58 已实现 HEAD9 S1 候选：永久快照身份、capture/release、持久限额、多根 COPY/GC 及完整恢复校验、HTTP/Node接口。其[模型精化](docs/architecture/retained-snapshot-restore.md)独立验证804正向/47负/3正对照；冻结产品 `55140bf` 已通过783项stable/nightly单元、67个生产Rust文件四维精确覆盖、99项SDK单位、7项HTTP loopback、严格TypeScript及完整独立模型复验；同一release的15类原native故障合同与1 GiB恢复也通过，39个ACK、16,384个随机BLOB逐项零错配。证据见[S1单位](docs/evidence/snapshot-s1-unit-local-2026-11-11.json)和[原合同复验](docs/evidence/snapshot-s1-native-capacity-local-2026-11-11.json)。这些原合同没有调用快照API；新增[快照真实夹具](experiments/object-snapshot-runtime/README.md)已提交，专项运行、独立审计与负控仍须在其冻结提交上执行。S2跨Scope恢复、任意时间PITR、硬RSS/磁盘预算、AWS和生产SLO没有由S1交付。接口见[快照合同](crates/scap-service/docs/snapshots.md)。

对 SQLite/EFS/NFS 风险、单库写入上限、多库扩展与 Turso 方案的具体判断见[存储安全与吞吐分析](docs/architecture/sqlite-s3-safety-and-throughput.md)。S3 条件发布解决持久权威与旧写者 fencing；它不自动提高热点单库的串行事务吞吐。

历史 [HEAD5 组合候选](docs/architecture/head5-runtime-composition.md)的冻结运行时 `778a4d2` 已通过完整538+538单位、发现/metadata专项以及[六个实际native/S3网络子门禁](docs/evidence/head5-runtime-network-local-2026-11-09.json)。本轮目录为116场景、1,000次ACK零错配，保留结果为12场景/72入口；这些使用Rust worker与真实签名S3，不替代仍待完成的HTTP服务、容量/部署恢复、owner和资源门禁，也不接受后续编码器/输出池源码。该历史候选由 PR #54 承接；新运行结果与新发现以顶部记录为准。

[PR #35 的发现与恢复组合](docs/engineering/discovery-recovery-validation.md)包含 #34 的有界 LIST/单次 HTTP 传输，采用 HEAD format 4。冻结候选有 stable/nightly 各 416 项单元、47 个生产 Rust 文件四维逐文件精确覆盖、九个 HTTP/S3 组合阶段，以及无需预知名称或 Scope 的新部署恢复合同。完整恢复检查九个永久 HEAD 槽位和全部五个需要数据的数据库，独立 oracle 与 23 个拒绝负对照/一个正对照通过；目录原生和 1 GiB 全量恢复也通过，全部 16,384 行另从真实关闭镜像逐行二次哈希。原失败与输入等价复用另列；SQLite 所有已存在临时目录候选和 host-global override 的准入检查也已补齐。

[PR #31/#32 的名称目录与执行隔离验收](docs/engineering/catalogue-actors-validation.md)已经完成并合入：名称目录与 actor 组合分别有 stable/nightly 各 300/307 单元、33 个生产 Rust 文件四维逐文件精确覆盖；116 场景/1000 ACK 的目录合同、真实 HTTP/SDK、全计算丢失恢复及冷库阻塞下热库/控制隔离通过。两组原完整 validator 的末项 oracle 失败与磁盘容量导致的服务启动失败保留；精确两文件修正、输入身份复用和独立重跑见[机器记录](docs/evidence/catalogue-actors-local-2026-11-08.json)。HEAD 采用 format 3，不可变 SCAPOBJ2 帧仍为 format 2，旧 HEAD 不自动迁移。

[PR #30 的名称目录协议与有界模型](docs/engineering/named-catalogue-model.md)另有 885 条正向历史和 25 个拒绝负对照。模型、正式实现和真实网络证据互不代替；后续完整目录发现按[独立方案](docs/architecture/catalogue-discovery-plan.md)实施，其本地验收见上方 PR #35 记录。

[PR #29 的生命周期真实合同](docs/engineering/n1-lifecycle-validation.md)绑定冻结候选 `fe1909b`：十二场景、两轮恢复及独立原始账本复核通过；78 次成功响应／30 个原身份分别核对保留结果、Deleted 和 Retired，零错配。生产 Rust／SDK 与上一验收候选逐字节相同，历史单元证据与本批真实实验分开记录。

[PR #28 的本地执行目录防护验收](docs/engineering/local-storage-validation.md)绑定冻结候选 `a11e61e`：stable／nightly 各 204 项 Rust 单元、24 个生产文件精确覆盖，以及真实 S3/原生故障、HTTP/SDK 和 1 GiB 全量恢复通过。首次格式与 release 构建失败均保留；独立原始审计的可确认范围和服务恢复响应账本的限制分别列明。

[PR #27 的 HTTP／Node 完整本地验收](docs/engineering/http-service-validation.md)绑定冻结候选 `aa01150`：stable／nightly 各 199 项 Rust 单元、23 个生产文件四维逐文件精确 100%，真实服务核对 10 个唯一请求和 8 次重复成功响应。全部计算缓存丢失恢复、原网络故障合同、保留结果及 1 GiB 全量恢复均有独立证据。该历史结果不认证后续源码；名称目录、自动路由、完整 N1/N2、AWS 与生产 SLO 仍未完成。

[PR #26 的 ALTER 与保留结果完整本地验收](docs/engineering/native-integrity-validation.md)覆盖 main `49408e0` 上冻结的合并候选：159 项 Rust 单元，14 个生产文件四维逐文件精确 100%；同一 release 通过原网络 15 类合同（含 schema）、保留结果 12 场景／60 入口，以及 1 GiB 全量丢失恢复。全部 ACK 原 receipt／结果和 16,384 个 BLOB 无差异。10 GiB 该轮未复跑，AWS Standard 仍为 NOT_RUN；精确身份及计数见[机器证据](docs/evidence/native-integrity-local-2026-11-06.json)。

[PR #21 的历史故障验证记录](docs/evidence/s3-n1-fault-contracts-local-2026-11-06.json)绑定冻结提交 `75df1d20bcc8eb56ca758d8801eb3060a70a1687`：基础 10 类合同加 4 类扩展全部通过，扩展包含 30 个场景（其中 1 个为依赖序列 pilot）。实际验证了 14 个依赖上传切点、HEAD 成功后进程丢失及两种 native 失败、五类依赖的缺失／损坏、恢复期间 HEAD 变化；基础 4 条与扩展 61 条 execute ACK 的完整回执和原结果均一致。正式单元与四维覆盖再次通过；同一 release 二进制复跑 1 GiB 数据，39 条已确认请求及全部 16,384 个 BLOB 核对无差异。本批扩展实验、观察接口和 CI，不改变正式生产源码；完整 OT-01–OT-08 与 AWS 仍未完成。

[PR #20 的本地容量基线](docs/evidence/production-capacity-local-2026-11-06.json)绑定运行时提交 `a302840d3232163ae16c85ff384abaae82cb9ff5`：130 项 Rust 单元、13 个生产文件四维精确 100%，74 项工具单元、89 项模型测试和 10 项真实本地 S3/进程合同通过。同一 release 二进制完成 1 GiB 独立随机数据验收及默认 **10 GiB 实际 SQLite 文件边界**验收；后者恢复后逐条核对 **363 条 ACK、162,564 个 BLOB**，原回执、原结果和全部数据哈希均无差异。达到配额后同尺寸更新成功，新页面分配被拒绝且 HEAD 不变。后续文档提交不改变实测源码；AWS Standard、完整 N1 和生产 SLO 仍未完成。

[PR #19 的历史本地验证记录](docs/evidence/object-native-local-2026-11-06.json)：87 项 Rust 单元测试通过，11 个生产文件四维覆盖率精确 100%；release 构建的 10 项真实本地 S3/进程故障合同通过。4 条成功写入均由独立持久账本逐条核对原回执与原结果；AWS Standard 保持 `NOT_RUN`。

## SQLite 文件系统边界

S3 权威架构不依赖跨节点 POSIX 文件锁，也不将 `.db`、WAL 或 SHM 作为共享网络文件读写。本地执行镜像仍必须满足 SQLite 的 I/O 语义；误把 `cache_directory` 配成 NFS/EFS/FUSE 不能因“缓存可丢弃”而视为安全。

[PR #28](https://github.com/ckanner/scap/pull/28) 已完成本地目录类型防护、补充测试及必要本地回归，见[验收说明](docs/engineering/local-storage-validation.md)与[存储安全说明](docs/operations/sqlite-storage-safety.md)。最初环境不可用及后续失败仍保留在[审查记录](docs/engineering/status-2026-11-07.md)；当前结果只绑定本轮冻结候选。真实 NFS/EFS/FUSE 挂载、AWS 和生产门禁没有由本地分类测试代替。后续按[路线图](docs/engineering/roadmap.md)继续。

## 实现入口

| 模块 | 职责 |
| --- | --- |
| [scap-object](crates/scap-object/src/lib.rs) | HEAD/对象格式、权限、精确请求身份、提交/取消/关闭窗口、接管/激活、独立强读及名称目录 |
| [scap-object-store](crates/scap-object-store/src/lib.rs) | 真实签名 S3 exact GET、同响应 ETag、条件创建/替换、截止时间和错误分类 |
| [scap-object-sqlite](crates/scap-object-sqlite/src/lib.rs) | 固定 libSQL SQLite 内核、私有连接、提交前物理页拦截、结果缓冲和只读快照 |
| [scap-sql](crates/scap-sql/src/lib.rs) | 有界 SQL 参数、精确指纹和完整类型化结果编码 |
| [scap-service / scapd](crates/scap-service/README.md) | 认证 HTTP、严格请求解析、独立控制与目录线程、租户／数据库排队与显式恢复 |
| [Node SDK](sdk/node/README.md) | 固定原 SQL／目录／owner 意图、无损 typed SQL、验证回执及结果、查证／取消；静态 owner 路由与显式协调，不自动重放 SQL |

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

关闭窗口只变更引用。**HEAD6 的显式管理员 compaction 与退休世代 GC 已完成本批整栈本地验收，默认仍未启用 GC 权限。** 协议与严格边界见 [HEAD6 设计](docs/architecture/head6-compaction-gc.md)和[管理接口](crates/scap-service/docs/reclamation.md)。旧块、索引和 orphan 只有在安全迁移、退休及公平重复 sweep 后才能回收；当前文件配额不限制 bucket 总量。HEAD6 保护 Deleted 最后一代；PR #55 的 HEAD7 已独立验证显式 seal 后的终态退休。内部 Rust API 的 principal 是可信准入输入；HTTP 服务从 token 摘要映射得到可信主体，再由最新 HEAD 检查数据库权限。发现分页不等于数据恢复或自动 owner 协调；这些接口和合同分别记录。

HTTP 服务用不可变五元组接入，`create` 后显式 `activate`。每次服务启动使用新的 `worker_instance`；全部计算丢失后以原 scope 查 HEAD，再 `takeover`／`activate`。Node SDK 在发送前用 `prepare`／`save` 固定 SQL、参数、世代和请求 ID；超时或断线后用原身份 `lookup`／`cancel`。配置和启动命令见[服务说明](crates/scap-service/README.md)，完整恢复流程见[运行手册](docs/operations/http-service.md)。

可选 `RoutedClient` 使用受信静态路由，fresh status 后最多派发一次原业务请求；独立 READ+ADMIN
`OwnerClient` 保存固定意图，再显式协调 takeover 与 activation。每个管理步骤携带预期目标 worker，
错绑地址在 S3/cache/恢复效果前拒绝。恢复的意图只供查证，UNKNOWN 不自动重发管理动作或 SQL。
这一切片没有故障检测、后台自动接管或动态选主；整体 N2 和生产门禁继续独立推进，详见
[owner 协调设计](docs/architecture/owner-reconciliation.md)与 [SDK 合同](sdk/node/README.md)。

命名入口独立启用 `POST /v1/catalogue`。保存固定创建意图后显式推进到 Ready，再按相同 Scope 激活；目录 Ready 不等于 writer 已激活。取消只竞争未绑定的 Reserved，正常删除先保留永久 Deleted HEAD 再释放名称。名称重用产生新 Scope，已有 SQL 意图不会自动改目标。

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

## 设计与后续阶段

- [已接受的完整方案](docs/architecture/object-storage-native-proposal.md)、[ADR-0020](docs/adr/0020-object-storage-native-authority.md)。
- [首个原生实现与格式选择](docs/adr/0021-object-native-runtime.md)、[可配置容量与 v2 恢复布局](docs/adr/0022-production-capacity.md)。
- [认证 HTTP 与新 SDK](docs/adr/0023-authenticated-http-and-node-sdk.md)、[真实服务恢复合同](experiments/object-service/README.md)。
- [名称目录与永久身份](docs/adr/0024-named-catalogue-and-permanent-identities.md)、[目录协议与范围](docs/architecture/name-catalogue-plan.md)。
- [全目录发现与恢复方案](docs/architecture/catalogue-discovery-plan.md)、[分段索引、pin/GC 与 PITR 方案](docs/architecture/storage-reclamation-plan.md)。
- [路线图](docs/engineering/roadmap.md)、[故障矩阵](docs/operations/failure-matrix.md)、[运行说明](docs/operations/runbooks.md)。
- [协作要求](AGENTS.md)、[本地验证身份](docs/engineering/local-validation.md)。

本仓库不承诺生产 SLA、跨 AZ 或长期低成本结论；GiB 恢复只按实际候选实验报告范围描述。完整阶段退出以路线图及对应证据为准。许可证仍由维护者决定，第三方组件保留各自许可证。
