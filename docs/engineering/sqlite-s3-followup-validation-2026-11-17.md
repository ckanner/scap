# SQLite on S3：恢复、实例身份与连接池组合验证

日期：2026-11-17。完整组合见 [PR #65](https://github.com/ckanner/scap/pull/65)。
它汇集 #59 的 owner/controller/S1、#60 的完整 Manifest proof、#61/#62 的永久身份及
自动编号、#63 的 S2 恢复和 #64 的有界 S3 连接保留。

**本轮实现和本地验证已经形成可运行候选；保持 Draft，未合入 main。**
stable/nightly 各 877 个 Rust 单位通过，Node 161 项及其覆盖/负控、严格 TypeScript
和 Clippy 通过；严格 Rust 逐文件四维门禁仍失败，AWS、生产 IAM 和 SLO 尚未验收。
各项原始来源、失败和 NOT_RUN 见[机器记录](../evidence/sqlite-s3-followup-local-2026-11-17.json)。

## 1. 精确代码与证据身份

| 对象 | 标识 |
| --- | --- |
| 产品、单位与正式 release 源码 | 本地 `6915aa5d11d2e4a92baba23ad57c0edb4c17b49a` |
| 等价的远端组合代码 | `82f3b37d7b0d8a44b729e38a4d08e4367a116743` |
| 两者完整 Git tree | `2c7d906932acaf95a3fb6c6bc2a2401e1b4c29f6` |
| 789 个跟踪文件的 source fingerprint | `fc2f21bc9d81dee018feb7e0f4e1bf876caaed73985a3c11706e7d91821ea382` |
| 正式 release `scapd` SHA-256 | `b21935233b1e2234692795e79fa4e4e89de20b50f975eb2306c1d409bcf2801d` |
| 固定 libSQL revision | `d8bc862d20bedc72945a1da27c8b7045414c0261` |
| 实际 native archive SHA-256 | `ab0981f53ac70eeafa604624f6ee4fdff0754f8b9195c713be35e138a85ba3f5` |

源码在构建前冻结，在单位、Clippy 和 release 后复核。stable、fresh nightly coverage
和 release 使用不同的专属 target，没有从其他 worktree 取旧二进制。实际服务使用
正式 release，不含诊断 allocator 或 `/__profile` 路由。

`f0cf548` 只补齐两个独立诊断目录的 research-harness 分类：
`experiments/head-fingerprint` 和 `experiments/service-profile`。它们不是 workspace
成员、正式产品依赖或编译进单位目标的源码。原门禁失败保留；相同 profile 用新分类
再次检查后，只移除了这三个错误的 missing-map 项，没有任何 crate 生产排除项。

后续实际恢复夹具、审计和报告追加均单独记录来源；只有核实 Cargo、crates、构建输入
逐字一致才复用这份正式二进制。SDK 的 161 项/类型测试来自组合 preflight，之后全部
SDK 输入逐字相同。不能把不同候选的测试数量相加，也不声称远端 CI 已通过。

## 2. 已实现的产品能力

### S2：从明确保留点建立独立新库

四个入口 `prepare_restore`、`inspect_restore`、`resume_restore`、`abort_restore`
接入核心、元数据消费者、HTTP 与 Node SDK。固定意图与 Empty create 共用原 operation
的永久 first-winner 槽，避免重试生成第二个竞争目标。

源数据的 chunk/node/manifest 逐层在新 Scope 下重封装；单个私有 native 镜像完成
结构校验；源 ADMIN+READ 在最后稳定屏障重新检查。完成证明持久化后，新库可以独立
于源 payload 继续推进和恢复。每次控制推进最多一个 Name/HEAD CAS；取消、删除、
发现、恢复、S1、owner 和 GC 都识别新阶段。

目标使用新 ACL、sequence=0、未激活 writer 和空请求空间。源非确定 SQL 的结果不被
重放，原请求身份也不迁入新库。对原库的 UNKNOWN 仍使用原 lookup/cancel。

审查复现并修复了一个权威丢失问题：completion 还在、目标永久 HEAD 却物理缺失时，
不能把相同 Scope 当成从未创建。新有界 exact GET 检查区分合法并发创建和稳定丢失，
分别返回 Conflict/Corrupt，绝不采用新 ETag 或重新 provision。

恢复拥有独立 worker/queue/intake、每租户及全局 staging 预算和共享 recovery 槽；
copy 的 source GET、target PUT、readback 与镜像大小分别计账。HTTP 超时不提前归还
实际运行资源。PreparedProfile 在永久实例身份消耗之前校验并构造，后续使用本次
实际分配的数值 worker。staging 是逻辑准入，不是物理磁盘/RSS 硬配额。

详见 [S2 设计](../architecture/retained-snapshot-restore.md)、
[接口与配置](../../crates/scap-service/docs/restore.md)及
[专项验证](snapshot-restore-validation-2026-11-17.md)。

### 自动实例编号与永久防复用

`worker_instance` 支持显式十进制 ID 和 `"auto"`。管理员明确初始化高水位后，普通
启动用同一 S3 authority 的 exact GET/原 ETag CAS 取得新编号，再永久占用并精确回读。
只有明确竞争失败才进入更大新候选；UNKNOWN 不重读收养、不复用，空洞永久保留。

身份改变不代表数据库 owner 改变，也不自动更新静态 controller 路由。旧 guard
继续返回 TARGET_MISMATCH，数据库接管继续走当前 HEAD 的 owner 协议。历史上界、
旧进程停止、counter/marker 的 IAM 和生命周期保留是部署前提。

组合测试明确检查：无效 restore 配置产生零身份 I/O；在 claim 回读时删除本地 cache
会导致真实恢复 worker 构造失败，返回 CACHE_IO，同时保留已消耗的永久身份。
独立自动编号的详细结果见
[自动编号验证](worker-instance-allocation-validation-2026-11-17.md)。

### 实际热路径分析与有限连接修复

正式诊断分开记录 actor 排队、Engine、native publication、checkpoint、对象等待、
CPU、Rust 分配和实际 TCP 建连。证据支持把共享 S3 客户端每主机空闲连接从 2 保留到
固定 8；生产维持 FULL、受检 TRUNCATE、条件写、回读校验、原 deadline 和 ACK 顺序。

#64 的固定四库写对照中新建连接 83→4，减少 95.2%；两边都是 704 GET、384 PUT、
6,632,904 下载字节和 3,568,556 上传字节，全部原结果与六库完整行审计通过。
两波各四个真实 TCP/SigV4 请求的回归在旧 cap2 上明确失败，在 cap8 上通过。

这是连接保留行为的证据。诊断四库写 TPS 107.52→112.20，但四库读却
1446.07→1334.83；不宣称普遍吞吐提升。其旧 cap2 四库写对象等待占 Engine 约
84.7%，同库四 lane 的排队仍明显高于执行。单库 writer 串行与对象请求开销没有消失。
**历史 #60 的两次约 24% 回退仍未完成因果归因。**

这份诊断有自己的源码和二进制，不冒充 #65 的吞吐认证。全部正负样本、失败和计量
限制见 [热路径报告](service-hot-path-profile-2026-11-17.md)。

## 3. 组合验证

| 层次 | 本轮结果 | 证据边界 |
| --- | --- | --- |
| Rust stable 单位 | 877 passed，0 failed，0 ignored | `--workspace --lib`，专属 stable target |
| Rust fresh nightly 单位 | 877 passed，另有 0 项 main harness | `--lib --bins --all-features`，branch instrumentation，单线程 |
| Rust 分项 | object479、SQLite81、store45、service235、SQL37 | 单次完整候选的分母 |
| Clippy／format | 通过 | 全 workspace/all targets/features，`-D warnings` |
| Node SDK／类型 | 161 项、V8 精确逐文件门禁及负控通过，TS 通过 | Node22.16.0，TS5.9.3，@types/node22.16.0；输入相同 |
| 实际自动身份 | 18/18 场景通过 | 本组合正式 release、真实进程、签名本地 S3、native SQL |
| 实际显式 ID 兼容 | 10/10 场景通过 | 新证据目录，同一正式 release |
| 实际恢复与独立审计 | 7/7 场景、126 个定向反例通过 | 新冻结 fixture，原始 HTTP/S3/进程及精确结果分别核对 |
| Rust 严格四维覆盖 | **FAIL** | 4 个核心文件尚有未命中计数，8 个文件 branch 分母为零 |

Rust 单位、实际 daemon/S3 与诊断 profile 相互独立。实际后端为固定 SeaweedFS4.51，
SHA-256 `eb9adf3a75b53c32f5ad9ba856e1fb652dae03dc6f6222673c3f88c0cbd25d0e`；
本地兼容端点不是 AWS Standard 合同。

### 最终真实恢复与独立审计

恢复实际绑定 fixture/source `548a5ad5ab6f9adf79fb4154885497c319ce15d8`，tree
`6cc147dea222dd5c636be5f69f585592a8b1cc07`，793 个跟踪文件的 source fingerprint 为
`d0254348924f865fe2fa8c5193437d0133dfcdf152b7c99fd6af52aa71fba80b`。
相对构建候选只增加了覆盖分类和恢复实验/审计文件；239 个 Cargo/crate/SDK 受保护
输入逐字一致，所有实际构建输入没有改变。使用上述 b219352 正式 release，运行前后
完整源码、fixture/SDK/codec/shared helper 和三个二进制再次复核。

| 七项实际合同 | 独立审计核对 |
| --- | --- |
| 快照保留原随机值和多块 BLOB | 独立结果 decoder、SQL fingerprint、原 Result frame hash、64 位整数、行和 BLOB 精确匹配 |
| Empty/Restore 共用 first-winner | 原 operation、source、target、完整 DTO 与冲突响应 |
| 复制被挂起时取消 | control 独立推进、永久 aborted、迟到复制 Conflict、名称无法解析 |
| 源权限撤销 | 原 source/principal、实际 ACL 修改、复制 Denied、重新授权后全新复制 |
| HTTP 回复丢失并 SIGKILL 重启 | 完整原 UNKNOWN 意图、旧进程退出/cache 删除、新进程、无源 payload 重取、原随机结果 lookup |
| 完成后目标 HEAD 被删 | completion digest、真实 DELETE/404、两次 HEAD404 与同一 completion GET200、inspect/resume Corrupt、无重建 PUT |
| 源 payload 删除后独立冷读 | 全部已观察键的 DELETE/404、新进程与空 cache、目标精确行值和原名称绑定 |

最终运行 **7/7 场景、独立审计与 126 个定向反例全部通过**；其中 122 个语义反例
同步修复 frame/body hash 等外围 bookkeeping，另有 4 个缺失/序号/摘要结构反例。
4 项审计器 parser/decoder helper 测试通过。审计从 2,960 条原始观察中核对 59 次 SDK
调用、911 次产品 S3 调用、30 次管理员故障调用、14 个实际消失的源 payload 和 3 个
owned daemon；不读取 producer 的 PASS/cases 汇总作为判据，不导入生产 SDK/codec。

原始观察 SHA-256 为
`94c267a216d54092a1ee904748130670612731b899225d245ca5c37ad3b9a244`，
运行 input manifest SHA-256 为
`f6dfeda33a974153a692b5e588fb3aba567374f29ebaa8b8d918013f7eadbe7f`。
所有 daemon 与 backend 子进程的退出、cache 清理和输入未变均确认后，runner 才记录 PASS。
HTTP 丢回复在 SDK fetch 交付边界注入，已经收到的成功响应被丢弃；不是把它描述成新的
TCP-reset 合同。稳定 HEAD 丢失是真实 S3 DELETE；合法并发出现 HEAD 的 Conflict 分支
仍由核心单位反例覆盖，不扩写为该实际场景已经运行。

这是一份固定小库的本地兼容 S3 故障合同；没有密码学证明全部观察未被恶意重写，也
不提供 AWS、GiB 容量或生产 SLO 认证。实验入口和记录格式见
[恢复专项](../../experiments/object-restore-runtime/README.md)。

## 4. 严格覆盖仍阻断合入

| 生产文件 | 行 | 函数 | Region | Branch |
| --- | ---: | ---: | ---: | ---: |
| `catalogue/create.rs` | 126/127 | 4/4 | 244/245 | 14/14 |
| `catalogue/records.rs` | 243/243 | 23/23 | 368/369 | 62/62 |
| `catalogue/restore.rs` | 401/403 | 20/20 | 611/622 | 56/56 |
| `catalogue/restore_copy.rs` | 242/243 | 21/21 | 394/408 | 17/18 |

另外，原有 catalogue/types、object_frame、service/catalogue、lib、main、owner_wire、
snapshot_wire，加上新的 restore_wire，共 8 个文件没有正 branch 分母。不能把
region 覆盖当作 branch，也不能用别的文件的正分母填补。规则与原问题见
[分支测量说明](branch-coverage-measurement-gap.md)。

部分余项属于已验证不变量之后的冗余防御检查，部分仍是实际可发生但未完整触发的
本地 I/O、native 清理后超期等路径。没有把所有余项叫作不可达，没有伪造分支、排除
生产文件或降低精确 100% 要求。因此即使局部能力测试通过，也继续 Draft。

## 5. Turso 的采纳边界与接续目标

参考的是持久化顺序、分块对象、本地可丢弃缓存、恢复独立性、有界后台工作和完整
故障证据。SCAP 已以这些约束实现本轮恢复、身份及资源控制。Turso 的 Cloud 路径、
开源 libSQL 和新 Rust MVCC 引擎分别对照，没有把上游产品的 benchmark 或能力直接
当作 SCAP 的结果。

当前生产继续 FULL 与受检 TRUNCATE。NORMAL 在已运行的诊断里没有一致收益；OFF
会减少运行时本地写入错误观察，因此没有通过关闭同步换取表面速度。

| 后续工作 | 当前状态 | 进入下一阶段必须完成 |
| --- | --- | --- |
| 当前合入门禁 | 未满足 | 四个文件的故障/防御路径与逐文件 branch 计量；受影响的精确源验证 |
| 批量事务 / group commit | 单请求多语句已有；独立事务合批未实现 | 逐请求原身份/原结果、取消、批内失败、同一 HEAD 原子发布、最大等待和公平性 |
| lazy VFS / 按需读页 | 未实现，仍完整冷恢复 | 固定授权 root、页/frame 校验、缺页失败、GC 与代际、缓存/在途预算及 native gate |
| 同库并行 reader/MVCC | 未实现，writer 串行 | 新执行/冲突协议、隔离与 WAL-reset/恢复证明，不能靠加 pod 获得 |
| 动态 fleet | 自动 ID 已实现；成员/路由动态更新未实现 | 可信登记与撤回、旧 guard、owner 计划、UNKNOWN 收敛和停机资源 |
| 任意时间 PITR | 未实现；S2 是显式 retained point 恢复 | 连续历史、时间索引、保留、GC 保护和恢复验证 |
| 硬资源与长期成本 | 逻辑预算已有，OS硬限制未完成 | RSS/磁盘/FD、持续开环过载、冷启动风暴、重复 GC 和存储增长 |
| AWS 与生产 SLO | NOT_RUN | 固定 region/storage class/IAM/故障域/负载，实际条件写、恢复、p99 与成本 |

完整决策和协议门槛见 [Turso 接续方案](../architecture/turso-adoption-next.md)及
[交付计划](sqlite-s3-delivery-plan.md)。这些后续项目没有因本轮代码提交被标为完成。

## 6. 保留失败与未运行项

S2 初始 service fixture 的四个身份构造失败、首轮 Clippy warning、永久目标 HEAD
缺失的旧代码反例均保留。最初完整覆盖的 19 个失败项也保留；合法补齐诊断源码分类
后剩余 16 个失败项，仍退出 1。自动编号独立候选的早期五次夹具失败和 discovery
测试竞争详见其原报告，本次组合的 18/10 实际则分别使用新的目录完整执行。

恢复审计器也保留了一次真实 review 失败：初版75eb2e5 的实际 preflight 给出7场景/
28负控通过，但独立20变体审查发现19条身份/Scope/SQL等语义变体被错误接受。原
preflight 及19条漏检保留，不能作为最终资格。91af703 收紧每个 HTTP DTO、完整
UNKNOWN、source/target、caller、查询及 release/deleted 绑定；相同原baseline继续
通过，相同20变体由独立审查者全部拒绝，继而冻结新fixture并完整执行上述新的实际。
原review与独立修正复核的 SHA-256 分别为
`b62450cc10447730290bb1889657f87f3f15db47d847df44dbc44820c04410b0` 和
`c7777557fdf75361a37ef4cf7334101350ce90858a3af876d0a4806ab892ea27`。

日志、运行配置、凭据、数据库和诊断原始档案没有进入 Git。仓库保存结构化观测、
源清单、原始 artifacts 的 hash、命令、失败原因和可复现实验源码。

本候选的旧 GiB 容量与全部历史 native/network 合同没有完整重跑；其余 NOT_RUN
包括 AWS/IAM/历史迁移、真实网络挂载矩阵、跨故障域恢复、持续过载、硬隔离、长运行
成本和生产 SLO。不能将历史候选的通过、单位、模型、诊断或本地 S3 相互替代。
