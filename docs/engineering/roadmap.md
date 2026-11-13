# 新对象架构实施路线

按 [PR #16](https://github.com/ckanner/scap/pull/16) 推进 SQLite on S3。对象存储是唯一持久权威，
SQLite 只使用本地私有执行镜像；旧 Raft 原型和 PR #17 不构成兼容或实现前置。

## 当前阶段

更新：2026-11-13（UTC）。执行环境已经恢复；本轮重新构建和执行缺少原始记录的
必要合同。主线、候选实现和验证工具各自保留身份，当前状态见
[本轮代码与验证](sqlite-s3-review-2026-11-13.md)。

| 代码范围 | 当前状态 |
| --- | --- |
| main `fab8ca0`（#54/#55） | 已合入 HEAD6 代际复制／持久 sweep 与 HEAD7 Deleted 终态 seal |
| [PR #59](https://github.com/ckanner/scap/pull/59) 的生产基线 `b15bc45` | 组合 HEAD8 owner-plan、有限 controller 与 HEAD9 S1 retained snapshots；继续 Draft |
| #59 验证接续 `8a5bd65`／`642383c` | 修正单文件 branch 0/0 检查与 service discovery 请求接收见证；分别保留工具源码、构建输入和新实际身份 |
| [PR #60](https://github.com/ckanner/scap/pull/60) 的生产候选 `fd508cc` | 已实现一次事务内消费已验证 Manifest 的私有证明，减少重复 GET；继续 Draft，吞吐回退尚未排除 |

**当前不能签发整体 merge-ready。** 两份 Rust 基线的单位测试均通过，但 67 个生产
文件中有 7 个只报告 branch 0/0；其他文件的正分母不能替它们提供分支证明。修复后的
检查器按现行规则拒绝这两份报告，未修改 `AGENTS.md` 或覆盖门槛。已发出计数全部
命中不等于逐文件四维覆盖已满足，详见[测量缺口](branch-coverage-measurement-gap.md)。

| 阶段 | 当前实现与已取得的证据 | 尚需完成的退出条件 |
| --- | --- | --- |
| N0 协议与格式 | SCAPOBJ2、HEAD6/7 复制／GC／seal、HEAD8 owner-plan 与 HEAD9 retained roots 已有代码；新 HEAD6 与终态全套实际／oracle／原负控通过 | 关闭逐文件分支测量缺口，按受影响源码重新核对组合门禁；模型与局部合同不替代整体出口 |
| N1 单库真实提交 | Rust/S3/native commit gate、强读、原结果查证／取消、增量页树、Session、逻辑配额和本地全计算丢失恢复；本轮 b15 固定 1 GiB 与完整原结果／BLOB 独立审计通过 | 真实 AWS Standard、完整 OT 合同及部署故障域另验；1 GiB 不认证默认 10 GiB 或任意容量 |
| N2 多库接入 | HTTP/SDK、目录／发现、按库 actor、控制／恢复／intake／output 期限；owner-plan、isolation、Missing、单 controller 与固定 12 场景矩阵已重新通过；新 `642383c` service discovery 完整验收通过 | 动态 fleet、在线策略、持久实例身份、持续过载、公平性与硬资源隔离 |
| N3 可持续存储 | HEAD6 持久 sweep、HEAD7 终态 seal；HEAD9 S1 保留根和多根 COPY/GC 实际／10 负控／1 正控通过 | S2 新 Scope 恢复、任意时间 PITR、长期保留／GC 成本；冷恢复优化另验 |
| N4 首发 | 已有绑定源码的本地故障与负载记录；Manifest 请求数减少取得两组对照证据，吞吐未取得一致收益 | 冻结目标后端／IAM／故障域与开环负载，实测吞吐、p95/p99、错误、恢复及成本，再判断非关键试运行条件 |

本轮 b15 的 stable/nightly 各 783 项、fd508 的各 791 项 Rust 单位通过；b15 的 SDK
157 项、codec 13 项、HTTP/TLS/CLI loopback 19 项及类型／工具／固定模型另有记录。
这些结果不补足 Rust 未被计数的分支，也不是产品完成率，历史候选的单位数不能相加。

### 本批合入门禁

| 本轮回归 | 已完成的范围与仍需判定的部分 |
| --- | --- |
| Rust／SDK／类型及 release 来源 | 新构建与单位结果各自绑定源码；严格逐文件分支门禁仍失败，不能标为四维 100% |
| b15 native／恢复 | 网络、schema、retained results、生命周期、116 目录案例、listing、bounded response、deployment discovery 已重新通过；固定 1 GiB 原实际、新全 BLOB／关闭镜像独立审计、5 负控及原正控完整通过 |
| b15 owner／controller／S1 | owner-plan 新完整实际／42 负控／1 正控、Missing 13／1、单 controller 15／1、S1 10／1 与固定矩阵通过；owner-plan 首轮 seed 失败独立保留 |
| 固定 controller 矩阵 | 12 场景、23 项夹具自测、31 负控；本轮原矩阵在负控前后独立复核。20 controller、108 受管子进程、586 HTTP（363 controller）、1,914 S3；24 ACK＋12 UNKNOWN、36 原 lookup、12 快照全部核对 |
| b15 原 13 项服务合同 | 原首轮为 11 项通过、isolation 与 service discovery 失败；新增 isolation 完整实际／21 负控／1 正控通过后，b15 共 12 项取得完整通过记录。资源与 42 例 GC transport 已包含，不能重复计数 |
| 新观测来源的 service discovery | 冻结 `642383c`、新正式 service 的完整 actual／oracle／32 负控及原正控通过；424 HTTP、25,278 S3；保留 b15 原失败，不合算成 b15 原 13 项全部通过 |
| HEAD6 组合 | 第二次完整 actual、独立 oracle、全部 23 负控／1 正控通过；首轮原 180 秒 hold 超时失败保留 |
| HEAD7 终态组合 | 本轮 actual、独立 oracle、25 负控／1 正控完整通过；固定 HEAD6/7 场景不替代 HEAD9 retained-root 的交错合同 |
| PR #60 的优化 | 原正确性合同与两组配对 actual／oracle／14 负控／3 正控通过；请求数减少已证实，吞吐回退尚未排除 |

已完成的 isolation、owner-plan 与 `642383c` service discovery、固定容量的完整状态由
[本轮 review](sqlite-s3-review-2026-11-13.md#2-验证状态与证据归属)逐项维护；本页不把
原父分组的 FAILED 改成整体 PASS，也不将新实际回填到其他源码。旧原件未恢复的记录仍保留
历史身份；已经提交的摘要与 hash 不能代替缺失的 HTTP／S3／ACK、构建或 profile 原件。
环境中断本身已不是当前阻断，当前也不再是“只余 HEAD6 两项”。

必要门禁全部满足后，重新核对精确 PR head/main 与最终 tree，再按既有授权合入。
当前两 PR 均保持 Draft；不修改分支保护，不把本地结果改称远端 CI 通过。

## 接续实施顺序与验收

详细设计、合入边界和出口统一维护在[交付计划](sqlite-s3-delivery-plan.md)。

1. 先关闭严格分支测量缺口，按精确源码审查已完成的 #59 本批合同及其完整原件；
   单位通过、HEAD6／终态通过均不能单独触发合入。#60 另须解释已观测的吞吐回退。
2. 实现S2新Scope恢复：固定复制意图、有界跨Scope对象重封装、完整native校验、源权限
   完成屏障、CompletionRecord、Name/HEAD取消与恢复、HTTP/SDK；不继承源owner、ACL
   或请求空间。任意时间PITR需要独立日志保留与恢复合同。
3. 对 #60 先隔离测量 actor／native／对象／响应等待，定位请求数减少而吞吐下降的原因；
   按实际账本优化对象往返和副本，比较已有 SQL batch。补持续开环过载、唤醒风暴、
   租户公平性、资源总账和长期GC。同库仍串行，冷恢复仍完整加载；group commit、
   lazy VFS、同库读池或MVCC引擎需独立设计。
4. 固定目标AWS/兼容后端、权限/密钥与部署故障域，执行真实条件写、恢复、长期成本及
   预先冻结的数字SLO。Express One Zone不能只靠checkpoint到Standard承诺跨AZ RPO=0。

本轮两组同环境配对使用相反执行顺序，均完成原实际、独立 oracle 和 14 负控／3 正控。
两组各自三个 phase 合计精确减少 160 个 Manifest GET（32／64／64），其他对象类别
请求计数相同；这证明指定负载下减少了请求数，不证明端到端性能收益。第一组 rate
混合，四库下降 24.00%；反向组单库 C1 为 7.838→6.442、同库 C4 为 6.356→5.538、
四库 C4 为 12.272→9.262 次／秒（下降 24.52%）。翻转顺序没有排除回退，下一步是
定位等待与资源成本，不用反复运行小样本替代分析，也不由此给出生产 SLO。

动态fleet、在线策略与持久实例分配另行验收；当前部署必须提供不复用的
`worker_instance`，数值guard不等于进程身份认证。

完整设计与代码映射见[安全与吞吐](../architecture/sqlite-s3-safety-and-throughput.md)、
[owner计划](../architecture/accepted-owner-plan.md)、[控制器](../architecture/owner-controller-plan.md)和
[快照／恢复](../architecture/retained-snapshot-restore.md)。历史失败继续保留；AWS与生产SLO
保持NOT_RUN，完整目标不以测试数或默认容量代替阶段退出。

## 历史：2026-11-11 至 12 日组合检查点

PR #59 的早期组合 `fc10287` 汇集 #56 `1d709db`、#57 `df922b95` 与 #58 `4216523`。
当时 `3b1d50c` 的 native／schema／原结果／生命周期／目录／发现与固定 1 GiB 冷恢复
报告通过，见[当时的 native 记录](../evidence/sqlite-s3-integration-native-local-2026-11-12.json)。
`6784258` 修正 S2 模型完成屏障的权限顺序，记录 38 项自测、804 正例／48 负控；
产品 S2 未开放，见[模型记录](../evidence/sqlite-s3-integration-models-local-2026-11-12.json)。

`e64eb56` 的[固定 controller 矩阵](../../experiments/object-controller-matrix/PLAN.md)
当时完成 23 项自测、12 项实际历史、独立 oracle 与 31 负控。其 runtime 来源仍为
`fc10287`，277 项 release 输入相同，57 项 Node/SDK/codec／观察器输入独立绑定；
原 `73a7140` 的源码绑定审计缺口未被回填，见
[当时的矩阵记录](../evidence/sqlite-s3-integration-controller-matrix-local-2026-11-12.json)。
当时的本地负载为单库 C1/C4 5.149/2.822 次每秒、四库 C4 7.206 次每秒、每写约
18–20 个对象请求，不能跨环境与本轮配对直接比较。

这些历史记录保留原提交、计数和退出码；其中部分原始执行文件未恢复，本轮已按所需
范围重新采集。下列各历史段中的“精确覆盖／四维覆盖”也仅指当时 checker 与编译器
已发出的计数，不构成现行严格规则要求的完整分支证明；不能据此绕过本轮 branch 0/0
阻断。旧失败不改写，新实际不回填旧候选。

## 历史：2026-11-10 实施顺序

以下保留当时的实施顺序；后续合入及本组合状态以上方为准。当日提交和结果见[实施状态](status-2026-11-10.md)及[组合验收](runtime-completion-validation.md)。
当时 HEAD6 `66f452e` 的 632+632 单位、59 文件覆盖报告、新 native/1 GiB、HTTP/资源/GC与负载
本地结果见[独立新记录](head6-runtime-validation.md)；覆盖仅对应当时已发出的计数。
下述 d60 是已完成但后来发现语义缺口的历史基线。PR #54 已承接 HEAD5 运行时组合，
冻结 `d60ea98` 完成 580+580 单位、57 个生产文件的当时四维计数报告和新的
native/HTTP/S3/1 GiB 合同。`6e107a1` 只修正 owner/discovery
反例构造，原实际历史和正向 verdict 不变。旧失败继续保留；不是把失败标记改为成功。

独立审查发现的核心 retained nonce 语义验证缺口，已与 HEAD6 共享 verifier 一起修复，
并在新冻结候选完成精确单位与受影响真实合同；没有复制旧 profile 或用 SDK 拒绝代替
core fail-closed。完整世代、闭包、checkpoint、迟到 GET/PUT/CAS/DELETE 和原结果合同
均已通过，PR #54 进入合入收尾。

当前 PR #55 正在独立验收 Deleted 终态退休；之后依次完成可恢复 owner controller、显式快照/PITR、完整资源和
冷恢复压力，再进入真实 AWS 与预先冻结的生产 SLO。执行存储始终为经过准入的本地
私有镜像，不把 SQLite 活动文件挂载到 NFS/EFS/S3 FUSE。

## 历史：2026-11-09 实施顺序

当日状态见[历史记录](status-2026-11-09.md)。HEAD5 的部署、service/TCP、owner、资源、
GC transport 与 discovery 当时尚未完成组合；`4329f30` discovery actual01 在续页传输
边界失败。该失败保持原样，后续精确构造修正与新实际候选由 2026-11-10 记录承接，
不能把新结果回填为旧候选成功。

## 历史：2026-11-08 实施顺序

当时主线已合入 #31/#32，原始失败及精确修正见[历史验收记录](catalogue-actors-validation.md)。本批 #35 的冻结 tree 与发布文件全部相同，416 项单元、47 个生产文件当时已发出的四维计数报告、新部署恢复和九个服务组合阶段见[该次验收记录](discovery-recovery-validation.md)。这些覆盖数字不补足当前分支测量缺口；当时也没有将 AWS、生产 SLO 或 N1–N4 整体标记通过。

1. [全目录发现方案](../architecture/catalogue-discovery-plan.md)：本批已实现有界原始 LIST/分页、正式全状态发现器、主体绑定 cursor 的 HTTP/SDK 和无需预知名字/Scope 的全计算丢失恢复合同；本地验收按冻结输入归属，普通在线分页不承诺跨 key 快照。
2. 自动 owner 路由与恢复协调；扩展 actor 的热点、公平性、唤醒风暴和资源压力合同，保留同库串行与控制预留。
3. [持续存储方案](../architecture/storage-reclamation-plan.md)：先分段请求索引，再独立 storage generation/head serial/pin/freeze，随后真实物理回收和显式快照/PITR。暂停 pin 未安全解除就阻止 GC，迟到 PUT 后重复 sweep；物理删除尚未开启。
4. 在真实目标后端及部署故障域上运行预先冻结的性能、恢复、成本和长运行 SLO；按既有范围另行获准后才进行非关键业务试运行。

当时记录的 owner 路由与 storage generation 独立候选属于历史开发进度；无法取得的候选不能继承到本轮。该日期的实现/目标/未运行项见[历史状态记录](status-2026-11-08.md)。

## 历史：2026-11-07 后续工作与阻断

最新核对主线 `d63f41e` 已合入 #28／#29／#30，#31 为正式名称目录开发草稿；此前 #26／#27 已合入，#22／#23 已由 #26 替代。仍开放的 #17 属于已废弃的 Raft 架构，不是对象路线的实现前置。

本地执行目录防护（PR #28）当时记录冻结候选 `a11e61e` 的必要本地验收完成：204 项 Rust 单元、24 个生产文件的已发出计数覆盖报告、真实 S3/原生故障、HTTP/Node 与 1 GiB 恢复，见[完整记录](local-storage-validation.md)。该覆盖报告不替代现行严格分支证明。最初环境失联、fmt 与 release 构建失败如实保留；真实挂载、AWS 及完整阶段退出另列。后续十二类生命周期合同已进入 [PR #29](https://github.com/ckanner/scap/pull/29)，修正版 `fe1909b` 的十二场景、完整响应／进程账本、两轮恢复和独立原始审计已通过，见[验收记录](n1-lifecycle-validation.md)。完整 N1 和 AWS 仍有独立门禁。

继续顺序：

1. 本地目录防护及精确覆盖／原生／服务／1 GiB 门禁已完成本轮本地验收，保留原始失败与验证范围；已合入主线 `3f011e5`，合并 tree 与已验证交付 tree 一致。
2. [生命周期与退休真实合同](n1-lifecycle-validation-plan.md)的 LC-01–LC-12 已完成本地验收；已通过 PR #29 合入主线 `84225c7`，其他 OT 组合与真实 AWS 单独验证。
3. 按[名称目录协议](../architecture/name-catalogue-plan.md)已完成冻结模型的 885 条正向历史／25 个负对照，并通过 PR #30 合入主线 `d63f41e`。正式固定创建意图、Provisioning、Reserved→Aborting 与 Bound 的竞争、永久 HEAD 身份屏障、删除/重用和 HTTP／SDK 候选正在执行精确覆盖与逐切点验收，见 [ADR-0024](../adr/0024-named-catalogue-and-permanent-identities.md)。Bound 后取消不在初版合同内；完整枚举恢复另有门禁，不能用已知名称名单替代。
4. 自动 owner 路由、冷恢复隔离与负载活性验收。
5. 请求索引分段、pin／generation／持久 GC 计划、PITR 和多轮成本收敛。
6. 真实部署故障域、长运行与预先冻结的生产 SLO 验收。

当前 Maintenance 允许强读，不能直接当成 GC 冻结屏障；必须先补读取／恢复保护和旧操作 fencing。默认 10 GiB 是逻辑数据库配额，不约束 bucket 总占用。

执行环境中断时，#31 的正式核心与逐切点门禁尚未完成；该时点的源码恢复与顺序保留在[恢复清单](named-catalogue-recovery-2026-11-07.md)。后续完成结果以上方 2026-11-08 记录为准，不把当时的开发检查点或部分模块结果当作 N2 退出。
