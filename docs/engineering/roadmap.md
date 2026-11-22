# 新对象架构实施路线

按 [PR #16](https://github.com/ckanner/scap/pull/16) 推进 SQLite on S3。对象存储是唯一持久权威，
SQLite 只使用本地私有执行镜像；旧 Raft 原型和 PR #17 不构成兼容或实现前置。

## 当前阶段

更新：2026-11-22（纽约）。#65/#66/#67/#68 已合入，审查基线为主线 `3be8be7`。
[PR #68](https://github.com/ckanner/scap/pull/68) 已合入默认关闭的
[独立事务 group commit](../architecture/independent-group-commit.md)，
真实逐事务 staging、每成员版本/原结果和一次原 HEAD CAS 已接通服务调度。
本地完整冻结验证已有 stable/nightly 各 969 项单位、82 个生产文件四维精确 100%，
正式服务的七阶段合同、28 份冷恢复原结果及 40 项审计负控通过。
验证来源见[本轮记录](group-commit-validation-2026-11-20.md)，远端状态见
[#68 checks](https://github.com/ckanner/scap/pull/68/checks)。下表 #66 的计数保留历史归属。

本轮 #69 处理 actor/control/reader/catalogue/recovery 在 worker panic 时的实际资源
归还顺序，新候选 stable/nightly 各 971 单位、82 文件四维精确覆盖与真实组提交合同
复测通过，并补组提交开关的固定开环配对，
新验证与范围见 [11 月 22 日复核](sqlite-s3-review-2026-11-22.md)。
该本地四轮配对已完成：640 个测量原事务、独立审计与 25 项负控通过。竞争样本
成功吞吐增加 5.43% / 21.18%，第一对成功数下降，低载无组；默认开关保持关闭。

| 范围 | 当前状态 | 保留的出口 |
| --- | --- | --- |
| 组合单位与代码质量 | #66 stable/nightly 各 911 单位、77 个 Rust 生产文件逐文件四维精确 100%；Node 182 单位、22 模块精确 V8、HTTP/CLI/类型通过；合并提交24/24 jobs成功 | 新变更使用自己的验证；历史失败不改写 |
| N0/N1 权威与提交 | 原 HEAD CAS、完整依赖回读、原结果、native publication、owner fencing、取消及 UNKNOWN 均保留 | AWS Standard 与部署故障域另验；有限本地合同不代表任意容量与云端合同 |
| N2 多库与身份 | actor、永久启动 ID、owner/controller、同库读池、有限策略历史/在线退役、真实 cgroup/tmpfs 准入与开环分窗进展合同均已合入 | 全局 fleet 共识/自动扩缩容、无限历史、每租户硬隔离、冷启动风暴另验 |
| N3 保留与恢复 | S1 retained roots 与完整 S2 新 Scope 恢复已实现；新 release S2 7 场景/126 负控通过，源 payload 删除后目标仍独立 | 任意时间 PITR、长期 GC/保留成本、冷恢复优化 |
| 吞吐与首发 | 有界 S3 idle pool 8 保留；#60 GET 省略候选关闭归档；固定单事务/SQL batch 与开环观察已合入 | 原约 24% 下降没有被宣称已解决；group commit 本轮实现并单独验收，跨库 WAL、lazy VFS、新 MVCC、AWS/SLO 仍有出口 |

四项实际分别有冻结候选与原件记录，内核合同来自真实 systemd/cgroup/tmpfs runner。
首轮 CI 的 GC region 与独立实验 lockfile 问题已修复；过载大 ZIP 改用保留全部硬链接
的归档交付。#66 的 PR 验收 tree 与合并主线 tree 均为 `8c1a7b2f`；本轮远端复核再次确认
主线全部 CI 成功。新代码不沿用这些历史计数作为自己的通过结果。

## 接续实施顺序与验收

详细方案与边界见[交付计划](sqlite-s3-delivery-plan.md)。

1. #67 参数绑定与 #68 同库独立事务组提交已合入；#69 修复五条通道的 panic 资源归还，
   并按新的完整代码候选采集精确覆盖、实际 HTTP/S3、进程故障和原字节审计。
   默认仍为单请求路径。
2. 配对测量组提交在目标后端的实际收益；所有原失败和负值保留。FULL、受检 TRUNCATE
   与最终 Manifest exact GET 保持，不以延后持久确认或删回读交换吞吐。
3. 根据单库/多库/冷启动瓶颈继续跨库对象打包、lazy VFS、PITR；新 MVCC 引擎、全局
   fleet 共识、自动扩缩容、每租户硬隔离和长期 GC 均需各自协议与故障合同。
4. 固定目标 AWS/兼容后端、IAM、故障域和数字 SLO，实际验证条件写、全计算丢失、
   长期成本与恢复。Express One Zone 故障域不能由 Standard checkpoint 改写。

本地活动 `.db/WAL/SHM` 始终私有，S3 仅通过对象 API 承担跨节点权威，详见
[存储安全与吞吐](../architecture/sqlite-s3-safety-and-throughput.md)、
[owner 计划](../architecture/accepted-owner-plan.md)、
[控制器](../architecture/owner-controller-plan.md)与
[S1/S2 设计](../architecture/retained-snapshot-restore.md)。Turso 的实践与采纳边界见
[接续设计](../architecture/turso-adoption-next.md)，其基准不能作为 SCAP 的性能证据。

历史报告保留原源码、工具、失败与已取得结果。旧原件缺失不由摘要或当前绿色补足，
不同候选的测试数不相加；AWS 与生产 SLO 保持 NOT_RUN。

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
