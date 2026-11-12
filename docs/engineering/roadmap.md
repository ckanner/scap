# 新对象架构实施路线

按 [PR #16](https://github.com/ckanner/scap/pull/16) 推进 SQLite on S3。对象存储是唯一持久权威，
SQLite 只使用本地私有执行镜像；旧 Raft 原型和 PR #17 不构成兼容或实现前置。

## 当前阶段

已合入主线的基准为 HEAD7 `fab8ca0`（#54/#55）。[PR #59](https://github.com/ckanner/scap/pull/59)
的组合起点 `fc10287` 汇集 #56 `1d709db`、#57 `df922b95` 与 #58 `4216523`；
这些来源已经提交，不能因代码齐备或原分支单位通过就将新组合标成已验收。

| 阶段 | 主线及候选已实现 | 尚需完成的退出条件 |
| --- | --- | --- |
| N0 协议与格式 | SCAPOBJ2、HEAD6/7复制/GC/seal已在主线；组合HEAD8 owner-plan/HEAD9 retained roots，完整Rust/SDK单位和精确覆盖新执行通过 | 完整受影响native/容量/资源/GC历史矩阵及跨协议交错；模型和局部实际合同不能替代全部产品出口 |
| N1 单库真实提交 | Rust/S3/native commit gate、强读、原结果查证/取消、增量页树、Session 与可调配额；多轮本地故障及全计算丢失恢复已有证据 | 真实 AWS Standard、完整 OT 合同与对应部署故障域，不能把本地兼容存储推成生产保证 |
| N2 多库接入 | HTTP/SDK、目录/发现、按库actor、控制/恢复/intake/output期限；持久owner-plan与有限controller的本次自动接管、重启、原结果合同通过 | 多controller竞争与完整故障矩阵；实例identity分配；持续过载、冷启动风暴、公平性、资源总账与硬RSS/磁盘边界 |
| N3 可持续存储 | HEAD6完整复制/持久sweep和HEAD7 Deleted终态退休已合入；HEAD9 S1保留根、多根COPY/GC专项实际及10负控通过 | S2从保留根恢复新Scope、任意时间PITR、长期保留/GC成本；整库冷恢复优化需另验证 |
| N4 首发 | 已有绑定提交的本地容量、故障和固定负载记录 | 冻结目标后端/IAM/故障域与开环负载，测长期吞吐、p95/p99、错误、恢复、成本；按既有范围另行启用非关键业务试运行 |

**本次列出的组合本地合同已通过，PR #59仍为Draft。** 新执行stable/nightly各783项单位、
67文件精确覆盖、157项SDK/21模块精确覆盖、类型和19项loopback；owner两专项、生产
controller实际/15负控、S1实际/10负控及固定负载实际/14负控+3正控均完成。
完整归属、原失败和审计缺口修正见[组合验收](sqlite-s3-integration-validation.md)。
历史HEAD7、owner、S1单位数字各自保留，不能相加。本轮单库C1/C4写5.149/2.822次每秒、
四库C4写7.206次每秒，含本地观察开销且不是生产容量；热点吞吐没有完成目标。
AWS与生产SLO没有运行，完整历史矩阵、资源和产品出口仍是独立工作。

## 接续实施顺序与验收

当前合入门禁与后续产品目标的分界、每阶段实现内容和验收出口，统一维护在
[接续交付计划](sqlite-s3-delivery-plan.md)。先完成 #59 必需的组合回归与 controller
实际矩阵，再合入这个有界的 owner／controller／S1 切片；S2、生产吞吐和 AWS 另行交付，
不把尚未实现的后续目标混记为本批功能，也不省略本批实际需要的验证。

1. 当前组合已冻结并完成单位/精确覆盖、Node/类型及本次owner/controller/S1局部实际合同；
   补齐完整受影响native/容量/资源/GC历史矩阵及交错验收后，再按仓库门禁判断合入。
2. 在本次持久owner专项和生产CLI重启接管合同之上，完成多controller竞争与其余故障矩阵：旧实例未退出、目标替换、
   prepare/claim/resume 丢响应、重启推进、取消与迟到请求、权限撤销，以及 TLS 配置错误。
   部署仍须提供不复用的 `worker_instance`；数值 guard 不代表进程身份认证。
3. S1捕获/释放、永久身份、多根COPY、GC/删除与冷恢复专项已通过；补充完整交错后，
   实现S2新Scope恢复和目录completion/cancel/discovery，不复活源权限、owner或请求空间；
   任意时间 PITR 需要独立日志保留和恢复合同。
4. 按实测账本减少对象往返和副本，验证 SQL batch 的收益；补持续过载、唤醒风暴、资源隔离和长期GC。
   同库仍串行提交、冷恢复仍完整加载。group commit、lazy VFS、同库读池和更换MVCC引擎须独立设计，
   不能预先记为本轮性能收益。
5. 在真实目标 AWS/兼容后端运行原条件写、权限/密钥故障、恢复与预先冻结的数字SLO；
   Express One Zone 不是跨AZ持久层，不能只因 checkpoint 到 Standard 就承诺跨AZ RPO=0。

完整设计与代码映射见[安全、并发和吞吐说明](../architecture/sqlite-s3-safety-and-throughput.md)、
[owner计划](../architecture/accepted-owner-plan.md)、[控制器](../architecture/owner-controller-plan.md)和
[保留快照／恢复](../architecture/retained-snapshot-restore.md)。已合入基座证据见
[HEAD6](head6-runtime-validation.md)、[HEAD7](head7-runtime-validation.md)；缺失环境记NOT_RUN，
原失败保持原样，完整目标不以测试数或容量配置代替阶段退出。

## 历史：2026-11-10 实施顺序

以下保留当时的实施顺序；后续合入及本组合状态以上方为准。当日提交和结果见[实施状态](status-2026-11-10.md)及[组合验收](runtime-completion-validation.md)。
最新 HEAD6 `66f452e` 的 632+632 单位、59 文件精确覆盖、新 native/1 GiB、HTTP/资源/GC与负载
全部本地门禁见[独立新记录](head6-runtime-validation.md)；下述 d60 是已完成但后来发现语义缺口的历史基线。
PR #54 已承接 HEAD5 运行时组合，冻结 `d60ea98` 完成 580+580 单位、57 个生产文件的
逐文件四维精确覆盖和新的 native/HTTP/S3/1 GiB 合同。`6e107a1` 只修正 owner/discovery
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

主线已合入 #31/#32，原始失败及精确修正见[历史验收记录](catalogue-actors-validation.md)。本批 #35 的冻结 tree 与发布文件全部相同，416 项单元、47 个生产文件四维精确覆盖、新部署恢复和九个服务组合阶段见[当前验收记录](discovery-recovery-validation.md)。没有将 AWS、生产 SLO 或 N1–N4 整体标记通过。

1. [全目录发现方案](../architecture/catalogue-discovery-plan.md)：本批已实现有界原始 LIST/分页、正式全状态发现器、主体绑定 cursor 的 HTTP/SDK 和无需预知名字/Scope 的全计算丢失恢复合同；本地验收按冻结输入归属，普通在线分页不承诺跨 key 快照。
2. 自动 owner 路由与恢复协调；扩展 actor 的热点、公平性、唤醒风暴和资源压力合同，保留同库串行与控制预留。
3. [持续存储方案](../architecture/storage-reclamation-plan.md)：先分段请求索引，再独立 storage generation/head serial/pin/freeze，随后真实物理回收和显式快照/PITR。暂停 pin 未安全解除就阻止 GC，迟到 PUT 后重复 sweep；物理删除尚未开启。
4. 在真实目标后端及部署故障域上运行预先冻结的性能、恢复、成本和长运行 SLO；按既有范围另行获准后才进行非关键业务试运行。

当时记录的 owner 路由与 storage generation 独立候选属于历史开发进度；无法取得的候选不能继承到本轮。该日期的实现/目标/未运行项见[历史状态记录](status-2026-11-08.md)。

## 历史：2026-11-07 后续工作与阻断

最新核对主线 `d63f41e` 已合入 #28／#29／#30，#31 为正式名称目录开发草稿；此前 #26／#27 已合入，#22／#23 已由 #26 替代。仍开放的 #17 属于已废弃的 Raft 架构，不是对象路线的实现前置。

本地执行目录防护（PR #28）已完成冻结候选 `a11e61e` 的必要本地验收：204 项 Rust 单元、24 个生产文件精确覆盖、真实 S3/原生故障、HTTP/Node 与 1 GiB 恢复，见[完整记录](local-storage-validation.md)。最初环境失联、fmt 与 release 构建失败如实保留；真实挂载、AWS 及完整阶段退出另列。后续十二类生命周期合同已进入 [PR #29](https://github.com/ckanner/scap/pull/29)，修正版 `fe1909b` 的十二场景、完整响应／进程账本、两轮恢复和独立原始审计已通过，见[验收记录](n1-lifecycle-validation.md)。完整 N1 和 AWS 仍有独立门禁。

继续顺序：

1. 本地目录防护及精确覆盖／原生／服务／1 GiB 门禁已完成本轮本地验收，保留原始失败与验证范围；已合入主线 `3f011e5`，合并 tree 与已验证交付 tree 一致。
2. [生命周期与退休真实合同](n1-lifecycle-validation-plan.md)的 LC-01–LC-12 已完成本地验收；已通过 PR #29 合入主线 `84225c7`，其他 OT 组合与真实 AWS 单独验证。
3. 按[名称目录协议](../architecture/name-catalogue-plan.md)已完成冻结模型的 885 条正向历史／25 个负对照，并通过 PR #30 合入主线 `d63f41e`。正式固定创建意图、Provisioning、Reserved→Aborting 与 Bound 的竞争、永久 HEAD 身份屏障、删除/重用和 HTTP／SDK 候选正在执行精确覆盖与逐切点验收，见 [ADR-0024](../adr/0024-named-catalogue-and-permanent-identities.md)。Bound 后取消不在初版合同内；完整枚举恢复另有门禁，不能用已知名称名单替代。
4. 自动 owner 路由、冷恢复隔离与负载活性验收。
5. 请求索引分段、pin／generation／持久 GC 计划、PITR 和多轮成本收敛。
6. 真实部署故障域、长运行与预先冻结的生产 SLO 验收。

当前 Maintenance 允许强读，不能直接当成 GC 冻结屏障；必须先补读取／恢复保护和旧操作 fencing。默认 10 GiB 是逻辑数据库配额，不约束 bucket 总占用。

执行环境中断时，#31 的正式核心与逐切点门禁尚未完成；该时点的源码恢复与顺序保留在[恢复清单](named-catalogue-recovery-2026-11-07.md)。后续完成结果以上方 2026-11-08 记录为准，不把当时的开发检查点或部分模块结果当作 N2 退出。
