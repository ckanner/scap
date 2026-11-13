# 新对象架构实施路线

> 2026-11-13 接续：执行环境已恢复，旧原件缺失的门禁正在重新采集；当前结果见
> [本轮代码与验证](sqlite-s3-review-2026-11-13.md)。本轮发现并修复检查器允许单文件
> branch 0/0 的缺口，严格逐文件覆盖门禁仍未满足，PR 继续 Draft；见
> [测量说明](branch-coverage-measurement-gap.md)。以下保留 11–12 日的原计划与历史结果，
> 其中“环境不可用”“只余两项”及旧 checker PASS 不代表当前状态。


按 [PR #16](https://github.com/ckanner/scap/pull/16) 推进 SQLite on S3。对象存储是唯一持久权威，
SQLite 只使用本地私有执行镜像；旧 Raft 原型和 PR #17 不构成兼容或实现前置。

## 当前阶段

更新：2026-11-12（UTC）。本组合的主线基准为 HEAD7 `fab8ca0`（#54/#55）。
[PR #59](https://github.com/ckanner/scap/pull/59) 的组合起点 `fc10287` 汇集 #56 `1d709db`、
#57 `df922b95` 与 #58 `4216523`，当前仍为Draft。执行环境在服务回归中断后被明确标为
不可用；剩余门禁未完成，不能因代码齐备或部分实际通过而合入。

| 阶段 | 当前实现与已取得的证据 | 尚需完成的退出条件 |
| --- | --- | --- |
| N0 协议与格式 | SCAPOBJ2、HEAD6/7复制/GC/seal；组合HEAD8 owner-plan/HEAD9 retained roots；完整Rust/SDK单位与精确覆盖、新native/1 GiB和固定controller矩阵通过 | 本批HEAD6完整负控与终态退休门禁；模型及固定本地合同不替代全部产品出口 |
| N1 单库真实提交 | Rust/S3/native commit gate、强读、原结果查证/取消、增量页树、Session、可调配额与本地全计算丢失恢复 | 真实AWS Standard、完整OT合同与对应部署故障域 |
| N2 多库接入 | HTTP/SDK、目录/发现、按库actor、控制/恢复/intake/output期限；owner-plan与固定12场景controller实际/31负控通过 | 动态fleet、在线策略变化、持久实例identity分配、持续过载、冷启动风暴、公平性、硬RSS/磁盘 |
| N3 可持续存储 | HEAD6复制/持久sweep、HEAD7终态seal；HEAD9 S1保留根及多根COPY/GC实际/10负控通过 | S2新Scope恢复、任意时间PITR、长期保留/GC成本；冷恢复优化另验 |
| N4 首发 | 已有绑定提交的本地容量、故障与固定负载记录 | 冻结目标后端/IAM/故障域与开环负载，实测吞吐、p95/p99、错误、恢复与成本，再判断非关键试运行条件 |

新执行stable/nightly各783项单位、67个生产文件四维精确覆盖、157项SDK单位／21模块
精确覆盖、严格类型及19项HTTP/TLS/CLI loopback；owner两专项、原生产controller合同、
S1及固定负载均保留自己的冻结源码，见[组合验收](sqlite-s3-integration-validation.md)。
这些数字不是产品完成率，历史HEAD7、owner与S1单位不能相加。

接续的 `3b1d50c` 完整native／schema／原结果／生命周期／目录／发现与固定1 GiB全冷
恢复、独立审计已通过，见[native记录](../evidence/sqlite-s3-integration-native-local-2026-11-12.json)。
`6784258` 修正S2模型完成屏障的权限顺序，新38项自测及804正例／48负控通过；产品S2
仍未开放，见[模型记录](../evidence/sqlite-s3-integration-models-local-2026-11-12.json)。

`e64eb56` 的[固定12场景controller矩阵](../../experiments/object-controller-matrix/PLAN.md)
完成23项自测、12项实际历史、独立oracle及31项定向负控。runtime仍是 `fc10287`，
277项release输入相同；57项Node/SDK/codec与观察器输入绑定冻结源码、实际路径和摘要。
原 `73a7140` 结果及其源码绑定审计缺口保留，新结果不回填旧历史，见
[矩阵记录](../evidence/sqlite-s3-integration-controller-matrix-local-2026-11-12.json)。

### 本批合入门禁

| 本轮回归 | 当前结果与剩余工作 |
| --- | --- |
| Rust／SDK／类型及原release来源 | 已通过；文档与夹具接续没有改变生产代码 |
| native与固定1 GiB | 实际、独立审计及指定负控通过 |
| controller固定矩阵 | 20个controller、108个受管子进程、586 HTTP（363 controller）、1914 S3；24 ACK+12 UNKNOWN、36原lookup及12快照全部核对 |
| 服务短合同 | HTTP、隔离、分段、发现、metadata、输出、expiry、资源和GC transport通过 |
| HEAD6组合 | actual和独立oracle退出0；完整23负控／1正控没有完成，原会话失联，不能拼接部分结果 |
| HEAD7终态组合 | 本轮实际／独立oracle／25负控与1正控完整闭环未完成 |

**当前阻断是执行环境不可用和最后两项验收缺失。** 中断事实与准确恢复入口见
[组合验收](sqlite-s3-integration-validation.md#执行环境中断与恢复入口)。恢复后先核对
原件、源码和存活进程；在新证据目录完成原门禁。门禁齐备再读取精确PR head/main并合入，
不修改分支保护，不把本地结果称为远端CI通过。

## 接续实施顺序与验收

详细设计、合入边界和出口统一维护在[交付计划](sqlite-s3-delivery-plan.md)。

1. 先收口#59剩余HEAD6负控和终态合同，按完整本地证据合入owner／controller／S1。
2. 实现S2新Scope恢复：固定复制意图、有界跨Scope对象重封装、完整native校验、源权限
   完成屏障、CompletionRecord、Name/HEAD取消与恢复、HTTP/SDK；不继承源owner、ACL
   或请求空间。任意时间PITR需要独立日志保留与恢复合同。
3. 按实际账本优化对象往返和副本，比较已有SQL batch；补持续开环过载、唤醒风暴、
   租户公平性、资源总账和长期GC。同库仍串行，冷恢复仍完整加载；group commit、
   lazy VFS、同库读池或MVCC引擎需独立设计。
4. 固定目标AWS/兼容后端、权限/密钥与部署故障域，执行真实条件写、恢复、长期成本及
   预先冻结的数字SLO。Express One Zone不能只靠checkpoint到Standard承诺跨AZ RPO=0。

本轮单库C1/C4写为5.149/2.822次每秒，四库C4写7.206次每秒，每写约18–20个对象请求。
它是含观察开销的小规模本地基线，未做同环境历史对照，热点吞吐仍未达到产品目标。
动态fleet、在线策略与持久实例分配另行验收；当前部署必须提供不复用的
`worker_instance`，数值guard不等于进程身份认证。

完整设计与代码映射见[安全与吞吐](../architecture/sqlite-s3-safety-and-throughput.md)、
[owner计划](../architecture/accepted-owner-plan.md)、[控制器](../architecture/owner-controller-plan.md)和
[快照／恢复](../architecture/retained-snapshot-restore.md)。历史失败继续保留；AWS与生产SLO
保持NOT_RUN，完整目标不以测试数或默认容量代替阶段退出。

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
