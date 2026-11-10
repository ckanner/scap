# 新对象架构实施路线

按PR16从零推进，旧原型与PR17不构成兼容或实现前置条件。

| 阶段 | 当前工作与退出条件 |
| --- | --- |
| N0 协议与格式 | 已有严格 SCAPOBJ2 格式、有界模型与独立历史判定；主线 #35 为 HEAD4。PR #54 的 HEAD6 生产候选已接通可中止普通操作、多世代复制与持久 GC checkpoint，按新源码单独验收 |
| N1 单库真实提交 | Rust/S3/native commit gate、强读/取消/接管、默认 10 GiB 配额、增量页树与 Session 已实现。#54 的 HEAD6 修复 retained nonce 校验缺口，完成全部新单位、native 故障、原结果、生命周期和 1 GiB 全计算丢失恢复；目标 AWS Standard 与完整阶段退出仍单列 |
| N2 多库接入 | 鉴权 HTTP/SDK、名称目录、有界 actor、独立控制/恢复、全目录发现、显式 owner 协调、intake/output/HTTP 期限已实现。#54 输出竞争、慢消费者、HTTP discovery、guarded status、owner 故障与固定多库负载全部本地门禁已通过；自动故障探测/controller、完整资源总账、开放到达/长期压力仍待完成 |
| N3 可持续存储 | HEAD6 core/store/service/SDK 已实现完整复制、单调退休、专用有界 GC 与重启 checkpoint，新单位、真实暂停故障、独立判定与23反例全部完成。PR #55 已提交 Deleted 最后 active generation 的终态退休实现，继续独立验收；显式 retained roots/PITR、增量冷恢复和长期成本收敛仍未完成 |
| N4 首发 | 真实目标 backend/IAM/故障域、MB/GiB、长尾/热点/唤醒风暴、长运行与性能/恢复/成本 SLO；另行获准后用非关键数据试运行 |

本轮不以原 Raft 的 538 测试或旧 SLO 认证新实现。门禁失败与新发现都保留，
缺失环境记 NOT_RUN；不将本地兼容后端的容量实测包装为整个阶段完成。

## 2026-11-10 当前实施顺序

当前提交和结果见[实施状态](status-2026-11-10.md)及[组合验收](runtime-completion-validation.md)。
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
