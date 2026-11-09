# 新对象架构实施路线

按PR16从零推进，旧原型与PR17不构成兼容或实现前置条件。

| 阶段 | 当前工作与退出条件 |
| --- | --- |
| N0 协议与格式 | 已有有界模型、独立历史判定及 v2 严格分块格式；本批分段索引使用 HEAD 4，保持不可变帧 2；冻结预算和真实 API，保持语义与实现一致 |
| N1 单库真实提交 | Rust 权威、S3 adapter、native gate、强读/取消/接管、可配置 10 GiB 默认及 Session 已合入；已有本地精确单元、兼容 S3、全计算丢失、1/10 GiB 容量及选定提交／冷恢复故障验收。完整 OT-01–OT-08 与 AWS Standard 仍待完成，尚未达到 N1 整体退出 |
| N2 多库接入 | token 主体鉴权、严格 HTTP/Node SDK、名称目录、有界 actor、独立控制及全目录发现已合入；PR #37–#39 增加资源生命周期、HTTP 传输上界、静态 owner 路由和显式接管意图。自动故障探测与 controller、更多负载下的公平性及活性仍待完成，尚未达到 N2 整体退出 |
| N3 可持续存储 | 数据树增量路径和分段请求索引已实现；旧 storage generation/head serial 本地候选无法取得，不计入当前实现。正在先建设原 Snapshot 捕获的对象上下文与独立模型；generation、pin/freeze/drain、增量冷恢复、物理 GC、PITR 及长期成本收敛仍待完成 |
| N4 首发 | MB/GiB、长尾/热点/唤醒风暴、长运行、故障域、性能恢复成本与运维；另行获准后用非关键数据试运行 |

本轮不以原Raft的538测试或旧SLO观测认证新实现。实际门禁失败保持阻塞，缺失环境记NOT_RUN；不将单库或本地兼容后端的容量实测包装为整个阶段完成。

## 2026-11-09 当前实施顺序

当前可取得的提交、已通过的精确源码门禁及缺项见[实施状态](status-2026-11-09.md)。
先完成资源/TCP/owner 组合验收，再以不可变对象上下文作为 generation/pin 的前置。
删除传输 capability 与产品 GC 分开，GC 在 pin、退休命名空间和真实故障门禁完成前关闭。

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
