# 新对象架构实施路线

按PR16从零推进，旧原型与PR17不构成兼容或实现前置条件。

| 阶段 | 当前工作与退出条件 |
| --- | --- |
| N0 协议与格式 | 已有有界模型、独立历史判定及 v2 严格分块格式；冻结预算和真实API，保持语义与实现一致 |
| N1 单库真实提交 | Rust 权威、S3 adapter、native gate、强读/取消/接管、可配置 10 GiB 默认及 Session 已合入；已有本地精确单元、兼容 S3、全计算丢失、1/10 GiB 容量及选定提交／冷恢复故障验收。完整 OT-01–OT-08 与 AWS Standard 仍待完成，尚未达到 N1 整体退出 |
| N2 多库接入 | 已实现 token 主体鉴权、严格 HTTP/Node SDK、固定数据库 lane、有界租户／数据库轮转、独立控制执行、显式 reader 与两 daemon 条件创建；已通过[冻结候选的真实 HTTP/S3、全计算恢复及独立审计](http-service-validation.md)。名称目录协议与[有界模型验收](named-catalogue-model.md)已完成指定范围；[正式目录](../architecture/name-catalogue-plan.md)仍待产品验收；自动 owner 路由、完整冷热点隔离与预定义负载活性仍待完成，尚未达到 N2 整体退出 |
| N3 可持续存储 | 数据树已支持增量路径；请求索引分段、增量冷恢复、compaction、pin、GC、PITR仍待完成；验证多轮回收安全及总成本收敛 |
| N4 首发 | MB/GiB、长尾/热点/唤醒风暴、长运行、故障域、性能恢复成本与运维；另行获准后用非关键数据试运行 |

本轮不以原Raft的538测试或旧SLO观测认证新实现。实际门禁失败保持阻塞，缺失环境记NOT_RUN；不将单库或本地兼容后端的容量实测包装为整个阶段完成。

## 2026-11-07 后续工作与阻断

主线 `e2c44b0` 已合入 #26／#27；#22／#23 已由 #26 替代。仍开放的 #17 属于已废弃的 Raft 架构，不是对象路线的实现前置。

本地执行目录防护（PR #28）已完成冻结候选 `a11e61e` 的必要本地验收：204 项 Rust 单元、24 个生产文件精确覆盖、真实 S3/原生故障、HTTP/Node 与 1 GiB 恢复，见[完整记录](local-storage-validation.md)。最初环境失联、fmt 与 release 构建失败如实保留；真实挂载、AWS 及完整阶段退出另列。后续十二类生命周期合同已进入 [PR #29](https://github.com/ckanner/scap/pull/29)，修正版 `fe1909b` 的十二场景、完整响应／进程账本、两轮恢复和独立原始审计已通过，见[验收记录](n1-lifecycle-validation.md)。完整 N1 和 AWS 仍有独立门禁。

继续顺序：

1. 本地目录防护及精确覆盖／原生／服务／1 GiB 门禁已完成本轮本地验收，保留原始失败与验证范围；已合入主线 `3f011e5`，合并 tree 与已验证交付 tree 一致。
2. [生命周期与退休真实合同](n1-lifecycle-validation-plan.md)的 LC-01–LC-12 已完成本地验收；已通过 PR #29 合入主线 `84225c7`，其他 OT 组合与真实 AWS 单独验证。
3. 按[名称目录协议](../architecture/name-catalogue-plan.md)已完成冻结模型的 885 条正向历史／25 个负对照，继续实现固定创建意图、Provisioning、Reserved→Aborting 与 Bound 的竞争、永久 HEAD 身份屏障、删除/重用及逐切点恢复，接入 HTTP／SDK。Bound 后取消不在初版合同内；完整枚举恢复另有门禁，不能用已知名称名单替代。
4. 自动 owner 路由、冷恢复隔离与负载活性验收。
5. 请求索引分段、pin／generation／持久 GC 计划、PITR 和多轮成本收敛。
6. 真实部署故障域、长运行与预先冻结的生产 SLO 验收。

当前 Maintenance 允许强读，不能直接当成 GC 冻结屏障；必须先补读取／恢复保护和旧操作 fencing。默认 10 GiB 是逻辑数据库配额，不约束 bucket 总占用。
