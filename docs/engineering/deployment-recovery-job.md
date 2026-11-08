# 部署根冷恢复作业

状态：N2-D 开发中的正式协调器。本文描述产品边界，不替代真实全计算丢失、独立原始输入／ACK／wire 分母和冻结候选验收。AWS Standard 合同尚未由本地端点证明。

## 产品路径

`catalogue::RecoveryJob` 在正式 `scap-object` crate 中协调恢复。输入只有 Objects、Listings、可信 deployment capability、可信 `TenantReaders` 身份映射、运行选项、总预算和绝对 deadline；没有已知名称、Scope、对象键或数据库数量参数。实验只装配这一正式路径。

作业从 deployment 根开始调用 `RecoveryInventory`。每次 `step` 最多分类一个候选；只有永久物理 HEAD 触发数据恢复，因此历史 Name/Create/Control/Proof 不会造成同一槽重复物化。内部状态只有固定深度 inventory 前沿、一个可空 pending Scope、累计计数和 deadline，不收集全部署 Scope 集合。

有权的元数据分类不等于 SQL READ。对于实际发现的 tenant，`TenantReaders` 从可信配置选择主体；映射缺失、主体没有当前 READ 都返回 `PermissionBlocked`，保留 pending Scope。既不从 descriptor.creator 推断主体，也不把 ADMIN、provision 或 inventory 能力当 READ。普通用户列名仍使用独立的 `VisibleNames` 合同。

## Ready + Maintenance 恢复 profile

每个需要恢复的槽重新读取完整 HEAD。命名槽复用正式 descriptor 来源、`Binding → Proof → HEAD → Binding` 稳定视图和目录分类；direct 槽验证实际完整身份。首次发现后的永久 HEAD 丢失是 Corrupt，不能退为 orphan。

对 Ready 和 Maintenance，在该新观察的 HEAD 上检查当前 READ，然后调用正式 `Database::restore`、`verify_results`：完整 data-tree 逐块认证和落盘、所有保留请求窗口及 Result 原字节验证、native SQLite 结构检查。结束时再次 exact GET HEAD，必须与选定版本的 body 和 ETag 相同。过程中不 activate、takeover、改 ACL、重放 SQL 或续作控制。对象包装器拒绝 PUT。

Provisioning 与 Deleted 的数据不属于本 profile 的可读数据恢复集合，但必须保留完整来源、生命周期及已有删除／取消屏障分类。Reserved、descriptor-only、Aborting、仅准入控制和 orphan 都按原有协议报告，不能被包装成空 Ready 库。原 ACK 的退休或删除解释由独立历史审计验证，不能从 ACK 分母中消失。

成功的 step 可交付一个 `RecoveredDatabase`，它只提供固定可信主体的 fresh READ query，没有 execute／activate 方法。句柄持有唯一 image lease；未丢弃它时下一 step 返回 Busy。native Session 关闭并清理私有目录后才释放 lease。最多一个活跃 native image；清理失败可能留下不可作为权威的本地 orphan，不声称故障情况下硬限制磁盘总占用。

## 失败与前沿

元数据分类与数据恢复分别累计。读取 Unknown、Corrupt、权限不足、本地目录失败或物化后的 HEAD 变化均不能清除未恢复槽；下一 step 明确重新验证同一个 pending Scope。只会在该槽的数据验证成功，或被当前严格元数据证明确认为 profile 不要求恢复的状态后，完成其数据前沿。

目录页内已分类前沿与一个 pending Scope 共同构成有界内存状态。它不是可重放的客户端 budget token。作业不提供持久 checkpoint resume；进程丢失后创建新作业，从 deployment 根重新扫描。原进程的预算或完成结果不能被声称跨进程继承。

`recovery_complete` 表示这次作业的有序前缀发现已结束，全部已分类物理槽按此 profile 完成，且没有 pending 或当前失败。它是逐槽验证点的覆盖记录，不是整个部署在一个共同瞬间的健康快照，也不是未来持续可用的承诺。完成后的再次取结果不重新验证所有数据库。

## 固定总预算

以下是单作业上限及默认值，允许调低，不能调高；并行度固定为 1。

| 资源 | 上限 | 计数范围 |
| --- | ---: | --- |
| LIST 请求 | 4,096 | 所有 tenant 与阶段，含失败和重新读取 |
| 候选 | 65,536 | 包括 tenant 前缀、目录记录、数据库前缀、pending 重试 |
| exact GET | 1,048,576 | metadata、data tree、request index、Result、结束 HEAD 及返回句柄的 fresh query |
| LIST bytes | 4 GiB | 成功的原始 LIST body；失败保留请求前的 1 MiB 预留 |
| metadata bytes | 512 MiB | HEAD 与 catalogue 成功 body；失败保留该次 bounded GET allowance |
| data bytes | 64 GiB | 其他 exact GET 的成功 body，包括对象 envelope；失败保留该次 allowance |
| 作业 deadline | 1 小时 | 所有 step 共用，调用者可设置更早的绝对 deadline |
| 活跃 native image | 1 | 物化和交付句柄共享同一个 lease |

计数跨 step 累计，没有隐藏重试或计数重置。每个目录调用还受 `RecoveryInventory` 单页预算及 5 秒限制；完整数据恢复使用独立的 `Options.recovery_timeout`，不会被包装成 5 秒列表 API 的性能承诺。

bytes 是保守的**预算消耗**，不是全部 HTTP 流量的精确计量。Objects 错误不携带已传输 body 长度；保留 allowance 不等于实际 S3 错误体大小。S3 guard 的错误体独立上限、HTTP 头、TLS、重传和 RSS 不由这些字段测量；实际 wire 成本必须另读原始网络证据。

每次 native restore、保留结果验证前后及最后 HEAD 比较后都检查同一有效 deadline。native progress interrupt 不能保证抢占 fsync 或阻塞系统调用；合同只保证超时不会交付新 healthy image 或将本次作业标为 complete，不宣称硬实时终止。

现有 exact Objects port 无独立 Denied 变体，S3 GET 403 保留 Unknown 并阻止前沿推进；LIST 的 typed Denied 则保留为 StorageDenied。两者都不能作为普通 READ 过滤项跳过。对象大小限制与作业限额均明确为 Limit，不模糊改报 Corrupt。
