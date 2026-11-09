# Takeover / Policy 的纯元数据发布

本文只涉及现有 HEAD5、storage.active_generation=1、allocated_through=1。
它不启用新世代、pin、回收、物理 DELETE 或新的管理动词。

## 1. 管理 ACK 的含义

takeover 和 set_policy 从新鲜 exact HEAD 检查当前 ADMIN 和调用方给出的业务
expected_revision，然后只发布管理字段。成功路径在 Objects 端口是一次 HEAD GET
和一次原 ETag 条件 PUT，不再为了这两个操作额外读取 manifest。

管理 ACK 表示该候选 HEAD 已条件发布。它不证明数据完整、数据库可以恢复或已经
可以写入。takeover 仍将 active 设为 false，之后 Activate 必须经过原来的完整
数据/历史验证与 fresh HEAD equality barrier。set_policy 不修改 data_root、
SQLite image 或 retained request windows。

这明确改变了管理操作顺便验证数据的行为：如果这个 Database handle 尚未观察到
manifest 缺失或损坏，仍可完成 fencing 或 ACL 修改；后续需要该数据的操作按原规则
失败。两个操作都不修复依赖、不改变旧根，也不把新 HEAD 当作健康证明。

## 2. 封闭构造，不能传入任意候选

core 的私有 MetadataUpdate 只有 Takeover 和 Policy 两个变体。publish_metadata
使用 Database::next 克隆原 HEAD，增加 business revision 与 head_serial，并构造
相同 nonce 的 transition；随后只允许以下差异：

| 变体 | 额外修改字段 |
| --- | --- |
| Takeover | checked owner_epoch +1；owner_instance=本 worker；active=false |
| Policy | checked auth_epoch +1；替换 policy |

其他字段全部继承原 HEAD，包括 format、完整 Scope、storage、data_root、sequence、
windows、request_epoch、retention、quota、creation、deletion 和 lifecycle。
两个分支不能在一次调用里同时修改 owner 和 policy。不存在接受任意 next Head 的
管理快捷入口，也没有供 quota、cancel、Delete 或 Complete 使用的额外变体。

原 control 的 ADMIN、lifecycle 和 expected_revision 检查保持；takeover 还要求 Ready。
checked counters 在首个 healthy 检查之前计算，保持已有错误优先级。严格 encode_head
继续验证 nonce、policy 和完整 HEAD 格式。

## 3. 健康状态、原条件和 UNKNOWN

发布仍检查 healthy 两次：在编码候选前一次，紧接原条件 PUT 前一次。该 handle
或 clone 已观察到的 immutable 缺失/损坏不会因为管理操作成功读取 HEAD 而被清除。
没有跳过 quarantine 的管理权限。

最后一次检查由原有依赖发布与这两个管理分支共同调用的私有 publish_healthy
执行。它只消费已经捕获的 PreparedHead，不构造候选，也不接受任意 Head；管理
候选仍只能从封闭 MetadataUpdate 构造。原路径在 manifest GET 期间观察到 clone
的故障时，同一个最后检查会拒绝 HEAD PUT。

现有 quarantine 是本地 handle 与 clones 的发布阻断，不是跨 worker 的持久 fence，
也不禁止所有读取；例如原结果仍可通过 lookup 查询。缓存淘汰和 Catalogue 新构造
的 Database 不等同于保留了另一 handle 的健康状态。

PreparedHead 捕获原 backend、完整 HEAD key、原 ETag、编码后的候选与原 absolute
deadline。发布只消费它一次：

- 并发更新先赢，原条件失败，返回 Conflict；不换 ETag、不 rebase。
- 条件 PUT 返回 UNKNOWN，原操作保持 UNKNOWN；可能已经生效，也可能尚未生效。
- 不额外执行 post-PUT HEAD GET，不把 PUT receipt 合成为新的 Snapshot。
- 原截止时间不续期；原 SQL 请求也不会因这个管理改动自动重放。

两个 healthy 检查不构成覆盖远程 I/O 的全局锁；本片没有声称取消最后检查之后才
发生的并发错误观察。

## 4. 保留原路径的操作

Activate、activate_session、Provisioning Complete、quota、cancel、close_full、
SQL commit，以及所有 lifecycle/Delete/AbortFence 分支继续使用原有路径。
其中配额需要实际 page_count，创建/业务写要持久化并回读新依赖，激活与 Complete
需要完整闭包。这些操作不能仅因为也会写 HEAD 就套用纯管理发布。

将来如为逻辑删除另做 metadata-only 路径，需要单独审查其精确构造和 Name/Control/
Proof 永久屏障；不存在 HEAD 的 AbortFence 仍需 bootstrap 依赖。本文没有改变这些
协议或错误码。

## 5. 验证目标

单元验证审计实际 HEAD-only 端口调用、原条件/deadline、完整字段差异集合、
UNKNOWN 的两种持久结果、两个原发布候选的竞争顺序、原计数/错误优先级，以及
管理 ACK 后 Activate/冷读仍拒绝缺失 manifest。共享 clone 的真实缺失观察继续
覆盖两个管理入口的 quarantine 阻断。

源码、工具、二进制和实际服务验收证据需随发布 commit 单独绑定；上述单位验证
不等同于真实 S3/HTTP、吞吐基准或生产 GC 验收。
