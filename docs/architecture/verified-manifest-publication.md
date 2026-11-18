# 在一次提交内复用已验证的 Manifest

状态：继续 Draft。生产／测试候选冻结于 `fd508cc`，对照基线为 PR #59 的 `b15bc45`。
2026-11-13 已同步 #59 的严格 checker、观测／容量审计工具与最终验证文档；这些提交
不改变原 receipt、profile 或 actual 的来源，也不宣称同步后的新 HEAD 已经全套运行。
本改动只减少业务提交中的一次重复对象读取，不改变 HEAD 格式、公开 API、持久化顺序或
单库串行语义。

两组相反顺序的完整固定负载及全部原独立 oracle／14 负控／3 正控均完成：每组测量
写入阶段少 160 个 Manifest GET，其他对象类别请求计数相同；但四库写入速率分别
下降 24.00% 和 24.52%，稳定吞吐收益没有证据，回退原因尚未定位。严格逐文件 branch
证明也未满足，当前不合入。完整账本、采样限制及下一步有界 profile 见
[性能验收](../engineering/verified-manifest-load-validation.md)；各冻结源码与容量／
discovery 等独立结果见[本轮 review](../engineering/sqlite-s3-review-2026-11-13.md)。

## 2026-11-17 接续决定

本页保留为独立 [PR #60](https://github.com/ckanner/scap/pull/60) 的设计草稿。新的
[历史诊断](../engineering/manifest-proof-causal-2026-11-18.md)没有关闭原性能回退阻断；
功能组合 #65 将恢复普通 `publish_in` 的 exact Manifest GET，并移除专用 proof 热路径。
下文描述未获合入验收的候选设计，不代表功能版已经启用它。有界 S3 idle pool 8
有独立合同，保留不受本拆分影响。

## 问题与范围

`Database::commit` 调用 `data_tree::update` 时，已读取并验证原 Manifest；有页变化时，
更新后的 Manifest 还经过不可变对象条件创建和完整字节回读。原实现返回根 hash 后，
`publish_in` 又顺序 GET 同一个 Manifest，检查它的页数是否超过当前配额。

这第二次 GET 增加一次对象往返。新的私有证明只复用**本次操作中已经完成的校验**，
没有持久缓存、跨调用缓存或跳过第一次 readback。已有请求的结果查证、强读和管理操作
不进入这个快速发布路径。总体瓶颈和既有本地数据仍见[安全与吞吐分析](sqlite-s3-safety-and-throughput.md)。

## 证明的产生和消费

`data_tree::update` 返回字段私有、不能克隆的 `VerifiedManifest`，借用原 `DataObjects`
实例并固定输入根、输出根 hash、页数和原 deadline。生产调用中的实例是原 `ObjectContext`。

| 数据变化 | 产生证明前必须完成的工作 |
| --- | --- |
| 无变化 | exact GET 原 Manifest，检查类型、格式、几何及本次页数；不能仅凭传入根构造证明 |
| 变为空库 | 对空 Manifest 条件创建、完整字节回读 |
| 页更新、增长或缩小 | 原树及变化页校验，必要的新 Chunk／Node 条件创建和回读，最后保存并回读新 Manifest |

`publish_updated` 消费证明前依次核对：

1. 原 context 尚未失败、隔离或观察到禁止继续使用的世代。
2. context 与数据库使用同一对象后端和同一 handle lineage；Scope、物理世代一致。
3. context 记录的原 HEAD body 身份和原 ETag 与本次传入的 Snapshot 完全匹配；
   同一库的新 HEAD 不能替换原基底。
4. context、证明和发布使用同一个原 deadline；证明来自同一个 context 实例，
   输入根等于原 HEAD 的根，输出根等于候选 HEAD 的根，页数不超过候选配额，期限尚未到达。
5. `PreparedHead` 仍验证完整候选格式和状态转换，并固定原 ETag；发布前重新检查共享
   lineage 健康，只执行一次原条件 HEAD PUT。

任何对象保存或 readback 失败都不会产生可发布证明。证明不授予 READ／WRITE 权限，
不允许换 ETag、延期或重放 SQL。上传期间发生权限、owner、取消或其他 HEAD 变化时，
原 CAS 仍须失败；迟到候选不能把已经读过的 Manifest 当作最新权限。

## 为什么不必再次读取不可变对象

这一复用依赖当前协议已有的两项约束：对象只按内容身份条件创建；GC 只删除已由 HEAD
协议永久退休的物理世代。原 active 世代仍受保护，不能因对象暂未成为新 HEAD 的根就
按年龄删除。相同对象的新读取也不能防止不遵守协议的管理员在读取之后直接删除它。

因此本改动没有增加新的存储假设，也没有把“对象始终存在”变为无限期缓存保证。
跨调用、换世代、冷恢复、保留结果闭包、S1 retained roots 和管理路径仍使用各自原有
的完整校验与新鲜权限检查。`publish_in` 保留其 exact Manifest GET。

## 不变量与验收

| 验收项 | 必须观察到的结果 |
| --- | --- |
| 首次写、无变化、增长、缩小 | 原结果和页根正确；proof 从真正的读或 readback 产生 |
| context／backend／Scope／世代不一致 | 发布前拒绝；不发出 HEAD PUT |
| 同代替换 ETag、body 或后继 HEAD | 发布前拒绝；不允许刷新旧候选 |
| 根、quota、期限或健康状态失效 | 发布前拒绝；原错误与 UNKNOWN 保持可查证 |
| PUT／readback 失败 | 不能返回成功，不能用未完成证明继续发布 |
| 远端 HEAD 已变、CAS 响应丢失 | 保留原 412／UNKNOWN 语义，不重新执行 SQL |
| Native publication | S3 接受后才执行原生提交；native 失败仍保留已提交 receipt |
| 对象请求账本 | 成功的新业务提交少一次 Manifest GET；原不可变对象 PUT 和 readback 均保留 |
| 管理与强读 | 原读取与权限边界不变；不能借业务证明给其他路径提权 |

修改后的生产文件须重新通过完整 workspace 单元和逐文件精确行／函数／region／分支
覆盖、严格 Clippy。实际 native＋签名 S3 合同另行验证 ACK、UNKNOWN、原结果与完整冷
恢复；固定负载使用同一夹具和后端比较请求账本。单元计数不替代实际合同。

测量时明确区分独立事务数与事务内 SQL 数。即使确定每次提交少一个 GET，也不能直接
按请求数比例宣称 TPS 或 p99 改善；CPU、checkpoint、排队和对象延迟仍影响结果。
本改动不实现 group commit、MVCC、同库读池、lazy VFS、S2 restore 或跨 AZ 保证。

