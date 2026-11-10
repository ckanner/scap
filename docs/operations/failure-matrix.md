# 对象原生故障矩阵

| 情况 | 要求的行为 |
| --- | --- |
| 依赖上传未完成 | 不发布HEAD，不交付SQL结果；残留对象保持未引用 |
| 依赖key已存在 | exact GET核对完整bytes，不能覆盖修复 |
| HEAD 412 | 仅该次条件失败；原业务仍按原身份查证 |
| HEAD响应丢失/409/5xx/超时 | 保留UNKNOWN，不换ETag、不重跑SQL |
| CAS成功后native失败 | 已提交但本地不可用；停止cache，保留对象中的原结果 |
| 旧writer恢复 | 旧ETag拒绝，不rebase旧页面 |
| 权限撤销 | 下一请求新鲜HEAD拒绝；在途提交与撤销按CAS排序 |
| 全部计算和本地盘丢失 | 以对象根重建页面、结果、权限和owner，不依赖本地唯一状态 |
| 权威HEAD缺失 | 失败关闭，不自动初始化 |
| 页/索引/结果缺失或摘要错误 | 关闭原读取前缀，不回退旧根或造空页；只有一次原期限内 exact HEAD 调查严格证明原物理世代已退休，才可返回 SnapshotExpired |
| S3不可用 | 新强读与新写均失败；无缓存成功降级 |
| 已退休身份 | 返回retired，不声明原业务未提交或自动换ID |
| Deleted | 拒绝普通后继，永久保留身份屏障；HEAD6 最后 active generation 仍保护，不能因 Deleted 直接清空 |
| 复制期间旧读取/旧写入 | 始终使用原 namespace；旧 CAS 保留原条件；普通旧读可因严格退休证明而中止，不自动换根 |
| GC DELETE 响应丢失 | checkpoint 原项保持 pending；新 exact inspect 的 typed NoSuchKey 可成为新 absence 证据，不能倒改原 UNKNOWN |
| GC inspect 看到新 ETag | 仍按 checkpoint 的原 ETag DELETE；只有实际条件冲突才结束原项，新候选另建批次 |
| sweep 完成后迟到 PUT | 永久退休不变；下一轮从起点重新扫描并回收 orphan |

AWS端点、区域持久性和生产故障域未通过本地兼容服务测试自动认证。HEAD6 GC 默认无删除凭据；显式启用仍须通过本候选门禁并遵守[退休与 checkpoint 协议](../architecture/head6-compaction-gc.md)。未回收的 orphan 和永久身份元数据仍有存储成本。

## 本地故障证据的划分

[网络实验](../../experiments/object-network/README.md)分别执行基础合同和 N1 提交／恢复边界。依赖 PUT 转发前崩溃、依赖已持久后崩溃、HEAD 成功后无回包、HEAD 成功后真实 native 失败是不同事实，须分别保存和核对。未转发的请求必须显式终止；终止计算进程本身不撤销已经发送到对象存储的 CAS。

冷恢复需要核对当前 Chunk、Node、Manifest 和保留 Index／Result；其中任一权威依赖缺失或损坏都不能退回旧根。已暖 handle 的发布隔离遵守 [ADR-0022](../adr/0022-production-capacity.md)：已知损坏阻止共享 handle 的后续 HEAD 发布，已经验证并且仍匹配新鲜 HEAD 的只读快照不因此被重新定义。冷恢复失败不自动证明跨进程持久 fencing 或已暖 handle 的全部行为。

各项实测计数、失败尝试和源码绑定见[验证记录入口](../engineering/validation.md)。完整权限／维护／删除竞赛、请求退休、ABA 和目标 AWS 故障域仍须独立完成；不能用这批选定故障代替完整方案矩阵。
