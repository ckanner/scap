# 名称目录协议：冻结有界模型验收

日期：2026-11-07。实测候选 `c0b067da5a8337c72c3c674dff64845787dde7d3`，tree `3b58b0747faeff32414fbc968a8d5473ba23947d`。181 个 tracked 文件的 source manifest 在所有门禁前后相同。[机器记录](../evidence/named-catalogue-model-local-2026-11-07.json)保存源码清单、910 份原始历史的逐文件摘要、实际范围、负对照、构建外工具门禁和此前失败。

**[PR #30](https://github.com/ckanner/scap/pull/30) 完成名称目录的协议固定和指定范围的模型验证。** 正式 Rust／HTTP／SDK 正在后续实现；本批不包含生产代码，不证明真实 SQLite/S3 目录操作，也不宣布 N2 退出。

## 固定的协议决定

[目录方案](../architecture/name-catalogue-plan.md)把跨对象动作拆成可以中断、查证和按原意图继续的阶段。不可变 CreateDescriptor 固定创建者、操作 ID、名称、Scope、原条件和初始有效配置；ControlDescriptor 固定调用者与 abort/delete 的完整条件。意图一旦持久准入，即使目标 CAS 返回 412 或 UNKNOWN，也不能用同 operation 改名、改 Scope、换 revision 或 nonce。

Reserved→Bound 与 Reserved→Aborting 竞争同一个名称 ETag。只有合法 Bound 来源才能完成 Provisioning→Ready。取消必须先建立同物理 HEAD key 的永久占用屏障，再保存不可变 AbortProof，最后释放名字；Proof 已写但名字未释放仍不是 Aborted。合法外来 HEAD 的占用可以阻止旧身份再创建，但不能修改或删除该外来数据库。

名称可以在 tombstone 后重用，物理数据库 ID、旧 HEAD 和原创建／控制意图永不复用。普通删除允许另一位当前 ADMIN 使用自己的固定控制意图；取消原创建仍限制为原创建者且需要当前 provision 权限。完整权限撤销竞争留给生产验收，模型只包含必要的符号授权关系。

## 实际执行范围

| 项目 | 实际结果 |
| --- | --- |
| Python 单元 | 121 项通过：原 authority 89 项、新目录 32 项 |
| 目录竞态历史 | 800 条：10 类竞态 × 两条三阶段链的 20 个合法交错 × 四种响应丢失组合 |
| 定向历史 | 85 条，含发布切点、丢失计算状态、ForeignOccupied、固定控制条件、名称重用、资源预算和未完成前缀 |
| 正向历史合计 | 885 条，全部被独立历史判定器接受 |
| 负对照 | 25 条，全部按预期不变量拒绝；1,722 个记录事件 |
| 实际调度观察 | 32,766 个按场景区分的 scheduler states、203 个持久 storage states、31,897 次命令／边、61,043 个正向事件 |
| 单历史实际峰值 | 17 次尝试、146 个事件、11 个持久记录 |
| 原 authority 回归 | 664 条正向历史、30 个拒绝负对照通过，范围仍按原模型解释 |
| 其他门禁 | 32 项环境控制器测试、文档链接／whitespace、固定 Actionlint 和 shell 语法通过 |

10 类竞态是 descriptor 准入、不同意图争同名、同意图 Provisioning、bind/abort、迟到 provision/absent tombstone、重复 abort、重复 Ready、不同 delete、相同控制 descriptor、不同 nonce 争同一控制 descriptor。每类枚举 `invoke → effect → receive` 的完整两链交错；不将网络响应接收顺序当作对象生效顺序。

默认有限预算为 32 个记录、revision/fence 最大 31、64 次尝试、8 个在途请求和每历史 1,024 个事件；一次历史只有一个名称槽，最多三个候选身份。上述观察计数不是任意状态空间总数，不能由它们计算穷尽覆盖率。

## 判定器与发现的缺陷

历史判定器不导入模型或调度器的状态转换函数；它从 exact GET、候选 bytes／原 ETag、invoke/effect/receive 和计算 generation 重建对象历史，检查身份、前提和实际业务观察。负对照包括旧候选换 ETag、未发送即生效、丢响应冒充失败、跳过 Provisioning、缺永久屏障、旧取消冒认、外来 HEAD 被修改、控制条件重定向等。

独立审阅曾发现两种跨进程丢失的旧读取可以被误认领：旧 Ready 观察在新计算中报告成功，以及旧 absent GET 被重新标为新进程的 prepare。修正将每个 GET 绑定计算 generation，并在认领时核对。冻结源码上的两份额外审阅反例均以 `READ_GENERATION` 拒绝；合法的“写已 invoke→计算丢失→服务端迟到生效→UNKNOWN”仍被接受。这保证防护没有错误取消已发出的网络副作用。

额外审阅脚本摘要为 `e86653a6002ee39235813141e3483e70ee28cc8325c102965e967816b02bcbbb`。它独立构造 mutation，但调用冻结的项目模型产生基础历史、调用项目 oracle 判定；它不是另一套完整协议 oracle。首次临时审阅保留结果 JSON，但没有保存精确脚本版本，因此不冒称早期审阅可逐脚本重放；新脚本与新候选复核已单独保存。

开发第 01 轮因 `emit(kind)` 参数重名退出，第 02 轮因定向场景遇到 `already_durable` 退出，两个失败及各自已产生的历史均保留。第 03–06 轮范围逐步补齐，最终正式接受的是新冻结候选的 885/25 结果；不会把不同范围的中间通过相加或覆盖早先失败。

## 尚未证明的事项

这是一组有界并发交错与定向切点，**没有穷尽 prepare 内多次 GET 之间的所有穿插**。模型也未枚举客户端先收到 timeout、对象稍后才生效的全部时序，或业务响应跨计算崩溃排队的全部行为。

生产身份哈希、严格 wire/对象格式、真实数据闭包、native SQLite、S3 的条件语义、完整 ACL／撤权竞争、任意活性、公平性、LIST／全目录恢复、GC/PITR 和 AWS 都需要独立实现与验收。若新生产代码发现额外交错，必须补模型或明确独立证据；不能用“模型通过”跳过这些门禁。

CI 与本地完整验收入口均已加入目录模型及原始历史产物。下一阶段按同一方案实现正式目录模块、Provisioning 普通入口防护、独立有界 HTTP 准入与 SDK 原意图保存，再执行真实逐发布边界、名称重用和全计算丢失恢复。
