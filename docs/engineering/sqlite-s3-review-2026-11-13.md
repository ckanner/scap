# SQLite on S3：2026-11-13 代码、验证与剩余交付

本页记录本轮恢复执行环境后的工作。两份生产 Rust 基线为 PR #59 的 `b15bc45` 和
PR #60 的 `fd508cc`；接续的测量／审计工具分别记录自己的源码与构建输入。文档与
工具提交不改变原构建、原 profile 或实际历史的身份。详细产品设计仍以
[主方案](../architecture/object-storage-native-proposal.md)、
[安全与吞吐](../architecture/sqlite-s3-safety-and-throughput.md)和
[交付计划](sqlite-s3-delivery-plan.md)为准。

## 1. 已提交的代码

| 代码 | 已实现的内容 | 当前交付边界 |
| --- | --- | --- |
| main `fab8ca0`，#54/#55 | HEAD6 代际复制、退休与持久 sweep；HEAD7 Deleted 终态 seal | 已合入的基础，仍需在新组合上完成必要回归 |
| [PR #59](https://github.com/ckanner/scap/pull/59)，冻结 `b15bc45` | #56 owner-plan、#57 有限 controller、#58 S1 retained snapshots 的组合 | 继续 Draft；重新采集原始记录，逐文件分支测量缺口单列 |
| [PR #60](https://github.com/ckanner/scap/pull/60)，冻结 `fd508cc` | 在一次新事务内消费已验证 Manifest 的私有证明，省去发布前重复的 GET | 已提交生产实现及针对性测试；保留原条件写、第一次回读与 native publication |
| 本轮验证工具修复 | 拒绝被其他文件正分母掩盖的单文件 branch 0/0 | 不改变数据库格式、API、SQL 行为或运行预算 |
| 目录发现观测与容量审计工具 | 同一原请求的 handler 接收见证；可复现的 1 GiB 全 BLOB／关闭镜像审计与捕获 | 243 项服务夹具、28 项审计工具测试通过；新 discovery 与固定 b15 的容量实际、独立审计及全部指定负控分别通过 |

PR #60 的生产改动只涉及 `data_tree.rs`、`object_context.rs` 和 `lib.rs`。
证明绑定原 ObjectContext、后端、handle lineage、Scope／物理世代、输入／输出根、
页数与原 deadline；消费时再核对原 HEAD body／ETag，最终仍仅使用原条件 CAS。
管理发布与普通强读保留原路径。实现和完整不变量见
[Manifest 证明设计](https://github.com/ckanner/scap/blob/fd508cc052c21dba0e3c54b8e8e82d11c167777a/docs/architecture/verified-manifest-publication.md)。

这项优化没有实现同库 MVCC、独立事务 group commit、lazy VFS 或异步确认。
对象请求减少与端到端 TPS／p99 改善分别验证；不能按少一个 GET 的比例推算性能收益。
本轮两组顺序相反的完整实际都证实了请求减少，但四库写入速率分别下降约 24.00%／
24.52%；吞吐回退尚未排除，PR #60 保持 Draft。详见
[性能验收与下一步 profile](verified-manifest-load-validation.md)和
[完整机器记录](../evidence/verified-manifest-load-local-2026-11-13.json)。

## 2. 验证状态与证据归属

旧 11–12 日的一部分原始执行记录未能恢复。已提交的历史结果不改判为失败；
但摘要、路径和 hash 不能替代已经丢失的原 HTTP／S3／ACK、coverage profile 和构建原件。
因此本轮按原范围重新执行受影响门禁，保留新正式 release、原始失败和新通过结果。
分组结果、原结果 SHA、重跑对应关系和源码身份汇总于
[本轮机器记录](../evidence/sqlite-s3-revalidation-local-2026-11-13.json)；配对性能另存独立记录，
避免把不同冻结源码的实际拼成一个不存在的统一运行。

| 验证层 | 本轮状态 | 不能推出的结论 |
| --- | --- | --- |
| b15 Rust | stable/nightly 各 783 项通过；67 文件 map 完整，已发出计数全命中 | 7 文件 branch 0/0，完整逐文件四维门禁未满足 |
| fd508 Rust | stable/nightly 各 791 项通过；67 文件 map 完整，已发出计数全命中 | 同上；旧 4d7 的 469/470 region 失败仍独立保存 |
| b15 SDK／类型／工具／模型 | SDK 157、codec 13、真实 loopback／CLI 19；原工具、环境和完整固定模型通过 | 模型不是产品 S2，SDK 结果不是 native/S3 验收 |
| fd508 实际正确性 | native 基础／故障／schema、retained、生命周期、S1 共 14 条原命令与规定独立审计通过 | 不能替代 b15 的独立基线，也不证明 AWS 或生产 SLO |
| b15 native／发现 | 完整网络、retained、生命周期、116 目录案例、listing、bounded response、deployment discovery 通过 | 固定 1 GiB 容量单独验收 |
| b15 owner／controller／S1 | owner-plan 新完整实际／42 负控及原正控通过；Missing、S1、单 controller、完整 12 场景矩阵及原独立审计／负控通过 | 动态 fleet、持久实例身份分配仍未交付 |
| b15 资源／GC transport | 原资源合同及完整 42 例 GC transport 通过 | 不等于全进程硬 RSS／磁盘上限或长期成本已完成 |
| b15 HEAD7 终态 | actual、独立 oracle、25 负控／1 正控全部通过 | 不表示终态前缀永远没有迟到孤儿 |
| b15 HEAD6 | 第二次完整 actual、独立 oracle、全部 23 负控／1 正控已通过 | 第一轮超时失败保留；不扩大为全部产品出口 |
| b15 服务专项 | 12 项已有完整通过记录，包含新 isolation 实际／21 负控／1 正控；service discovery 原失败保留 | 新观测 schema 的 discovery 实际属于不同冻结来源，不回填 b15 |
| `642383c` 服务 discovery | 新正式 release 上的完整 actual、独立 oracle、32 负控及原正控通过；424 HTTP、25,278 S3，源码与构建输入不变 | 这是服务发现合同，不宣称完整数据恢复、AWS 或生产 SLO |
| 两组配对负载 | 基线→候选及候选→基线各自完整 actual／oracle／14 负控／3 正控通过 | 请求减少有证据，吞吐改善没有证据；四库两次均更慢 |
| 固定 1 GiB | 冻结 b15 原 actual、关闭镜像捕获、完整独立审计、5 负控与原正控全部通过；38 原 ACK＋1 原 UNKNOWN、39 冷 lookup、16,384 BLOB／1,073,741,824 字节无失配，integrity_check 为 ok | 默认 10 GiB、fd508 容量、AWS 与生产 SLO 未运行；关闭副本审计不是第二次 S3 恢复，本页不签发整体 merge-ready |

分支测量问题已在[独立说明](branch-coverage-measurement-gap.md)中纠正。
修复前的检查器对原报告曾返回成功，并不意味着 `match`／`?` 的所有分支已经被独立计数。
修复后的严格检查器对原两份报告均退出 1；原测试退出码和采集数据保持原样。
按 `AGENTS.md`，必要门禁未满足，两个 PR 均不合并。

本轮首个 HEAD6 actual 因原 180 秒 hold 窗口超限而失败；同参数空闲重跑实际通过，
但该结果不足以唯一归因到 CPU／I/O。isolation 首轮在热库探测时返回 RECOVERY_BUSY，
前后调用间隔超过原 3 秒 idle；owner-plan 首轮在原 8 秒期限的 seed 阶段返回
Store(Unknown)。这些失败保留。isolation 后续完整实际用时 27.391 秒，21 负控／
1 正控用时 8.797 秒；owner-plan 后续实际 230.199 秒、oracle 12.674 秒、42 负控／
原正控 436.378 秒，均在原参数下通过，源码前后相同。owner-plan 的 295 份原 SQL ACK、
721 个 HTTP、10,047 个 S3 与 27 个 owned wait4 单独核验。新通过不回填旧失败，
也不足以唯一归因前次差异到某一种宿主资源。

service discovery 原 429 个 HTTP 区间通过身份／次数核验，但 25,292 个 S3 请求中有
一个 GET 被代理记录于前一 HTTP 返回后 2.292 ms、下一调用开始前 6.907 ms，原归属
oracle 因此拒绝。该页在原 5 秒期限内以 UNKNOWN cursor 返回；代理的原记录时刻位于
读请求、SigV4 校验与锁之后，没有产品发出时刻。现有原件不能证明这个请求必然合法，
也不能据此断言生产在返回后新发起了工作。失败保持原样，修复需增加准确的原请求
观测绑定，不能扩大时间窗、删除 no-post-return 判据或给旧历史补写字段。

接续已经增加真实 handler 入口见证，保留原认证日志时钟、全部原 29 个负控和原预算，
另加 3 个时钟负控；完整服务夹具单元 243 项通过。由于正式 build inputs 包含这些
Python 文件，已在冻结 `642383c` 新构建正式 service，278 个输入与 730 文件源码身份
分别核对；全新实际／独立 oracle／32 负控及原正控合计 1,847.424 秒，完整通过。
424 HTTP、25,278 S3、26 SDK／3 service／4 backend 的 owned wait4 与清理状态均核对；
旧失败原报告 SHA 不变，新结果不能复用旧 receipt 或归属旧 b15 源码。
详见[观测修复](discovery-request-clock-validation.md)。容量审计与捕获工具已经进入
[独立实验目录](../../experiments/object-capacity-audit/README.md)，28 项小型工具测试通过。
随后在 discovery 完整退出后，冻结 b15 的原固定 1 GiB actual 用时 370.425 秒，关闭
镜像捕获 12.753 秒，完整独立审计及 5 负控／原正控 42.655 秒，全部退出 0。原 38 个
execute ACK 与 1 个 UNKNOWN 分别保留，39 个冷 lookup 原结果逐一一致；审计器重新
读取最终全部 16,384 个 BLOB 的 1 GiB 字节并核验哈希，完整 integrity_check 为 ok。
11 个原实际子进程均有 owned wait4，之后才捕获关闭镜像；审计器另有独立 wait4。
审计器的 RSS 观察不作为产品硬内存上限，关闭副本也不是第二次 S3 恢复。完整范围、
原报告身份与未运行项见[容量验收](capacity-gib1-validation-2026-11-13.md)。

本批计划的本地实际均已取得最终结果，原失败、成功重跑及不同冻结源码继续分开保存。
接续文档提交和 PR #60 的基线同步不产生新的运行身份，不能把旧实际改称最终合并
commit 的全套验证；严格分支证明与 PR #60 的性能回退仍是阻断项。

## 3. NFS／EFS 问题是否被解决

SCAP 不跨主机共享活动 `.db/WAL/SHM`。每个执行实例只打开准入后的私有本地镜像，
跨节点顺序由 S3 中的单库 HEAD 条件发布和 owner epoch 决定。本地目录可以全部丢弃，
对象闭包和原结果仍应足以恢复。网络文件锁不承担数据库的跨节点所有权。

成功确认依次经过：原生 SQLite 暂存事务与原结果；不可变依赖条件创建及完整回读；
原 ETag 的 HEAD CAS；native publication；客户端 ACK。HEAD 响应丢失保留 UNKNOWN，
只能按原请求身份查证／取消，不能自动重放 SQL。远端已接受而本地发布失败，仍保留
原 receipt，不能将其解释为远端回滚。新的强读重新检查当前 HEAD 和权限。

这避开了用户担心的共享网络活动文件问题，仍依赖正确的本地 I/O、对象服务合同、
部署文件系统与未复用的 worker incarnation。overlay 的底层与真实 NFS/EFS/FUSE
挂载验收仍不能由类型分类测试代替。具体前提见[部署要求](../operations/sqlite-storage-safety.md)。

[SQLite 网络文件说明](https://www.sqlite.org/useovernet.html)讨论锁、同步和写入顺序的风险；
[WAL 说明](https://www.sqlite.org/wal.html)要求共享 WAL 的进程同机运行。
SQLite 可同机多进程，EFS 也支持 advisory byte-range locks；这两点都不能推出
跨主机共享 SQLite WAL 安全。不能将“所有 NFS 都立即损坏”作为本方案的论据。

## 4. 目标与剩余产品工作

当前目标是服务大量独立租户／Agent 数据库，保持明确的提交、原结果和恢复语义。
不同库可以并行；同一个库仍由一个 actor 串行执行。增加 pod 不会自动提升同库写吞吐，
长查询仍可能占住该库 actor。冷恢复仍完整读取闭包，尚未按页懒加载。

| 后续工作 | 必须共同交付的内容 | 当前状态 |
| --- | --- | --- |
| 关闭当前测量缺口 | 可审计的源码／控制流计数、未执行路径反例、准确的无适用分支语义 | 严格 checker 修复；完整分支证明尚缺 |
| 热点与多库性能 | 定向产品 CPU／分配／等待与观察器分解；随后冻结开环负载、尾延迟、错误、排队、对象成本 | 两组账本证实少 Manifest GET，其他对象计数相同；两次多库速率下降，原因尚未定位 |
| native 依赖与未来读并发 | 保留提交前 WAL gate，按精确上游修复验证 WAL-reset；再考虑同文件连接池或后台 checkpoint | 当前固定 native 尚未修补；正常生产路径靠私有单连接／串行 checkpoint 排除已知触发拓扑，这不等于引擎已修复 |
| 动态自动恢复 | 在线 fleet、策略变化、不复用的持久实例 identity、竞争／撤权／停机合同 | 当前仅有限 controller 与部署提供的身份 |
| S2／PITR | 新 Scope、跨 Scope 重封装、源权限完成屏障、CompletionRecord、Name/HEAD 取消、独立冷恢复 | S1 已实现；S2 模型与完整设计已有，产品 API 未开放；任意时间 PITR 另设计 |
| 资源与持续运行 | decode/native heap/磁盘总账、持续过载、公平性、冷启动风暴、多轮 GC 与长期元数据成本 | 已有有界准入与逻辑预算，硬隔离和长期合同未完成 |
| 目标后端与上线 | 真实 AWS Standard 的条件写、IAM/KMS、区域故障域、长运行和预定义 SLO | NOT_RUN；本地 SeaweedFS 不能代替 |

native 修补来源、固定引擎身份、当前连接拓扑及升级必须重验的提交门，见
[WAL-reset 源码评估](../architecture/sqlite-wal-reset-assessment.md)。该评估仍保留其
原只读核查日期；本轮没有运行新的漏洞复现或更换 native 依赖，S3 条件写也不修复
SQLite 内核中计算出来的错误页面。

Turso 值得借鉴的部分是远端持久化参与提交、跨库 WAL 合批和分块缓存。开源 libSQL
Bottomless 的异步复制、Turso Cloud 的 S3 Express 存储路径、新 Rust 引擎的 MVCC
是不同层次。它们不能拼成“使用 S3 就自动具备多 writer 和高吞吐”的结论。
官方来源、固定上游代码与 SCAP 的明确取舍见
[Turso 复核](../architecture/sqlite-s3-turso-review.md)及
[安全与吞吐第 6–7 节](../architecture/sqlite-s3-safety-and-throughput.md#6-turso-可以借鉴什么)。

本轮提交解决具体实现与证据问题；S2、动态 fleet、硬资源、真实 AWS、长期成本和生产
SLO 继续按独立退出条件交付，不用测试数量或文档长度表示产品完成率。
