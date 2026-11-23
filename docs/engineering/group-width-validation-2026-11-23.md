# 组提交上限 8 与 4：相同 seed 本地与 CI 验收

更新：2026-11-23（纽约）。对应 [PR #72](https://github.com/ckanner/scap/pull/72)。

## 结论与当前决策

**本轮目标已完成：设计先提交，实验与独立审计已实现，两个环境的八 cell 实测、
30 项负控和 1 项正控均通过。cap 4 的性能采用条件未满足：本地 2/4，CI 0/4。**
组提交保持默认关闭，不将 cap 4 标为通用推荐配置，不修改生产默认，也不扩大
intake、队列、deadline 或内存/磁盘预算。

较小组确实缩短了每次成组调用，却同时增加了调用次数和 HEAD 发布开销；四个
高档配对的 DATA queue 均值都更长。局部调用变短没有稳定转化为端到端收益。
低档多数轮次没有触及 cap，不能将其时延波动直接归因于 4 与 8 的差别。

完整逐 cell 数值、分窗计数、计时完成状态、资源、存储、源身份和精确覆盖计数见
[机器证据](../evidence/group-width-local-and-ci-2026-11-23.json)。这两份环境结果
分开记账，不合并为“2/8 成功率”，也不把 5% 工程门槛解释为统计显著性。

## 1. 先行设计与冻结身份

设计先行提交 `acd9c18d39a8a91d6a8ae7445e203b4ebab267c3`，之后才提交实现
`7cb0c222d8aeb8dd05921c4fe211633eec3432ab`；先行合同见
[组宽比较设计](../architecture/group-width-comparison.md)，执行入口见
[新 fixture](../../experiments/group-width-load/README.md)。

| 身份 | 本地 | GitHub CI |
| --- | --- | --- |
| workflow/PR head | `7cb0c222` | `7cb0c222` |
| fixture 与实际 build commit | `7cb0c222d8aeb8dd05921c4fe211633eec3432ab` | `f648fd5f9529aad7a52d990adf0cdf178fc78db0`（PR synthetic merge） |
| fixture 输入 | 43 个文件 | 同 43 个文件，全部 SHA 相同 |
| build 输入 | 328 个文件 | 同 328 个文件，全部 SHA 相同 |
| 服务 binary SHA256 | `872305efeecd6b30458b162657346ffa7969026843b365a4718a48e83bda3164` | `321d2a19497b92fb269e47bd86df4d2f4a5f9e18952ae777ca635525c5ae93b6` |

本地 tree 为 `0d0436507310f6578c65e401ff142af7d6f62c95`，基线主线为 PR #71
合并点 `b8e24d0f252e01efa91726a0ea3909d148c25587`。生产 crates、SDK、Cargo
输入与旧 equal-seed/group-commit-load fixture 均无改动。
两环境的 build-source.tar SHA 都为
`2606228ad97bc01df9da4b737415c869a3d4b69d41a1a4dfe98e57482eb6510d`。
Rust 1.90.0、Node 22.16.0、SeaweedFS 4.51 固定；Node/weed binary SHA 相同，
scapd/Python binary SHA 不同。这里证明相同源码输入分别正式构建，不宣称同一
build commit、同一机器或二进制完全复现。

本地正式 build 用时 153 秒；八 cell actual 用时 1152.115 秒。本报告引用的是
两个环境各一次冻结矩阵，没有自动重跑、被删除的有效慢轮或运行后的阈值调整。本地清理
错误为空；源码、工具和 fixture before/after 校验通过。

## 2. 固定合同与实现

两 arm 均开启 group commit，仅 `max_members` 为 8/4；每档按 8→4→4→8
运行，先 12/s，再 32/s。每 cell 全新 backend/service/database/cache，256 行 seed
以 4/s 写入并全部原始 ACK、drain 后，再执行 32 秒开环负载及八个 4 秒窗口。
两边的 SQL、payload、random witness、原身份、client inflight 192、tenant intake
40、其他 group 字节/page 限额和全部资源/deadline 保持不变，不等待凑组。

起始 geometry 全部一致：256 行、21 pages、257 retained requests、87844 结果
bytes，data tree level 0、request index level 1，没有 freelist/overflow pages。
random witness 保留，所以不要求对象 hash 或数据库字节相同。

新增实现使用初始化阶段的两个固定 cap spec/reader/runtime 绑定，复用已有正式
Cell、owned process 监控、原 SDK probe 和原始闭包审计。cap 4 的原始 HEAD
publication 审计真实使用 4；全部成功 diagnostic，包括未选中的 polling 响应，
都检查 selected/consumed 桶上限。oracle 不导入 runner/生产 serializer，执行时
不修改全局 profile。

新增 26 项单元覆盖配置、原始 publication、全快照 cap、异常归一、性能阈值和
合法零组/零窗口 ACK/零 load 成功的控制路径。保留旧 22 项负控语义并新增 8 项
cap 负控；每项必须命中预定规则。零实际组仅在内存负控中明确添加 synthetic
组，HEAD 控制按 load→seed_rows→seed 取真实来源；不把投影当实际观测。

## 3. 完整分母、ACK 和拒绝语义

| 环境 | measured | 原始 ACK | BACKPRESSURE | 32 s 窗口 ACK | seed INSERT ACK | DDL ACK | generator 拒绝 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 本地 | 5632 | 3438 | 2194 | 3271 | 2048 | 8 | 0 |
| CI | 5632 | 4367 | 1265 | 4221 | 2048 | 8 | 0 |

各环境另外 64 个 load control、32 个 seed control 全部成功。所有 BACKPRESSURE
的原始首层拒绝均为 `intake_data_requests_tenant`，used=40、limit=40、requested=1。
这指出最先触发的边界，不能单独推导“应增加额度”或唯一吞吐原因。

本地逐原始字节复核：7688 个 original execute 身份各只有一次 POST；全部
19884 个 HTTP POST 对应 17690 个 HTTP 200 和 2194 个 HTTP 429。原始 measured
终态没有 UNKNOWN、timeout 或其他终态，但这些 BP 的 SDK `outcome` 仍为
`unresolved`，不能写成 unresolved 从未发生。

结算时首次 lookup 观察到 5494 committed（含 seed/DDL）和 2194 unknown，随后
2194 个 cancel 返回 cancelled，并由 2194 次后续 lookup 确认 cancelled；最终
未解决身份为 0。没有重放 SQL，没有将 lookup 得到的 committed 冒充 original ACK。
CI measured 最终结算为 4367 committed + 1265 cancelled。

本地另外核对了 6053 个成功 HEAD PUT 原始 body、全部 16 个成功 diagnostic，
发布 sequence 增量与 selected/consumed 桶均未超各 cell cap；启动 config SHA
全部匹配。两环境各 30 个唯一负控均精确命中、1 个 unchanged positive 通过。

## 4. 本地八轮

下表按实际执行顺序。drain 是该负载从起点至全部原始终态排空的完整时间；
窗口 ACK 只计固定 32 s 内的原始 ACK。S3 req/ACK 为 load cohort，包含其 drain，
不包含 seed 与后续 verify。

| cell（rate/cap/次序） | ACK | BP | 窗口 ACK | drain s | 成功 p99 ms | control p99 ms | S3 req/ACK |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 12/8/1 | 384 | 0 | 380 | 32.196 | 1474.444 | 39.323 | 20.58854 |
| 12/4/1 | 384 | 0 | 383 | 32.063 | 247.496 | 33.640 | 21.11198 |
| 12/4/2 | 384 | 0 | 383 | 32.020 | 273.904 | 33.125 | 21.11198 |
| 12/8/2 | 384 | 0 | 383 | 32.020 | 280.410 | 53.667 | 21.00260 |
| 32/8/1 | 483 | 541 | 443 | 34.003 | 3075.812 | 43.854 | 18.57143 |
| 32/4/1 | 484 | 540 | 444 | 34.274 | 3042.766 | 42.729 | 18.94215 |
| 32/4/2 | 484 | 540 | 444 | 34.193 | 3148.180 | 43.825 | 18.94215 |
| 32/8/2 | 451 | 573 | 411 | 34.213 | 3502.675 | 122.837 | 18.57206 |

## 5. CI 八轮，单独记账

CI 的正式 [actual/audit job](https://github.com/ckanner/scap/actions/runs/45132546751/job/137551292945)
已完整通过。其绝对性能不能与本地混为同一硬件/二进制实验。

| cell（rate/cap/次序） | ACK | BP | 窗口 ACK | drain s | 成功 p99 ms | control p99 ms | S3 req/ACK |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 12/8/1 | 384 | 0 | 384 | 32.000 | 64.494 | 25.005 | 21.17448 |
| 12/4/1 | 384 | 0 | 384 | 32.001 | 62.339 | 27.514 | 21.17448 |
| 12/4/2 | 384 | 0 | 384 | 32.001 | 61.440 | 27.175 | 21.17448 |
| 12/8/2 | 384 | 0 | 384 | 32.001 | 62.461 | 25.338 | 21.17448 |
| 32/8/1 | 717 | 307 | 682 | 33.442 | 1958.604 | 27.290 | 18.59554 |
| 32/4/1 | 710 | 314 | 674 | 33.592 | 1970.305 | 30.695 | 18.96056 |
| 32/4/2 | 702 | 322 | 662 | 33.594 | 1963.018 | 26.911 | 18.96011 |
| 32/8/2 | 702 | 322 | 667 | 33.445 | 1966.618 | 26.449 | 18.59259 |

## 6. 按预登记门槛判定

每对要求 original ACK/窗口 ACK 均不减少；成功/control p99、S3 requests/ACK、
双向 bytes/ACK 各最多回退 5%；同时 original ACK 增加 5%、S3 requests/ACK
减少 5%、成功 p99 减少 5% 至少一项成立。以下变化均为 cap4 相对 cap8。

| 环境/配对 | ACK 变化 | 窗口 ACK 变化 | 成功 p99 | control p99 | S3 req/ACK | 双向 bytes/ACK | 门槛 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 本地 12/s 第1对 | +0.00% | +0.79% | -83.21% | -14.45% | +2.54% | +0.10% | 通过 |
| 本地 12/s 第2对 | +0.00% | +0.00% | -2.32% | -38.28% | +0.52% | +0.02% | 未通过 |
| 本地 32/s 第1对 | +0.21% | +0.23% | -1.07% | -2.57% | +2.00% | +0.11% | 未通过 |
| 本地 32/s 第2对 | +7.32% | +8.03% | -10.12% | -64.32% | +1.99% | +1.59% | 通过 |
| CI 12/s 第1对 | +0.00% | +0.00% | -3.34% | +10.04% | +0.00% | +0.00% | 未通过 |
| CI 12/s 第2对 | +0.00% | +0.00% | -1.63% | +7.25% | +0.00% | +0.00% | 未通过 |
| CI 32/s 第1对 | -0.98% | -1.17% | +0.60% | +12.47% | +1.96% | +0.35% | 未通过 |
| CI 32/s 第2对 | +0.00% | -0.75% | -0.18% | +1.75% | +1.98% | +0.07% | 未通过 |

本地未通过的两对没有达到任何一项 5% 改善目标；不能把“没有明显回退”算
通过。CI 低档还有 control p99 门槛未过，高档第一对 ACK/窗口 ACK 均减少，
第二对窗口 ACK 减少。每 cell 只有八次 control，其 p99 接近样本极值，不能
推导总体尾延迟或把小幅变化都归因于 cap。

CI 12/s 的四个 cell 完全是 384 次 singleton publication，group attempts=0，
load S3 请求都为 8131，双向 bytes 完全相同；该档根本没有触及 cap。
本地两个 cap4 低档都是 368 次 singleton + 8 次 size2，cap8-2 是 340 次
singleton + 22 次 size2；只有首个 cap8-1 出现 size3–8 以及较大的积压与尾延迟。
首个慢轮必须保留，但其 −83% p99 不能作为普遍收益；现有数据不能分清积压
形成与大组等待的因果次序。

## 7. 组变短以后，排队仍在

下表的成组调用来自 lifecycle group counters；它不同于对每个 DATA 请求重复
计入的 invocation 持有区间。不能除以成员数后当成实际单 SQL 时延。

| 环境/高档配对 | 成组调用数 8→4 | 单组均时 ms 8→4 | DATA queue 均时 ms 8→4 | DATA total_hold 均时 ms 8→4 |
| --- | ---: | ---: | ---: | ---: |
| 本地 第1对 | 61→121 | 555.2→282.2 | 1993.6→2329.9 | 2551.6→2612.0 |
| 本地 第2对 | 57→121 | 597.8→281.5 | 2146.5→2322.4 | 2748.1→2604.0 |
| CI 第1对 | 92→178 | 362.5→188.3 | 1267.6→1517.1 | 1635.8→1705.6 |
| CI 第2对 | 90→176 | 370.7→190.4 | 1298.5→1536.9 | 1675.0→1727.5 |

高档 cap4 形成了满4组，处理差异确实存在。四对的 queue 均值都增加，除本地
第二对外 total_hold 也增加。尤其本地第一对，ACK 只从483增至484，按完整
排空时间计算的 ACK/s 从14.205降至14.121；单组耗时减半没有带来吞吐翻倍。
本地四个高档 cell 的组 invocation 总时长约33.87–34.14 s，CI 约33.35–33.51 s。
这主要改变了串行工作的分段方式。

DATA post_work_hold 仍很小：本地高档约0.11–0.14 ms，CI 约0.066–0.085 ms。
该证据继续不支持优先改变租约释放边界。

## 8. 完整成本与资源边界

高档四个配对的 S3 requests/ACK 均增加约1.96%–2.00%。本地第一对 HEAD PUT
从62增至122，load S3请求8970→9168；result PUT仅483→484，index GET
2422→2427。逐事务不可变对象工作仍在，主要增加的是组级发布开销。

本地第二对完成更多事务的同时，load S3请求8376→9168（+9.46%）、双向
body bytes增加9.02%；不能只报每ACK请求约+2%而漏掉绝对工作量。
高档的 verify/settlement 成本也必须单列：

| 环境/cell | load S3 请求 | verify S3 请求 | 整轮 S3 请求 | load 双向 MiB | orphan MiB | 最终 live MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 本地 cap8-1 | 8970 | 12154 | 26157 | 142.557 | 76.504 | 1.059 |
| 本地 cap4-1 | 9168 | 12149 | 26350 | 143.016 | 76.594 | 1.060 |
| 本地 cap4-2 | 9168 | 12157 | 26358 | 143.016 | 76.594 | 1.060 |
| 本地 cap8-2 | 8376 | 12572 | 25981 | 131.184 | 73.381 | 1.027 |
| CI cap8-1 | 13333 | 9116 | 27482 | 215.938 | 94.498 | 1.305 |
| CI cap4-1 | 13462 | 9203 | 27698 | 214.583 | 94.097 | 1.296 |
| CI cap4-2 | 13310 | 9309 | 27652 | 213.331 | 93.802 | 1.289 |
| CI cap8-2 | 13052 | 9313 | 27398 | 213.182 | 93.793 | 1.289 |

这些 S3 数字及 bytes 是工作量代理，不是 AWS 金额。verify 包括 lookup、取消
屏障及最终查询，不能加进 original ACK，也不能从整轮成本中移除。
所有 cell 的分阶段 GET/PUT 状态、双向 bytes、seed 成本及资源明细见机器证据。

资源未触发冻结接受上限，不等于资源整体改善或硬隔离通过。采样目标100 ms，
本地最大实际间隔约231 ms，CI 约103 ms，可能漏过短时峰值。service/backend/
Node 的 wait4 CPU 是完整子进程生命周期，包含seed、load与verify，不是load
单独CPU；也不包含observer自身，不能冒称总CPU。observer的原始采样和进程
身份保留在完整证据中，其开销不等于诊断功能的净开销。

GC在本实验中关闭。高档当前不可变对象字节约98.6%为报告定义的orphan；该统计
排除mutable HEAD版本和worker identity。有限资源通过没有解决长期存储增长。
结束geometry随实际成功数变化，不能将byte成本当固定数据库大小的稳态结果。

## 9. 验证、来源与交付

| 验证 | 本轮结果 |
| --- | --- |
| 新 fixture 单元 | 26/26 |
| 原 equal-seed / group-commit-load 回归 | 33/33、34/34；旧文件未修改 |
| Repo/链接、actionlint、diff | 通过 |
| 正式 release 与 build receipt | 本地通过；CI单独构建与绑定通过 |
| 本地实际/原始审计/负控 | 八cell、30负控、1正控通过 |
| CI实际/原始审计/负控 | 八cell、30负控、1正控通过 |
| Rust unit-only 精确覆盖 | 本轮fresh 1020/1020单位，85个生产文件四维各自精确100% |
| AWS Standard / 跨AZ / 稳态 / 生产SLO | NOT_RUN |

当前冻结候选的 [Rust coverage job](https://github.com/ckanner/scap/actions/runs/45132546814/job/137551446582)
原始日志逐文件核算：lines18228/18228、functions1605/1605、regions27692/27692、
branches3652/3652；没有用集成profile补单位。coverage artifact为14798816545，
其SHA与选取的原日志计数保存在机器证据。源输入相同不替代分别记录环境与build身份。

CI完整原件artifact为14799258285，ZIP184746031 bytes，SHA256：
`66a6fb6494d96b0fb01347f0bed8d5b71945b2da5dd937fa995e08528f45ed45`。
下载后重算一致；内部85841个条目，没有遗留私有执行目录。
本地原件ZIP为168951234 bytes，SHA256：
`b6e493a03234a2444b5b839cb438800cd339e513e58e84a2a9d6587dad3882bd`。
本地包内tar有83650个条目，其校验清单随包保存。两份原始audit的SHA、
manifest与bundle身份见机器证据及随交付的校验清单。原始HTTP/S3、对象body、
资源/进程、诊断、source archive和build日志不提交Git，只提交本派生验收记录。

首次冻结实现候选 `7cb0c222` 的 6 个工作流、29 个 job 已全部成功，最终状态
按机器证据中的逐 job 快照记账。原件包保留打包时的早期快照，最终派生记录
另列完成状态，不改写原始执行文件。最终 PR/merge 与后续 checks 状态见
[PR #72](https://github.com/ckanner/scap/pull/72)。本报告的文档提交不改变已测 fixture、
生产或 SDK 字节；补充文档后再次逐 SHA 核对 43 个 fixture 与 328 个 build 输入
完全一致，不将其另算一轮 actual 或宣称后续提交的 CI 已完成。

## 10. 下一目标，尚未实施

继续固定tenant40与原队列，不做无依据的额度扩容或继续盲扫组宽。下一候选先
有界拆分invocation内的native SQL、对象构建/编码、immutable PUT/readback、
request-index、最终Manifest/HEAD耗时；用明确计时边界区分重叠区间与观测开销。
只有证据支持时，才设计固定小并发（例如1→2）的独立不可变对象持久化对照。

依据是正式 [commit_group](../../crates/scap-object/src/group.rs) 仍逐成员做数据树
更新、原结果保存及请求索引追加，只共用最后HEAD；
[save_raw](../../crates/scap-object/src/object_context.rs) 仍逐对象create-only PUT
与exact GET。下一轮应研究真实服务时间，不能把少量HEAD摊销变化当成整体
持久化工作消失。

先冻结设计和资源上限，再实现、覆盖、故障注入和真实对照。保持每成员SQL/
结果/身份顺序、fresh HEAD、原ETag CAS、全部依赖持久且回读、native publication
后ACK；不删除最终Manifest exact GET，不把UNKNOWN改为自动重放，也不借增加
intake、cache、queue或timeout换取好看的结果。涉及生产变更时，完整四维单位覆盖
和受影响的原生/HTTP/S3/崩溃恢复门槛必须重新完成。
