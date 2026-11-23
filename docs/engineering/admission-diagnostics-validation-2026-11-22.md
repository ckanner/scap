# 资源拒绝诊断与固定到达曲线：验证与接续决策

更新：2026-11-22（纽约）。[PR #70](https://github.com/ckanner/scap/pull/70) 已完成
代码、严格单位与本地真实 HTTP/S3 验证。诊断确认了本次样本首先命中的预算，但没有
证明提高额度能提高处理能力；group commit 继续默认关闭，原容量和资源释放规则保持。

基准为主线 `d066354`，即已合并的 [PR #69](https://github.com/ckanner/scap/pull/69)。
#69 最终 head `1c8bce1` 的 6 个 PR 工作流、26 个 job 均首次运行成功。这些历史
计数不作为本轮新增代码的证明。本轮来源、完整分窗与哈希见
[机器证据](../evidence/admission-diagnostics-local-2026-11-22.json)。

## 1. 实现及精确来源

[设计](../architecture/resource-rejection-diagnostics.md)规定可选、默认关闭的
`resource_diagnostics`，包含 41 个计数型与 5 个来源型原因。计数来自原互斥锁内
首个实际拒绝点，单个 `x-scap-rejection` 响应头最多 256 ASCII 字节。SDK 只在原
错误 envelope 已验证后添加冻结的 `RemoteError.resourceRejection`；u64 数字保留
十进制字符串，非法、未知或重复 metadata 不改变原错误和结果不确定性。

保留原 HTTP 状态、UNKNOWN、已提交回执和不重试 SQL 的合同；没有改变 intake、
队列、输出预算、优先级、FULL／受检 TRUNCATE、完整依赖回读、原 ETag CAS 或
native publication 与 ACK 的先后顺序。排队额度仍包含已取出、尚未实际释放的
组成员；诊断中的 `used` 不能替换成物理队列长度。启用诊断的匿名共享池占用可见性
以及默认关闭时的小量固定元数据开销，均在设计中明确，不声称零开销。

| 来源 | 固定值 |
| --- | --- |
| 本地运行源码 | `c6a40f41cda0aa188b1aef5da50019bb3bcc663f` |
| 源码 tree | `b6d6814f02c1866f9417677853f01567a39f6f98` |
| 正式 `scapd` SHA-256 | `1fe40b8d42e7cfcafdd34c25d96ecc46788bf546d36ce58d200a389bf1f1e6d9` |
| 实际链接 native archive SHA-256 | `ab0981f53ac70eeafa604624f6ee4fdff0754f8b9195c713be35e138a85ba3f5` |
| release 构建 | Rust 1.90.0，`--release --locked`，323 个输入逐文件 SHA-256 |
| 实际后端与客户端 | 本地 SeaweedFS 4.51；Node 22.16.0；独立 SQLite observer 3.53.1 |
| 原始证据归档 SHA-256 | `9c45e1ae434056970acd38f97df1ad0dea07e3b0b73479fce3177c1cdf4e0d29` |

归档为 `scap-admission-c6a40f41-evidence-2026-11-22.tar.gz`，89,310,446 字节，
保存全部原件、原始失败、源码归档、LLVM 报告及确切 executable/native archive。
Git 只保存派生摘要与哈希，不包含运行日志或数据库。后续本文与路线图的证据提交
没有修改生产、SDK 或实验输入；这些本地结果仍明确归属 `c6a40f41`，不能把报告
提交日期或新的 Git SHA 当作再次实际执行。

## 2. 验证台账

| 范围 | 状态 | 结果与边界 |
| --- | --- | --- |
| Rust stable 全 workspace | PASSED | 983 项；独立于集成 profile |
| Rust fresh nightly 单元覆盖 | PASSED | 同样 983 项；83 个生产文件逐文件四维精确 100% |
| Rust fmt／Clippy／独立 manifest | PASSED | 全 workspace/all-targets/all-features `-D warnings`；resource-limits 独立清单可构建 |
| Node SDK 单位 | PASSED | 192 项；23 个生产模块精确 V8 单元门禁 |
| Node HTTP／controller 进程 | PASSED | 独立 21 项，不补充 unit 覆盖 |
| TypeScript／codec | PASSED | TypeScript 5.9.3 严格声明；codec 13 项与精确覆盖 |
| 实验观察器 selftests | PASSED | 34 项，原 23 项保留；不代替 actual |
| 工具／文档／workflow | PASSED | 工具 76 项、401 statements/184 branches 精确覆盖；固定 actionlint 1.7.12、文档与 whitespace |
| 正式 release + 原组提交合同 | PASSED | 78 commands、82 HTTP、699 业务 S3；28 个提交及 28 份冷恢复原结果；20 个接受的 HEAD 与 1 个拒绝的组 CAS |
| 原组提交独立审计负控 | PASSED | 21 个原账本反例 + 19 个投影反例；不增加 actual 执行数 |
| `short-v1` actual／oracle／controls | PASSED | 640 个测量原 POST；34 个负控 + 1 个正控 |
| `admission-curve-v1` actual／oracle／controls | PASSED | 3,072 个测量原 POST；34 个负控 + 1 个正控 |
| AWS Standard、生产 SLO、长期成本 | NOT_RUN | 本地兼容后端与有限样本不能替代 |

Rust 四维合计为 lines **17,718 / 17,718**、functions **1,539 / 1,539**、
regions **26,935 / 26,935**、branches **3,592 / 3,592**；合计之外还检查了每个
生产文件，没有缺失 map、排除文件、零分母或用集成结果补单元。新
`rejection.rs` 自身是 92 lines、7 functions、108 regions、8 branches 全命中。
LLVM 完整报告 SHA-256 为
`0853883c762889f0cb98aaa5e2e0b525c00bc745e2126037f647ed1d4b829138`。

两套负载合计 **3,712 个测量原 POST = 2,039 ACK + 1,673 BACKPRESSURE**。
另有 8 个 schema 身份不进入测量分母。80 个 status 探针全部成功；测量中
UNKNOWN、transport failure、COMMITTED_BUT_UNAVAILABLE 和生成器拒绝均为 0。
每个测量原身份经过 lookup 和仅必要的 cancel 收尾，最终 2,039 committed、
1,673 cancelled；没有重试原 SQL，也没有用后续 lookup 替换原 ACK 数。
8 个独立 S3 重建数据库全部 `integrity_check=ok`，全部原随机结果与最终行集匹配。
这些是本次观察值，不能承诺未来无 UNKNOWN。

## 3. 固定实验合同

| profile | 每轮固定到达 | 轮次与分窗 | 总测量事务 |
| --- | --- | --- | ---: |
| `short-v1` | 32 @ 4/s（8s），128 @ 64/s（2s） | off-1/on-1/on-2/off-2；2s 窗口 | 640 |
| `admission-curve-v1` | 64 @ 4/s，192 @ 12/s，512 @ 32/s，各 16s | 同一 ABBA；每档四个 4s 窗口 | 3,072 |

每轮采用新后端和新库，同轮各档则共享持续增长的数据库与 retained index。
`steady` 只是固定中档的历史标识，不代表已达到稳态。原始到达计划、offer lag、
客户端在途数、实际 POST、原 HTTP metadata/正文、SDK 投影、S3 原件及配置全部独立绑定。
不使用人工 queue gate，不自适应降速，不在运行中扩大容量，不筛掉负面 pair。

两套合同的数据 intake 全局 80、租户默认 40；队列 global/tenant/database 为
96/80/72，control 预留 8，所以单库 data 额度 64。单请求 body 预留 64 KiB，
data body 全局/租户均 5 MiB，客户端在途上限 192。组上限 8 成员、input 1 MiB、
changed pages 1,024、result 1 MiB；服务保留配置仍为 4,096 identities／256 MiB。
短、长观察器分别限定 32/128 image pages 和 161/769 retained identities；
长合同已在 on-1/on-2 实际达到 34/33 页，验证了第二个 data chunk 的连续重建，
但不把未出现的最大 128 页称为实际装载结果。所有其他预算及截止时间见机器证据。

报告中的 TPS 是**原 ACK 数 / 从固定到达起点到完整 drain 的时间**。p99 是成功
原请求从预定到达到原 terminal 的 nearest-rank 样本分位数；它包括客户端调度、
网络和服务等待，不能解释成内部 SQL 或 queue-only 时间。拒绝延迟另报，避免
快速 BACKPRESSURE 把全体请求中位数变成“查询很快”的错觉：长 on-2 高档的
全体 p50 仅 12.184ms，而成功请求 p50 为 4,422.506ms。

## 4. 观察结果

### 4.1 首个拒绝预算已确认

全部 1,673 条原 HTTP 资源诊断均为：

```text
v=1;reason=intake_data_requests_tenant;used=40;limit=40;requested=1
```

短合同 289 条、长合同 1,384 条，SDK 无损投影与原 header 一致。独立 Python
observer 不调用 SDK parser，检查原因、原 code/status、配额和 u64 数学关系；
反例覆盖原 header 缺失／变形、计数与配置冲突及 SDK 投影被替换。

这证实的是**原判断时第一个阻止准入的计数器**。没有 queue first-trigger 样本，
不表示队列等待、SQL、对象持久化、最终 native 或响应持有没有消耗 intake 生命周期。
外部时间戳与同阶段 group HEAD 只提供时间关联，不能构造锁内决策时刻或因果结论。

### 4.2 原短合同：轻载无组，竞争档有局部收益

每轮轻载 32/32 原 ACK，约 4/s，全部单成员，32 次 HEAD 和 580 次 S3；每 ACK
18.125 次 S3。数据库从 2 页/0 行增长到 5 页/32 行。竞争档每轮 128 个原到达：

| 轮次 | 原 ACK / BP | 成功率 | 完整 drain（s） | ACK/drain（次/s） | ACK p99（ms） | HEAD PUT | S3 请求/ACK |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| off-1 | 53 / 75 | 41.406% | 5.701 | 9.296 | 4264.204 | 53 | 18.075 |
| on-1 | 57 / 71 | 44.531% | 4.740 | 12.025 | 3179.741 | 8 | 15.491 |
| on-2 | 57 / 71 | 44.531% | 4.905 | 11.621 | 3113.229 | 8 | 15.491 |
| off-2 | 56 / 72 | 43.750% | 5.375 | 10.419 | 3750.565 | 56 | 18.071 |

两对 ACK/drain 分别增加 **29.35% / 11.54%**，S3 请求/ACK 下降
**14.30% / 14.28%**；开启组提交均为 7 个八成员组加 1 个单成员，56/57 个
成功事务实际成组。竞争档结束均为 9 页，最终行数依 ABBA 为 85/89/89/88。
这是此固定工作负载的局部观察，不是普遍吞吐承诺，也不与 #69 的另一轮样本拼接。

### 4.3 较长中档：12 次/秒到达已有积压

长合同轻载每轮 64/64 原 ACK，约 4/s，全部单成员，64 次 HEAD 和 1,156 次 S3；
数据库从 2 页/0 行到 7 页/64 行。中档每轮固定 192 个到达，持续 16 秒：

| 轮次 | 原 ACK / BP | 成功率 | 完整 drain（s） | ACK/drain（次/s） | ACK p99（ms） | HEAD PUT | S3 请求/ACK |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| off-1 | 192 / 0 | 100.000% | 20.750 | 9.253 | 4795.276 | 192 | 20.062 |
| on-1 | 192 / 0 | 100.000% | 17.314 | 11.090 | 1944.709 | 51 | 17.859 |
| on-2 | 192 / 0 | 100.000% | 19.440 | 9.877 | 4026.556 | 63 | 18.047 |
| off-2 | 178 / 14 | 92.708% | 20.450 | 8.704 | 4599.854 | 178 | 19.978 |

| 轮次 | 4 / 8 / 12 / 16 秒时客户端未完成数 | 各 4 秒窗口内 ACK |
| --- | --- | --- |
| off-1 | 14 / 20 / 29 / 39 | 34 / 42 / 39 / 38 |
| on-1 | 5 / 12 / 16 / 16 | 43 / 41 / 44 / 48 |
| on-2 | 2 / 8 / 14 / 38 | 46 / 42 / 42 / 24 |
| off-2 | 5 / 23 / 40 / 39 | 43 / 30 / 30 / 36 |

前三轮虽然没有拒绝，但结束时仍有 39/16/38 个未完成请求；所有四轮完整 drain
都超过 16 秒，ACK/drain 也均低于 12/s。不能把“192 条最终全成功”写成已验证
可持续 12 TPS。未完成数来自客户端观察，不是服务端 queue 或 active 快照。

### 4.4 较长高档：吞吐比值与接纳能力必须分开

每轮固定 512 个原到达、32/s、持续 16 秒：

| 轮次 | 原 ACK / BP | 成功率 | 完整 drain（s） | ACK/drain（次/s） | ACK p99（ms） | HEAD PUT | S3 请求/ACK |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| off-1 | 155 / 357 | 30.273% | 20.302 | 7.635 | 6444.397 | 155 | 21.052 |
| on-1 | 185 / 327 | 36.133% | 19.674 | 9.403 | 4900.184 | 25 | 18.476 |
| on-2 | 165 / 347 | 32.227% | 18.876 | 8.741 | 5413.567 | 22 | 18.461 |
| off-2 | 173 / 339 | 33.789% | 21.871 | 7.910 | 6027.020 | 173 | 21.058 |

| 轮次 | 4 / 8 / 12 / 16 秒时客户端未完成数 | 各 4 秒窗口内 ACK |
| --- | --- | --- |
| off-1 | 39 / 40 / 39 / 39 | 32 / 28 / 34 / 22 |
| on-1 | 40 / 39 / 39 / 37 | 35 / 33 / 40 / 40 |
| on-2 | 41 / 40 / 40 / 40 | 29 / 32 / 32 / 32 |
| off-2 | 40 / 40 / 40 / 40 | 33 / 34 / 33 / 33 |

两对 ACK/drain 分别增加 **23.16% / 10.51%**，HEAD/ACK 下降
**86.49% / 86.67%**，S3 请求/ACK 下降 **12.24% / 12.33%**。
第二对同时出现下列负面结果，必须保留：

- 原 ACK **173 → 165**，减少 8 条；成功率 **33.789% → 32.227%**，下降
  1.5625 个百分点；到达窗口内 ACK 也从 **133 → 125**。
- 完整 drain 从 **21.871s → 18.876s**，缩短得更多，所以 ACK/drain 比值上升。
  不能仅凭这个比值判为接纳或容量优化通过。
- 高档起点不同：off-2 为 **242 行 / 20 页 / 243 retained identities**，on-2 为
  **256 行 / 21 页 / 257 retained identities**。差异来自前一档 off-2 的 14 次拒绝。
  ABBA 控制开关顺序，没有消除累计阶段的工作集差异。

成本与控制延迟也没有全面同向改善：第一对高档总 S3 请求 **3,263 → 3,418**，
即使每 ACK 请求更少，总数仍因更多成功和增长而增加。第二对每 ACK 请求／响应
body 字节约增加 **1.28% / 1.46%**。第一对高档 status 最大延迟
**54.162ms → 127.269ms**；每档只有 4 个探针，全部成功不等于控制尾延迟已改善。

## 5. 成本完整分账与解释限制

| 合同 | 测量阶段 S3 请求 | 全运行 S3 请求 | 全运行请求 body 字节 | 全运行响应 body 字节 |
| --- | ---: | ---: | ---: | ---: |
| short | 6,056 | 11,208 | 19,879,272 | 71,916,256 |
| curve | 32,296 | 62,674 | 195,715,600 | 533,205,814 |

全运行 S3 账包含启动、schema、负载，以及 `verify` 阶段的 lookup/cancel 和最终查询。
独立离线 oracle 从已经捕获的原字节重建与审计，不发出额外 S3 请求；它的 CPU／本地
I/O 成本不属于上表 S3 计数。机器摘要保留每档、每轮和全运行账，不只报 HEAD 节省。
这里仅计被观察到的 body 字节，不含完整 HTTP headers/TLS，也不能直接换算 AWS
账单。原字节捕获、fsync、代理与资源采样本身有开销；本地 SeaweedFS 与目标云端的
延迟和计费不同。

RSS/cache 采样峰值在摘要中保留，明确 `sampled_resource_peak_is_hard_bound=false`；
不能以采样峰值代替内核资源包络。单位覆盖、实际正确性和性能结论各自独立。
34 个负控验证 observer 拒绝被篡改证据的能力，没有生成额外真实并发样本；这次
负载只实际触达 intake 租户预算，其他原因的单元证明不能改称各原因都在此负载出现。

## 6. 原始失败与远端 CI

首次新增 SDK 单元的成功响应夹具使用空 SQL 数组，被既有 codec 合同拒绝：191
通过、1 失败。只改为合法 `SELECT 1` 与空参数列表，生产代码未为此放宽；随后完整
192 项与严格覆盖通过，原失败日志保留。不能将失败轮显示的 100% 覆盖称作测试通过。

首次增强 scheduler concurrent-starting 单元误期待 actor draining；原 gate 顺序先
检查 queue，实际为 `queue_database_data` 的 8/8/1：293 通过、1 失败。只修正测试
期待，没有改变生产顺序，随后完整 service 294 项通过。首次 codec 命令误用不存在的
`test/run.mjs`，属于 NOT_STARTED；按既有 `npm test` 执行后 13 项与覆盖通过。

<!-- CI_SNAPSHOT_START -->
截至 2026-11-23 00:24:00 UTC，生产 frozen source `c6a40f41` 的 **6 个 PR 工作流、27 个 job
全部首次运行成功**。单独的 push documentation run 不计入这 27 个 job。完整 run/job
身份见机器证据；所有实际阶段及最后的证据归档均已结束。评论与审查在合并前另行核对。

后续六文件 README/docs 交付使用新的 source manifest 与文件集／模式／blob 差异，
并重新执行文档内容、链接和 whitespace 门禁；323 个 release 输入、21 个 fixture 输入
及全部生产、SDK、实验、工具和 workflow 文件与 `c6a40f41` 原字节一致。这遵循
[本地验证规范](local-validation.md)的受影响输入验证，不改写实际运行身份。后续文档
head 自动触发的全套 CI 状态单独见 [PR #70 checks](https://github.com/ckanner/scap/pull/70/checks)，
不能把上面的 27 个成功 job 改署给新 head。
<!-- CI_SNAPSHOT_END -->

## 7. 决策与下一阶段

本轮拒绝诊断、短／长固定合同和当前来源的本地验证已完成。保持 group 默认关闭、
租户 intake 40、原队列与真实生命周期；不通过提前退款让尚存的 native／body／
response clone 脱离计费。要改变 work 与 response 的计费，必须先设计独立预算和
原子所有权转移，保留异常与不确定结果语义。

下一步按[相同起点的容量实验与生命周期诊断](admission-capacity-next.md)推进：
每个到达率单元独立使用相同已确认 seed 状态，冻结全部预算与运行上限，再观察
intake 获得、排队、worker/持久化、编码及最后响应释放各段。先定位服务时间，再
一次改变一个优化机制；提高额度的 sweep 另列。验收同时约束原 ACK、到达窗口内
ACK、拒绝率、成功与控制尾延迟、全账成本，不能只选更大的 TPS 比值。

96 秒多档等下一轮参数仍是待冻结设计，**NOT_RUN**；没有把本次 16 秒数据包装成
长时间稳态。AWS、长期 GC/保留成本、跨故障域恢复、预登记生产 SLO、跨库对象打包、
lazy VFS、任意时间 PITR、新 MVCC 和全局 fleet 共识继续按
[交付计划](sqlite-s3-delivery-plan.md)分别验收。
