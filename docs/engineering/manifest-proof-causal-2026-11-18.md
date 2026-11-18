# Manifest proof 历史回退：服务与观察器的分离诊断

评审日期：2026-11-17，America/New_York；原始执行时间为 UTC 2026-11-18。
文件名保留 UTC 归档日期，所有原始时间戳不改写。

## 结论与工程决策

**历史两组四库吞吐约 24% 的下降仍未归因，没有记成已修复。** 本次按事先
冻结的 2×2 计划，只运行四个样本；直连四库写下降 7.39%，原始 S3 证据代理
四库写下降 1.98%。同库、串行和读阶段方向也不一致，不能拼成统一收益。
全部原始样本和不利结果都保留。

本研究提交保留 #60 的操作内验证凭证研究记录和 #64 的 idle pool 8 证据；它没有
签发包含 #60 的合入许可。当前工程决策是让功能候选恢复普通精确 Manifest GET，
将 GET-elision 留在独立 #60 Draft，继续保留独立的 pool 8 修正。此决定须由新生产
候选完成受影响验证，不能借用这四个历史样本。**#60 的独立验收仍未闭合，
不宣称生产 SLO 或历史回退消失**。
理由与边界如下：

- 本次重新审查没有找到这两条当前路径的新正确性缺陷。proof 仍绑定原
  Objects/context/lineage、完整 HEAD、原 ETag、原 deadline、输入和输出根，
  消费时检查 quota/过期，在原 CAS 前重新检查共享健康状态；不可变对象仍然
  条件创建并完整回读。pool 8 仅增加每 host 的空闲连接上限，不开启重试，
  不改变条件 PUT、超时、ACK 或 UNKNOWN。它不是「所有并发连接最多 8」。
- 初始 proof 的确定性 String 指纹和 root clone 成本已由 `9b5e9ae` 的二进制
  指纹与 borrow/Cow 修正；这些变化保留完整绑定。此次历史对照刻意恢复了
  **修正前**的实现。不能用本次四个样本认证当前 9b + pool 8 整体的吞吐。
- 额外完整 HEAD 指纹在本次四库阶段只有约 0.76–0.84 ms 的 CPU 差异，
  远小于约 39–45 ms 的阶段耗时差。没有证据支持删除绑定校验来追回吞吐。
- #64 之前已独立证明四库连接 churn 的确定性问题，且有有界连接复用测试；
  这次两种历史实现都保持 pool 2，避免把该修正混入 proof 对照。没有理由
  把已证明的连接修正撤掉，也没有发现需要继续增大 pool 的依据。
- 本次没有新的生产改动；保留研究草稿不等于允许其进入完成功能验收的组合。
  功能批次已选择单独恢复业务提交的 `publish_in` 精确 Manifest GET 路径，
  将尚未验收的 GET-elision 留在 #60；#64 是独立 store 修改，继续保留。
  该拆分需要新生产候选、完整受影响单元/覆盖和实际合同，不是给历史下降找到
  根因，也不能未经验证仅切换调用就宣布通过。没有为规避门槛引入运行时开关。

### 哪个是既有门槛

这里没有新设一个「TPS 不能下降」的数字合入规则。原
[配对验证说明](verified-manifest-load-validation.md)第 44 行明确没有新增数字
TPS 通过阈值；[object-load 计划](../../experiments/object-load/PLAN.md)要求完整
实际、独立 oracle、负控、资源和来源证明，并固定 `production_slo_passed=false`。
因此机器记录中不把这个假定数字规则称为失败的既有 gate。

但是 #60 有明确的独立交付阻断：
[2026-11-13 review](sqlite-s3-review-2026-11-13.md)第 97 行把性能回退列为阻断；
[交付计划](sqlite-s3-delivery-plan.md)第 8–9、127–142 行对当前 9b 候选继续标记
Draft，并要求分解回退原因；原配对说明第 139–140 行要求表示/分配修改后保留
原反例与实际合同，再做独立冻结验收。这四个历史诊断没有完成该出口，不能把
旧分支覆盖缺口已关闭当成同时关闭 #60 性能问题。

#64 的交付依据与此不同：
[连接修正报告](service-hot-path-profile-2026-11-17.md)第 122–139 行明示接受依据
是确定的连接保留行为、旧 cap2 负控和原 fault/unit 合同，不是选取正向 TPS。
所有上述行号对应本轮审查起点 `42b50aa` 的文档内容。

实现依据见 [data_tree.rs](../../crates/scap-object/src/data_tree.rs)、
[object_context.rs](../../crates/scap-object/src/object_context.rs)、
[publication](../../crates/scap-object/src/lib.rs)、
[S3 client](../../crates/scap-object-store/src/lib.rs) 与
[HTTP connector](../../crates/scap-object-store/src/listing_guard.rs)。
前一次连接修正的独立证据见
[服务热路径诊断](service-hot-path-profile-2026-11-17.md)。

## 问题、冻结来源与工作量

原始负面证据完整保留在
[2026-11-13 验证报告](verified-manifest-load-validation.md) 和
[机器记录](../evidence/verified-manifest-load-local-2026-11-13.json)。
旧四库样本依次为 10.738→8.161 TPS（−24.00009%）和反向执行的
12.272→9.262 TPS（−24.52352%）。当时没有对应的 CPU、native、队列和
观察器阶段 profile，不能从今天的记录倒推出当时每个阶段的原因。

本次完整计划是 [CAUSAL_PLAN.md](../../experiments/service-profile/CAUSAL_PLAN.md)。
GitHub commit 对比确认，b15→967 与 fd508→b25 都没有 Rust、Cargo、SDK
或 object-load 输入变更；差异是文档、其他实验和覆盖工具。因此用本地 967
恢复 baseline，用远端 b25 的全部 11 个差异文件恢复 initial proof，并核对
每个 Git blob。生产差异只有 `data_tree.rs`、`object_context.rs`、`lib.rs`。

| 实现 | 原始生产输入 | 加同一探针后的本地冻结 commit | instrumented scapd SHA-256 |
|---|---|---|---|
| baseline | b15bc455 / 9674bb1 | `2ca9fa6d089f31bc0782cd38d15c8cd02e3ad35b` | `3efa4b1b104239fd0fcb32d4b75ad27e2fa80e330cd94bcccf4d15a1ca7f7320` |
| initial proof | fd508cc0 / b25b7855 | `b5824bc35198a167cd09332acb672c9d6965cbca` | `85a3f816e135b71c127fd60f9b602ffc2999162d60d0746d170e0c1215222466` |

这不是旧两个正式二进制的重跑。两个新源码副本使用相同 Rust counters、
global allocation 计数和 SDK probe，各自使用全新的专属 target。Rust 1.90.0、
LLVM 20.1.8、Node 22.16.0、SeaweedFS 4.51；libSQL 固定为
`d8bc862d20bedc72945a1da27c8b7045414c0261`。两个实际 `liblibsql.a` 散列一致：
`ab0981f53ac70eeafa604624f6ee4fdff0754f8b9195c713be35e138a85ba3f5`。

固定执行顺序是 baseline/direct、proof/evidence、proof/direct、baseline/evidence。
所有协作线程先明确停止编译、测试和后端负载，整个窗口约 87 秒；四个样本
均一次通过，等待各自服务、代理和后端退出后再开始下一个，没有重跑或剔除。

每个样本为 280 次 SDK POST：18 次设置、144 次计时请求、112 次原始结果
lookup、6 次最终数据检查。四个样本的请求 body SHA/长度多重集完全相同。
4 KiB payload 由固定公式产生，原始 `RETURNING random()` 结果逐一原样查回，
所有最终行/payload 均核对。这个小诊断与正式 871 请求合同不同：没有 32 MiB
冷库、cancel/fault 矩阵、正式 HTTP 证据 ledger 或资源 sampler。S3 evidence
两格保留的是原始完整 S3 代理，不能称为完整正式负载验收。

## 全部阶段结果

以下都是单次固定样本的成功请求/秒，未计算置信区间或跨样本平均。

| 阶段 | baseline 直连 | proof 直连 | 直连变化 | baseline 证据代理 | proof 证据代理 | 代理变化 |
|---|---:|---:|---:|---:|---:|---:|
| 单库串行写，16 次/C1 | 32.563 | 43.695 | +34.19% | 17.425 | 20.179 | +15.81% |
| 四库写，64 次/C4 | 112.648 | 104.324 | −7.39% | 33.038 | 32.384 | −1.98% |
| 同库写，32 次/C4 | 32.854 | 38.545 | +17.32% | 22.307 | 19.034 | −14.67% |
| 四库读，32 次/C4 | 1345.086 | 1347.476 | +0.18% | 821.100 | 758.469 | −7.63% |

精确整数计数、所有 stage 和延迟分位数见
[机器 JSON](../evidence/manifest-proof-causal-local-2026-11-18.json)。
这里的读结果也说明不能把小时间区间中的正负号直接当作只改写路径的稳定因果。
没有以「噪声」为名删去它们。

## 确定的请求与分配成本

两种传输下，四库写都得到完全相同的网络工作量差异：

| 64 次四库写 | baseline | initial proof | 差异 |
|---|---:|---:|---:|
| S3 GET | 768 | 704 | 少 64，恰好每次 SQL 发布一次 |
| S3 PUT | 384 | 384 | 无变化 |
| GET body bytes | 6,648,492 | 6,632,904 | 少 15,588 |
| PUT body bytes | 3,568,556 | 3,568,556 | 无变化 |
| 直连 Rust allocation calls | 189,872 | 181,252 | 少 8,620 |
| 直连累计 requested bytes | 90,796,178 | 88,147,507 | 少 2,648,671 |
| HEAD fingerprint 次数 | 64 | 128 | 多 64 |
| 直连 fingerprint CPU ms | 0.432 | 1.193 | 多 0.761 |

这里减少了 5.56% 的总 S3 请求，但只有约 15 KiB 的 GET body，PUT 工作量
完全未减少。每次提交仍有平均 11 个 GET、6 个 PUT，不能把少一个小 manifest
GET 等同于整个提交链同比加速。累计分配请求容量不是 live heap、RSS 或
native SQLite malloc；Rust instrumentation 本身也计入开销。

两份 evidence 原始记录分别有 2,569 / 2,451 次 S3 交换，差 118，等于
112 次业务写加 6 次 schema execute。使用历史冻结源码中的独立 wire reader
核对了全部交换的完整条件、签名 payload 摘要、原始 body/ETag、合法版本链和
不可变对象 frame；每个样本的 112 个随机原始结果均绑定到 result PUT、
完整 GET 回读和随后对应 HEAD。计时阶段的 wire 调用数和 body bytes 与 Rust
Objects 计数逐项相等。每个样本有 738 个 accepted versions；baseline 的
1,831 个 exact GET 配对和 proof 的 1,713 个配对均通过。

此诊断没有记录完整业务 HTTP ACK 区间，故独立 ACK 时间绑定标为
`NOT_CAPTURED_FOR_DIAGNOSTIC`；直连没有独立完整 wire transcript，也明确
标记未捕获。正式 871 请求 oracle 继续单独负责这些合同。

## 时间在哪里

### 原始证据代理本身占有明显成本

原代理逐字未变：每个 S3 响应 `Connection: close`，每次 RawStore 保存都
取得原有锁，新 body 的预算文件及 body 文件各 fsync；Trace 每行 flush，
关闭时 fsync，**不是每一行 Trace.emit 都 fsync**。新增包装器只计数，保留
原返回对象、异常和持锁行为。它们也会增加成本，两种实现使用相同包装器。

| 四库阶段 | baseline 代理 | proof 代理 |
|---|---:|---:|
| 阶段 elapsed ms | 1,937.191 | 1,976.294 |
| 观察器 process CPU ms | 1,899.882 | 1,742.482 |
| RawStore 锁累计等待 ms | 1,773.372 | 1,866.594 |
| RawStore.save 累计 wall ms | 3,170.774 | 3,264.781 |
| Trace 锁累计等待 ms | 1,089.391 | 1,022.407 |
| fsync 次数 | 768 | 768 |
| fsync 累计 wall ms | 391.483 | 517.190 |
| 实际新 TCP 连接 | 1,152 | 1,088 |

观察器 CPU 相当于阶段 elapsed 的约 98% / 88% 的一个 CPU，且等待锁的
成本显著。S3 GET+PUT inclusive wall 占 engine wall 约 97.7% / 97.1%；
直连分别约 86.8% / 88.0%。这证明代理是本诊断中的重要成本来源，不能把
代理测得的全部时间叫作 S3 后端延迟。

这些数是多线程累计且嵌套的 wall，**不能相加当总耗时**。RawStore.save 包含
锁等待和 fsync；上游 response wait 也不等于纯服务端存储时间。

### 本次剩余负值的位置，并不等于历史因果

直连四库阶段，proof 比 baseline 多 45.333 ms elapsed。engine 的累计 wall
多 185.656 ms，GET+PUT 的累计 wall 多 187.915 ms，其中 GET 少 64 次但
累计 wait 多 57.663 ms，PUT 数量相同而累计 wait 多 130.252 ms。checkpoint
累计 wall 反而少约 8.1 ms，native publication 约相同。新增指纹 CPU 约
0.761 ms 无法解释这些等待差异。

代理四库阶段多 39.103 ms elapsed；GET wall 少约 202.2 ms、PUT wall 多约
250.0 ms，checkpoint/native publication 也有不同等待。数据能指出差异出现
在何处，不能证明是 proof 改变了调度，也不能给旧 24% 下降指定一个根因。
两个实现的原始代码与探针相同关系是确定的，但每格只有一个样本；旧运行缺少
这些剖面，因此本次保持「未归因」。

## 下一步边界

不再为这次问题追加短 TPS 样本。没有证据支持改 FULL 同步、立即检查的
TRUNCATE、HEAD 验证、不可变回读、ACK 或 UNKNOWN。直连四库 checkpoint
仅约 engine inclusive wall 的 3.4–4.1%；为此做大范围存储改造不合适。

同库四并发仍然排队：直连 baseline/proof 每请求平均 queue 为 83.2/70.0 ms，
engine 为 30.3/25.9 ms。S3 权威和多库并行不会消除单库 writer 的串行阶段。
如后续产品目标明确要求提升这类吞吐，应单独设计有界 group commit 或更少的
durable round trips，先规定每个原事务结果、顺序、取消/权限屏障、UNKNOWN
和 native publication 的语义，再做协议和故障验收。lazy VFS 主要解决冷读与
cache 行为，不能仅凭本次 warm 写样本宣布必要或完成。

后续性能验收应先冻结用户要发布的实际配置、完整当前生产候选和验收阈值，
把无证据代理的性能观测与完整 oracle 的正确性验收分别保留。这样不会拿
减少证据作为产品优化，也不会以今天的小诊断替代 AWS 或生产容量验收。

## 工具与保留的证据

工具在 [service-profile](../../experiments/service-profile/README.md)：
`causal.py` 复用已有 backend/代理，`historical-instrumentation.patch` 与 Rust
metrics 只进入独立诊断副本，`summarize.py` 只读聚合并调用独立 wire reader。
三项包装器语义测试、Node 语法检查和两份诊断源码的 fmt/build/source identity
检查通过。全套正式 product unit、strict coverage 和 CI 另有记录；研究代码
不进入生产覆盖分母。

原始文件没有提交 Git。仓库外留存 1,528 个文件，包括四份所有调用记录、
完整 source tar、两个冻结二进制、源码清单、构建日志、原始及补全的 native
archive inventory、固定顺序和第一次审计结果。归档名
`historical-profile-raw-2026-11-18.tar.gz`，20,562,856 bytes，SHA-256：
`2c5591719784c92c00dcc9244f9d5bc2e51b2946a8e239606b0f98f6bf82a658`。
文件清单 `historical-profile-raw-manifest.json` 的 SHA-256：
`e0640cca936ef05a1ed7c9f01baf1b03666e95df737bde93274449da8c74000c`。
机器 JSON 记录每个 profile/run/source/binary 散列和全部聚合计数。
