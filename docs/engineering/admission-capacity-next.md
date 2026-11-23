# 下一阶段：固定资源下的接纳容量与请求持有时间

状态：**设计提案，尚未实现或运行**。本文的 96 秒、五档到达率、两个 ABBA block、
256 条 seed 等数值都是待冻结的设计参数，不是当前夹具已经支持的新 profile。
必须先完成本文件规定的硬上限推导、验收阈值和来源清单，再形成新的版本化合同。

依据为候选 `c6a40f41cda0aa188b1aef5da50019bb3bcc663f` 的真实本地 S3 验证，
对应 `short-v1-oracle.json` 与 `curve-v1-oracle.json`；执行来源、归档和最终验证状态见
[本次验证记录](admission-diagnostics-validation-2026-11-22.md)。本文不修改已完成的
生产代码、SDK 或实验夹具，也不将下一阶段设计计入当前证明。

## 1. 当前证据与待回答的问题

短 profile 的 289 条、长 profile 的 1384 条 BACKPRESSURE 原 HTTP 观测，全部首先命中：

```text
reason=intake_data_requests_tenant;used=40;limit=40;requested=1
```

现有 `data_intake=80` 是全局请求额度，省略的 v1 profile 将每租户额度设为 40；
单库数据队列额度为 `72 - 8 = 64`。本夹具只有一个租户和数据库，普通 HTTP data 请求
先经过 intake。因此这些观测已经定位了拒绝点，不能把未使用的队列额度直接解释为
应该增加的接纳名额。配置及原始工作量见
[固定 spec](../../experiments/group-commit-load/spec.py)，计数合同见
[资源拒绝诊断](../architecture/resource-rejection-diagnostics.md)。

### 1.1 零拒绝没有证明持续容量

长 profile 的 12/s 档固定在 16 秒内提供 192 条原事务：

| 模式 | 原 ACK | BP | 完整 drain 时间 | 4/8/12/16 秒的客户端未完成数 | 成功请求 p99 |
| --- | ---: | ---: | ---: | --- | ---: |
| off-1 | 192 | 0 | 20.750 s | 14 / 20 / 29 / 39 | 4.795 s |
| on-1 | 192 | 0 | 17.314 s | 5 / 12 / 16 / 16 | 1.945 s |
| on-2 | 192 | 0 | 19.440 s | 2 / 8 / 14 / 38 | 4.027 s |
| off-2 | 178 | 14 | 20.450 s | 5 / 23 / 40 / 39 | 4.600 s |

off-1 虽然最终全部成功，到达停止时仍有 39 条未完成。on-1 后段的积压较平缓，
但一个有限窗口也不足以证明长期平稳。这些数值是客户端未完成请求和样本分位数，
不表示服务端 queue/active 峰值。原 profile 名中的 `steady` 只是阶段标识。

### 1.2 drain TPS 必须与原 ACK 一起解释

长 profile 第二对高档固定到达 512 条、持续 16 秒：

| 指标 | off-2 | on-2 |
| --- | ---: | ---: |
| 原 ACK | 173 | 165 |
| 原成功率 | 33.789% | 32.227% |
| 到达窗口内 ACK | 133 | 125 |
| 完整 drain 时间 | 21.871 s | 18.876 s |
| ACK / 完整 drain 时间 | 7.910/s | 8.741/s |

完整 drain TPS 上升 10.51%，同时原 ACK 减少 8 条，成功率下降 1.5625 个百分点。
分母缩短不能单独构成接纳能力改善。

该对高档的起始状态还存在差异：off-2 为 242 行、243 个保留身份、20 页，on-2 为
256 行、257 个保留身份、21 页。差异来自前一档 off-2 的 14 条拒绝。ABBA 控制
开关顺序，不能消除同库累计阶段带来的起点变化。

以上数据与解释边界均来自本次 `curve-v1-oracle.json`，详见
[验证记录](admission-diagnostics-validation-2026-11-22.md)和
[当前实验合同](../../experiments/group-commit-load/README.md)。

### 1.3 还缺少哪些因果证据

拒绝快照没有区分 40 个名额分别在等待 body、排队、执行 SQL、持久化对象、HEAD
发布、native completion、编码或响应传输中的持有时间。它也不证明 group 持有
queue credits 是拒绝的唯一原因。没有 queue first-trigger，不等于队列后的串行执行
与对象 I/O 对 intake 持有时间没有影响。

HEAD PUT 减少也不等于总成本同比下降。第二对高档每 ACK 的 HEAD PUT 从 1 降至
0.133，全部 S3 请求数/ACK 下降约 12.33%，请求和响应 body 字节/ACK 却分别上升约
1.28% 和 1.46%。该对还有起始工作集差异，不能据此归因或外推 AWS 账单。
后续必须保留各成本维度及其分母。

## 2. 本阶段保留的资源与持久化边界

**保持租户 intake 40，不提高额度，不提前释放现有 lease。** 新设计的第一项目标是
测清原名额的实际驻留过程，并在相同资源内提高有效完成量。

当前 lease 在读取 body 前获得；完整读取后只退还未使用的 body extent。Job 在排队、
执行和清理时继续持有，响应 body、数据 frame、`Bytes` clone 和非空 slice 也持有
原 lease，最后一个实际所有者消失后才退款。超时、断开、receiver 消失与 native
工作完成不是同一个边界。group 未消费成员的额度和原请求身份继续保留。

实现依据为 [intake](../../crates/scap-service/src/intake.rs)、
[HTTP ownership](../../crates/scap-service/src/http.rs)、
[worker ownership](../../crates/scap-service/src/scheduler.rs)、
[group consumed boundary](../../crates/scap-service/src/scheduler/group.rs)及
[生命周期合同](../../crates/scap-service/docs/intake-reservations.md)。

直接增加名额会增加允许驻留的工作量；完成速度不变时，增加部分可能转化成等待、
尾延迟和内存持有。删除某个 lease owner 则会令计数与仍存活的工作或字节脱节。
两者都不能作为当前观测的直接修复。

所有后续候选继续遵守：原 SQL/参数/请求身份不变、不自动重放；不可变依赖完整
持久化并回读验证；HEAD 使用原 ETag 条件发布；FULL 与最终 native publication
处于成功确认之前。UNKNOWN、CBU、取消、冲突和失败关闭保持原语义。

## 3. 固定相同 seed 起点的有限增长实验

### 3.1 单元定义与唯一变量

一个实验单元是一个到达率、一种 group 开关、一份新后端、新服务、新数据库和
私有 cache。每个单元独立完成 seed 并 drain，不能承接上一档的成功数或取消记录。

第一份对照只改变 `admission.group_commit`。两边使用同一版本的诊断能力与观察器，
不同时改变 intake、队列、group 上限、原 SQL、payload、deadline 或缓存策略。
下列现有资源值继续作为基准，完整配置须逐字段冻结并由独立 oracle 核对：

| 资源 | 保留值或冻结要求 |
| --- | --- |
| data intake | 全局 80、租户 40；最大 body 65536 字节；全局和租户 body 额度各 5242880 字节 |
| queue | global/tenant/database total 为 96/80/72；control 预留 8；对应 data 额度 88/72/64 |
| actor 与 control | global actor 2、tenant actor 1、control workers 2；原 idle timeout |
| group on | 最多 8 成员；input 1048576 字节、changed pages 1024、result 1048576 字节 |
| 其他生产预算 | control/recovery intake、output、transport、cache、native recovery、typed result memory 和 retention 保持完整原配置 |
| 到达与期限 | 原客户端 inflight 192；固定 offer-lag 门槛；全部服务、客户端、S3 和传输 deadline 单独记录 |
| 环境 | 固定 CPU/内存/临时盘/任务资源合同、后端和客户端版本、观察器资源及其与服务的隔离方式 |

已有 RSS/磁盘采样峰值不构成资源硬上界，不能用它们反推更小的内存或磁盘合同。
若使用现有 kernel resource envelope，先完成容量推导与该环境的验收，再冻结完整配置。

### 3.2 建议矩阵，尚未冻结

| 设计参数 | 当前建议 | 冻结前要求 |
| --- | --- | --- |
| seed | 256 条已确认 INSERT，加原 schema execute | seed 走正式提交路径；核对全部原身份、结果与阶段边界 HEAD |
| 到达率 | 4、8、12、16、32/s | 每档独立新库；原开环时间表，不等待前一条完成 |
| 到达持续时间 | 每单元 96 秒 | 完整 drain 另计；服务和客户端单请求 deadline 不延长 |
| 分窗 | 12 个 8 秒窗口 | 同时报告 cohort 最终结果与时窗内实际完成量 |
| control | 每 4 秒一个 status，共 24 个 | 两边同一时间表，单独报告结果与尾延迟 |
| 重复 | 每档两个完整 ABBA block | 每档 8 个独立单元，全部配对和失败保留 |

这组建议对应 40 个单元，仅到达窗口就合计 **3840 秒**，尚未包括 seed、drain、
settlement、审计和清理。不能沿用当前全套 1200 秒期限。五档各单元的测量事务数
依次为 384、768、1152、1536、3072，建议全矩阵共 55296 个测量原身份。
若资源评估要求缩小矩阵，必须在第一条新证据产生前修改并冻结新合同版本。

seed 使用当前独立 INSERT、256 字节 payload 与 `random()` witness，不用本地 `.db`
拷贝替代权威恢复，也不把不确定的 seed 自动重放。计时前核对相同 schema、行数、
保留身份数、页数、epoch 和 cache 冷热规则，并记录原 HEAD/Manifest 来源。
独立初始化的随机 witness 和对象摘要可以不同；它们必须各自可验证，不能因此省略
起始形状对照。seed 未完整确认或起点不匹配时，该单元不进入有效计时样本。

计时期间保留原 INSERT，所以工作集仍会增长。报告应称为**相同起点的有限增长对照**。
每窗同时报告实际已提交身份、保留身份、page_count 和组尺寸；不能把它改称恒定工作集
或用一个增长中的 run 外推任意数据库规模的稳态容量。

## 4. 运行前必须完成的全部硬上限推导

以下为执行前阻断门槛。每项都必须给出数值、单位、推导、触顶行为和对应独立 oracle
规则；任何未填写项都令新 profile 保持 `NOT_RUN`。不接受沿用旧默认值作为推导。

| 上限域 | 必须覆盖的最大范围与推导内容 |
| --- | --- |
| 原身份与 retention | 每库 schema、seed、全部 offered 原身份，包括最终 cancelled；不能只数 ACK。建议最高档为 `1 + 256 + 3072 = 3329` 个，低于当前 4096 entry 上限；同时核对原结果字节额度。create/activate、status、lookup 等另入调用账本 |
| SQLite image | 从最多 3328 行、固定 schema/payload/witness、页大小、B-tree/overflow 和 SQLite 元数据推导完整逻辑 image 字节与页数上界；不得继续假定当前 128 页，也不以旧样本 34 页代替上界 |
| 数据与请求树审计 | 按 image 页数计算 32 页 chunk 数、末块长度、数据树允许层级及节点总量；另算 request/result 索引、保留条目和闭包遍历上限。不能未经推导继续假定 `data_tree_max_level=0` |
| HTTP 调用 | 枚举 create/activate/schema、seed、测量、control、最终 query、startup probes、每原身份的 lookup/cancel/再次 lookup；对所有 retry/settlement 分支采用合同允许的最大次数，不增加 SQL 重放 |
| S3 请求 | 按全部操作、最大对象/树规模、冷恢复、条件写冲突及已有有界重试推导 GET/PUT/其他操作上限；计入失败尝试、回读、取消屏障和查证，不仅统计成功 HEAD PUT |
| 原字节 capture | 汇总 HTTP/S3 请求和响应最大 body、capture 副本、header 副本、索引和封存开销；计算 per-body 与 aggregate 上限。当前 2 GiB raw、30000 个 S3 请求不能自动继承 |
| trace、diagnostics、采样 | 按每调用/每对象操作最大事件数、事件最长序列化尺寸及阶段事件推导 rows/bytes；固定直方图桶、计数器和 overflow 标志；按完整进程最长生存时间及采样间隔推导 sample 数 |
| 并发与对象所有权 | 单独冻结客户端 inflight、HTTP connections、proxy handlers、后台任务、fd、线程，以及解析/编码/审计同时持有的 buffer 数与字节；观察器不得形成无界等待队列 |
| 磁盘与 inode | 同时容纳 backend 权威对象与 orphan、native/WAL/sidecar、私有 cache、raw/trace、独立 image 重建、封存文件和失败证据；区分逻辑长度、实际 allocated bytes、inode 与预留空闲空间。GC 关闭时保留总增长账本 |
| 分阶段时间 | 分别固定 startup、seed、offer、drain、settlement、独立重建/审计、graceful shutdown 和强制清理期限；把原单请求 deadline 与并发限制纳入推导，不因 timeout 释放仍执行的工作 |
| 单元与全矩阵时间 | 明确 run ceiling 是一个单元、一个 ABBA block 还是全矩阵；覆盖全部固定单元和收尾。建议矩阵仅 offer 已需 3840 秒，旧 1200 秒不足 |
| 工具与输入身份 | 固定源码清单、release/SDK/native archive、后端/Node/观察器摘要、完整配置、plan、seed 和到达账本；独立观察器只能接受固定 registry 中的合同 |

retention 的 3329 是**每库原身份上界**，不是 S3 对象数、总请求数、image 页数或磁盘
上界。多个 scope/数据库之间也不能借这个数字隐含共享预算。

若推导出的完整最坏范围在本机资源内不可执行，先调整尚未冻结的矩阵或观察器实现，
再形成新候选。运行中任一硬上限触顶，必须停止并保留原始失败，标记相应单元未完成；
不能截断记录后声称通过，也不能扩大限额后覆盖原证据。后续新运行必须有新身份和
明确原因，不能用重复运行挑选成功样本。

## 5. 低基数生命周期诊断设计

这一项是未来生产候选的独立变更，当前没有实现。目标是拆解 intake 名额的实际
驻留时间，既有 `x-scap-rejection` 合同保持不变，不把直方图装入逐请求 header。

### 5.1 观测点与语义

| 观测 | 起止事件 | 解释边界 |
| --- | --- | --- |
| intake 总持有 | 成功 acquire → `Lease` 最后 drop | 包括真实工作和所有响应 owner；只记录一次 |
| 上传/派发前段 | acquire → 完整 body/成功 enqueue | 未到达后续阶段的拒绝或失败独立计数 |
| scheduler 等待 | enqueue → 实际 worker 执行开始 | 出队、选入 group 与 native 开始可不同，不能混用 |
| worker 阶段 | 实际执行开始 → 可信 consumed/native 返回边界 | 不把 HTTP deadline 当成工作结束；panic/unresolved 单列 |
| 最终编码 | 开始编码 → 最终错误或成功 envelope 确定 | 编码 fallback、CBU 和无 Reply 保留原分类 |
| 完工后的持有尾段 | 实际工作/编码结束 → 最后 lease drop | 只能解释该资源仍被持有的时间，不等同客户端业务处理时间 |

group 共享阶段应按 group 报告，并记录成员数；需要按成员统计时只使用每个成员真实
边界，不能把组耗时平均分配后称为原测量。多个 owner 可同时存活，重叠的阶段/资源
指标不能求和冒充一条串行时间线。被取消但尚未从队列移除的 Job 也继续按原生命周期计费。

### 5.2 有界实现要求

- 默认关闭，固定版本的实验两边同时启用。只使用固定 admission/outcome/stage 枚举；
  不以 tenant、database、request、SQL、对象 key 或路径建立标签。
- 时间戳/状态随已有有界 lease/Job 所有权携带；只保留固定数量字段。聚合为预分配
  固定桶直方图与计数器，没有每请求历史、后台日志队列或关键路径文件 I/O。
- 时钟、单位、直方图边界、观测遗漏和计数溢出的处理在实现前冻结。溢出/遗漏必须
  令该项诊断不可用于归因，不能静默截断后继续宣称完整；诊断失败不改变原提交结果。
- 导出走独立、受控且总字节有界的实验通道，不新增面向任意调用者的高基数接口；
  原匿名负载可见性与配置授权边界仍适用。
- 不为采集增加 S3 权限读取，不持有资源锁等待网络、native 或导出，不改变 worker
  drop 顺序、Batch consumed 边界、lease clone/frame/slice 或 deadline 行为。
- 定向验证 normal、queued cancellation、disconnect、timeout、panic、CBU、UNKNOWN、
  group 部分消费及最后字节 owner；仍通过每生产文件四维精确单元覆盖与独立真实生命周期验收。

带诊断的数据明确标记观察器开销。内部时钟提供阶段证据，HTTP/S3 外部原字节继续
负责结果与持久化核对；两种证据不能互相替代。

## 6. 证据驱动的优化出口

### 出口 A：排队或执行/持久化时间占主导

先区分等待与实际服务时间，以及 native、对象依赖、HEAD 发布和编码的主要占用。
选择一个有资源上界的候选，例如既有组大小参数的固定对照，或仅对相互独立的
不可变依赖执行有界 I/O 并行。对象依赖未全部验证前不得跨越 HEAD 发布屏障，原
ETag 和最终 native completion 不变；不把同库 SQLite writer 改成共享 WAL 的多写者。

一次候选只改变一个机制，intake 保持 40；不能同时提高队列、连接数或内存上限。
低负载没有自然兼容成员时允许组尺寸为一，不人为等待、阻塞或重排请求来凑组。
只有阶段证据和固定对照都支持时，才进入相应实现，当前不预定某一机制一定能提速。

### 出口 B：工作完成后的响应持有尾段占主导

此时才评估分离 work 与 response 额度。设计必须先取得独立的全局/租户 response
count 与 bytes 额度，完成 backing 与 ownership 的原子转移后才退还相应 work 额度。
仍执行或清理的 worker 保留自己的额度，body/frame/clone/slice 最后释放才退还响应
额度；转移失败保持原 UNKNOWN/CBU/receipt 语义。

该方案需要重新证明输入图、执行结果、编码 backing、响应 owner 的重叠上界与
异常路径，不能只删除现有 lease clone。当前证据尚未证明应采用此方案。

### 出口 C：容量参数的独立研究

只有前述归因与资源包络证明完成后，才另立 intake 参数对照，例如 32/40/48。
具体值仍待冻结，不能与 A/B 机制修改合并成一个变量。其结论是接纳、等待、资源
之间的取舍；没有相应有效完成量改善时，不把更大的等待容量称为吞吐优化。

## 7. 验收与交付顺序

### 7.1 证据合同通过条件

全部原 offered 身份进入分母；生成器拒绝、offer lag、诊断缺失、迟到 HTTP 观测和
所有失败如实保留。原 ACK、原结果字节、随机 witness、lookup/cancel、S3 闭包和
独立 SQLite `integrity_check` 全部符合原合同。控制通道与资源实际释放也须通过。
原 HTTP 晚于 SDK deadline 时，不能用诊断重写 SDK 的 UNKNOWN/DEADLINE。

完整原字节、配置、输入、来源、正对照及定向反例均通过独立 oracle；没有改善甚至
组尺寸全为一，也可以得到完整有效的测量证据。证据通过不自动成为优化结论。

### 7.2 优化候选通过条件

候选在运行前登记优化目标、所有配对和非退化阈值。建议将以下各项同时作为出口：

| 项目 | 必须冻结并报告的判定 |
| --- | --- |
| 业务完成量 | 原 ACK/全部 offered、到达窗内 ACK、拒绝率；若声称容量提升，原 ACK 与窗内 ACK 均应满足预登记的非退化要求，建议默认不容许减少 |
| 吞吐时间分母 | 原到达窗口、完整 drain 和全部原事务终态同时报告；不能单凭 ACK/drain 比值选胜者 |
| 尾延迟 | 成功、拒绝、其他失败各自的 p50/p95/p99，以及 control 延迟；冻结允许退化比例与绝对期限，保留每轮样本数，不事后选择有利分位数 |
| 未完成趋势 | 对声称可持续的给定工作集范围，冻结后段窗口及趋势判定；不能存在持续积压与延迟增长，仅靠有限 drain 清空不够 |
| 成本 | 按原 offered 和原 ACK 分别报告 S3 各操作次数、请求/响应 body 字节、CPU、RSS、临时盘和持久对象增长；冻结目标成本项与其他项的容忍范围 |
| 完整费用账本 | seed、load、drain、lookup/cancel settlement、独立重建/审计和清理分账后再合计；不能漏掉拒绝后的查证与取消成本 |
| 资源与观察器 | 所有硬上限、采样口径、诊断/观察器开销和输入来源不变；采样峰值仍不宣称硬上界 |

具体尾延迟、成本和改善幅度阈值目前**尚未冻结**，因此本文不能触发实施或宣称
任何候选已经满足生产 SLO。样本分位数与本地 body 字节成本继续保持原解释边界；
AWS Standard、跨 AZ、长期工作集、真实账单与生产尾延迟必须另行验证。

### 7.3 可执行交付顺序

1. 冻结矩阵、相同 seed 条件、完整配置、全部硬上限、成本分账和判定阈值；形成
   版本化 plan 与来源清单。任何待填项未解决，执行状态继续为 `NOT_RUN`。
2. 单独实现有界生命周期观测，验证默认关闭及原 ownership/结果不变，完成原单元
   与真实生命周期门槛；然后冻结新的源码与 release，不借用 c6a40f41 的证明替代。
3. 在相同起点、相同诊断和资源条件下收集完整 off/on 配对，独立审计全部原证据。
   保留不改善、容量触顶和失败结果，不在实验中途调整配置。
4. 根据主要驻留阶段选择 A、B 或继续保持原实现。每个优化机制另设候选、原样对照
   与完整验收，只有通过预登记非退化和资源门槛才形成部署建议。
5. 容量参数 C 与更大工作集/AWS 验收另行建档，不将当前有限本地样本升级为通用容量承诺。

本文是下一阶段实施入口；当前已完成证据及其有效范围仍以
[c6a40f41 验证记录](admission-diagnostics-validation-2026-11-22.md)为准。
