# SQLite on S3：当前状态、目标与接续交付

更新：2026-11-20（纽约）。#65/#66/#67 已合入，基准主线为 `68246fd6`。
owner/controller/S1/S2、永久 worker 身份、有界连接复用、同库强读池、受信动态 fleet、
内核资源准入和固定开环合同均保留各自[历史交付来源](sqlite-s3-scale-validation-2026-11-18.md)。

## 本轮接续范围

[独立事务 group commit](../architecture/independent-group-commit.md)已实现三层协同：
private native 逐事务 staging、每成员逻辑版本/原结果及一次原 HEAD CAS、默认关闭的
有界 writer 队列组批。SQL 失败保留安全前缀，未开始后缀保序留队；取消/owner/权限等
仍在同 HEAD 排序；已执行成员不重试。完整单元/精确覆盖、独立协议模型与实际
HTTP/S3/进程恢复按[本轮验证记录](group-commit-validation-2026-11-20.md)归属。

接续目标继续分开交付：

1. 在目标后端对同一固定开环负载配对测单请求与组提交，报告独立成功事务、排队、
   p50/p95/p99、对象请求/字节和控制延迟。正确性与减少 HEAD CAS 不等于生产收益。
2. 跨库 WAL/对象打包仍需共享寻址、逐库发布和共享对象 GC；lazy VFS 仍需已授权
   固定根、native pager、校验按需读页和有界在途 I/O。具体边界见
   [Turso 接续设计](../architecture/turso-adoption-next.md)。
3. 任意时间 PITR 还需连续历史、时间索引与 GC 保护；现有 S2 是显式保留点的完整
   新 Scope 恢复。新引擎 MVCC 需 SQL、隔离、冲突、挂点和恢复独立兼容验收。
4. 目标 AWS、长期 GC/保留成本、跨故障域恢复、预先冻结的生产 SLO 保持 NOT_RUN。
   跨 controller 共识、自动扩缩容、每租户硬隔离和冷启动风暴仍有独立出口。

下文标明日期的组合数量和旧阶段描述保留各自历史身份；当前状态以上述主线为准。

以下 #65 数量是历史冻结结果，新候选仍需自己的完整门禁：

普通精确 Manifest 读取路径的冻结组合 `aab8a22` 的 stable/nightly 各 887 项 Rust 单位通过，76 个生产文件的
行／函数／region／branch 均精确 100%，无缺失 map 或零分母；fmt、严格 Clippy、
Node 161 项单位及其覆盖、HTTP 7 项和 controller HTTP/进程 12 项通过。新正式
release 又完成 S2 7 场景／126 负控、显式 ID 10 场景、自动 ID 18 场景及 TCP 8 场景。
这些是各自有来源绑定的结果，远端整体 CI 与合入状态以 [PR checks](https://github.com/ckanner/scap/pull/65/checks)为准。

本轮冻结源码、构建、修复及远端结论统一见
[self-review 与 CI 收口](sqlite-s3-self-review-2026-11-17.md)。旧候选的 877 项单位、
4 个核心文件未命中、8 个 branch 零分母和初版恢复审计漏检继续原样保留在
[前一组合验证](sqlite-s3-followup-validation-2026-11-17.md)。历史约 24% 四库吞吐
下降仍未归因，新诊断及保留的负面样本见
[因果诊断](manifest-proof-causal-2026-11-18.md)；性能验收不能仅凭正确性绿色批准。

## 1. 要交付的产品

目标是面向大量独立租户／Agent 的 SQLite 服务：应用使用 SQL 与明确的请求身份，
S3 中的 HEAD 和不可变对象保存唯一持久权威，计算实例和本地镜像可以全部丢失。
多实例通过同一 HEAD 的条件发布排序；单库 writer 由一个 actor 串行执行，本批
可选的固定 reader pool 使用相互独立的私有镜像并行强读。

验收目标按行为定义，不能把“SQLite on S3”当作已满足的性能或运维承诺：

| 目标 | 必须保持的可观察结果 | 当前证据与缺口 |
| --- | --- | --- |
| 持久提交 | ACK 前数据、原结果、请求身份与屏障已共同发布；断线后不重新执行 SQL | native gate、原 HEAD CAS 和原结果合同已有代码及新本地证据；严格单位门禁已通过；组合退出仍受各实际合同与完整 CI 约束 |
| 安全接管 | 旧实例迟到候选不能覆盖新 HEAD；controller 不把权限、忙或配置错误当成死亡 | 持久 owner 与固定 controller 已合入；#66 的有限配置历史、SIGHUP、不可逆退役和旧计划收敛已按动态实际合同验收合入 |
| 无状态计算 | 清空全部计算和缓存后，从真实对象闭包恢复原数据与原结果 | native／schema／原结果／生命周期／目录／deployment discovery 合同持续进入主线 CI；历史 `642383c` discovery 和 b15 固定 1 GiB／39 原结果／16,384 BLOB 实际各保留原始审计来源 |
| 明确保留与恢复 | 显式快照永久身份、完整 retained roots、释放与 GC 不误删；恢复生成全新数据库身份 | S1/S2 已通过 #65 合入，含独立目标、全部消费者及 HTTP/SDK；任意时间 PITR 仍未实现 |
| 可控资源与成本 | 有界准入、期限、请求和输出预算；失败不提前归还仍被占用的资源 | 资源／GC transport 持续回归；#66 的可选 cgroup/tmpfs 准入与固定开环进展合同已验收合入；每租户硬隔离和长期 metadata 增长仍需独立工作 |
| 可用吞吐 | 预先冻结工作负载和后端，再报告成功率、排队、p95/p99、恢复和每事务成本 | #64 保留对象/native/连接剖析；#66 已完成固定 64 条写的 SQL batch 比较和完整开环到达审计；#60 已关闭归档，历史回退未被归因或改称通过 |

本地 SQLite 活动文件必须在准入后的私有本地文件系统内。S3 不挂载为 `.db/WAL/SHM`，
不同节点不共享这些活动文件；跨节点 fencing 依赖对象条件写。相关实现和官方依据见
[安全与吞吐](../architecture/sqlite-s3-safety-and-throughput.md)及
[部署要求](../operations/sqlite-storage-safety.md)。这消除了方案对网络文件锁的依赖，
没有消除本地 I/O 故障、错误部署或单库 writer 串行的边界。

## 2. 已完成、当前在做、尚未完成

### 已合入：2026-11-18 接续实现（#66）

- 读池已实现：独立 native 镜像、固定 worker、tenant/database 活跃额度、共享排队
  与控制预留、SQL 前最多一次 stale 重建、panic/停机的真实资源归还。
- 动态 fleet 已实现：完整有界策略历史、不可逆退役、原目标 guard、旧计划处理、
  进程内 revision 和 SIGHUP；新配置只能来自受信部署输入，原 SQL 不重放。
- 资源准入已实现：有限 cgroup v2、普通 CPU 调度、有限 tmpfs 总容量/inode、整组
  OOM 与非免疫任务；`--check-config` 可在领取永久身份之前验证部署条件。
- 四个独立实际入口均已完成各自冻结来源的运行与 CI 审计；读池 19 负控、动态
  fleet 13 负控、内核 24 负控均有原件核验，过载首轮 CI 的完整 18 负控门禁通过，
  大 ZIP 的取回范围与后续保留硬链接的包装修复分别记录。
- 最新组合 stable/nightly 各 911 单位、77 个 Rust 生产文件逐文件四维精确 100%，
  Node 182 单位及 22 模块精确 V8、HTTP/CLI/类型通过。所有原失败与最终提交 CI
  归属见[当前记录](sqlite-s3-scale-validation-2026-11-18.md)，不把旧候选认证转给新 head。

### 历史：2026-11-17 代码与证据

- #59 `b4c5236` 在调度锁内、创建 actor 和占用队列前拒绝过期请求。独立 stable/nightly
  各 787 项单位通过，两个调度文件的行／函数／region／branch 都完整覆盖。
- #60 `9b5e9ae` 保留完整 HEAD 指纹及所有原 proof 绑定，减少十六进制和根字符串分配。
  独立 792 项单位与严格 Clippy 通过；有界 helper 分析不认证整体吞吐，原 24% 回退未定位。
- #61 `841da9c` 在同一对象后端永久登记启动 ID。独立 stable/nightly 各 797 项单位、
  真实进程 10 个启动故障与 8 个 bounded TCP 场景通过；自动分配随后由 #62 实现。
- #62 在显式管理初始化后，用 exact GET／原 ETag CAS 分配单调新编号，再永久占用。
  独立 stable/nightly 各 808 单位、真实自动分配 18 场景及显式 ID 兼容 10 场景通过。
  UNKNOWN 不收养、不复用；自动 ID 不更新静态路由，也不自动接管数据库。
- #63 实现 retained point 到全新 Scope 的完整恢复：first-winner、重封装、native
  校验、完成记录、撤权／取消屏障、独立副本、HTTP/SDK、长恢复资源及所有元数据消费者。
  实际运行与最终覆盖绑定新候选；原 S1 模型和旧库容量实验不替代这些证据。
- #64 完成真实服务诊断和有界连接修复。四库写的新建连接 83→4，同一阶段对象调用／
  字节完全相同；局部 45 单位和实际 TCP 负控通过。读写 TPS 方向不一致，保留 FULL
  和受检 TRUNCATE，历史约 24% 回退仍未解释。

以上是各 PR 当时的局部结果。后续 #65 self-review 已关闭原 8 个 branch 零分母与
恢复核心未命中计数，完整 887 项单位／76 文件四维门禁通过；旧报告的失败不改写。
当前完整实际及 CI 的候选身份由本页开头的新记录维护。

### 2026-11-13 历史组合证据

以下 b15、fd508、642 结果只认证当时各自冻结的源码，不认证本轮新提交。

PR #59 已组合 HEAD8 owner-plan、生产 controller 和 HEAD9 S1 retained snapshots。
PR #60 只在一次新事务内消费已验证 Manifest 的私有证明，省去发布前的重复 GET；
仍保留不可变对象条件创建及第一次回读、原 HEAD body／ETag 与原 deadline 的核对、
原条件 CAS、native publication 和 ACK 顺序。它没有实现 group commit、同库 MVCC、
lazy VFS 或异步确认。

本轮 b15 的 stable/nightly 各 783 项、fd508 的各 791 项 Rust 单位通过。两份报告的
67 个生产文件都有 map，已发出计数全命中，但其中 7 文件 branch 0/0；旧检查器没有
阻止其他文件的正分母掩盖该缺口。修复后的严格检查器对原两份报告均退出 1，因此
不能称作四维 100% 通过。问题涉及未被独立计数的 `match`／`?` 等路径，不是再加几项
通过测试就能证明；现行要求与可审计修复方向见
[分支测量说明](branch-coverage-measurement-gap.md)。

b15 的 SDK 157 项、codec 13 项、HTTP/TLS/CLI loopback 19 项与类型／工具／模型另有
本轮证据。native／schema／retained results、生命周期、116 目录案例、listing、
bounded response 和 deployment discovery 已重新通过。固定 b15 的原 1 GiB actual、
关闭镜像捕获、全 BLOB／原结果独立审计及 5 负控／原正控也完整通过，详见
[容量验收](capacity-gib1-validation-2026-11-13.md)。默认 10 GiB、fd508 容量与真实
AWS 仍未运行，关闭副本审计不计作第二次 S3 恢复。

owner Missing 的 13 负控／1 正控、单 controller 的 15／1、S1 的 10／1 均完成。
[固定 controller 矩阵](../../experiments/object-controller-matrix/PLAN.md)本轮有 23 项
夹具自测、12 场景 actual、独立 oracle 与 31 负控；完整原矩阵在负控前后复核，
不是两次新实际。按本轮 12 份 case 报告汇总：20 个生产 controller、108 个 owned
子进程、586 个 HTTP（其中 363 个控制器请求）、1,914 个 S3 请求；36 个原 SQL 身份
包含 24 个 ACK 和 12 个 UNKNOWN，随后 36 次原 lookup 与 12 个保留快照逐一核对。

原 13 项服务合同中 11 项完整通过，isolation 和 service discovery 首轮失败；资源与
42 例 GC transport 已包含在这 13 项中。owner-plan 首轮在 seed 阶段失败，未进入其
后续故障合同。这些父分组仍记录 FAILED。HEAD6 首轮原 180 秒 hold 超时也保留，
第二次完整 actual、独立 oracle、23 负控／1 正控已经通过；HEAD7 终态的 actual、
独立 oracle、25 负控／1 正控通过。首轮失败不能拼接成新通过，也不能只归因于机器忙。

其后的 isolation 完整实际／21 负控／1 正控和 owner-plan 完整实际／独立 oracle／
42 负控／1 正控均按原预算通过，因此 b15 服务合同现有 12/13 项完整通过记录，
owner／controller／S1 五项均有完整通过记录。新结果分别保留，未覆盖失败父分组。
`642383c` service discovery 和固定容量均以新的证据目录与原预算完成，其精确来源由
[本轮 review](sqlite-s3-review-2026-11-13.md#2-验证状态与证据归属)维护。
service discovery 增加真实 handler 入口见证，保留认证日志时钟、原 29 负控，
另加 3 个时钟负控；不扩大原 HTTP 归属窗口，不给旧历史补字段。该修复在正式 release
输入范围内，已使用新正式构建 receipt 和全新实际；完整入口／独立 oracle／32 负控
及原正控通过，424 HTTP、25,278 S3，来源仍为 `642383c`，不回填 b15。

### 历史请求数收益与当前吞吐边界

PR #60 的原正确性合同与两组相反顺序的配对 actual、独立 oracle、原 14 负控／3 正控
均通过。每组的单库 C1、同库 C4、四库 C4 phase 分别少 32／64／64 个 Manifest GET，
合计少 160 个；其他对象类别请求计数相同。这个结论只证明固定负载下减少了请求数。

第一组端到端 rate 混合，四库下降 24.00%。反向组 baseline→candidate 的单库 C1 为
7.838→6.442、同库 C4 为 6.356→5.538、四库 C4 为 12.272→9.262 次／秒，四库下降
24.52%。顺序翻转没有排除回退。PR #60 保持 Draft，后续先定位 actor、native、对象
请求与响应等待，不继续用重复的小样本配对代替分析，也不按减少 GET 的比例推算
TPS、p99 或生产成本收益。上述是当时状态；2026-11-18 的[正式决策](manifest-get-elision-decision-2026-11-18.md)
已选择保留普通 GET、归档该候选，不继续把没有归因的回退作为待合入优化。

### 历史：#65 合入台账与产品出口

#65 已合入；下表保留其交付时边界，早期 #59/#60 的局部报告仍是历史来源。
本批四项接续能力使用开头的新记录，正确性、性能与后续产品能力分别判定。

| 工作 | 当前合入边界 | 交付判据 |
| --- | --- | --- |
| 单位、逐文件精确覆盖、Node／类型、二进制来源 | 完整 #65 单位与严格四维门禁已通过；实际／CI 来源继续核对 | 每份实际与构建 receipt、源码清单相符；各生产文件的必要计数与原反例独立可审计，不放宽门槛 |
| native／schema／retained results／生命周期／目录／发现／1 GiB | 本批全部已取得最终结果；b15 与新 discovery 的来源分开记录，原失败保留 | 固定完整场景、原始 ACK／BLOB／对象账本和独立审计；新提交仍按受影响源码判定，不复用旧 receipt 冒称最终合并源码全测 |
| HTTP／隔离／资源／输出／GC transport／HEAD6／终态 | HEAD6、终态、isolation 全套已完成；service discovery 的新 `642383c` 观测来源也已通过完整验收，原失败保留 | 原实际入口、独立 oracle、原负控与资源归属全部完成；不覆盖失败父分组，不拼接实际历史 |
| owner-plan／Missing／controller／S1 | 五项均有完整实际及规定审计／负控通过；owner-plan 首轮失败保留 | 原控制与业务身份、HTTP／S3／进程和实际 Node/SDK 源匹配；不扩大为动态 fleet 与持久实例身份已交付 |
| Manifest 优化与配对性能 | #60 独立交付；请求数下降已证明，吞吐回退未排除 | 保持提交语义与原结果正确性，分解回退原因；不能以请求数减少代替吞吐、尾延迟或整体退出 |
| S2 restore、任意时间 PITR | #59 只交付 S1；#63 已实现 S2，保持独立审查；PITR 未实现 | S2 按新产品／消费者／实际故障证据退出；PITR 还需连续历史、选点和 GC 协议 |
| worker 永久登记、自动分配与动态 fleet | #61 防复用，#62 自动分配已有完整局部验证；历史迁移与 IAM 另验 | 动态成员、路由刷新、自动 owner 接管与硬隔离分别设计、实现和验收 |
| 真实 AWS、长运行成本、生产 SLO | 不作为本地 S1 有限交付已完成的声明；阻断相应生产承诺 | 目标后端／权限／故障域和负载先固定，再实际执行 |

维护者已授权完整本地验证作为合入依据。远端 CI 的失败和无法取得的日志仍原样记录，
不把本地结果改称远端 CI 通过，不修改分支保护。所需本地门禁缺失时保持 Draft；
门禁齐备后重新读取 PR head/main，用精确 head 合入并核对最终 tree。

### 历史检查点与本轮重新采集的区别

11–12 日的 `3b1d50c` 记录 native 普通合同、30 个扩展故障、schema、12×6=72 个
retained-result 入口、生命周期、116 个目录案例、deployment discovery 和固定
1 GiB 冷恢复通过。容量记录核对 16,384 个 64 KiB BLOB 和 native integrity_check；
38 个原 execute ACK 与一个 UNKNOWN 后原 lookup 分列，不能把 39 条账本都称为
原 ACK，见[当时的 native 记录](../evidence/sqlite-s3-integration-native-local-2026-11-12.json)。

`e64eb56` 当时完成固定 12 场景、23 项自测与 31 负控，其 runtime 来源是 `fc10287`。
更早 `73a7140` 的 12 例实际、旧 oracle 和 28 负控虽然完成，后续反例发现 Node 入口
只验证路径后缀。接续增加完整路径、逐文件 hash 与运行选项绑定及 3 个负控，并重跑
完整矩阵；没有给旧事件补字段，见
[历史矩阵记录](../evidence/sqlite-s3-integration-controller-matrix-local-2026-11-12.json)。

`6784258` 的 S2 模型修正完成屏障：两次源 HEAD 均先检查当前 ADMIN+READ，再读取
元数据或分类冲突；撤权后失败的复制前缀不能续用。记录为 38 项自测、804 正例／48
负控，原 804／47 保留；产品 restore API 未开放，见
[模型记录](../evidence/sqlite-s3-integration-models-local-2026-11-12.json)。当时的负载
5.149／2.822／7.206 次每秒、每写约 18–20 个对象请求是另一环境的历史基线，不与
本轮配对混算。

上述历史提交、退出码和计数保持原样。部分原始构建、profile 或运行文件未恢复，
摘要及 hash 不能替代原件，所以本轮重新采集必要合同。历史“精确覆盖”只表明当时
编译器已发出的计数与 checker 结果，不证明现行严格要求下所有分支均被测量，也不能
抵消本轮 branch 0/0 阻断。

## 3. 分阶段合同与接续出口

### 第一阶段：owner、controller、S1（#65 已交付，保留持续回归）

本阶段的目标仍是完整交付有限 owner／controller／S1，不是扩大成动态集群控制器。
环境恢复、HEAD6 全部 23 负控／1 正控和终态全部 25 负控／1 正控已有历史完整记录；
#65/#66 的严格分支门禁、完整组合 CI 与必要实际审计均已完成，继续作为新提交的回归要求。测量修复须能发现未
执行的 `match`、or-pattern、错误返回等路径；不把 0/0 改成成功，不删生产文件、不混入
集成 profile，也不因其余文件计数为正而跳过。

原 isolation、owner-plan、service discovery 失败及新实际分别保留；新请求接收见证
只能用于真实采集它的新历史。固定容量必须完成完整 BLOB／镜像／对象账本与原负控，
不能从工具自测推断。完成后将精确源码、正式 release／receipt、命令、原始轨迹、
独立审计、负控与原件归档逐项对应；只有完整必要门禁齐备才能判定合入。

已经完成的固定矩阵与原 owner／Missing 专项分层证明下列合同，范围不能扩大到任意
fleet 或未验证的实例身份分配：

1. 相同 policy／同一 S 的多实例竞争和 first-winner；prepare 丢 ACK、无本地输入
   重启，以及 Missing 读取与迟到 immutable PUT 的相遇。
2. 不同 policy／creator 与人工 marker 的阻断；当前 authority、accepted 历史阶段、
   当前 HTTP 回执分别解释，不能仅信 CLI 的 active 报告。
3. Claimed 与 Cancelling 的重启收养，abort 前后旧 CAS 到达和 UNKNOWN 后的新一步。
4. 权限撤回、目标替换／误绑、429、S3 不可用和 wire 错误不会触发无条件接管。
5. 原 deadline、停机及 owned 资源归属；controller 全程不 execute，原业务仅用原
   lookup／cancel 查证，保留非确定 SQL 的原结果。

可复用低层 owner 真实合同的前提是注明其精确覆盖范围；模型、手工 owner 客户端、
生产 CLI 和服务资源合同互不代替。新增夹具先固定场景与负控，再提交冻结，实际执行
使用新的证据目录。任何产品缺陷另提交修复，并重跑受影响门禁。

显式模式仍要求部署提供不复用的 `worker_instance`；#62 的 auto 模式可以从永久
counter 取得新身份，但初始化历史、counter/marker 保留与 IAM 仍是部署前提。
数值 guard 不能代替进程身份认证。动态 fleet、在线策略更新与自动扩缩容需要独立
协议、迁移规则和竞争／撤权／停机实际，不由当前固定 controller 矩阵推导。

### 第二阶段：S2，从一个保留点恢复到全新 Scope（#65 已交付）

[HEAD9 设计](../architecture/retained-snapshot-restore.md)的 S2 已在 #63 作为完整协议
切片实现。以下约束都属于产品和消费者，不是只开放一个 copy 按钮：

- 固定 source SnapshotRef 与 target creation recipe，永久 first-winner 身份和严格格式；
  断线重试和重启沿原意图查证，不另造可竞争的目标身份。
- 全部 Catalogue create／inspect／discovery／recovery／abort 消费者识别恢复阶段；
  普通 Empty 创建路径不能把 Copying 目标发布为 Ready。
- 有界后序遍历，自底向上重封装 Chunk／Node／Manifest；每个目标对象都属于新 Scope，
  逐个条件创建和回读。完整 native 校验之前不得形成 completion。
- CompletionRecord 固定已授权、独立完成的复制；没有它的重启需要重新验证源，
  有它的合法续进不再依赖已释放源 payload。两次源 HEAD 的当前 ADMIN+READ 检查
  必须先于元数据读取／冲突分类，完成屏障的最后检查与撤权竞争有明确时序；目标
  侧的当前权限与取消屏障仍需独立验证。
- Name 与目标 HEAD 的永久取消屏障。迟到对象／completion 不能复活已取消目标；
  Ready 使用新 ACL、owner 准入、sequence 和空请求空间。
- 认证 HTTP／SDK、明确 resume 和 recovery admission；单次控制调用最多一个权威 CAS，
  长 copy 的源 GET、目标 PUT／readback、本地临时文件和总期限独立计账。

交付出口包含 source 撤权／释放／GC、同 target 双 resume、逐切点 UNKNOWN、全缓存
丢失、target abort 与迟到原请求，以及删除源全部 payload 后目标独立冷恢复。每类
都需产品原生实际、HTTP／SDK、独立原始审计和定向反例；模型通过不能替代消费者。
S1 历史候选仍保持 `restore_origin = null`；S2 在完整消费者中识别 Copying/Copied，
不能用旧 S1 receipt 认证新格式。完成记录还在但永久目标 HEAD 丢失时必须拒绝重建；
合法并发创建与真实权威丢失分别分类。恢复准入在启动身份占用之前校验并构造，运行
任务一直持有原租户／恢复额度直到 native 和临时目录释放。

任意时间 PITR 还需独立的历史日志保留、时间／提交点选择、GC 保护与恢复验证，不作为
S2 的隐含能力。HTTP 字段、资源配置和 SDK 用法见
[恢复接口](../../crates/scap-service/docs/restore.md)，实际合同见
[S2 实验](../../experiments/object-restore-runtime/README.md)。

### 第三阶段：资源与吞吐，先量化再改协议

本轮已用真实服务拆分对象等待、native publication、checkpoint、CPU、Rust 分配和
TCP 连接；#64 的固定四库写样本中，对象等待约占 Engine 的 84.7%，同库写的排队
仍显著高于执行时间。有界 keep-alive 池修复了被直接观测到的连接反复创建，保留全部
正负 TPS 样本；没有降低同步或 ACK 要求。完整来源和限制见
[#64 报告](https://github.com/ckanner/scap/blob/5775c07e71bf83f6055146a183128079b962cb3c/docs/engineering/service-hot-path-profile-2026-11-17.md)。

PR #60 两组配对中减少 Manifest GET 但 rate 下降的历史因果仍待解释。固定候选、构建、
后端、预算、事务与观察方法，拆分 actor 排队、native、对象上传／回读、HEAD CAS 和
响应等待，并独立记录 CPU、内存、磁盘与后端成本。不能预先把差异归因为环境噪声，
也不靠删除必要审计或延长原 deadline 让候选变快。

沿现有提交语义比较相同逻辑事务与成功结果；对比同环境下单语句与已有 SQL batch。
独立报告事务数／秒与逻辑操作数／秒，不把批量更多语句写成独立事务吞吐提升。

随后根据账本选择减少重复读取／副本与对象往返，保留 #66 已交付的固定开环过载、
热点/quiet/control 分窗进展与资源归还合同，继续补冷启动风暴和长期重复 GC。
每项优化同时保留正确性回归和同环境
前后对照，不能省掉必要 readback 或延后 ACK 后才上传来换取表面吞吐。

资源验收覆盖 decode／native heap、在途对象、输出与 staging 磁盘，以及受管子进程；
逻辑数据库配额、对象数量、进程 RSS 与 bucket 总占用分别计量。固定开环到达率、
租户分布、热点与冷库比例后，观察持续过载时的有界队列、拒绝／取消、期限、租户
公平性及资源归还。超时或取消不能提前归还仍被 native 或 I/O 使用的额度；停机后
所有 owned 工作的结束也属于实际合同。长运行需跨多轮 GC、保留／释放和全缓存
丢失，验证 metadata 与存储增长的收敛，不以一次 sweep 或逻辑配额代替。

已合入的同库读池以私有完整镜像和每次新 HEAD 授权实现，见[独立合同](../../crates/scap-service/docs/read-pool.md)。
group commit、跨库 WAL 聚合、lazy VFS 与新 MVCC 引擎仍各自改变提交／可见性／恢复关系，必须独立
立项；现有跨库并发、reader pool 和 SQL batch 不能宣称已经实现这些能力。Turso 的公开实现与
Cloud 路径只作设计参考，不能借用其基准作为 SCAP 实测。采纳、暂缓理由与后续协议
要求见 [Turso 接续设计](../architecture/turso-adoption-next.md)。

### 第四阶段：目标后端与试运行出口

明确目标 S3 产品、IAM／KMS／版本与删除策略、区域／故障域、对象配额和成本口径；
执行真实条件创建、回读、HEAD CAS、条件删除、并发、撤权、超时／UNKNOWN、全计算
丢失恢复和长运行。部署验收同时核对本地文件系统准入及真实挂载；类型分类测试不能
替代 NFS/EFS/FUSE 或 overlay 底层的实际验证。

先冻结业务需要的数字目标、工作负载与故障场景，再报告成功率、吞吐、排队、p95/p99、
恢复时间、对象请求数、存储增长及成本，按该目标判断非关键业务试运行条件。本页
不虚设未测量的 SLO。真实 AWS 项目当前保持 NOT_RUN；本地 SeaweedFS 不代替 AWS
Standard，S3 Express One Zone 也不能仅靠向 Standard checkpoint 就推出跨 AZ RPO=0。

## 4. 提交与证据维护

每个能独立审查的协议、产品、夹具或文档改动及时提交；运行前固定提交和源码清单。
原始失败保留在原目录，新候选使用新目录和完整场景，机器记录只摘录必要哈希、计数、
退出码与边界。生产变更重新构建并执行受影响的精确覆盖和实际合同。判断二进制能否
复用依据正式构建输入逐文件清单，不能仅凭“只改 Python／夹具”作决定；本轮 discovery
时钟文件属于正式 service 构建输入，`642383c` 使用新 release／receipt。仅在构建输入
完全相同的情况下才可复用原二进制，并同时写明运行时与新夹具两份来源。

已完成原件按明确白名单保存、校验并建立索引；失败与通过 scope 分开，私有 fixture
凭据不进入公开证据或 Git。历史原件丢失须明确记录，重新采集使用新身份；不能用
旧机器摘要恢复出不存在的 HTTP／S3／ACK、receipt 或 coverage profile。

每次交付更新本页、[路线图](roadmap.md)和相关验收记录，明确哪些已经合入、哪些只是
候选、哪些已经实际验证。当前不以测试数量、设计文档长度或默认容量表示产品完成率。
