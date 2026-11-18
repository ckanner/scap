# PR #65：self-review、严格覆盖与 CI 收口

日期：2026-11-17，America/New_York。实际执行的 UTC 日期为 2026-11-18。
本页及[机器记录](../evidence/sqlite-s3-self-review-local-2026-11-17.json)承接 [前一组合验证](sqlite-s3-followup-validation-2026-11-17.md)，保留旧失败，
只为明确冻结的源码、正式构建与实际运行给出结论。

## 1. 当前决策

[PR #65](https://github.com/ckanner/scap/pull/65) 已改为直接面向 main，汇集
owner plan、有限 controller、S1/S2、永久 worker 身份与有界 S3 连接复用。
本轮审查发现并修复恢复上下文、真实错误路径、旧 fixture 启动身份和 CI 接入问题。
原严格覆盖阻断已经在冻结组合 `1cbe6b3` 关闭：stable/nightly 各 887 项单位通过，
76 个生产 Rust 文件的行、函数、region、branch 均精确 100%，没有缺失 map 或零分母。

**功能候选已拆出 #60 的 Manifest GET 省略优化，完整单位与受影响本地实际重新通过。**
#60 的既有验收明确将四库吞吐回退列为阻断；新的历史诊断不能解释旧约 24% 下降，
因此不能借其他正确性绿色把该优化合入。普通功能路径恢复 `publish_in` 的精确
Manifest GET；专用 proof 快速路径删除，#60 保持独立 Draft。#64 有界 idle pool 8
有独立连接行为与故障证据，继续保留。这里没有增加或放宽数字 TPS 阈值。

下方第 6 节记录拆分后生产候选的新验证；旧检查点的 PASS 保留精确来源，不自动
继承给新代码。远端最终流水线与合入状态以
[PR checks](https://github.com/ckanner/scap/pull/65/checks)为准，本页记录提交前的验证事实。

## 2. 审查修复

| 问题 | 修复与行为 |
| --- | --- |
| restore 可以构造失配的复制描述或丢失原资源上下文 | 已验证 descriptor 保留容量，Restoring 绑定源与自己的 recipe；源检查使用原 READ ObjectContext 和同一 metered Database/原 deadline |
| native 校验与清理的取消/期限边界缺少真实反例 | 沿同一个 ReadInterrupt；真实 writer/image Drop 后再次检查，补目录 unlink 后 fsync、占用 staging、坏子树、页数与序列边界反例 |
| 完成记录存在但永久目标 HEAD 消失 | 保持 UNKNOWN/拒绝重建；不把权威缺失变成新空库 |
| 旧 Rust 分支映射出现 0/0，恢复核心另有未命中计数 | 用真实控制流和真实反例使映射可审计；没有伪造分支、排除生产代码或放宽 checker |
| worker 启动 marker 被误算成数据库对象，或就绪事件借用别的进程身份 | 完整检查 exact marker PUT/GET、正文、同一 ETag、签名与实际投递；一对一绑定 owned spawn/ready、角色和 incarnation |
| 网络日志完成回调可能晚于下一请求或就绪事件 | 校验合法事件区间及真实完整投递，不错误假定日志回调代表客户端接收的严格因果顺序 |
| 老负载/冷恢复 fixture 重启复用永久 ID | 每次启动使用新 ID；保留原 HEAD owner、原业务意图、原工作量与所有原结果，不删除 marker |
| isolation readiness 漏记 worker ID | started、配置与 ready 绑定同一个冻结 ID |
| bounded transport CI 未传必需的 `--weed` | 使用工作流已下载并校验的固定 SeaweedFS binary |
| 有限模型将证据目录放在源码 checkout 内 | 改为 RUNNER_TEMP 下独立目录，满足原冻结输入要求 |
| owner/controller/S1/S2/身份合同没有完整进入 CI | 新增独立控制面工作流；每份实际与模型都有原始证据、source/build 绑定与负控 |

核心逐项理由与反例见 [恢复核心审查](restore-core-review-2026-11-18.md)。编译器对某些
Rust 语法不发独立 branch counter 的边界，以及不能用 region 差分补证明的反例见
[分支测量说明](branch-coverage-measurement-gap.md)。四维计数精确通过不是形式化证明。

## 3. 拆分前的完整冻结检查点

| 身份 | 值 |
| --- | --- |
| 本地生产组合 | `1cbe6b39fdfff72610956a18bb6fe1d523bab8eb` |
| 完整 tree | `de2317e25fb840fb1338090088c1b1b434bf0277` |
| 全源码清单 | 802 个 tracked files；运行前后逐文件核对 |
| 正式 scapd SHA-256 | `a941b366cf5c9ccba5e27cb64c26f172fce5fd16dc9f2085c9f088e52982ced5` |
| 正式 build receipt SHA-256 | `b3faf4fb88e4a15539c8ba2e9cb49ba8272a98d7843411b2f27d76605ccf076f` |
| 远端检查点 | `e00f117e83598bf7f7bd695b83da6e1f1f2d4bc3`，等价本地 `a2af32e`，完整 tree `47429358dcb300ae2e0b6cbddb57c24980bca6d0` |

远端检查点比 `1cbe6b3` 增加工作流所需的 `--weed`，没有生产代码差异。远端 commit
与本地 commit 的历史不同，发布时按完整 Git tree 核对，不能假定两者 commit SHA 相同。

| 分层门禁 | 拆分前精确检查点的结果 |
| --- | --- |
| Rust stable 1.90.0 | 887 passed，0 failed，0 ignored |
| fresh nightly-2025-09-18 unit-only | 887 passed，0 failed，0 ignored |
| 原严格 coverage checker | 76 个生产文件；四维全部精确 100%，无 0/0、无缺失 map；未混用 runtime profile |
| 格式/Clippy | workspace fmt 与 all-targets/all-features `-D warnings` 通过 |
| Node SDK | 161 单位、严格覆盖、HTTP 7、controller HTTP/进程 12 通过 |
| 独立有限模型 | controller 402 正例/40 负控/3 正控，S1/S2 804 正例/48 负控通过；终态模型通过 |
| 正式 S2 实际 | 7/7 场景、126/126 负控；独立审计 2,960 records、59 SDK calls、911 S3 calls；14 个源 payload 逐一 DELETE/GET404 后目标独立 |
| 正式 worker 身份实际 | 显式 ID 10/10、auto 18/18，原始失败分类、就绪、全 owned 资源回收通过 |
| 正式 TCP 实际 | 8 场景与独立 oracle 通过，原 SIGINT 与 wait4 清理完成 |

每项实际使用单独证据目录并校验原源码、正式 binary、build receipt、执行输入和结束
后的源码身份。S2/身份原始计数与散列见
[正式组合恢复/身份验收](combined-restore-runtime-2026-11-17.md)。新 fixture 的单元
自测只检验观察器；它们不能代替实际 daemon、native SQLite 或 S3 行为。

## 4. CI 工作流与失败保留

质量工作流继续保留 Rust、工具覆盖、有限模型、native/HTTP/S3、1 GiB、HEAD6、
终态、资源/GC 和固定负载。新增
[控制面工作流](../../.github/workflows/control-plane.yml)运行 owner、Missing、
controller、固定矩阵、S1、S2、显式 ID、auto ID 与独立模型。全部 PR 运行完整门禁，
合入 main 后再运行；同一 feature push 不重复启动第二套重型作业。SDK/codec 不再因路径过滤漏跑，
TypeScript 5.9.3、@types/node 22.16.0、undici-types 6.21.0 固定并严格编译公开声明。

`e00f117` 的 PR 工作流：

- [质量作业](https://github.com/ckanner/scap/actions/runs/44214850594)。
- [控制面作业](https://github.com/ckanner/scap/actions/runs/44214850551)。

其 Rust 严格覆盖、工具覆盖、有限模型、终态、资源/GC、固定负载、owner-plan、Missing、
controller、S1、S2、显式和自动身份均观察到远端 success；push 的 HEAD6 也通过。
两个具体旧断言失败独立保留：

- matrix 的完整实际已运行，独立审计仍要求旧277个构建输入；新清单实际为305。
  修复从完整已校验源码推导全部构建路径/哈希，与原 receipt 精确相等，并拒绝漏根、
  漏输入、多输入及错 hash；不是把277换成305或改成数量下限。
- owner 的144个HTTP已执行，proxy记录619次物理S3，业务子集611次；旧清理断言
  忽略8次已认证启动请求。guarded同类检查一并修复，全部物理交换仍先核对字节、
  签名与handler，业务子集单独核对原身份/结果。旧 `/tmp` 条件与 runner 的
  evidence.parent 合同也不一致，改为真实规范化路径及完整生命周期身份。

上述运行不是最终拆分源码的 CI 结果。最终流水线在本报告写入检查点为 NOT_RUN，
随后按 PR checks 留存新源码的实际和最终 verdict，不以旧运行认证新 helper。

旧 `ac8fd86` 的模型路径/transport 缺参数失败、旧 `12f` 的启动身份夹具失败均
保留。后续推送取消了部分旧作业，结论记为 cancelled，不能改写为整体通过。
缺参数的本地最小复现 exit 2、尚未启动后端；它与原 GitHub stderr 分开保存，
不冒称是下载得到的原 CI 日志。

## 5. 性能、Turso 与发布边界

[完整历史诊断](manifest-proof-causal-2026-11-18.md)冻结四个样本，保留全部正负值。
它确认少一次 GET 的请求数收益和证据代理明显成本，但无法给旧运行未采集的阶段
剖面补出因果。`#60 acceptance = BLOCKED` 是既有独立验收，不能称为一个已经预定
数字阈值的 TPS 测试。功能候选通过移除未获验收的快速路径解除对这项优化的依赖。

Turso 可借鉴的持久化后确认、分块对象、可丢弃本地镜像、明确恢复来源与资源预算已经
进入对应实现。SCAP 仍使用本地私有 SQLite 执行镜像和对象 API，跨节点通过 HEAD CAS
与 owner fencing 排序，不共享活动 `.db/WAL/SHM`。这解决架构对 NFS 文件锁的依赖，
不消除单库 writer 串行、本地 I/O 故障或错误部署。依据与代码映射见
[安全与吞吐](../architecture/sqlite-s3-safety-and-throughput.md)和
[Turso 接续设计](../architecture/turso-adoption-next.md)。

动态 fleet、任意时间 PITR、group commit、lazy VFS、同库 MVCC/reader pool、硬
RSS/磁盘隔离与长期过载/GC 成本都有独立产品协议和验收出口，不能从 S2 或自动编号
推导已经完成。真实 AWS Standard、实际网络挂载、跨 AZ 故障域和生产 SLO 仍为
NOT_RUN；本地带签名 SeaweedFS 不能替代这些承诺。

## 6. 最终拆分候选

生产候选冻结为 `aab8a223f3cb4f4cf981990b4f5de80288b0dadc`，tree
`81f39821d3ed74735903f27675b96f885e75b4ad`，完整815文件；所有受测源码在运行前后
均核对。正式 release SHA-256 为
`24797df0d6b9ab3aca9fa3157c4f3094b24724b7b415b5d0ee351586c57ba1ce`，原构建
receipt 为 `849019b6fdbb7225434f17326cfaef8a5d49670a6a47cfee97824fc28e9e780e`。

| 拆分后的新门禁 | 结果 |
| --- | --- |
| stable + fresh nightly unit-only | 各887 passed，0 failed，0 ignored |
| 严格单位覆盖 | 76 个生产文件四维精确100%，无零分母或缺失map |
| fmt / strict Clippy | 全 workspace/all-targets/all-features 通过 |
| Node / codec / 类型 | SDK161、codec13及精确V8计数，HTTP7、controller HTTP/进程12、固定TypeScript严格声明编译通过 |
| S2 / worker 实际 | 7场景/126负控、显式10、auto18通过；本次2966 records、59 SDK、913 S3 |
| TCP | 8场景及独立oracle通过 |
| 冷库隔离 | 21HTTP：20成功及1个预期BACKPRESSURE；独立oracle、21负控/1正控通过 |
| 分段索引 | 全7阶段、2145HTTP、2116原输入、2原SQL ACK/2112取消；21339物理S3=21327数据库+12启动请求；22负控/1正控通过 |
| 元数据 | 41POST，203物理S3=199业务+4启动；M的17次I/O全部HEAD-only；9投影/6原始记录负控通过 |
| 输出预算 | 18POST、17完整响应；86物理S3=84业务+2启动；15负控通过 |
| 响应期限 | 11POST、4次服务器截断；56物理S3=54业务+2启动；16负控、SIGINT回收通过 |

S2 与身份原件的逐项索引见[正式普通读取路径验收](manifest-get-runtime-2026-11-17.md)。
metadata/output/response 的夹具分别冻结为 `3280863`/`c9824bd`，其正式305个构建
输入与 `aab8a22` 原 receipt 完全相同，夹具源码另行固定；没有改写 receipt。
metadata 首次完整实际在旧 `/tmp` 路径断言处失败，原运行保留；修正 runner 与审计器
合同后，新冻结夹具重跑通过。运行目录属于 evidence.parent，仍须有规范化绝对路径、
原创建/配置/删除身份及设备/inode证明。

最终 fixture 修复另有独立源码和 Python 回归。pre-Popen 下界修复针对确切的父子
调度竞态，基线误拒绝和新正负控同时保留；旧历史不会补字段。构建输入等价检查
使用完整路径和哈希集合，不能用旧277项硬编码或仅检查子集。物理请求、已认证的
启动请求与数据库请求分别计数，源字节/签名/owned清理仍覆盖全部物理交换。

以上本地结果只认证相应生产与夹具来源。后续 fixture 变更进入最终 CI 的正式重新
构建和完整实际，不把旧 receipt 改称新 fixture 的证明。最终 PR 的全量门禁齐备后，
按精确 head/main/tree 判定合入；最新结果通过本页开头的 PR checks 链接查证。

最终夹具组合 `bb82b9d3d7e20a8007dcf3810f7e8cbb823311eb` 的817文件在测试前后
完整核对；14组共627项观察器/夹具单元全部通过。该组合的全部 crates、SDK、Cargo
清单/lock、toolchain、覆盖分类与严格checker和 `aab8a22` 逐文件相同；最终 fixture
完整实际仍由新的 CI 验证。这里没有把627个观察器单位加进887个Rust单位或native
实际分母。源码清单、命令、每组退出码和原始日志hash见机器记录。
