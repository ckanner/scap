# 名称目录与多数据库执行隔离：本地验收

2026-11-08，名称目录 [PR #31](https://github.com/ckanner/scap/pull/31) 和多数据库 actor [PR #32](https://github.com/ckanner/scap/pull/32) 已完成各自所需的本地门禁并合并。合并后的 tree 与冻结交付候选完全相同。完整身份、逐文件四维计数及报告摘要见[机器记录](../evidence/catalogue-actors-local-2026-11-08.json)。这项结论覆盖两个实现增量；完整 N1–N4、AWS Standard 和生产 SLO 没有因此完成。

## 1. 交付身份

| 内容 | 原完整运行 | 修正后交付候选 | 合并提交 |
| --- | --- | --- | --- |
| 正式名称目录 | `5b4e97e276988bd10ecfd25ff7abbf2a547a6459` | `791739a0d959128c47c18d3edafcafaf3d1acf4c` | `65489f1bff0a3fa79424e9c642ea31ced7b11b11` |
| 目录与 actor 组合 | `b379306bfa8d51855116bbe4fb5bf7cddf79df86` | `32f3369e13cd89e32521d5d371ecbfda6834322c` | `9d6ac1b9150576f0f746c2d0a5187fdb1442ee6a` |

名称目录交付 tree 为 `1e15637ff28f86f5fdb2036c7097767a14740c39`；actor 组合为 `bc3eba30cd74dec3436e38f157a72122c98d438d`。GitHub 原始 Git commit、父提交、签名 payload 与 tree 均已核对。后续本说明仅改变文档，不改变上述运行时、测试、依赖或工作流输入。

## 2. 名称目录解决的具体问题

正式目录保存规范化、不可变的 CreateDescriptor 与 ControlDescriptor。名称、调用者、operation、Scope、原 revision 和初始配置在持久准入后不能改投。Reserved、Bound、Aborting、Tombstone 与 Provisioning/Ready/Deleted HEAD 的竞争使用原条件逐步推进；响应丢失返回 UNKNOWN，查证和重入保留原意图。

稳定读取采用 **Name → AbortProof → HEAD → 同一 Name**。首次与末次名称的 body/ETag 必须一致；proof、descriptor、HEAD 的完整来源另行校验。缺失应存在的控制 descriptor 被判为损坏，删除重入不能通过重新创建 descriptor 掩盖权威丢失。永久 HEAD 身份槽不回收；同名重建派生新 Scope，旧请求不会自动改目标。

HTTP `POST /v1/catalogue` 使用独立有界目录队列；Node SDK 在发送前保存完整创建或控制意图。目录 Ready 与 writer 已激活是不同状态。此版本 HEAD 为 format 3，不可变 SCAPOBJ2 为 format 2，没有旧 HEAD 自动迁移。

这是一套精确名称协议。它没有实现 deployment 全目录枚举，也没有把已知名称列表当作全计算丢失后的完整发现分母。

## 3. Actor 解决的具体问题

旧固定 hash lane 可能把冷库 A 与热库 B 分到同一同步执行线程。公平排队不能抢占已开始的完整冷恢复。新实现以物理 HEAD key 建立有界活跃 actor，每个 actor 的线程独占其 SQLite Session；即使请求携带不同 incarnation/generation，同一物理 HEAD 仍不能形成两个执行 actor。

Starting、Running、Draining 都计入全局和租户上限。空闲退出后，固定 reaper 在请求路径之外等待线程、native 连接及 TLS 清理完成，再释放容量。请求提交不执行同步 join。data/recovery/control 共用总队列计数，控制操作保留独立容量；恢复不会吃掉 lookup/cancel 的预留。

容量不足返回 BACKPRESSURE。独立 actor 解除指定冷恢复对其他库的执行阻塞；CPU、S3、磁盘、网络和 HTTP runtime 仍共享。线程与排队上限不构成进程 RSS 或磁盘硬隔离，单库发布仍串行。

## 4. 单元与构建门禁

| 检查 | 名称目录 | Actor 组合 |
| --- | --- | --- |
| stable 与 nightly Rust 单元 | 各 300 | 各 307 |
| 生产 Rust 文件 | 33 个，各文件 line/function/region/branch 精确 100% | 33 个，各文件四维精确 100% |
| 业务 core 单元 | 149 | 149 |
| service 单元 | 63 | 70 |
| 网络实验 fixtures | 151 | 151 |
| 修正后服务 fixtures | 60 | 82，包含 22 个隔离 oracle fixtures |

没有分支的生产文件明确记录 0/0；实际 `scapd` 入口仍在生产分母。真实进程与 S3 profile 不补单元覆盖。工具单元 74 项、401 statements/184 branches 精确覆盖；环境控制器 32 项、280 statements/36 branches 精确覆盖。Node codec/SDK 原始 V8 function/range、独立 Fetch、固定 TypeScript 5.9.3 声明编译、actionlint 及仓库检查通过。

模型独立运行 121 个单元，原 authority 664 条正向/30 个负控，以及名称目录 885 条正向/25 个负控。模型不替代真实对象或 native SQLite 合同。

release 构建记录实际 executable、libSQL native archive、固定工具版本、源码输入和完整 Cargo JSONL 的最后成功事件。原始文件均保留；独立审查实际回取 executable/native 字节，不能以一份摘要代替。

## 5. 真实网络、容量与目录合同

两组原完整运行分别执行基础网络、30 个故障场景、schema、保留结果、1 GiB、生命周期和目录切点矩阵。

| 范围 | 实际核对 |
| --- | --- |
| 故障与 schema | 30 场景、90 个原始输入、61 条故障 ACK；schema 14 输入、12 ACK、36 个恢复/重放结果与 30 组完整结构状态 |
| 保留结果 | 12 场景、60 个冷入口、30 ACK；重建损坏 Result→Index→HEAD 完整字节并与真实 backend PUT/GET 摘要匹配 |
| 1 GiB | 39 个原结果 ACK，全部 16,384 行最终长度/hash，1,073,741,824 字节；所有计算缓存丢失和后端重启后恢复 |
| 生命周期 | 12 场景、78 次成功响应、30 个原身份，完整 build/native/source 与恢复链 |
| 名称目录 | 116 场景、1000 ACK、2791 个完整响应、619 个计算实例、501 个缓存丢失观察、153 个明确丢失调用 |

生命周期/目录在原始记录上分别实施 8/5 个定向负对照，均在预期语义条件拒绝。旧网络/容量补充审查每候选另有 22 个实际记录变异拒绝。它们是对已经取得的实际轨迹做的证据反例，不冒充额外网络故障实验。

1 GiB 的三个点更新从原始 wire 重算出 GET/PUT 分别为 16/8、18/9、18/9 次；对应响应/上传字节为 591,199/292,098、854,445/423,603、632,951/312,738。它说明本地指定实验未按整库大小上传；不能推导 AWS TPS、延迟或长期成本。

## 6. 审计修正与受影响服务重跑

两组原完整 validator 都在最后 catalogue HTTP oracle **exit 1**。实际合法请求在新 creation 复用旧墓碑时，先读准确旧 Binding，再 GET 旧 AbortProof；原 oracle 的归属规则漏掉这条路径。

修正仅涉及 `catalogue_oracle.py` 与 `test_catalogue_controls.py`。名称候选其余 233/235 文件、actor 其余 242/244 文件逐字节不变，特别是全部生产 Rust、SDK、native、锁、工作流及业务 workload。修正要求同一次 HTTP 调用实际先读到 backend 200 的规范 Tombstone，名称、tenant、expected revision、完整旧 creation 与 proof key 一致；旧 proof PUT、未知来源、跨租户、错误版本和晚到 Binding 仍拒绝。

原记录由修正后的 oracle 完整重新审查通过，报告同时标明运行源码与审计源码。原 `completion.json` 仍然是 exit 1。未改变输入的单元、网络、容量及 lifecycle/core catalogue 通过记录按精确身份复用，不宣称在新 commit 下又运行了一遍。

两份新 release 构建后，普通及目录服务合同在新目录重新执行。第一次服务启动因测试机剩余磁盘低于 SeaweedFS 1% 可写阈值而失败，尚未启动 SCAP/Node；没有捕获 OS syscall ENOSPC。释放空间后复用经完整字节复核的构建，第二次运行通过，原失败保持。

每个最终候选的普通服务有 105 HTTP、620 S3，10 个唯一已确认请求、18 个成功 execute、18 个恢复 lookup，以及 1 个单独保留的 UNKNOWN。目录服务有 70 HTTP、543 S3、3 个唯一 SQL、6 个成功 SQL、4 个保留结果与 2 个已删身份拒绝；真实 late provisioning 得到 backend 412，3 次接受后丢响应保留固定原意图。两者均完成全部计算缓存丢失后的恢复及实际 wait4 核对。

## 7. 新隔离合同

固定 1 daemon、2 个同租户活跃 actor、1 控制线程、1 恢复许可与 3 秒空闲阈值。A 写入独立随机 BLOB 后变冷，B 每 750 ms 保持热状态；持有 A 原始第一块 GET，在释放之前执行 B 查询、A Status 和第三库容量拒绝。

实际结果为 21 HTTP：20 成功、1 预期 BACKPRESSURE；87 S3：23 个条件 PUT、64 个 GET，全部归属唯一。4 个热库/控制调用都在预先固定的 4 秒预算内且在释放前完成；第三库拒绝产生 0 个 S3 请求。A 随后下载全部 4 个 chunk、6 个数据树依赖、401,408 字节；10 个驻留查询只读 HEAD，两个原始 SQL/BLOB/random 结果及 lookup 回执完整一致。

真实记录的 21 个损坏负控全部拒绝；替换 controller summary 的唯一正控仍通过，证明摘要不被当作审计权威。独立复核再次执行 full oracle，核对实际配置、二进制、native、源码、1 daemon/5 SDK/4 backend 的原进程及 wait4。源文件与原始/变异证据审查前后哈希均相同。

## 8. 必须保留的证据限制

- 旧基础网络没有独立完整的预调用 stdin 账本，部分基础/容量 HEAD 只保存 hash/ETag。
- 容量原始 BLOB 临时文件已删除：38 个 BLOB 请求的 SCAPSQL 指纹不能离线重算，6 个被覆盖历史版本不能从最终状态核验。全部最终行的 hash 已比较，但没有保存恢复后完整 1 GiB 字节供再次离线散列。
- fault/retained 的原始 BLOB 仍可取得，每候选 84 份、12,386,304 字节已与调用前账本逐份核对并保全。没有复制 backend 凭据或私有目录。
- native 故障有真实资源/SQLite 读者/WAL/S3/receipt 观察，但没有 exact errno 或 checkpoint syscall 返回轨迹。
- 旧 pre-forward cut 是明确 abort，不等于已测进程死亡后迟到转发；3 个仍存活进程的迟到 HEAD 候选实际得到 412。
- 缓存删除是源码绑定的控制器文件系统观察，不是外部存储设备证明。旧审计阶段边界误判及无法核验的历史 BLOB 负控失败保留，没有删除或改写。

## 9. 合并与后续

远端 Actions 仍报告 failure；取得的原 job 样本为 `steps=[]`、`runner_id=0`。没有足够证据确认根因，也不把本地结果描述为远端 CI 成功。依维护者已有授权，在本批必要本地门禁完成后合并，未修改分支保护。

完整发现/分页及恢复见[全目录方案](../architecture/catalogue-discovery-plan.md)；分段索引、storage generation、pin、可重启 GC 和 PITR 见[持续存储方案](../architecture/storage-reclamation-plan.md)。这两份方案的设计状态与实现/验收状态分开记录。AWS Standard、跨 AZ、全负载活性、长运行、生产吞吐和成本 SLO 均保持未完成。物理 GC 继续关闭。
