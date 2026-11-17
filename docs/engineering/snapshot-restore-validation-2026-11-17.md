# S2 独立快照恢复：实现与验证记录

日期：2026-11-17。产品候选见 [PR #63](https://github.com/ckanner/scap/pull/63)，
后续组合见 [PR #65](https://github.com/ckanner/scap/pull/65)。协议见
[HEAD9/S2 设计](../architecture/retained-snapshot-restore.md)，HTTP、配置与 SDK 见
[恢复合同](../../crates/scap-service/docs/restore.md)。逐项源码、二进制、失败及计数见
[机器记录](../evidence/snapshot-restore-local-2026-11-17.json)。

S2 的核心、全部元数据消费者、认证 HTTP、Node SDK 和独立恢复资源已经实现。
**当前仍是 Draft：完整逐文件四维单位覆盖未通过，也没有 AWS 或生产 SLO 结论。**
后续实际复测的准确来源由组合报告记录，不能将早期通过沿用为新代码全部验收。

## 1. 本次交付的行为

`prepare_restore` 固定 source Scope、SnapshotRef、目标名称、原 operation 和配额。
它与 Empty create 共用永久 first-winner 编号槽；相同编号不能换成另一种创建方式、
换来源或换目标。保存过的 SDK 意图只作查证和显式推进，不自动更换身份或重放 SQL。

目标先取得名称预约及自己的 Provisioning HEAD，然后在新 Scope 中逐层重新封装
Chunk、Node 和 Manifest。对象 frame/hash 绑定目标身份，因此新库不能只是引用源根。
一个新私有 native 镜像用于完整 SQLite 校验；源 GET、目标 PUT、目标回读和镜像大小
分别计量。全部 payload 操作结束、native 镜像释放后，才进行最后的源权限稳定屏障。

两次源 HEAD 都先要求当前 ADMIN+READ；撤权优先于中间元数据错误或冲突分类。已合法
准入的复制在快照释放后仍可能完成，前提是原 accepted proof 证明同一保留点且 payload
仍可读取。完成记录一旦持久化，合法后续推进依赖目标的权威与完整闭包，不再依赖源。

每次 resume 或 abort 最多发布一次可变 Name/HEAD CAS。取消建立永久屏障，迟到的
payload 或 completion 不能复活目标。Ready 使用新 ACL、新请求空间、sequence=0 和
未激活 writer；不继承旧 owner、请求结果或取消状态。之后的 SQL、S1、owner V2、
compaction 与 GC 都识别 Copied provenance；旧 provenance 不永久保留已过时的数据根。

## 2. 资源与服务组合

恢复使用独立 worker、queue 和 intake；按租户及全局预约一个逻辑镜像加固定 sidecar
余量，并共享既有 recovery 并发槽。HTTP 断线或超时不会提前释放尚在运行的 job 额度。
临时镜像必须是准入后的私有本地目录；上传/解析期限与长恢复执行期限分别受限。

一次 metadata-only resume 如果在检查后并发遇到 Copying，source GET、target GET
和 target PUT 三个方向的额度都为零；它会在打开未预约的 native 镜像之前停止。
仅把镜像上限设为零不足以阻止合法的空镜像，因而三个方向都必须限制。

`PreparedProfile` 将完整资源校验和构造放在启动前；#65 组合进一步保证它发生在
永久 worker identity claim 之前。最终分配出的数值身份传入 restore factory。
无效配置没有身份 I/O；claim 后 worker/cache 失败仍永久消耗该身份。

这些是逻辑准入和生命周期约束，**不是 OS 硬磁盘配额或 RSS 限制**。清理失败可能留下
cache orphan；部署仍须提供磁盘、进程、FD 和故障域隔离。

## 3. 审查中发现并修复的问题

| 问题 | 修复与反例 |
| --- | --- |
| Serde 的内部标签 unit variant 接受额外 Copying 字段 | 使用严格空字段结构，保持合法 wire 字节不变，增加未知字段拒绝测试 |
| 临时镜像 append I/O 故障被错误归类为权威 CORRUPT | 本地 I/O、停止和中断保留 UNKNOWN；真正 InvalidImage 为 CORRUPT，资源/结果限额为 LIMIT |
| 完成记录存在但永久目标 HEAD 被物理删除后，旧路径可能判为 Reserved | 先保留原失败反例，再增加有界 completion/HEAD 检查；合法并发创建为 Conflict，稳定丢失为 Corrupt，不采用新 ETag、不重建同一 Scope |
| 启动时对已验证的恢复配置重复进行不可能失败的检查 | 一次生成可消费的 PreparedProfile，后续使用原限额/资源；没有用 expect、伪造故障或修改覆盖阈值绕过 |

## 4. 精确候选和已完成验证

### 首个完整实际候选

本地 `76e3900a5846a659743a8e001f64ad257aa1cbf5` 与远端 `d78573e` 的完整 tree
同为 `7f0add6c58e827d2ebfc460ae0853b4a234b0ea2`。759 个跟踪文件已冻结，
source fingerprint 为 `c63592151c2ad866a08fba54770b14ae0fb5256f181306d9d5a35d7f736e7745`。
正式 release `scapd` 的 SHA-256 为
`a0253208364caa00aee0a3d517d214b634872ce08fc883dc87b7672ec7815d58`。

该候选 fresh nightly workspace 有 821 个单位通过，Node 161 项及逐文件 V8 门禁、
门禁负控和严格 TypeScript API 检查通过。真实 native/HTTP/Node/签名 SeaweedFS
六场景全部通过：非确定原值及多块 BLOB、first-winner、取消迟到复制、复制中撤权、
丢 HTTP 响应并 SIGKILL 后原意图续进、源 payload 删除并清空全部 cache 后目标冷读。
最后一项实际删除并逐一 GET=404 的源 payload 为 14 个，恢复库保留 2 行精确类型值。

它没有包含之后的永久 HEAD 缺失修复；因此这些通过只认证旧候选。该首轮实际也没有
后续独立外部审计器，不能改称已完成新审计合同。

### 修复、扩展测试与组合

独立 core `a5af6f6` 的 stable/nightly 各 466 单位通过；最后 test-only `dd5146c`
增加四项测试并通过 46 个 scoped restore 测试。独立 service `31b8ccd` 的 stable/
nightly 各 214 单位及 strict Clippy 通过，新增 service 可测量计数完整命中。

包含最终 S2、身份、完整 Manifest proof 与连接池的组合 `6915aa5` 使用新的独立
target：stable/nightly **各 877 单位通过**，strict Clippy 通过。新组合 SDK 与类型
输入逐字保持相同。其正式 release SHA-256 为
`b21935233b1e2234692795e79fa4e4e89de20b50f975eb2306c1d409bcf2801d`。
本地源码与远端代码 `82f3b37` 的完整 tree 均为
`2c7d906932acaf95a3fb6c6bc2a2401e1b4c29f6`。

核心测试包括所有观察到的 prepare、五个 resume 阶段及已有 completion 验证的
I/O 切点：调用前 UNKNOWN 与 PUT 接受后丢回复分别注入，再沿原身份显式恢复。
另外覆盖源退休世代重启、目标退休、两个复制者、名称与身份冲突、源快照记录重绑、
缺 completion、根目录发现/恢复、普通删除，以及 SQL/S1/owner/GC 保留 provenance。
一个实际 native 单位使用 **34 MiB BLOB** 和超过 256 个 chunk 的树，删除源 payload
后重新冷读目标；它属于单位证据，不冒充 AWS 或 GiB 级 HTTP 容量验收。

### 最终实际与独立审计

最终组合实际使用 `548a5ad` 的恢复夹具/审计输入和上述 b219352 正式二进制，
793 个跟踪文件在运行前后复核。相对6915构建候选的差异仅为覆盖分类及恢复实验文件；
239 个 Cargo/crate/SDK 受保护输入逐字相同。

七个实际场景全部通过，增加了“completion 存在而永久目标 HEAD 被 DELETE”的真实
场景。独立审计核对 2,960 条观察、59 次 SDK、911 次产品 S3、30 次管理员故障调用、
14 个已消失的源 payload 和3个daemon；原始整数、随机值、BLOB、receipt、恢复意图
与目标空请求空间均核对。全部进程/cache/backend清理与输入未变通过。

审计器不读取 producer PASS/cases 汇总、不导入 SDK/codec，独立解析 SCAPRES1 并计算
SQL fingerprint/Result frame hash。**126 个定向反例通过**：122 个语义反例修复了
外围摘要/序号后仍被拒绝，另有4个结构反例；4项parser/decoder测试通过。
原始观察 SHA-256 为
`94c267a216d54092a1ee904748130670612731b899225d245ca5c37ad3b9a244`。

原先75eb2e5预检的7场景/28负控虽然通过，独立review随后发现19个错误语义变体会
被旧审计器接受；原件全部保留，不作为最终验收。91af703 修复每个调用的完整 DTO、
Scope、principal、SQL、UNKNOWN及release/deleted绑定；相同20变体在独立复核中
全部被拒绝，再用新目录完整执行本次最终实际。机器记录包含原漏检、修复和新结果。

HTTP丢回复是在SDK fetch交付边界丢弃实际成功响应；它不声称新的TCP-reset合同。
缺失HEAD是实际S3删除；合法并发出现HEAD的Conflict仍由核心单位覆盖。完整组合
报告见[PR #65](https://github.com/ckanner/scap/pull/65)，本地S3仍不替代AWS或容量资格。

## 5. 未通过的覆盖与保留的失败

最终组合的四个未完整命中的核心文件如下；函数计数均已完整命中：

| 文件 | 行 | Region | Branch |
| --- | ---: | ---: | ---: |
| `catalogue/create.rs` | 126/127 | 244/245 | 14/14 |
| `catalogue/records.rs` | 243/243 | 368/369 | 62/62 |
| `catalogue/restore.rs` | 401/403 | 611/622 | 56/56 |
| `catalogue/restore_copy.rs` | 242/243 | 394/408 | 17/18 |

部分是前置校验已经建立的不变量后的重复防御检查；部分是尚未完整触发的本地 image
finish/open I/O、native 清理后越过 deadline 等真实效果路径，不能统称为不可达。
原有 7 个生产文件和新增 `restore_wire.rs` 的 branch 分母为零，仍不满足 AGENTS。
没有把 0/0 当成 100%，没有用实际进程的 profile 补单位计数。

最初四个 service 测试使用了与真实派生身份不一致的伪造 Creation，207 pass/4 fail
原日志保留；改为由 Catalogue.prepare 产生合法身份后 211 项通过，生产校验未放松。
首轮 Clippy 的测试初始化 warning 及其修正也保留。新增永久 HEAD 缺失回归先在旧
代码得到错误 Reserved，再由修复后的测试证明拒绝；原失败没有删除。

## 6. 范围之外

S2 从明确保留点生成完整独立新库，尚不提供任意时间 PITR、仅改元数据的瞬时 clone、
lazy VFS、同库 MVCC/group commit 或动态 fleet。自动 worker ID 也不自动刷新路由。
单库仍串行；全量镜像恢复仍有下载和本地空间成本。

本地 SeaweedFS 4.51 不证明 AWS Standard/IAM、跨 AZ/region、历史身份迁移、真实
NFS/EFS/FUSE 挂载矩阵、长运行成本、硬资源隔离或生产 SLO。旧候选的 GiB 容量和
其他 native 合同不能借用为新组合的完整认证。后续正式实际、独立审计与其定向反例
由 #65 的精确候选记录维护；源码、单位、实际与审计身份必须分别可查。
