# 全目录发现、分段索引与部署恢复验收

本批实现位于 [PR #35](https://github.com/ckanner/scap/pull/35)，包含 [PR #34](https://github.com/ckanner/scap/pull/34) 的有界 LIST 与单次 HTTP 传输。它补齐无需预知数据库名称或 Scope 的 deployment 发现和数据恢复，并把原请求索引改为有界不可变树。自动 owner 路由、物理 GC、PITR、AWS Standard 与生产 SLO 仍有独立门禁。

## 候选和证据身份

| 对象 | 冻结身份与用途 |
| --- | --- |
| 最终实现 | 发布 commit `5a04716a3f68ab51776c1ea8706097efe001fa2a`，tree `da90d317d1fdc6697cb92667fbae119d9f3ba2bd`；全部 323 文件与本地 `94e6d51658ac18382a1a176dc14e5a4ea4fd2d26` 逐字节相同 |
| 原组合候选 | 本地 `e8cbc61082c1cf49722fb6a6fc5cbdaa018c3be1`，已单独发布历史检查点 `f076cb717eda40ad758c1bd1eca63562c912b195`；tree `78672c3c55e593680a687c78d6d31b82b2962e93`；321 文件前后不变，原审计失败仍保留 |
| 修复范围 | e8→94 只改变部署恢复的 Python 夹具、独立审计、导入隔离及其说明；101 个 Rust 文件及 Cargo/单元输入相同 |
| 正式服务 | 实际 `scapd` SHA-256 `a84e262602c90633d87118f822a7a362235830d9d1c1d3dd9b35b6388a837e7b`，按 e8 原 build receipt 归属，不改写为在 94 重建 |
| 最终恢复执行器 | 实际 release SHA-256 `124b4cdaa6b567489f02e43ad013d419b6a5bd34793455219a28719e75601363`，在 94 新构建并运行 |
| Release native archive | 实际 `liblibsql.a` SHA-256 `3ee6c6612ca2d1394a420cd7aab030638ff83b0e84d9eb18270a48caa54e54b3` |

API 发布的 commit ID 与本地 ID 不同，不能仅比较短 SHA 推断源码。发布检查同时比较完整 Git tree 和每个文件字节。最后的交付说明仅改变文档和机器记录，须单独核对；不把文档提交冒称为重新执行全部实验的源码。

## 正式产品行为

有界 LIST 每页最多 32 key，完整原始 XML 最多 1 MiB；它只发现候选，当前权限和状态仍来自 exact GET。签名 HTTP 关闭自动重试、重定向及隐式代理，错误响应按流限制保留 64 KiB；这不表示传输栈恰好只接收 64 KiB 网络字节。成功 PUT 响应丢失保持 UNKNOWN，正常 412 保持 Conflict。

发现 cursor 绑定 namespace、worker、deployment、tenant、principal、操作、视图和过期时间；换进程或超时不能继续。HTTP 既有五秒 deadline 内预留一秒封装部分进度，稳定延迟下可返回带原 cursor 的 UNKNOWN。SDK 每次方法调用只发一个 POST，不自动翻页、重启或重放 SQL。发现有独立全局/租户准入额度，调用者丢弃响应不会提前释放仍在工作的额度。

请求索引采用不可变 COW B+ 树，叶最多 128 项、内部最多 32 分支，最多 65,536 个保留身份、树高最多三层。插入改写变化路径；全量冷恢复仍检查所有分支、保留原结果及真实结果长度。HEAD 升为 format 4，不可变帧保持 format 2；未知或旧 HEAD 拒绝，不自动迁移。

部署恢复从 deployment 根开始，可信配置只提供各租户可使用的 reader，不提供名称、Scope、对象 key 或 ACK 名单。作业的 LIST/GET/候选/字节/时间预算累计不重置；最多保留一个待处理 Scope 和一个恢复 session lease。Ready/Maintenance 验证完整数据、全部保留结果、真实 native 镜像和最终同 body/ETag HEAD；Provisioning/Deleted 保留元数据屏障，不自动激活。它提供每个槽位各自的验证时刻，不承诺跨 key 的同时全局快照。

## 单元与静态门禁

| 门禁 | 结果与范围 |
| --- | --- |
| Stable workspace | 94 候选 416 项通过：object 212、SQLite 69、store 25、service 92、SQL 18；零 ignored |
| Nightly workspace | e8 候选 416 项通过；与 94 的完整 Rust/单元输入等价，不拼接集成 profile |
| 生产 Rust 四维覆盖 | 47 个生产文件逐文件行、函数、region、分支精确 100%；无分支文件明确 0/0 |
| Strict Clippy | 94 的 workspace/all-target/all-feature `-D warnings` 通过 |
| 工具脚本 | 74 tests、401 statements、184 branches，精确 100% |
| 环境控制器 | 32 tests、280 statements、36 branches，精确 100% |
| SDK 与仓库检查 | Node 单元/生产 V8 计数、真实 Fetch、strict TypeScript、编解码、fmt、文档链接、workflow 与模型门禁分别留存 |
| 恢复夹具 | 94 的 22 项通过，包含不同 RequestId 的真实 404 语义、现存 Binding 改变及两种模块导入顺序 |

SQLite 临时文件防护覆盖固定 Unix VFS 的环境、回退和 cwd 候选。所有已存在候选均用打开的同一个描述符检查文件系统类型；只有 open 的 NotFound 可跳过。首次原生打开前以只读 probe 拒绝 host-global `temp_store_directory`，不修改全局设置。原生独立子进程覆盖本地、procfs、symlink、环境/回退/cwd 及全局覆盖值。实际 NFS/EFS/FUSE 挂载没有运行，procfs 拒绝只证明文件系统政策检查。

## 真实 S3、原生与 HTTP 组合

最终新部署恢复运行完成 4,088 个签名 S3 请求、1,480 个 LIST 页、62 个实际进程、13 个原输入和 11 个 ACK。完整 profile 分类 65 份元数据，检查九个永久 HEAD 槽位，其中五个需要数据恢复且全部通过；其余四个明确不需要数据。独立 full oracle 单独运行通过，23 个真实历史负对照全部拒绝，一个合法日志延迟正对照接受。

缺少租户 reader 或只有 ADMIN 没有 READ，均停在 PermissionBlocked 且 `recovery_complete=false`；缺少 closed window 的原结果停在 Corrupt，并保留待处理项。cancelled、retired、deleted，以及已提交但 native publication 未完成而没有 execute ACK 的身份均保留在分母，不从成功统计中消失。

同一冻结 e8 正式服务二进制通过九个组合阶段：普通 SQL/SDK、目录 HTTP、目录独立 oracle、冷热隔离、隔离历史负对照、分段索引 HTTP、分段索引独立 oracle、分段历史负对照和发现 HTTP。分段历史控制为 19 个拒绝负对照及一个正对照。最后的发现运行仍明确 `data_recovery_complete=false`；全数据恢复结论来自上方独立部署恢复合同。

原生网络、保留结果和十二类生命周期合同已在相同输入身份下通过。保留结果按十二场景乘六个入口统计，共 72 组合，包含直接 `Database::query`；84 份原随机 BLOB 输入按账本 SHA 单独保留。补充审计最初仍按旧五入口规则拒绝，精确改为六入口后单独通过，另用三个负对照和一个正对照检查其判定，不覆盖原失败记录。

目录原生合同和独立 full oracle 均通过：116 个场景、1,000 个 ACK、2,944 次调用及 153 个 UNKNOWN，独立核对 21,108 个顺序约束。所有 UNKNOWN 仍在原分母，不用最终成功抹去其历史结果。

1 GiB 的第二次完整同源运行及独立审计通过：39 份已确认结果中，38 份直接来自 execute，一份在 execute UNKNOWN 后由原身份 lookup 确认。256 个批次覆盖 16,384 行、1,073,741,824 字节，394 次调用、34,866 个请求、三个 worker 和八个 backend incarnation 均有原始记录；包含一次热 HEAD 黑洞，不能以暖缓存降级成功。

另以独立只读程序打开全部子进程退出后的真实最终 SQLite 镜像，使用 `mode=ro&immutable=1`，确认 WAL 为空，逐行重新哈希全部 1 GiB BLOB。结果同时匹配原输入账本的最终版本和 256 个已发出批次；镜像、WAL/SHM、原账本前后 SHA 不变。这项补充实际读取保留字节，不只是再次比较 controller 自报哈希。原随机输入文件已按旧夹具流程删除，六个被覆盖的历史 BLOB 版本仍不能从最终镜像重算；涉及它们的原 SQL 指纹也不冒称可完整离线重算。此次没有重跑历史 10 GiB 档位。

## 原始失败与限制

原发现 deadline 缺陷在同一旧二进制上两次重现；修复后独立正式运行通过。发现 real01 的 phase 审计匹配错误、real02 的实际后端低磁盘 500、旧临时目录候选的一处 region 缺口、原 e8 部署恢复的 404 witness 审计失败、旧五入口保留结果审计失败，以及资源不足时未启动的阶段均保留。诊断重审不把原正式失败改成成功。

本批第一次 1 GiB 运行虽然通过外层十进制 7 GB 启动守卫，但在 root_change 操作前低于夹具原有 4 GiB 空闲线而退出，保留 37 个已准备请求和 37 个 ACK；尚未进入最终全计算丢失恢复，仍记 FAILED。其六个已结束计算缓存删除前记录 SHA，完整后端、未调用输入、原始账本、源码和实际二进制全部保留。第二次在 10,931,236,864 字节空闲下启动，原源码、原二进制和内部 4 GiB 守卫均不变；两个运行单独归属。

逐文件覆盖计数、源/构建/原始报告摘要及失败映射见[机器证据](../evidence/discovery-recovery-local-2026-11-08.json)。

原 e8 恢复失败的原因是两次真实不存在的 NameBinding GET，其错误 XML 含不同 RequestId；正确的缺失语义相同。修复仅对分别认证过的同 key 404/无 ETag 承认相同缺失；200 的 body/ETag 仍须来自同一真实版本。新 94 是独立构建和完整新执行，不以修正旧报告替代重跑。

远端 `5a04716` 的 checks 仍报告 failure；取得的 job 信息没有 steps，尝试获取工具 job 日志返回 BlobNotFound。具体原因未确定，不能宣称 CI 成功，也不能推定是账单或代码问题。按仓库既有维护者授权，只能在所需本地门禁完整后合入，且不修改分支保护。

GC 关闭，旧块、索引与 orphan 可增长；逻辑 10 GiB 配额不限制 bucket 总量。完整冷恢复仍下载整个数据库和保留结果，没有 lazy VFS。单库原 ETag HEAD 串行发布点不因 pod 数增加而消失。AWS Standard、真实网络文件系统挂载、生产 TPS/P99、长期成本收敛及 PITR 不在本批通过范围。
