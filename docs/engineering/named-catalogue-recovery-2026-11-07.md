# 名称目录实现恢复清单（2026-11-07）

## 当前状态

**BLOCKED_ENVIRONMENT / NOT_COMPILED / NOT_MERGE_READY。** 本文是恢复工作用的源码与验证边界记录，不是验收报告。

最近已合并主线为 `d63f41ee274f84cc98b0480f5e348a53f4527f4b`，tree 为 `934d772f7e960f3297c668e229f7270a4da0ef7a`。PR #28、#29、#30 的冻结范围及证据继续有效；它们不认证后续名称目录运行时代码。

[PR #31](https://github.com/ckanner/scap/pull/31) 的运行时开发检查点为 `f16a4f6d12c0b8275e0563f56fa9d5017c3293ac`，tree 为 `16186b3085723ce3e71aec53209a6596ef0a43a9`，包含 81 个修改/新增文件。后续文档提交不把这份运行时检查点变成正式验收候选。

执行端失联后，连只读 `pwd` 都返回 “No usable execution environment is available”。GitHub 对象 API 仍可用，因此将可精确重建的记录补丁、完整候选文本和待实施修复意图保存为恢复提交。**恢复分支不是失联工作区最终字节的完整快照**：无法再次读取该工作区的文件、未提交 diff、源码 manifest 或最后命令的实际结果。不能从一次工具断连推定写入成功或测试成功。

## 已有证据与缺失门禁

| 项目 | 实际边界 |
| --- | --- |
| #28 本地目录防护 | 已合并；204 项 Rust 单元、逐文件覆盖门禁、原生/兼容 S3/服务/1 GiB 等必要本地验收见原冻结报告 |
| #29 生命周期 | 已合并；LC-01–LC-12 的本地真实合同、两轮恢复和独立原始审计已完成 |
| #30 名称模型 | 已合并；885 条正向历史和 25 个负对照，不等于正式 Rust 或真实目录验收 |
| #31 核心开发 | 重构前曾完成 104 项核心单元；覆盖仍不完整。最后 Canonical/类型化视图重构尚未确认可编译 |
| #31 服务开发 | 单独服务 stable/nightly 各 63 项、服务模块覆盖与严格 Clippy 的开发记录已完成；不是整个恢复候选通过 |
| #31 SDK 开发 | 单元、原始 V8、真实 Fetch 与固定 TypeScript 检查有开发结果；没有以它们替代整包正式门禁 |
| HTTP 开发诊断 | 目录 70 HTTP/545 S3、普通服务 105 HTTP/620 S3 的诊断记录已完成；使用开发 binary，formal 为 NOT_RUN |
| 目录网络 oracle | 首轮 31 项测试中存在 Trace 缺字段和测试向量错误；修复后的实际重跑未完成 |
| 仓库外 HTTP 审计 | 正向开发复核已执行；最后一轮负对照命令结果在失联后未能回取，不能标通过 |
| 恢复源码完整验收 | fmt/编译/Clippy、unit-only 四维覆盖、原生 release、全部真实合同与独立审计均待新冻结候选完成 |
| AWS/生产 | AWS Standard、跨 AZ、真实网络挂载、长运行、完整生产 SLO 仍 NOT_RUN |

远端检查点 `f16a4f6` 的 8 个 Actions runs 均为 failure，14 个 job 均为 0 steps；已读取的质量任务 runner_id 为 0。未获得可执行的远端替代验证，也未确认平台失败的具体根因。不能把 GitHub 的“无合并冲突”当作测试通过。全部合并条件继续遵守 [AGENTS.md](../../AGENTS.md)。

此前 #28–#30 的归档保存了各自完整公共原始证据、失败、工具/二进制身份及独立审计源码；该归档不包含 #31 后续开发运行。失联工作区若能恢复，先保全其原始记录，不覆盖旧失败，不把重建后的脚本冒充当时实际执行的版本。

## 必须保留的协议修正

1. 外来命名 HEAD 的合法占用证明须读取其真实 CreateDescriptor，核对完整 Scope、来源与规范字节摘要；不能信任一个只在 HEAD 中自报的来源。
2. 已持久化的 caller/kind/control operation 必须先核对完整原意图。改目标、revision 或 nonce 返回 Conflict，即使新目标不存在；不能为适配夹具把它改为 IdentityConflict。
3. Bound 或自身终态绑定所指 HEAD 缺失/错源必须失败关闭；合法外来物理占用的分类不能隐藏自身权威损坏。
4. resolve 遇到取消 Tombstone 时验证永久 AbortProof，遇到 Bound 配正常 Deleted HEAD 时验证原 Delete ControlDescriptor，再返回不可服务；不能把损坏伪装成普通 NotFound。
5. 原 abort 遇同名后继绑定与自身正常 Deleted HEAD 时，要求后继 revision 严格大于旧终态 revision，并核对原正常删除来源；不得编辑新绑定。
6. Canonical 包装只从严格 decode、语义验证、规范重编码一致的记录构造，保留已验证字节及摘要。名称和 HEAD 仍 fresh exact GET，不能用类型封装消除必要的权威读取。
7. Aborting 的稳定名称下，读取顺序采用 Binding→Proof→HEAD→Binding；Proof 是永久记录且晚于身份屏障发布。必须用 HEAD 从 404 或 Provisioning 并发推进到 Deleted+Proof 的行为测试验证，不能让旧 HEAD 配新 Proof 误报 Corrupt。
8. HEAD JSON format 3 与不可变 SCAPOBJ2 format 2 分别校验；保留 HEAD 2 结果作为历史证据，新源码须重新运行受影响真实合同。

## 恢复与继续顺序

1. 保留失联工作区（如果仍可读取），另建隔离 checkout；从上述精确 Git 检查点和恢复提交逐文件核对，先辨别“已记录补丁重建”和“未编译最终候选”。不要强制重置已有未提交文件。
2. 按[开发环境说明](../../dev/environment/README.md)恢复固定工具链，核对 lockfile、native 依赖与实际版本。工具可执行的探针不计入数据库验收。
3. 收敛 core 的 records/mod/create/inspect/control 类型和测试调用；完成上节的缺失权威、来源证明、固定控制意图与终态 revision 反例。运行 fmt、严格 Clippy 和真实单元；不通过删检查、排除生产文件或混入集成 profile 填覆盖。
4. 修复目录 oracle 的测试 Trace、派生身份向量及消费切点的行为判定。负对照要拒绝漏掉整组 I/O、漏 ACK、错身份/结果/权限、响应未被消费和计算/后端时序不成立；不采用源码字符串断言代替实际行为。
5. 冻结完整新候选，保存源码清单、工具链、release/native archive、全部实际退出码与原始失败。活动证据写入新的独立目录；结束后逐文件校验再复制归档，不复用或覆盖失败目录。
6. 使用[完整本地入口](../../dev/environment/validate.sh)及[验证规范](validation.md)，重新执行 workspace 单元与逐文件精确覆盖、工具/环境覆盖、SDK/Fetch/类型检查、两组模型和实验夹具，再执行原网络、保留结果、1 GiB、十二类生命周期、普通服务、新目录全 PUT 切点和目录 HTTP/SDK 合同。正式真实合同必须提供冻结 release build receipt，不传诊断模式。
7. 用原始输入、完整 HTTP/结果字节、body/ETag、条件写、进程 wait4/缓存丢失和四后端重启链做独立复核。固定输入和所有成功响应决定分母；UNKNOWN、无 ACK 已提交、Deleted、Retired、Cancelled 分开列出。
8. 必要本地门禁全部完成后，更新文档/机器记录、核对文档交付与已验证生产源码一致，再按维护者既有授权合并 #31。无须因环境中断重复申请合并权限；也不能把该授权解释为测试豁免。

这批精确名称目录完成后，仍按[路线图](roadmap.md)推进全目录发现/分页和完整恢复、自动 owner 路由、冷热隔离与负载活性，再进入分段请求索引、pin/generation、安全 GC、PITR 和长期成本验证。当前物理 GC 保持关闭，完整冷恢复仍物化全库。

## 恢复来源清单

精确文件路径、Git blob、来源分类、已知缺失及未执行修复由同批恢复提交的机器清单记录。读回相同 blob 证明保存文本一致，不证明该文本可编译、被实际运行或与失联磁盘最后一刻完全相同。

- [总恢复机器清单](../evidence/named-catalogue-recovery-2026-11-07.json)：精确 Git 基线、文件 blob、来源分类及远端检查状态。
- [核心恢复清单](named-catalogue-core-recovery-manifest-2026-11-07.md)：类型适配、尚未编译的源码及并发修正。
- [网络恢复清单](../evidence/named-catalogue-network-recovery-2026-11-07.json)：原首轮失败、无法回取的日志和矩阵边界。
- [尚未应用的网络修复](named-catalogue-network-proposed-edits-2026-11-07.json)：每项绑定原 blob 和唯一 literal 匹配条件，保持 PROPOSED_NOT_APPLIED_NOT_RUN。
