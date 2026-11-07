# N1 生命周期真实合同：本地验收记录

日期：2026-11-07。冻结实测提交为 `fe1909bf9f6b46cbfdd8536d4b8a649999a784b0`，tree 为 `25ef8eda98950ada53c9284197ab06e09b1c7da7`；173 个 tracked 文件的 source manifest 摘要为 `8e16b336b492941babe54de4c43dcb167c7ee5b4f29e065a3cb5bf32601195d3`，运行前后身份一致。

**[PR #29](https://github.com/ckanner/scap/pull/29) 的十二类生命周期合同已通过本地真实 S3 兼容端点、原生 SQLite、多进程和独立原始账本复核。** 这补齐了[固定计划](n1-lifecycle-validation-plan.md)的 LC-01–LC-12，不表示全部 OT-01–OT-08、AWS 或 N1 整体退出。机器记录见 [lifecycle-contracts-local-2026-11-07.json](../evidence/lifecycle-contracts-local-2026-11-07.json)。

## 交付与身份

实验 worker 只新增正式 `Database::set_lifecycle` 的直通入口；控制器记录独立输入、完整调用和成功响应，oracle 离线重算原结果、HEAD 条件顺序和进程时序。CI 与本地完整验收入口已加入本合同。

本次未修改生产 Rust、SDK、根依赖和 toolchain：75 个相关文件与已验收的 `a11e61e` 逐字节／Git blob 相同。该历史基线的 stable／nightly 各 204 项单元及 24 个生产文件精确覆盖仍明确绑定其原候选；本批没有新运行生产 unit/coverage，也不把真实实验 profile 混入单元。新增 Rust worker 与首候选 `135ef89` 的 61 个 Rust／依赖输入相同，首候选严格 Clippy 和格式检查通过。修正后的 Python 夹具在新冻结候选重跑，共 78 项通过，其中新增生命周期测试 37 项。

实测 release worker SHA-256 为 `1380d04f8588c86fe94e5df17e14a2765b8749ae7ec2c524f2e193ad530f5027`，构建输入摘要为 `5e2fc86fdb315a02ed7945b40c31c19f6ca890886176a527ef8aec3b3b3caa0e`。固定 Rust 1.90.0、实际 Cargo compiler artifact、native libSQL archive、原始构建日志及运行前后检查均保留。后端为 SeaweedFS 4.51／`153ab668c99731a6d29492bf6c61d0b4fa701101`。

## 实际结果

| 分母 | 本轮结果 |
| --- | --- |
| 计划场景 | 12/12；每场均核对计算丢失恢复与后端重启恢复两个阶段 |
| 独立输入与调用 | 56 个调用前保存的输入；642 对完整调用／响应；122 次 execute 响应 |
| 成功响应与身份 | 78 次 execute ACK，归并为 30 个完整原身份；56 个 SCAPSQL1 指纹和全部 78 个 SCAPRES1 原结果独立重算 |
| ACK 分类 | 71 次属于可查的保留原结果；5 次属于 Deleted 后访问拒绝；2 次属于 Retired 身份；零错配 |
| 恢复内容 | 46 次冷恢复后的原身份成功重发，54 次完整 Committed lookup/cancel 观察，20 次完整业务行查询；均与原始见证一致 |
| 取消与拒绝 | 12 个取消身份、34 次取消证明观察；4 次撤权访问拒绝、40 次删除后检查、11 次 Retired lookup、1 次 Closed lookup |
| 真实条件竞争 | 六个被拒绝旧候选的真实后端 412；五个提交先胜的真实 200；另有三次迟到原候选／快照的 412；不以代理伪造响应替代后端 |
| HEAD 权威链 | 12 个物理 HEAD，138 个连续已接受 revision，595 对同一次 exact GET 的 body/ETag；不可变对象条件创建及摘要校验通过 |
| 传输账本 | 2,125 个真实后端响应：2,090 个 200、35 个 412；按调用、phase、request serial 和时刻交叉核对 |
| 进程与缓存 | 59 个完整计算进程 incarnation、36 组缓存丢失、24 个恢复阶段；后端四个进程均有 wait4 SIGKILL 与新 spawn，切断后端时零计算进程存活 |
| 清理 | 全部自有计算与后端进程退出；proxy_errors 与 cleanup_errors 均为空 |

LC-08 在原 execute ACK 尚未到达时，cancel 已查证原 Committed；这是一次先到的已提交观察，不是新增业务效果。该请求后来仍收到原 execute ACK，因此本轮“最终没有 execute ACK、仅查证为已提交”的身份分母为零。

删除和退休分列验收。Deleted 不允许重新激活或借另一个 incarnation 覆盖同一物理 HEAD；Retired 不表示原业务未提交。不能把这七次成功响应的后续拒绝描述为“原结果仍可访问”，也不能从可查恢复分母中悄悄删掉它们。

同一个 v2 worker 另跑原网络回归：15 类合同、30 个扩展故障场景，基础 4 次和扩展 61 次 ACK，以及 schema 的 12 次原成功／12 次原身份重发全部通过。该回归的控制器结论与原始日志单独保留，不冒称本轮第二套人工审计器也完整重审了它的每项断言。服务／SDK、保留结果与 1/10 GiB 本批未另跑；其生产输入未变，历史证据仍按历史候选引用。

## 独立审计与失败保留

第二套仓库外只读审计器没有导入 runner、项目 oracle 或生产协议实现，也不把 summary 的 passed 字段当作结论。它从原输入重算 SCAPSQL1、完整 SCAPRES1／Result 对象及 receipt，逐调用绑定实际网络、原 If-Match、HEAD revision 和完整进程时序。审计脚本 SHA-256 为 `37d3e15893076e8af5fb95dd512be38a679647eeadd65679c1805f467cc66300`，最终报告摘要为 `6f1bcc80e38212a09a23f98d00d8244cf32dfa26666837628da10e494d19c1fa`。其固定编解码辅助脚本、各次审计失败版本及 provenance 也保留。

首候选 `135ef89` 完成了实际场景调用，但在 LC-03／LC-06 的两轮恢复中使用重复 invocation label，oracle 拒绝，整轮保持 FAILED。修复为内部 `<stage>.deleted.*` 标签，并在发送前拒绝重复标签；四组调用图有专门回归。没有重写原账本或把诊断标签规范化结果当作正式通过。

修正版首次 release 的 Cargo 返回 0，但捕获日志缺少最后的 `build-finished` 事件，构建收据门禁仍正确拒绝。相同冻结源码、相同 target 和配置下，实际再次执行 Cargo，新的完整 trace 与二进制／native archive 收据通过；没有合成缺失事件。日志异常原因未确定。实际运行先写入独立临时目录，完成后复制的 12 份生命周期文件、15 份网络文件逐字节核对；原失败和成功记录互不覆盖。

## 证明边界与下一步

本轮使用 4 MiB 数据配额、四条 current 请求窗口和 128 MiB 结果预算，目的是触发状态转换。它不证明默认 4,096 条窗口的留存 sizing、AWS 耐久性、跨 AZ、设备断电、实际 NFS/EFS/FUSE 挂载、长期运行或生产 SLO。历史缓存删除是控制器 I/O 观察，离线复核只能与原进程时序交叉校验，不能重新观察过去的文件系统。

之后依[路线图](roadmap.md)实现名称目录、创建／撤销／删除与名称重用，逐切点验证后接入服务；自动协调、冷热隔离、目录完整枚举、GC/PITR 继续保留独立门禁。后续生产 HEAD 格式或 Rust 代码变更必须重新完成受影响的单元、精确覆盖和真实合同，不能沿用本次结果认证新实现。
