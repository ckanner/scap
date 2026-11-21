# 独立事务 group commit：2026-11-20 验证记录

日期按 America/New_York。基准主线为已合入 #67 的
[`68246fd639d0331d5c90a31d8b3134e96532b3b5`](https://github.com/ckanner/scap/commit/68246fd639d0331d5c90a31d8b3134e96532b3b5)。
本轮新增实现与证明见[设计](../architecture/independent-group-commit.md)和
[实际合同](../../experiments/group-commit/README.md)。

## 范围和验收状态

新增 native 私有 staging、逐请求逻辑版本和原结果、一次原 HEAD 条件发布、默认关闭
的 writer actor 组批、持续计费的队列资源以及逐成员输出。普通单请求、协议字段、
Node SDK 业务调用和默认部署路径继续回归；新增生产文件进入原精确覆盖分母。

本轮 [PR #68](https://github.com/ckanner/scap/pull/68) 的完整 workspace 单位、精确覆盖、
正式 release 的新增真实合同和独立审计已经在各自冻结源码上通过。下面明确区分单位
候选与最终实际候选；后续文档交付不改写它们的来源。远端状态以
[最终 PR head 的 checks](https://github.com/ckanner/scap/pull/68/checks)为准，本地报告
不代替远端结论。AWS、生产 SLO、长期 GC/成本与性能配对保持 NOT_RUN。

## 冻结来源与完整本地结果

[机器记录](../evidence/group-commit-local-2026-11-20.json)保存源码、工具、二进制、原日志、
HTTP/S3 账本、失败和通过结果的摘要。原始运行凭据、数据库与日志不提交 Git。

| 来源 | 冻结身份与核对 |
| --- | --- |
| Rust/Node 单位候选 | `9b332b949f2bc7e29e46d5d4464df4db1be7c3a3`，tree `2c13d8425692e34f4b8315e8d40b8aa7fae3c328`；896 个 tracked 文件前后逐字节一致 |
| 最终真实合同候选 | `a82e6de87b8fab38ed07b77bb3870774d415c2e0`，tree `6c5a55d7c85c099efa480ba2f78016215ce9289e`；896 个 tracked 文件、完整 source archive 和原始 build receipt 一致 |
| 两候选差异 | 仅三份说明文档和 group 的 run/oracle/controls/test_protocol；Rust、Node、生产与单位源码、覆盖规则、锁文件和工作流完全相同 |
| 实际 release | Rust 1.90.0；`scapd` SHA-256 `c8ecf12e0209ec03c9ec4358c21147c47a353ef0371f403cd994c1a4957bb1c0`；319 个正式构建输入、native archive、Cargo 最终成功事件及退出码 0 均核对 |
| 实际工具 | Node 22.16.0、经认证的 SeaweedFS 4.51；独立 SQLite 观察器 3.53.1；工具原二进制摘要单独保留 |

| 门禁 | 实际结果 |
| --- | --- |
| Rust stable/nightly 单位 | 各 **969/969**，不是两份 profile 合并后的覆盖 |
| 第一方生产 Rust | **82 个文件逐文件四维精确 100%**；17,347/17,347 行，1,525/1,525 函数，26,600/26,600 regions，3,574/3,574 branches；无缺 map、零分母或覆盖排除 |
| 原始单位 profiles | 93 份 profraw 和 1 份 profdata 保留，未混入真实 HTTP/S3 执行 |
| 代码质量 | workspace 严格 Clippy（`-D warnings`）、fmt、diff 和文档检查通过 |
| 仓库门禁自身 | coverage 7.10.6；76 项单位、401/401 statements、184/184 branches |
| Node | 184 项单位、22 个生产模块精确 V8 门禁与其负控通过 |
| 新模型与观察器 | 11 项 model + 21 项 observer 单位通过；有限模型 2,940 个调度，独立于实际执行 |
| 正式服务实际 | 78 个固定 command、82 个原 HTTP 请求；28 个已提交独立事务、28 个冷恢复原结果 lookup；20 次 accepted HEAD、1 次原组候选 412 |
| 实际证据审计 | 699 次业务 S3 请求；独立数据闭包重建与 `integrity_check` 通过；40 项反例全部按精确原因拒绝，其中 21 个原账本副本、19 个语义投影；新增实际执行次数为 0 |

## 实际合同的结果和限制

四成员成功组确实只发布一次 HEAD，但成员仍各有连续 sequence/revision、原随机结果、
中间数据根与 receipt。固定阶段观察到的成功发布组宽分别为：success `[4]`，
first_failure `[3]`，middle_failure `[1, 2]`，last_failure `[3]`，duplicate `[3]`，
response_loss `[4]`。cancel_race 没有成功组发布，控制请求先安装中间成员的取消屏障，
整个原候选以旧 ETag 得到真实 412；成员不改身份、不刷新 ETag、不重新执行 SQL。

首、中、末成员的 deferred foreign key 都在自己的真实 COMMIT 边界失败，后续补父行
不能挽救前一请求。成功前缀可以发布，未开始后缀保持顺序后继续；失败行没有泄漏。
重复原身份返回原随机结果，未重新执行 DDL 或 INSERT。

丢失一个成员的成功 HTTP 响应后，SDK 保留 UNKNOWN；其余成员正常各自答复。
真实 SIGKILL 第一服务并记录、删除全部私有缓存后，使用新的永久 worker 身份和空目录
启动第二服务。显式 takeover/activate 后找回 28 份原结果，包括从未收到 ACK 的那个
成员；完整 receipt 和原字节均与独立捕获结果相同。最终 19 条 witness 业务行、父表、
空子表和 DDL 内容逐项一致，独立原字节 SQLite 重建检查通过。

20 次 accepted HEAD 包含建库、激活、取消和恢复等控制动作；不能用 28/20 推算组宽、
TPS 或成本改善。本合同没有性能配对，全部逐成员 FULL 同步、最终 Manifest GET 和
受检 TRUNCATE 仍保留。真实 AWS、生产尾延迟、长期成本和故障域结论未由此得到认证。

## 本地真实运行中保留的失败

`actual-v1` 使用 `9b332b9`，在响应丢失阶段失败：四个成员已进入 HTTP handler 后才
设置 drop rule，而代理在请求进入时就选择规则。原件证明 response_loss_b 收到了
HTTP 200，`suppressed=false`；SDK 的“预期失败必须发生”断言正确拒绝了该运行。
不能把断言中出现的 `UNKNOWN` 字样读成 SDK 已观察到 UNKNOWN。

`872edd17` 把 drop rule 移到原请求发送之前。`actual-v2` 使用新的完整源码归档和
构建收据，所有实际阶段与当时的 35 项负控通过。随后审查补充故障命名及区间绑定：
arm 早于原 HTTP request，fault entry 指向原 http_serial，成功响应早于 entry，entry
早于 suppression，且 suppression 的 id/reason 必须匹配显式丢回复。新增五个精确反例
后，`a82e6de8` 的 `actual-v3` 再次完整运行并通过 40 项负控；原 v1/v2 文件未修改。

远端旧 `9b332b9` 的 group job 也记录了同一真实夹具失败；随后提交触发的取消与
产品测试失败分开记录。最终 head 的成功与否由实际 checks 决定，不能把旧候选的
成功、取消或失败改写为新候选结果。

## 开发期已发现并修正的问题

- Native scoped 首轮 101 项单位通过，但新 staging 文件存在阶段中断和重复单态实例
  的覆盖缺口；原 `unit.json` 保留。补真实 native COMMIT 后、远端发布前中断，并将
  内部 gate/effects 使用同一动态边界后，新鲜采集的 102 项单位与 native 9 个生产
  文件四维精确 100% 通过；不合并前后 profiles，不降低任何门槛。
- 实际观察器初稿在 ENGINE/CONFLICT/BACKPRESSURE 失败分支过早退出，未核对固定
  SQL/指纹。审查发现后把所有 execute 原输入校验前置，并绑定 lookup/cancel 原身份；
  不允许用另一条更容易失败的 SQL 冒充 deferred foreign key 边界。
- 独立 SQLite 观察器实测发现内存 `deserialize` 不能读取保留 WAL header 的 checkpoint
  镜像。改为写入完整原字节，使用 readonly immutable 文件连接检查，再验证观察期间
  原字节未变化；没有修补权威页头或调用产品恢复来替代独立校验。
- Service scoped 首轮有 shutdown 后缀交付循环的 LLVM 计数缺口，已有测试确实观察
  后缀 UNAVAILABLE 与 Usage 清零。将可信 worker 边界与消费/交付方法分开后 fresh
  profile 全绿；随后独立审查发现直接 Rust Engine API 在聚合预算检查前会复制输入，
  增加分配前整组预检，再重新采集最终 280 lib + 1 bin 单位和 28 个生产文件精确四维
  100%。三轮日志、原始 profile 和严格检查器结果分别保留，没有合并 profiles。
- Core scoped 最终 503 项单位、36 个生产文件的 8,939 行、705 函数、13,817 region、
  1,834 branch 全命中；首轮未命中与修正保留。新增 native/core/service 交叉审查核对
  private COMMIT、受检 rollback、ObjectContext、窗口预留、取消竞争和 panic 清理顺序。
- Node 22.16.0 的 184 项单位及 22 个生产模块精确 V8 门禁通过；新增两项兼容回归
  保留每成员旧 receipt 和 UNKNOWN/已提交输出失败，不自动派发第二次 SQL。
- 开发期模型与观察器先有 28 项单位通过，有限模型覆盖 2,940 个调度。发现并修正模型
  允许重复 rejected CAS 的观察缺口，新增明确反例。正式实际先通过 35 项负控，再补
  命名故障的五个精确反例；最终 32 项单位与 40 项实际证据负控见上文，不混合计数。

开发期局部测试和失败不等于最终冻结验收。后续文档提交只增加记录和状态入口，
不改变正式运行时、SDK、实验、测试、锁文件、工作流和门禁；原冻结来源保持不变。
未来代码修正继续重新采集受影响 gate，不能继承这些计数或实际结果。
