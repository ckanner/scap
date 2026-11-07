# N1 生命周期、请求退休与迟到候选验收计划

- 日期：2026-11-07。
- 源码审阅基线：`e2c44b099132700e1305c275c6551c8e156fe510`，即已合入认证 HTTP 服务与 Node SDK 的主线。
- 状态：**NOT_IMPLEMENTED / NOT_RUN**。本文是待实施合同，不是测试报告，不表示 N1 退出。
- 本次环境在首次修改实验 worker 前失去执行能力；没有新增可执行生命周期实验，没有构建、运行或产生本计划的通过证据。
- 实施遵守 [AGENTS.md](../../AGENTS.md)、[主方案](../architecture/object-storage-native-proposal.md)、[验证规范](validation.md)与[本地源码身份要求](local-validation.md)。

## 1. 目的与准确范围

主线已有真实 S3 兼容端点、提交切点、原结果、计算丢失恢复与部分接管实验。剩余缺口包括权限、维护、删除、请求世代关闭／退休和迟到候选之间的完整网络排序证据。现有单元与有界模型覆盖部分转换，但不能替代多进程真实原生 SQLite 和 S3 的合同。

本计划补充主方案 OT-01、OT-04、OT-05、OT-06、OT-07 的指定场景，并为 OA-ACK、OA-FENCE、OA-RESULT、OA-BOOT 提供独立证据。即使全部完成，也不自动覆盖 OT-01–OT-08 的所有条件，更不代替真实 AWS Standard、跨 AZ、目录、GC、PITR 或生产 SLO。

实验只调用正式 Rust crate，不复制提交、取消、退休或恢复算法。物理 GC 保持关闭。所有数据库和凭据均为隔离的合成夹具；不得对真实业务数据库注入故障。

## 2. 当前可复用边界与最小接口缺口

[现有 worker](../../experiments/object-network/src/main.rs)已提供以下直通入口：

| 类别 | 已有入口 |
| --- | --- |
| 对象观察 | `store_get`、条件 `store_put`、`authority_keys`、`authority_inventory` |
| 生命周期控制 | `create`、`status`、`takeover`、`activate`、`activate_session`、`set_policy`、`close_full` |
| 原生执行 | `execute`、`session_execute`、`query`、`session_query`、`session_open`、`session_close` |
| 请求与结果 | `prepare_request`、`lookup`、`cancel`、`lookup_identity`、`cancel_identity`、`decode_result` |
| 有界夹具 | 配置中的 `fixture_limits.quota_bytes`、`retention_entries`、`retention_result_bytes` |

唯一必需的新实验命令是 `set_lifecycle`：将输入严格解析为正式 `Lifecycle`，直接调用 `Database::set_lifecycle(principal, expected_revision, nonce, lifecycle, deadline)`。不得在 worker 内自行编辑 HEAD 代替正式控制 API，也不增加无条件对象写入接口。

计划新增 `experiments/object-network/lifecycle_contract.py` 及其独立自测文件，复用 [现有代理与进程装配](../../experiments/object-network/run.py)。这些文件目前不存在，状态为 NOT_IMPLEMENTED。本文未修改 worker。

## 3. 冻结的夹具语义

### 3.1 身份与预算

| 项目 | 本批计划 |
| --- | --- |
| 作用域 | 每个场景独立 deployment／tenant／database；incarnation 和 generation 固定且不可复用 |
| 主体 | 原写入主体与独立管理员两个主体；都从 worker 可信配置进入正式 API |
| owner | 每个新进程实例使用新的非零 worker identity；不得让两个不同进程冒用同一个存活实例身份 |
| 单库夹具配额 | 4 MiB，通过正式 Options 配置，不修改生产默认值 |
| 当前窗口 | 4 条终态，以便有界地完成关闭与退休 |
| 原结果字节预算 | 128 MiB；本批实际结果很小，按条数触发满窗 |
| 保留语义 | current 与两个完整 closed epochs，沿用正式协议 |
| 数据 | 小表、独立记录的输入、SQLite `random()` 生成且通过原结果见证的随机字段 |
| 期限 | 遵守原 worker、S3 adapter 和代理的现有期限，不为使断言通过而无限延长等待 |

小窗口只证明转换顺序，不能证明默认 4096 条窗口的容量、费用、延迟或按小时保留能力。4 MiB 是实验 profile，不是新增产品限制。

### 3.2 不能误判的现有行为

- Maintenance 当前阻止新写与 takeover，但允许已授权的新强读和结果查证。正式单元已明确这种行为；本批不得把 Maintenance 下读取成功判为缺陷。
- Deleted 拒绝后续业务与管理转换，不能再改回 Ready。不得为了审计数据反向激活已删除的作用域。
- 412 只证明该次带原 ETag 的条件写失败。它不自动证明同一业务身份从未在其他调用中提交。
- Unknown、Closed、Retired、Cancelled 与 Committed 必须分别断言。Retired 不代表未提交或可换 ID 重做。
- 控制 API 的 expected revision 和 nonce 绑定一次意图。Unknown 后不得刷新 revision 盲重试，也不能仅因 nonce 相同宣布原控制成功。
- 提交先于撤权或删除时，原 SQL 的成功响应可能晚到；不能按响应到达先后反推提交顺序。
- 新鲜授权强读选择调用期间的 HEAD。已经开始的合法读与并发撤权需要按其实际准入顺序判断，不能追溯否定先获准的快照。

## 4. 十二类真实场景

每个场景先显式创建并激活新库，提交建表及种子事务。SQL 输入在发送前同步保存，种子 ACK 完整保存。代理必须捕获 HEAD 请求 body、同次 GET 的 body／ETag、请求条件、后端响应和实际故障边界。

| ID | 场景 | 必须观察的边界与结果 |
| --- | --- | --- |
| LC-01 | 撤权先于旧写提交 | 暂停旧写 HEAD PUT 于转发前；独立管理员撤销原主体读写权并成功 CAS；释放旧 PUT，后端真实 412，旧写不能 ACK；随后新 query／lookup 按当前权限拒绝 |
| LC-02 | Maintenance 先于旧写提交 | 同样暂停旧候选；先进入 Maintenance，再放行并要求旧 CAS 412；新写与 takeover 拒绝，仍具 READ 权限的强读按当前合同允许 |
| LC-03 | Deleted 先于旧写提交 | 先发布 tombstone，再放行旧候选并要求 412；后续 query／lookup／activate／takeover／改回 Ready 拒绝；同一 HEAD key 的显式 create 不得覆盖墓碑 |
| LC-04 | 写提交先于撤权，ACK 晚到 | 在 SQL HEAD 已被后端接受为 200 后暂停响应；管理员随后撤权；释放原响应，允许原提交得到正确 ACK；新读和新查证仍按当前权限拒绝 |
| LC-05 | 写提交先于维护，ACK 晚到 | 后端接受提交后再进入 Maintenance；释放后原 ACK 保留，后续新写拒绝；业务内容与原结果符合提交先胜的顺序 |
| LC-06 | 写提交先于删除，ACK 晚到 | 提交后端 200 后才发布 Deleted；晚到 ACK 不被改成回滚；删除之后的可访问性与墓碑单独验收，不冒称仍可通过业务 lookup 找回原结果 |
| LC-07 | Cancel 先胜 | 旧 SQL HEAD PUT 在途但未转发时，使用原完整请求身份完成 cancel；再放行旧 SQL，要求真实 412；后续查证同一个取消 transition，原 SQL 不得再被执行 |
| LC-08 | Commit 先胜 | SQL HEAD 后端 200、客户端尚未收到 ACK 时调用 cancel；cancel 应返回原 Committed receipt／结果；释放原响应后完整匹配，两种观察不混算成两次业务效果 |
| LC-09 | Cancel 响应丢失 | 必须先观察取消 HEAD 已被真实后端接受，再丢弃响应；原调用为 UNKNOWN，查证得到 Cancelled；新计算恢复后仍保留同一取消屏障，原 SQL 永不重放 |
| LC-10 | 精确请求身份与零变化事务 | 同 ID 同原 SQL／参数重复 execute 返回同一 receipt／原结果；同 ID 变 SQL 或参数、变主体及未来 epoch 拒绝；读型 execute 与零变化 UPDATE 仍产生正式原结果记录 |
| LC-11 | 满窗关闭、保留与退休 | 旧 SQL 候选在途时用其他独立请求填满 current，close_full 先胜后旧 CAS 412；closed 原结果仍能逐字节查回，closed 中 absent 返回 Closed；多轮关闭后 epoch 1 返回 Retired，其已提交业务效果仍在当前数据中 |
| LC-12 | owner 交替与旧版本／ABA 拒绝 | A 的旧候选暂停后由新实例 B takeover／activate，再由新的 A2 实例接管；旧 owner 与原 ETag 候选拒绝；Ready→Maintenance→Ready 的外观回归仍推进 revision，旧 expected revision 和旧 ETag 不能复活 |

### 4.1 竞争断言必须绑定真实网络事实

“控制先胜”的断言至少同时满足：

1. 旧候选的 HEAD PUT 已到代理，记录完整候选摘要与原 If-Match，但尚未转发。
2. 控制操作使用正式 API，后端成功接受其 HEAD CAS。
3. 旧候选原样释放后，对应同一 request serial 的后端响应为 412，而不是代理伪造错误、超时或本地拒绝。
4. 旧 execute 没有成功响应，最终 HEAD 与控制后的 body／ETag 一致；不存在自动换 ETag 再发布。
5. 最终结果及业务行符合先胜者，未获 ACK 的请求单独查证，不凭最终行数推断其历史。

“提交先胜”的断言必须证实真实后端 200 发生在控制 CAS 前，而 SQL ACK 被代理延迟到控制之后。不能仅观察客户端成功便推定顺序。

代理的有限 hold 预算必须被遵守。LC-11 先在一次有界 hold 内证明关闭屏障拒绝原 SQL；完成多轮退休后，另用保存的同一候选 bytes 与原 ETag 检查迟到重发。后者是原候选的条件对象重发，不重新执行 SQL，也不能冒称原 SQL 调用在整个退休过程持续存活。

### 4.2 ABA 的证明边界

测试仅证明协议参与者不能用旧 ETag、旧 expected revision 或旧 owner 恢复先前权威。S3 不理解 HEAD 内容的业务合法性；持有当前 ETag 和直接写权限的恶意进程仍可能写入非法旧内容。不能把这种违反信任模型的操作拿来要求 S3 自动拒绝，也不能以禁止单次原始写入宣称抵御恶意管理员。

Deleted 身份复用测试须包括改变 incarnation／generation 但仍命中同一物理 HEAD key 的尝试。应从正式 create／读取路径验证墓碑或 scope 不匹配拒绝，不能通过换 key 生成另一个库后声称旧身份被保护。

## 5. 独立输入、ACK 与查证分母

必须建立独立于对象存储和计算缓存的同步账本。客户端输入在调用前保存，成功响应在客户端实际观察后保存。原始失败和 UNKNOWN 不覆盖、不转写为成功。

至少分别报告以下集合：

| 集合 | 含义 |
| --- | --- |
| Inputs | 每次业务意图的原 SQL、参数顺序、scope、epoch、ID、principal、指纹；发送前持久记录 |
| ExecuteResponses | 每次 execute 调用的真实响应或无响应事实，包含失败和重复调用 |
| ACKResponses | 客户端实际观察到成功的所有 execute 响应；同身份的成功重复响应也保留 |
| ACKIdentities | ACKResponses 按完整业务身份归并后的集合；不得只按数字 ID 归并 |
| ResolvedWithoutACK | 没有 execute ACK、后来 lookup／cancel 查证为 Committed 的请求及原结果 |
| CancellationProofs | 成功取消或后来确认的取消屏障；不是 SQL ACK |
| RejectedCandidates | 有明确原候选失败证据的尝试；不等于业务从未提交 |
| RetiredChecks | 按本次显式关闭步骤和保留合同已退休的身份，预期状态为 Retired |
| DeletedAccessChecks | 删除后按当前权限／生命周期拒绝查证的身份，不能计为原结果可查恢复通过 |

完整 receipt 包括 scope、request、sequence、transition、data_root、result_hash。原结果必须比较完整 SCAPRES1 字节，不能只比较摘要、行数或部分 JSON 字段；typed 结果的重复列、整数和字节值也不能被有损规范化。

对仍保留且仍有权限的每条 ACK，恢复后的 lookup 和成功重复 execute 必须等于原 receipt／原结果。重复 execute 是同一已固定身份的结果返回检查，不能重新生成请求 ID 或重写 SQL。

退休与删除场景必须分列：可以验证其业务效果或拒绝屏障，但不能将 Retired／Lifecycle 当成“完整原结果恢复相等”。报告中所有 ACK 应被逐条分类，未检查项为 NOT_RUN，不得从总分母删掉。

随机字段的期望值来自首次实际成功响应或单独的已提交查证见证，绝不从恢复后的数据库反读生成期望。重复成功响应不新增预期业务行；未提交和 cancelled 候选不得出现在业务行集合中。

## 6. 独立 oracle 与负对照

场景控制器只负责输入、故障注入与记录。另建只读审计器，读取冻结账本和代理历史，不导入 controller 的“通过”状态，不导入正式数据库转换算法作为自己的预期生成器。

| Oracle | 必须检查 |
| --- | --- |
| 顺序 | 以对应 request serial 的转发／后端响应及完整 HEAD 转换建立顺序；客户端响应时间不能代替 CAS 生效时间 |
| Fence | 每个被保护的控制转换之后，原条件候选不得成为后继；旧候选内容和条件未被刷新 |
| 结果 | 同一请求的完整原结果与 receipt 一致；提交与取消不能同时成为终态 |
| 效果 | 从独立输入、ACK 与单列的无 ACK 已提交见证生成期望业务行，完整比对当前数据 |
| 身份 | scope、世代、主体、SQL／参数指纹和 transition 无别名；退休后旧身份永久拒绝 |
| 恢复 | 只凭原 S3 数据与必要配置，新的 worker 重建正确根；旧本地目录确实删除 |
| 副作用 | 明确拒绝或只读检查不能悄悄产生新业务提交；允许的控制 CAS 与数据 CAS 分别记账 |
| 证据身份 | 实际二进制、native archive、源码、依赖锁、输入与原始日志属于同一冻结候选 |

自测应对每项断言提供负对照，至少包括：伪造或缺失 412、把代理注入当成后端响应、丢失 ACK、仅比较结果摘要、receipt 字段漂移、重复响应重复计算业务效果、Unknown 被改成未提交、Retired 被当成 Cancelled、缺少旧候选条件、异常时自动刷新 ETag、删除后错误重新激活。

这些 oracle 自测属于夹具测试，不参与正式 Rust 单元覆盖率，也不能当成真实 S3 合同已通过。

## 7. 计算丢失与后端重启

每组完成竞争后，保存最终预期与全部账本，再实际 SIGKILL 该场景所有计算进程并等待确认退出；删除该场景完整计算目录，核对不存在，然后用新 worker identity 和新目录恢复。

未删除的库使用正式 takeover／activate_session，并核对 data_root、保留结果与当前业务行。关闭窗口和退休屏障在新进程中必须仍然生效。Deleted 库只检查 tombstone、scope 和操作拒绝，不执行恢复到 Ready。

最终可在全部计算停止后重启四个本地 S3 后端进程，再以新计算进程复核各作用域。必须分别记录计算进程丢失与后端重启的实际 wait 状态、身份和检查分母。一机 SeaweedFS 重启仍不是 AWS 持久性、跨 AZ 或设备断电证明。

## 8. 构建、失败保留与退出要求

1. 实现时先固定场景清单、输入 profile、断言与账本 schema。场景增减必须版本化记录，不在结果出来后缩小分母。
2. 冻结完整候选，使用独立 target 和 [正式 release 构建收据](../../experiments/object-network/build.py)；读取实际 Cargo 成功终止事件、唯一 worker、native archive 与完整输入摘要。
3. 运行夹具自测、仓库格式／静态检查及受影响正式单元。正式生产代码若有变更，必须重新执行逐文件行／函数／region／分支精确 100% 门禁。
4. 真实实验单独执行，不继承 LLVM 插桩，不把其 profile 混入 unit。每次使用新的证据目录，不覆盖先前失败。
5. 实验前后校验源码与 worker 身份；其他并行工作变更输入时拒绝沿用原构建收据。
6. 独立审计器重算全部分母和结果。任一漏记、错序、原结果不一致、旧候选成功或缓存丢失未完成，均为失败。
7. 单机兼容端点与真实 AWS 分开标记。没有 AWS 配置时保持 AWS NOT_RUN，不自动创建云资源。
8. 按现有协作规范，所需验证缺失时只能草稿审查，不合并、不借用其他提交的历史测试结果。

## 9. 本文交付时的状态

| 项目 | 状态 |
| --- | --- |
| 主线源码与现有合同审阅 | 已完成静态审阅 |
| 十二类场景、语义及独立账本要求 | 本文已定义 |
| worker 的 set_lifecycle 扩展 | NOT_IMPLEMENTED |
| lifecycle_contract 与独立 oracle | NOT_IMPLEMENTED |
| 夹具自测 | NOT_RUN |
| 新候选 Rust 编译／原生 SQLite／精确覆盖率 | NOT_RUN |
| 本计划真实本地 S3 合同 | NOT_RUN |
| 真实 AWS Standard、跨 AZ、生产 SLO | NOT_RUN |
| N1 整体退出 | 未达到 |

相关入口：[现有网络实验](../../experiments/object-network/README.md)、[故障矩阵](../operations/failure-matrix.md)、[对象运行时](object-runtime.md)、[路线图](roadmap.md)。
