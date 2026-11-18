# 真实 HTTP 服务与 Node SDK 合同

这个实验启动正式 `scapd` 和正式无依赖 Node SDK，通过真实 HTTP/SigV4/S3 调用固定 SeaweedFS 4.51。实验不实现数据库协议，不贡献 Rust 或 SDK 单元覆盖率，也不会发现、创建或修改 AWS 资源。

## 运行

在固定 Rust 1.90、Node 22.16.0 与原生编译依赖就绪后：

```bash
python3 experiments/object-service/build.py \
  --target-dir /absolute/isolated-release \
  --evidence /absolute/new-service-build
python3 experiments/object-service/run.py \
  --server /absolute/isolated-release/release/scapd \
  --weed /absolute/weed \
  --build-record /absolute/new-service-build/build.json \
  --evidence /absolute/new-service-evidence
```

build receipt 绑定实际 stable release、所有 Rust/SDK/fixture 输入和工具版本，并记录构建时实际 native libSQL archive 的摘要。最终运行在开始与结束核对源码输入清单、`scapd` 字节以及实际 Node／S3 可执行文件摘要；运行时不重新链接或读取 archive。`--diagnostic` 只用于开发定位，完成时标记 `completed_diagnostic` 和 `formal_gate_status: NOT_RUN`，不产生冻结验收结论。缺二进制、缺收据、测试失败或清理错误都非零退出。

## 实际判据

1. 无效 bearer 和跨租户 scope 拒绝；拥有正确服务身份仍须获得当前 HEAD 权限。
2. SQL i64、随机 BLOB、Unicode/BOM/NUL、随机 RETURNING 原结果无损。重复请求、lookup 与 committed cancel 返回同一完整 receipt 和原字节；改 SQL 却复用 ID 拒绝。
3. Cancelled 身份不能再提交；撤权使暖会话的新读立即拒绝。一个库维护不改变另一租户库的数据。
4. 两个独立 daemon 并发创建同一 ID，恰好一个成功、一个 Conflict；双方观察同一 HEAD 身份。
5. 在真实后端已接受 HEAD 后丢失响应，execute 保持 UNKNOWN；使用原身份 lookup 找回随机原结果，不重放 SQL。
6. 已有热缓存时阻断远端 HEAD GET，query 必须失败。
7. 第二 daemon 显式 takeover/activate 后，旧 daemon 写入必须 FENCED。
8. SIGKILL 全部 daemon，删除全部本地计算缓存，SIGKILL 四个对象后端进程，再从原对象目录和全新 owner 恢复。两个租户的有数据数据库分别接管、激活并实际读表，核对 9+1 条业务记录；独立核对全部 ACK、业务 BLOB 哈希、取消屏障与未收到 ACK 的原结果。

测试包含 10 个唯一成功请求、8 次成功重复 execute，共 18 次成功 execute 响应，另有 1 次 execute UNKNOWN。重复响应独立记账并在恢复后全部重查；UNKNOWN 的后续 committed 查证单独记账，不修改原尝试分母。随机业务输入在发送前写入独立 fsync 账本，ACK 只在客户端真实观察 committed 后登记。恢复比较完整字节，不只比较行数。未知写的实际 SDK Fetch 调用次数必须为 1，不能用常量声明没有重试。

公开 evidence 包含源码/构建身份、网络历史、输入、ACK、UNKNOWN 查证、阶段结果和清理状态。`http-client-ledger.jsonl` 保存每次完整 HTTP 请求及响应的原字节、摘要、唯一 call ID 与单调时间，不保存 Authorization。`recoveries.jsonl` 逐条关联 18 次原成功 execute 响应及 UNKNOWN 的后续查证，恢复查询和控制的完整返回也都在 HTTP 账本中。`process-ledger.jsonl` 记录 owned Popen 身份、服务 ready、退出请求、内核 wait4、缓存删除、四个后端的退出/重启和客户端进程时间链。

`service_oracle.py` 是只读独立审计入口：从原始 HTTP、输入、ACK、恢复及网络事实重算分母，严格解码 SCAPRES1，并独立重算 SCAPSQL1 指纹和 SCAPOBJ2 Result envelope 摘要；它不执行 controller，也不凭阶段汇总中的行数作恢复证明。成功 execute 必须绑定真实已接受的 HEAD。已知运行中的本地后端是兼容端点，不能据此宣称 AWS 合同。

private fixture 目录另存随机测试凭据、日志和数据库；它从不进入 artifact 上传。通过后删除 private 目录；失败保留以便诊断，summary 明确记录路径和是否删除。进程已停止不等于目录已删除。

### 启动请求与父进程观察时间

worker claim 的下界是 producer 在调用 `Popen` **之前**采样并原样保存的
`spawn_requested_ns`。`identity.spawn_monotonic_ns` 是 `Popen` 返回后父进程的
观察时间，用于 owned child 身份和生命周期核对；子进程可以在父进程再次得到调度前
完成条件创建及精确读回，因此该观察时间不能作为 claim 的下界。

共享 `audit_wire.owned_startup_interval` 要求四个时刻都是正整数，并核对
`spawn_requested_ns <= identity.spawn_monotonic_ns <= started.monotonic_ns < ready.monotonic_ns`。
`service_startups` 还要求每个服务唯一的 start/ready 和同一 owned identity；
raw/closed adapter 按唯一的 `service-*` ID、role 和 incarnation 绑定 readiness。
原有 claim 的 PUT、交付、GET、精确 bytes/ETag 与 ready 顺序仍逐项检查；真正早于
`spawn_requested_ns` 的请求仍拒绝。没有 pre-Popen 字段的旧证据不能用较晚观察值补齐，
也不能通过给历史记录追加推测时间来重新认证。

| 合同 | pre-Popen producer | 独立审计入口 |
| --- | --- | --- |
| 基础 HTTP、catalogue | `object-service/run.py::Service` | `service_startups` |
| owner、isolation、guarded-status | 各自的 `Service` | `service_startups` |
| discovery、segmented | 各自 `Service` 已保存的 `spawn_requested_ns` | `service_startups` |
| resource-limits | `resource-limits/run.py::Running` | `worker_startup` → `owned_startup_interval` |
| reclamation、owner-plan、owner-absence、snapshot、terminal-retirement、controller、controller-matrix | 共享 `object-reclamation-runtime/support.py::Child` | `raw_worker_claims` 或 `closed_worker_claims` |

定向 unit 正控保留“claim 完成早于父观察、晚于启动请求”的合法记录，负控拒绝真正的
pre-spawn claim、缺失或反转时钟、非 owned 身份和借用 readiness。共享 `Child` 另有
真实 Python 子进程管道握手：父进程等子进程先报告时钟后才记录 identity，并最终以
owned `wait4` 回收；它验证 observer 时序，**不计作实际 SQLite/S3 验收**。

### 分段索引的冷恢复进程身份

`segmented_contract.py` 按冻结计划启动六个独立进程，分别使用永久 worker ID
8871–8876，每次关闭后删除该进程的全部缓存。最初写入的 HEAD owner 保持 8871；后续
进程只执行有当前授权的 open、query、lookup 和 status，继续检查原始结果及完整冷恢复，
不会为了重启而删除实例 marker 或重写数据库 owner。

独立 oracle 先核对全部 S3 请求的原字节、签名和完整交付记录，再把每个进程严格对应的
条件创建与精确读回绑定到其 owned spawn→ready 区间。原始 S3 请求总数包含这 12 个
启动请求，并另报数据库请求数和 6 次身份 claim；不能按路径前缀跳过未验证请求。

## 名称目录服务合同

新增 `catalogue_contract.py` 装配同一正式 daemon、正式 `CatalogueClient` 和本机 S3 后端；`catalogue_probe.mjs` 只保存原意图及调用 SDK，不实现目录状态转换。构建完成后另开 evidence 目录：

```bash
python3 experiments/object-service/catalogue_contract.py \
  --server /absolute/isolated-release/release/scapd \
  --weed /absolute/weed \
  --build-record /absolute/new-service-build/build.json \
  --evidence /absolute/new-catalogue-service-evidence
python3 experiments/object-service/catalogue_oracle.py \
  /absolute/new-catalogue-service-evidence
```

目录正式 CLI 必须提供通过的 release build receipt，不提供跳过它的诊断开关；开发诊断应在仓库外明确装配 Suite，并与正式 gate 输出分开。

目录服务测试有 15 个固定客户端阶段，覆盖 5 组接口合同：

| 合同 | 实际观察 |
| --- | --- |
| 原意图与权限 | 当前 provision 拒绝、同 create ID 改名/改 quota 冲突、同名竞争、精确大小写、ADMIN 不等于 READ；创建 descriptor 不冒充 Ready |
| 取消与迟到创建 | descriptor-only 取消为 NotReserved，Bound 为 CannotAbortBound；阻塞原 Provisioning HEAD 条件创建，让第二 daemon 的取消先建立 Deleted 屏障；迟到原请求必须得到真实后端 412，原取消重入保持 Aborted |
| UNKNOWN | 实际接受 descriptor、Ready HEAD、Deleted HEAD 后分别丢响应，SDK 一次原始 POST、保存完整原意图、显式查证/重入；相同 delete operation 改 nonce 冲突 |
| 删除与名称重用 | 非 creator 的 ADMIN-only 主体按原 Creation 删除；Tombstone 后新创建得到新 Scope；旧创建返回 Deleted 和空 binding revision，旧固定 SQL 不指向新库 |
| 准入与冷恢复 | 独立目录 worker/intake 被 exact-name GET hold 时，目录返回 BACKPRESSURE，而普通 lookup/cancel 在 hold 释放前完成；杀死全部计算与四个后端、删除所有计算缓存，再从固定原意图恢复 |

目录 profile 明确使用 1 个目录 worker、1 个 intake、全局/租户/名称排队上限 4/3/2、64 KiB 正文和 10 秒绝对预算。这是可观察隔离的测试配置，不用于推断默认吞吐、公平性性能或容量 SLO。

SQL 分母为 3 个唯一请求、3 次成功重复 execute，共 6 次成功响应。原库随后删除的 2 次响应仍在分母里，恢复时逐条要求原 Scope 返回 LIFECYCLE；另 4 次要求恢复完整原 receipt、随机原始结果和 BLOB 字节。3 次目录 UNKNOWN 单独记录，不改写成确定失败或新的成功尝试。

`catalogue_oracle.py` 不导入 controller，从固定计划、原意图、全部 HTTP、客户端 ACK 和内核进程事实独立重算。它核对每个对象请求的原 HTTP 时间区间和名称/Scope/来源引用，取消前的原 HEAD 条件、真正来自后端的 412、UNKNOWN 的实际 200 后丢响应、独立 capacity 时间区间，以及每次原 SQL 的 SCAPOBJ2 Result 和发布 HEAD。已删除响应单独归类，不从分母消失。审计负对照包含错路径/租户/世代、越过原调用区间、把只读 proof 读取伪造成写入、错误阶段/nullable DTO、丢失或篡改 HTTP 结果、错误进程 incarnation/非内核退出来源/提前替代进程等。

本服务合同按已保存的精确名称/原操作恢复，**不是全目录枚举**。目录 core 的逐发布切点、外来身份占用、Proof 和 Binding 所有交错由独立 object-network 合同覆盖；这里的最终查询和公开进度不代替那个故障矩阵。新增代码在冻结、Rust/SDK 精确单元覆盖和两套真实服务实验完成前都应标记 NOT_RUN，不能借用先前 HEAD v2 或旧 probe 的结果。

这些小库本机合同不证明默认 10 GiB 的本次重验、跨 AZ、AWS Standard、hard RSS、公平调度性能或生产 SLO。GiB 验收使用独立 [object-capacity](../object-capacity/README.md)；完整目录恢复、自动路由、GC/PITR 仍有单独门禁。
