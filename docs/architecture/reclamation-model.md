# N3.2：物理世代与 pin 的有界交错模型

状态：独立有限模型已实现，源码及固定程序在
[`experiments/object-reclamation-model/`](../../experiments/object-reclamation-model/README.md)。
完整门禁分别运行 unit、全部 BFS、独立原始图 oracle 和反例控制。本文不表示 HEAD 5、产品 pin、GC、DELETE、PITR 或
物理成本收敛已交付。当前生产格式仍为 HEAD 4；已完成的 `ObjectContext` 改造
只冻结一次操作使用的对象命名空间、backend 与 quarantine 身份。

本批新增 `experiments/object-reclamation-model/` 和本说明，并把门禁接入 CI 与
`dev/environment/validate.sh`。模型不导入生产
Rust/SDK，不操作真实 bucket，不给普通 SQL 服务增加 DELETE 能力。目标是先把
[持续存储方案](storage-reclamation-plan.md) 中的安全约束变成可以穷举、重放与
独立否定的有限状态机，再决定生产 HEAD 5 的最小格式和准入协议。

## 1. 要验证的边界

模型把业务根、保留结果与索引表示为一个固定的有限内容图。对象的内容身份不可变；
物理位置是 `(logical_scope, storage_generation, content_hash)`。完整闭包包括
当前数据树、保留请求索引与原 Result 对象，而不是只复制最新 manifest。
`StoredResult.data_root` 是原回执身份，不自动成为历史数据闭包的边；显式 PITR
保留根须另外设计。模型没有假设
不同物理世代可以重新解释为同一位置。

拟议 HEAD 字段与现有实现的对应关系如下。它们是模型字段，不是已经上线的 wire
字段；实际 codec、256 KiB HEAD 上界和兼容策略须在生产切片中另行冻结。

| 模型字段 | 含义及后续映射 |
| --- | --- |
| `head_serial` | 每次成功 HEAD CAS 严格递增，包括 pin、freeze、seal、promote、abort；达到上界即拒绝，不能回绕 |
| `revision`、`transition` | 业务或管理操作的版本与原身份；技术变更保持它们不变，现有 expected revision + 1 语义继续成立 |
| `active_generation=A` | 当前全部数据、索引和结果使用的物理世代；区别于完整逻辑 `Scope.generation` |
| `allocated_through=M` | 已经分配过的最大物理世代；只分配 `M+1`，放弃也不退回计数 |
| `staging_generation=T` | 至多一个正在复制、尚未公开的目标；与 A 一同排除删除 |
| `pins` | 有界 durable pin 表，固定完整 Scope、worker、process incarnation、broker identity、acquisition nonce 与 generation；本批没有租约到期或强制撤销 |
| `freeze` | 单一计划身份、源/目标世代、冻结的完整根集合、复制/封存阶段；它不是当前的 Maintenance 状态 |
| `acl`、`owner`、`quota`、`lifecycle` | 与 pin、世代变更在同一 HEAD 条件序列中排序；Promote 保留当时的有效 ACL |

`GcS3` 已限制的物理 payload 前缀为：

```text
scap-object/v1/{deployment}/{tenant}/{database}/inc/{incarnation}/gen/{generation}/storage/{storage_generation}/objects/
```

模型沿用这个空间划分。HEAD、Catalogue、永久 tombstone 不属于可删除对象集。
逻辑 Scope 不因一次物理复制而改变，未发布的旧候选也不能借新 generation 继续。

## 2. pin 取得与原写候选的封存顺序

不能把 PinAdd 塞进已经选定业务 `Snapshot` 的 `ObjectContext::capture`：PinAdd
本身修改 HEAD，会立即使该候选的原 ETag 失效。模型使用明确的先后关系：

1. exact GET HEAD，校验完整 Scope、当前权限、生命周期和准入状态。
2. 通过原 ETag 执行仅操作元数据的 PinAdd CAS。此路径不得先下载数据 manifest；
   当前普通 `Database::publish` 的 manifest GET 因此不能原封不动复用于 PinAdd。
3. PinAdd 成功后重新 exact GET HEAD。Snapshot 的 body/ETag 必须来自这同一次 GET，
   不能由本地候选 body 加 PUT 返回的 ETag 合成。
4. 再次确认自己的 pin、generation、当前 ACL、owner 与冻结状态，然后封存
   `AttemptContext { original_snapshot, object_context, original_request, deadline }`。
5. 后续 immutable I/O 固定在该 context，最终 HEAD 发布只使用封存时的原 ETag。
   任意技术 CAS 或业务 CAS 使其失败时，都不能换 ETag、换 generation 或重放 SQL。

第 2 步和第 3 步之间允许另一写者、权限更新或协调操作进入。Pin 保护整个物理
世代，不代表读权限仍然有效，也不代表业务快照仍然相同。第二次 GET 不满足准入
条件时，只能结束本次准入并处理自己的 pin，不能直接采用更晚的 Snapshot 继续
已经执行过的 SQL。

Pin 身份不能只使用“准备提交的下一个 serial”：两个竞争但尚未接受的 PinAdd
可以同时提出同一个 serial。同一个 process 中的两个独立 broker 也不能共用一个
仅有 worker/process 的 token。UNKNOWN 之后的检查必须匹配完整 holder、broker、
acquisition nonce、Scope 和 generation，不能把另一个 holder 的成功 pin 认作自己的保护。

UNKNOWN PinAdd 后若 exact GET 仍看到原 serial 且 pin 不存在，原 CAS 可能还在
途中，此时只能记为 `pending_absent`。只有观察到更大 serial 且自己的完整 token
不存在，或关闭本地 gate、排空 guards 后完成一次元数据 fence/Release CAS，才能
确定原 Add 不会再生效。一次“没找到”不是完整清理证明。

本批模型先使用有界 holder/guard。后续 production broker 可在进程、完整 Scope
和 generation 相同的前提下合并 pin，但必须原子关闭本地 admission gate 并排空
所有实际 guard，再释放 durable pin。HTTP 超时、取消、线程暂停和进程崩溃都不
证明 guard 已经排空；暂停或失联 holder 的 pin 保持存在，回收报告 `GC_BLOCKED`。

PinRelease 使用新的 exact HEAD 与原条件 CAS，只删除指定的自己的 pin，同时
保留此时的 ACL、lifecycle、owner、roots 和其它 pins。不能把 PinAdd 时保存的
HEAD 整体写回。即使数据已 quarantine 或生命周期为 Deleted，原 holder 仍可
执行这种窄范围清理；它不恢复 READ 权限、不授予新 guard、不读取 immutable
对象，也不能被普通 `healthy()` 或 `publish` 的 manifest GET 挡住。

已放弃的候选没有再次**发起**发布的权限。已经发到后端但结果不明的 immutable
PUT 可在后来落地，仍只能写它原先捕获的 generation。已经发出的 HEAD CAS 也
必须单独保留为未决 token：本地 native abort 不会撤回网络请求。它若先于
PinRelease 成功，可以成为当前 durable HEAD；若 PinRelease/Freeze 已先成功，
它只能按原 ETag 得到冲突。调用方已经超时仍为 UNKNOWN，不能事后伪造原 ACK。

## 3. 首版较保守的冻结准入

为了先建立可审查的闭合协议，本模型首版要求 durable pins 为空才开始 Freeze，
并在冻结期间拒绝新的 PinAdd 和需要远端数据的准入。Status 与已经完整物化的本地
暖查询不读取远端 immutable 对象，可继续使用现有 fresh HEAD 权限检查。

这比总方案中允许短暂 control lookup 的可用性设计更窄。模型不会把 lookup、
冷恢复在 Freeze 期间成功算作目标，也不把这个选择隐写成“GC 没有停顿”。后续
放开读准入，必须另行验证 Seal 前的关闭 gate 和 drain。

Freeze 一次性固定源根与新目标 `M+1`。复制、Seal、Promote 均携带同一个计划
身份；放弃 T 后，T 永久属于已退休集合，下一次只能分配更大的世代。冻结期间：

- SQL/root 变化、quota、takeover 被阻断，必须先显式 Abort。逻辑 Delete 可在
  同一次 HEAD CAS 内先放弃 T 再置为 Deleted，保留 M/A/pins、当前 ACL 和根。
  旧复制 token 只能留下 orphan；原 Promote 不能复活 Deleted 或恢复旧 owner。
- ACL 更新可以继续按当前 HEAD CAS 排序；复制计划不因此获得恢复旧 ACL 的权限。
- Seal 必须确认目标的完整闭包；Promote 在新的 exact HEAD 上确认同一计划、
  源根和目标，保留最新 ACL，才原子选择 T。
- 复制保留原始 frame bytes/hash；重新编码语义相同的 JSON 也不能冒充原对象。
  每次捕获新计划都清空旧复制/验证缓存。GET 的原 Scope、plan id、source、target、
  roots、key 与 raw hash 必须与当前捕获计划一致；迟到的旧验证响应不能补入新 T。
- `Provisioning` 和 `Deleted` 不允许 PinAdd 或新的 GC 技术变更。逻辑 Delete
  保留已有 pins，不因一个暂停 reader 而永久阻止逻辑删除或新 Scope 的名称复用；
  Deleted 中只允许原 holder 的窄范围 PinRelease。已有 pin 没有被撤销，也不
  代表此时允许新读取。
- **Deleted 的最后一个 active generation 的物理回收不在首版范围内。** 本模型
  不允许为了清空它而放开 Deleted 的 GC 准入，也不把逻辑删除说成已释放全部 payload。
- Named Provisioning 的原始 revision 1 → 2 完成协议单独保留；技术操作不能
  在它之前穿插并改变隐含的初始版本条件。

## 4. 迟到 I/O、清扫计划与 UNKNOWN

模型把已发送的 GET、CreateOnly PUT、带原 ETag 的 DELETE 和 HEAD CAS 表示为
有界不可变 token。网络可以任意延迟、先应用后丢失响应，或先返回调用方 UNKNOWN
再落地。token 的 key、generation、完整候选 body、原条件和身份不能随当前 HEAD
改写；“已放弃本地操作”和“远端请求被撤回”是不同事实。

退休资格是 `1..=M` 去掉 A/T，并满足 pin 保护约束。它描述永久不可重新激活的
名字空间，不等于该空间此刻没有对象。只要 generation 永不复用，旧 DELETE
即使在新世代已经公开之后执行，也不能命中新数据；旧 PUT 重新创建的对象只能
成为已退休世代的 orphan。

一个清扫计划与 cursor 必须绑定完整 Scope、目标世代和原计划身份；恢复时重新
检查该目标仍是退休空间。旧 cursor 不能移到新计划或新 generation。LIST 只
列出候选；DELETE 仍须 exact GET 候选、固定原 ETag，并重新核实删除权限。

一轮 empty scan 只证明那次观察为空。迟到 PUT 可以在该观察后出现。因此模型
从不产生“永久为空”或“空间已经永久收敛”的成功标志。DELETE 的 UNKNOWN 也
不能变成 Applied、Missing 或明确未应用；它只保留原 token 供后续显式查证。

## 5. 穷举与独立验收方式

采用 26 个明确命名的有限 actor 程序集合，分别提供 reader、writer、GC coordinator、
ACL/lifecycle 管理及不确定网络的操作序列。BFS 枚举这些固定程序所有可执行的
交错与网络选择，状态包含 HEAD、pins、本地 guard、封存候选、物理对象集合、
未决 token、计划/cursor 和各 actor 的程序位置。状态采用不可变值和规范序列化，
不依赖 Python 对象身份或 wall clock。

边界已写入并哈希冻结在 `inputs.json`：每个 profile 的 actor 数与 629 条总指令、
pin/guard/token 槽、8 个对象的 raw bytes/内容图、世代和序号上界、
操作程序、网络结果集合，以及独立的执行资源上限。真正的证明边界是所列程序和
有限状态空间；不能把这些有限交错的穷举说成无限运行或任意工作负载的证明。

只有 BFS 队列完全耗尽才报告该 profile `complete=true`。达到状态数、边数、时间
或外部内存限制都报告 `INCOMPLETE`，保留已产生记录并失败退出，不裁掉剩余状态
后声称完成。实际 visited/edge/terminal 数由原始记录重算，独立 oracle 验证所有
状态可达且每个状态的 enabled action 集合恰好等于记录的后继集合。

独立 oracle 不导入模型的 reducer 或生产代码。它读取原始状态、动作和结果，
校验每次动作的权限、原观察身份、delta、对象效应及不变量；同时核对程序前沿、
每个状态的全部后继及完整遍历声明。所有原始输入、状态、边和反例 trace 都保留
hash。producer 的汇总、计数或 `passed` 不构成通过依据。

必须具备的 mutation counterexamples 包括：

| 不正确变更 | 独立检查必须拒绝的事实 |
| --- | --- |
| PinAdd/Release 不递增技术 serial | 同内容 HEAD/ETag ABA 让旧业务候选重新有效 |
| Abort 后按 A+1 再分配 | 旧 PUT/DELETE 的目标被重新当作 staging/active |
| 先读 HEAD，晚些时候不登记 pin 就 GET | 未保护的旧世代对象读取越过 GC |
| TTL/时钟强制释放 paused pin | 尚有 guard 的闭包被删除 |
| 给旧候选换新 ETag/generation | 原 SQL 身份和原发布尝试被重新解释 |
| Promote 恢复 Freeze 时的 ACL | 已生效的撤销被物理迁移覆盖 |
| 未复制全部依赖就 Seal/Promote | 新 active 根缺失闭包 |
| DELETE active、staging、HEAD 或 Catalogue | GC 能力越过已经证明的退休空间 |
| 旧 DELETE 随当前 generation 改写 key | 新公开数据被旧请求命中 |
| Provisioning 上插入技术操作 | Named revision 1 → 2 的初始条件被破坏 |
| empty scan 声称永久不存在 | 迟到旧 PUT 使“完成”结论失真 |
| 旧计划/cursor 被新计划复用 | 清扫前沿与被授权退休集合不一致 |
| UNKNOWN DELETE 被宣称未应用 | 客户端知识超出原响应证据 |
| T2 验证缓存或迟到回复被 T3 采用 | 新计划根本没有完成目标复制 |
| native publication 失败仍给 SQL ACK | 已提交权威被错误表示为业务成功或回滚 |
| reader 未物化、已结束或 caller 已离开仍返回成功 | API 出口消费了未受保护或未经完整观察的数据 |

### 5.1 reader 与 native 出口的最小抽象

Reader 必须在实际 guard 仍存活时，从原 GET 已观察的完整 raw frames 构造物化结果，
绑定原授权 Snapshot 和捕获世代。之后可以结束 guard、Release pin；即使 GC 随后
删光旧世代，return 只能消费已物化字节。实际 worker 结束以后才来的 GET 不再补充
结果。caller 已停止等待时，return 记为 `WITHHELD`。并发 ACL 变化不引入额外的
“出口再读最新 ACL”语义；原操作继续遵守 fresh HEAD 准入的线性化合同。

Writer 在原 HEAD CAS 已知成功后还要执行显式 `native_publish`，模型分别枚举
commit/fail。成功才允许 SQL ACK；失败保留原提交 reference，并记为
`COMMITTED_BUT_UNAVAILABLE`，不撤回 HEAD、不重新执行 SQL。UNKNOWN 的原 CAS
仍可后来生效，但不能凭后端事实补造原调用的 ACK。这里是 native 结果的抽象分支，
没有执行 SQLite C engine；真实 native 崩溃、恢复与结果 codec 继续使用单独的实际合同。

### 5.2 时间与其它明确排除项

`caller_timeout` 只表示 caller 已离开/不再等待，不表示 native worker 或其独立
operation deadline 已经结束；`ticks` 仅用于证明时钟推进不能撤销 pin。后台继续
推进是存储安全检查的保守范围。**absolute deadline 的时间行为为 `NOT_MODELED`**，
不能从本图推断 timeout 后禁止新 dispatch。SDK 的绝对 deadline、实际 TCP/HTTP、
真实 S3 与 SQLite 行为由其它门禁验证。

模型固定一个完整逻辑 Scope，网络 key 使用该固定 Scope 下的原物理 generation
和内容 hash，诊断用对象名称不参与存储寻址。跨 Scope/PITR、versioned bucket、
Object Lock、实际 IAM、分布式时钟、真实 LIST 分页与 checkpoint 网络 UNKNOWN 不在
本批模型范围。Checkpoint 在模型中是有界、原版本比较的原子持久记录；它不是已完成的
产品 wire 格式。部分 profile 从明确合法的 pinned、Copying 或 retired 状态开始，
并不声称从任意损坏状态自动恢复。

## 6. 安全、阻塞与成本活性分别报告

安全报告检查可达与受 pin 保护的完整闭包、原候选 fencing、永久退休和条件删除
边界。阻塞报告记录暂停/崩溃 pin、准入冻结、耗尽序号/槽等造成的合法停止。

成本活性只在额外条件下讨论：旧请求总量有限，所有已发 PUT 最终结束，holder
最终实际退出并显式释放，存储持续可用，重复 sweep 公平覆盖所有退休 key，保留
集合与数据库身份集合有界。即使这些条件成立，最后一批当前世代 orphan 仍需要
最后一次迁移。无条件无限暂停或无限迟到请求下不承诺物理收敛。

本批之后仍需生产 HEAD 5 codec/最坏字节预算、broker guard/refcount、完整对象
路径切换、持久回收计划、真实暂停 PUT/DELETE/GET 与进程退出合同、backend 权限
隔离、AWS 条件删除与版本配置验收，以及保留快照/PITR 的独立模型和实现。
