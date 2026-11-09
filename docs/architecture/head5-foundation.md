# HEAD5：技术序号与物理世代基础

这一步把有限回收模型中的两个前置条件落实到生产代码：每次 HEAD 替换都有严格递增的
`head_serial`，每次不可变对象操作都捕获独立的物理 `storage_generation`。它还提供一个
私有、只执行元数据条件替换的 `PreparedHead`，供后续保护协议使用。

这一步没有实现 durable pin、freeze/copy/seal/promote/sweep、物理 DELETE 或 PITR。
HEAD5 当前只接受物理世代 `1/1`；只要相应的 I/O admission 尚未完成，就拒绝其他世代、
pins、staging 和 freeze 字段。不能把格式基础或有限模型通过称为 N3 已完成。

## 1. 精确格式与身份

HEAD 仍是严格 JSON，沿用原有字段与上限，增加以下必填字段：

```json
{
  "format": 5,
  "head_serial": 1,
  "storage": {
    "active_generation": 1,
    "allocated_through": 1
  }
}
```

上面只是新增字段片段，不是完整 HEAD。实现位于
[`crates/scap-object/src/format.rs`](../../crates/scap-object/src/format.rs)。

| 字段 | 本批严格约束 | 含义 |
| --- | --- | --- |
| `format` | 必须为整数 `5` | HEAD 的格式版本 |
| `head_serial` | 非零 `u64`，且 `head_serial >= revision` | 每次成功条件替换的技术序号 |
| `revision` | 既有非零 `u64` 业务序号 | SQL、所有权、ACL、配额和生命周期转换 |
| `transition.revision` | 仍严格等于 `revision` | 业务转换与原始请求的身份 |
| `storage.active_generation` | 只能为整数 `1` | 本次 HEAD 引用的物理对象命名空间 |
| `storage.allocated_through` | 只能为整数 `1` | 已分配物理世代的上界；后续协议将单调推进 |

新字段不能省略，不能以 `null`、字符串、浮点数或布尔值替代。HEAD 与 `storage` 都拒绝
未知字段和重复字段。`0/0`、`1/2`、`2/2` 等世代组合全部拒绝；没有通过“暂时忽略”未知
状态来承诺未来兼容。`head_serial` 超出 `u64` 范围也会拒绝，绝不截断或回绕。

`Scope.generation` 继续属于数据库的逻辑身份，与物理 `active_generation` 不相同。
所有权、ACL、结果保留、命名创建/删除屏障仍共享同一个永久 HEAD slot。

| 对象 | 物理 key |
| --- | --- |
| HEAD | `scap-object/v1/{deployment}/{tenant}/{database}/head` |
| 不可变对象 | `scap-object/v1/{deployment}/{tenant}/{database}/inc/{incarnation}/gen/{logical_generation}/storage/{storage_generation}/objects/{hash}` |
| Catalogue | 沿用现有 `catalogue/v1/...` key，与物理世代分离 |

不可变对象的 `SCAPOBJ2` frame、逻辑 Scope、内容字节与 SHA-256 规则不变。物理世代只进入
key，不进入 frame；同一份原始 frame 可以在不同物理世代下拥有相同内容哈希。这为后续
按原始字节复制闭包保留了条件，但本批不提供复制或提升入口。

## 2. 序号推进与业务兼容

初次创建使用 `revision = 1`、`head_serial = 1` 和 `storage = 1/1`，通过 `If-None-Match: *`
创建永久 HEAD。`create_head` 还校验候选的完整 Scope 与目标数据库一致，拒绝把后续序号
伪装为初次创建。没有 HEAD 的命名 AbortFence 同样创建 `1/1` 的永久删除屏障。

所有既有业务替换由 `Database::next` 对两个序号分别执行 `checked_add(1)`。任一序号
耗尽都返回 `Error::Limit`，不发布新 HEAD。不能用饱和加法、回绕或更换原始 ETag 绕过
耗尽状态。

命名创建中的 `Provisioning → Ready` 和已有 Provisioning HEAD 的 AbortFence 原先直接
填写业务 revision 2；现在也使用相同的序号构造器。它们的业务结果仍为 revision 2，
对应技术序号为原 `head_serial + 1`。命名 Delete、普通 SQL、cancel、takeover、activate、
ACL、quota、lifecycle 和窗口关闭均遵循同样规则。

公共 service status、receipt 和 Node SDK 的业务接口保持现有含义：`expected_revision`
仍比较业务 revision，成功转换的 `transition.revision` 仍是原值加一。技术序号不混入
请求 ID、transition nonce、owner epoch 或命名删除的 expected revision。

技术序号与业务序号分离意味着，未来只改元数据的技术转换可以保留业务标记。每个这种
转换仍会改变 HEAD 原始字节；即使添加与释放某项保护后其他字段恢复原样，内容型 ETag
也不会因为 HEAD body 完全相同而出现 ABA。旧 SQL 候选仍携带旧 ETag，一次失败后不会
改用最新 ETag 重放。

本批没有公开的“技术序号加一”操作。单元测试通过私有边界构造这种转换，以验证序号
分离和原始 CAS 的防护；这些测试不代表 pin admission 已经存在。

## 3. 一次操作捕获一个物理命名空间

[`ObjectContext`](../../crates/scap-object/src/object_context.rs) 同时持有后端 Arc、完整
逻辑 Scope、物理 `storage_generation` 与共享隔离状态。

- 观察到 HEAD 的路径，从该次已校验且已授权的 HEAD 捕获 `storage.active_generation`。
- 显式创建的 bootstrap 路径固定捕获 `INITIAL_STORAGE_GENERATION = 1`。
- `load`、`save`、条件创建后的 exact read-back 全部使用捕获的 generation 构造 key。
- 数据树、请求索引、结果读取与冷恢复不会在中途重新读取可变的当前 generation。

原始 `Snapshot`、ObjectContext、request 与 deadline 继续属于同一个 `AttemptContext`。
捕获过程本身不做 HEAD GET，不延长 deadline，也不构造新的授权。更改源变量或丢弃源
Database 后，已捕获的对象操作仍使用原命名空间和原后端。

这只是命名空间固定性，没有提供远端存活保护。后续普通操作选择验证可中止的世代
方案，不默认执行持久 PinAdd/Release：完整物化的原始授权读可返回；尚未完成的旧读
遇到对象失败，只有新的同 Scope 权威证明该世代永久退休后才能返回 SnapshotExpired。
当前、复制目标或 retained hold 保护的世代损坏仍必须拒绝；无法取得权威时不能伪造
退休结论。原 SQL AttemptContext 始终保留原 ETag，不因技术转换重新封存或重放。

上述方案仍在独立模型中验证，并未由本基础切片实现。显式保留根与当前复制计划各自
需要持久保护，不能把普通操作的可中止生命周期套到它们上面。不可撤销 pin 的保守
模型保留为独立替代方案；其崩溃 pin 可永久阻塞准入和回收，不能直接作为默认下一步。

## 4. 私有元数据条件发布

[`PreparedHead`](../../crates/scap-object/src/head_publication.rs) 的字段不可由调用方
修改。内部构造器接收原 `Snapshot`、候选 HEAD 与原 deadline，校验后捕获：

- 原始后端 Arc 与永久 HEAD key；
- 原始非空 ETag；
- 完整校验、编码后的候选 bytes；
- 原始 deadline。

构造器要求原 Snapshot 的 Scope 与 Database 一致，候选 Scope、storage 与原 Snapshot
一致，并要求 `next.head_serial == base.head_serial.checked_add(1)`。它不会在调用方忘记
推进序号时替调用方修正候选，也不会接受跳号。候选还必须通过完整 HEAD5 格式校验。

`publish(self)` 消费候选，只执行一次 `If-Match: original_etag` PUT。它不做 HEAD GET、
manifest GET、健康状态判断、重试或重绑定。返回值只表示该次原始调用的结果，永远不是
可继续执行业务的 Snapshot；需要新 Snapshot 的调用方必须重新 exact GET。

| 后端结果 | 私有发布结果 | 允许的推断 |
| --- | --- | --- |
| 成功 | `Ok(())` | 原候选被后端接受 |
| 条件冲突 | `Error::Conflict` | 原条件没有匹配；不重新绑定 |
| 不确定 | `Error::Store(StoreError::Unknown)` | 可能已生效，也可能未生效 |
| 其他存储错误 | 保留原 `StoreError` | 不能据此制造成功或新 Snapshot |

元数据 primitive 不提供任何新权限，也不证明闭包完整性。普通业务 `publish_in` 先准备
不可变候选，再保留原有的 manifest、quota 和两次健康状态检查，最后消费该候选。
因此抽取 primitive 不会让普通业务绕过损坏隔离。

primitive 不调用 `healthy()`，但每个未来技术转换仍须在自己的窄权限边界证明用途。
例如回收 checkpoint 的记录、确认和清理，不能顺带获得 READ、重建旧 ACL 或恢复旧
生命周期。保守 pin 替代方案中的 Release 还需要本地 gate 关闭和实际 guard 清空证明。
本批没有提供这些技术操作、durable pin 或 Release API，不能直接暴露该 primitive。

## 5. 格式边界与验证

HEAD4 会被 HEAD5 decoder 拒绝，不自动迁移、回退或建空库。HEAD key 不变，因此旧永久
HEAD 或 tombstone 也不能被一次新条件创建绕过。验收使用全新的隔离 fixture scope；不能
把既有 HEAD4 证据重新解释为 HEAD5 已通过。

`MAX_HEAD_BYTES = 256 KiB` 与 `MAX_PRINCIPALS = 1024` 不变。独立计算的最大字段宽度
HEAD5 witness 为 **79,621 bytes**，距离 HEAD 上限仍有 **182,523 bytes**。该 witness
包括 1024 个不同的 20 位 principal、3 个最大计数窗口、完整命名创建/删除标记，以及
最大合法整数宽度。它是格式可编码的边界，不是声称实际业务能够到达的完整历史。

对应单元检查位于：

- [`format_tests.rs`](../../crates/scap-object/src/format_tests.rs)：必填字段、严格类型、
  旧格式、未知技术状态、技术/业务序号关系和确切最大编码长度；
- [`head_publication_tests.rs`](../../crates/scap-object/src/head_publication_tests.rs)：
  无对象读取的元数据 CAS、捕获后不可重绑定、内容型 ETag 的 ABA、原 deadline、
  UNKNOWN 的两种实际后端结果和初次创建约束；
- [`object_context_tests.rs`](../../crates/scap-object/src/object_context_tests.rs)：
  物理命名空间与原后端固定，原始 frame 和哈希不变；
- [`tests.rs`](../../crates/scap-object/src/tests.rs) 与 Catalogue 边界测试：全部业务
  构造器的 serial 推进、耗尽不发布，以及命名屏障继续使用业务 revision。

发布前仍需要本候选自身的完整 unit/四维覆盖，以及更新后的独立真实 HTTP/S3、native
publication、进程退出与冷恢复验收。有限模型证明、抽象 native 成败转换、已有 HEAD4
真实结果与这些生产验收各有边界，不能互相替代。

## 6. 后续生产切片

先交付借用原始 frame 的完整闭包游标：校验当前数据树、全部保留请求窗口及原始结果，
保持固定 Snapshot、物理世代和绝对 deadline；私有续步不能成为新的发布或删除授权。
随后完成独立可中止世代模型及其反例，再实现普通操作的本地停止边界、精确退休证明、
按世代隔离的失败语义，以及 Provisioning 和迟到复制响应的处理。所有不可变 I/O
admission 都满足这些条件后，才能接受更多 HEAD storage 状态。

回收阶段再落实不可复用的世代分配、原 ETag Freeze、当前计划及 retained root 的持久
保护、按原始字节复制完整闭包、带完整 plan 身份的验证和 Promote。条件 DELETE 必须
晚于对原始有界 key/ETag 批次的持久记录及 exact HEAD 观察，只能作用于永久退休世代。
异步旧 PUT、旧 HEAD CAS 与 DELETE 仍可能晚到；原始 key/ETag 不会因调用结束而撤回。

普通操作不写永久 pin 的选择避免了崩溃 pin 耗尽准入这一阻塞来源；它本身不证明 GC
可用性或成本收敛。Deleted 最后一个 active generation、checkpoint transport UNKNOWN、
跨 authority 的快照/PITR、真实 AWS 与长期运行仍须分别实现和验收。当前仍只允许
storage 1/1，产品 GC 关闭。最新状态见[实施记录](../engineering/status-2026-11-09.md)。
