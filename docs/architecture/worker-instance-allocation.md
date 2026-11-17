# 计算实例身份的持久自动分配

状态：在[永久启动占用](worker-instance-claim.md)之上的独立实现候选。
显式 ID 的 JSON 配置继续兼容；HEAD、owner plan、SQL 请求身份、Node wire 格式均不改变。
实际验证结果须绑定冻结源码，本设计不等于 AWS、IAM 或生产上线资格结论。

## 1. 使用方式与初始化

正常部署配置使用 `"worker_instance": "auto"`。每次进程启动通过同一数据库对象权威
分配新 ID；重启、Pod 漂移和新副本不需要修改配置文件，也不依赖本地持久状态。
原有 `"worker_instance": "5001"` 仍表示显式选择 5001，必须是未使用过的 ID。
JSON 数字、空白、前导零、负号、大小写变体和未知字段仍拒绝。

每个 authority bucket 先执行一次明确的管理命令：

```bash
scapd --init-worker-allocator /absolute/scap-service.json HIGH_WATER
scapd /absolute/scap-service.json
```

初始化要求配置采用 `"auto"`，使用配置中的同一 S3 后端和凭据，不启动数据库 worker 或
HTTP listener。`HIGH_WATER` 是规范十进制 u64，包括 0；**0 只适用于可以证明没有历史身份的新
authority**。旧环境必须先停止并禁止旧程序再次启动，证明所有已发 ID 均不大于该参数。
旧 HEAD 的当前 owner、一次 LIST、Pod ordinal 或当前进程集合都不是历史发号证据。

初始化只执行 `If-None-Match: *` 创建和原 key 的 exact GET 回读，已有 counter 返回
`INSTANCE_ALLOCATOR_EXISTS`，即使正文完全相同也不收养或重置。成功记录为：

```json
{"event":"worker_allocator_initialized","high_water":"100"}
```

初始化响应不明时该命令失败关闭；运维须核对原操作和迁移前提，不能删除对象后重试。
在明确完成初始化之前，不启动 auto 副本。普通启动看不到 counter 时返回
`INSTANCE_ALLOCATOR_MISSING`，不会假定是新 bucket，也不会自动初始化或回滚到 0。

## 2. 同一权威上的两个记录

| 固定 key | 含义 | 写入规则 |
| --- | --- | --- |
| `scap-worker/v1/allocator` | 自动分配已预留至的数值；不是所有显式 ID 的完整目录 | 初始化仅条件创建；其后只用同次 GET 的 ETag 条件递增 |
| `scap-worker/v1/instances/{ID}` | 某个数值已经被一次启动永久占用 | 保持原条件创建和完整正文/ETag 回读；不可覆盖、删除或释放 |

counter 正文为 ASCII `SCAP-WORKER-ALLOCATOR-v1`、一个 NUL 字节、big-endian u64。
长度和 magic 精确检查，ETag 必须存在。其 scope 是整个 bucket，与永久 marker 相同；
不把 endpoint 别名、凭据、deployment、tenant、缓存目录或机器名称放入可变命名空间。
所有对象 I/O 使用与数据库相同的 `Objects` 实例；没有 LIST 或额外协调后端。

不同 authority bucket 可独立分配相同数值。数据库从一个 bucket 迁往另一个 bucket 时，
必须另行证明迁移、所有权和身份历史，不能复制数据库后用空 counter/registry 重用旧身份。

## 3. 自动启动状态机

在所有本地配置、预算、缓存目录和 capability 检查完成后，从 `Options.operation_timeout`
生成一个绝对 deadline。分配和永久登记始终使用这一个期限；单次请求继续受 S3 timeout 限制。

1. exact GET counter，同时取得原始正文和 ETag。缺失、损坏、不确定读取立即拒绝。
2. 计算 `candidate = high_water + 1`，用 checked arithmetic；超出 u64 时拒绝，永不回绕。
3. 仅一次 `If-Match: 原 ETag` PUT 新 counter。明确成功的 ACK 预留 candidate；响应丢失、
   timeout、空 ETag 或超过原期限均立即返回 UNKNOWN，不再查询、换 ETag 或尝试其他候选。
4. 使用原永久登记协议条件创建 candidate 的 marker，再 exact GET 验证正文和 ETag。
   只有成功才把最终数值交给 Engine、catalogue 和 discovery。
5. **只有明确的 CAS 冲突，或明确已存在的 marker**，才可以读取新 counter 并选择另一个候选。
   新候选必须严格大于本次启动的前一候选；没有前进返回 BUSY，倒退返回 CORRUPT。
   绝不拿新 ETag 重发同一个候选。

最多尝试 16 个候选、最多 64 次产品对象请求，并始终受同一总期限约束。16 次额度耗尽返回
BUSY；不会无限自旋、等待 lease、重放 SQL 或把不确定结果按竞争处理。调用方可以启动新的
进程尝试，由新的 exact GET 和新的候选开始；不是继续原不确定操作。

counter 是可变对象。一次成功 CAS 后，其他分配器可能已经继续推进它，所以不要求把 counter
回读成恰好自己的值；成功 CAS ACK 是该预留的排序点。**必须 exact GET 回读的是随后创建的
不可变 marker。** marker 仍是最终防复用屏障，不能只凭 counter 较大就宣称身份已经归自己。

## 4. 失败、并发与耗尽

| 结果 | 稳定错误或行为 |
| --- | --- |
| 正常 auto 启动缺 counter | `INSTANCE_ALLOCATOR_MISSING`；无创建/修复 |
| 再次初始化 | `INSTANCE_ALLOCATOR_EXISTS`；无覆盖/收养 |
| counter magic/长度/ETag 错误，或本次观察倒退 | `INSTANCE_CORRUPT` |
| counter 达到 u64::MAX | `INSTANCE_EXHAUSTED`；无写入、无回绕 |
| 16 次竞争/已占用，或新读取没有新的候选 | `INSTANCE_ALLOCATION_BUSY` |
| CAS/marker PUT 结果不明、读取不明或期限耗尽 | `INSTANCE_UNKNOWN`；当前启动终止 |
| marker 明确成功并回读一致 | 可以继续构造服务；并未获得数据库 owner |

成功 CAS 后崩溃、丢 ACK、marker 故障、codec/worker/runtime/listener 构造失败，都不会把
counter 降低。自动分配的后续启动跳过已预留数值；不回收空洞，也不删除 marker。显式调用方
继续只执行永久 marker 协议，可以与新自动进程或原 PR #61 的显式进程共存；若它抢先占用
auto 刚预留的数值，auto 会选择后一个候选，两个进程不会取得同一 marker。

counter 不会随显式 ID 自动提高到全局最大值。较大的未来显式 ID 由自己的永久 marker
保护；auto 以后遇到它时明确跳过。一段密集显式 ID 可能耗尽单次 16 候选预算，BUSY 必须保留，
不能取消限额来承诺永远一次启动成功。初始化的历史上界与后续显式混用是两个不同问题。

正常协议只写严格递增正文，不复用 counter 状态；同次 GET 的 ETag 绑定 CAS。禁止删除、
无条件覆盖和回滚是防止 counter ABA 的部署前提，IAM 无法检查正文是否数学递增。
永久 marker 是额外防线，但不能把它说成能够证明恶意管理员删除/回滚全部元数据后的安全性。

## 5. 启动可见性、Rust API 与 discovery

`assemble_identified` 返回 `Assembly { address, worker_instance, state }`，其中身份已是
最终非零数值；原 `assemble`、`assemble_with_listings`、`assemble_with_storage` tuple
入口继续可用，并经过相同登记。直接 Rust 配置改用 `WorkerInstance::Explicit(u64)` 或
`WorkerInstance::Auto`，这是编译期 API 变更；JSON 显式数值形式保持兼容。

真实 daemon 构造成功后输出非秘密 JSON stderr 记录 `worker_identity_claimed`；listener
成功绑定后才输出 `worker_identity_ready`，两者都包含规范十进制 `worker_instance`。
只有 claimed 记录可能随后以 LISTEN/RUNTIME 失败退出；没有 ready 不能解释为已经监听。
healthz 仍然只表示 liveness，不增加 S3、数据库可用性或 owner 权限承诺。

分配和 ready 记录不会改写现有静态 `OwnerController` 或 route registry。相同地址上的新
进程取得新 ID 后，仍带旧 `expected_worker_instance` 的请求返回 `TARGET_MISMATCH`；部署
控制器必须消费新的实例登记并更新目标期望。数据库原 owner 也保持不变，后续仍需按当前
HEAD 和持久 owner 计划完成明确交接。此候选提供可自动重启的身份分配，不实现动态 fleet
登记、路由刷新或数据库自动接管。

discovery 的 master key 格式和 namespace 在分配前验证；auto 使用 `PreparedDiscovery::Automatic`
保留准备材料，拿到最终数值后调用原 `CursorCodec::new`。原每次启动随机盐、HKDF 绑定、
递增 nonce 及 cursor 不跨进程恢复的规则均不变。显式模式的预构造 codec 继续使用
`PreparedDiscovery::Ready`；两种选择与 worker mode 不匹配时在任何对象 I/O 前拒绝。

## 6. IAM、GC、部署与恢复

普通 runtime 需要 counter 的 `GetObject`、带 If-Match 的 `PutObject`，以及原 marker prefix
的 `GetObject`、带 `If-None-Match: *` 的 `PutObject`。初始化身份另需 counter 的条件创建权限。
可用同一配置指向权限更高的初始化凭据完成一次管理命令，再部署仅允许 CAS 的 runtime 凭据；
两者必须绑定同一 bucket。代码不读取或修改 IAM。

| 资源 | 运行角色 | 初始化角色 | 必须拒绝 |
| --- | --- | --- | --- |
| `arn:aws:s3:::BUCKET/scap-worker/v1/allocator` | GET、If-Match PUT | GET、If-None-Match PUT | 无条件 PUT、DELETE、DeleteObjectVersion、删除后重建/回滚 |
| `arn:aws:s3:::BUCKET/scap-worker/v1/instances/*` | GET、If-None-Match PUT | 初始化命令不需要 marker 权限 | If-Match 覆盖、无条件 PUT、删除/生命周期过期 |

两类 key 都不在 payload GC 白名单内。bucket 生命周期、备份和恢复必须保留 counter 及
全部 marker；仅保留数据库 HEAD/objects 的备份不满足身份恢复合同。自动化不得把
`--init-worker-allocator` 放入每次 Pod 启动的 init container；已有 counter 冲突是管理错误，
普通缺 counter 也不是让自动化删除后重建的信号。

AWS 的条件写和 IAM 条件键说明见[条件写](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)、
[强制条件写政策](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes-enforce.html)。
本地签名 SeaweedFS、单位 HTTP fixture 和进程测试不替代目标 AWS/IAM 的实际验收。
