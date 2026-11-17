# 计算实例身份的永久启动占用

状态：独立实现候选；不改变 HEAD、owner plan 或 Node wire 格式。实际验证结果单独记录，
本设计不是 AWS、自动故障切换或生产上线的验收结论。

## 1. 要解决的错误

`worker_instance` 标识一次计算进程启动，不是机器、Pod、端口或 StatefulSet ordinal。
旧实现只要求部署者提供不复用的非零 u64。两个进程误用同一数值时，
`expected_worker_instance` 不能区分它们，HEAD 的 `owner_instance` 比较也无法识别
它们属于不同启动。只增加随机数生成或本地文件锁不能证明不同主机永不误用同一身份。

本实现保留显式配置数值，增加对象存储中的一次性占用。它是防止误复用的永久登记，
不是自动编号分配器，也不是数据库所有权、租约或自动接管。

## 2. 固定命名与协议

普通数据库 authority 使用的**同一个 `Objects` 后端**保存下列 key：

```text
scap-worker/v1/instances/{worker_instance}
```

数值为非零规范十进制 u64。作用域是整个 bucket；不加入 endpoint、区域、凭据、
deployment、tenant、数据库、缓存目录或可配置前缀。改变 endpoint 别名或服务凭据，
仍然访问同一 bucket 时不能获得第二份身份占用。不同 bucket 属于不同对象权威。

正文固定为 ASCII `SCAP-WORKER-INSTANCE-v1`、一个 NUL 字节以及 big-endian u64。
不保存凭据、主体、地址或业务明文；只需有限常量大小即可永久拒绝重用。

[`instance::claim`](../../crates/scap-service/src/instance.rs) 执行：

1. 检查非零身份和同一个绝对 deadline。
2. 恰好一次 `Condition::Absent` PUT（S3 `If-None-Match: *`）。
3. 只有明确成功才对原 key 做一次 exact GET；检查完整正文与返回 ETag 都等于本次创建。
4. 在原 deadline 内完成后才允许服务启动。

不会 LIST、刷新 ETag、覆盖、删除、重试或把既有相同正文当作幂等成功。
两次正常启动即使输入完全相同也代表两个 incarnation，所以第二次必须拒绝。

| 结果 | 启动行为 |
| --- | --- |
| PUT 明确成功且原期限内 exact GET 完全匹配 | 可以继续构造服务 |
| PUT 冲突/412 | `INSTANCE_REUSED`；不 GET，不接管既有记录 |
| PUT 响应丢失、超时或其他不明确结果 | `INSTANCE_UNKNOWN`；不继续查询或启动 |
| 成功 PUT 后 GET 缺失、实际超限、损坏或正文/ETag 不匹配 | `INSTANCE_CORRUPT` |
| 成功 PUT 后 GET 不可得，或任何出口超过原期限 | `INSTANCE_UNKNOWN` |

失败没有启动资格。成功占用后发生线程、运行时、监听端口或其他启动资源失败，
该数值也永久消耗。正常退出、SIGKILL、丢失全部本地目录都不会释放。
UNKNOWN 后改用新的明确身份是新一次启动；不能删除原 marker 来“修复”重启。
PUT 可能已成功的 UNKNOWN 会保留一条无人使用的 marker，这是保守拒绝的成本。

## 3. 服务接入与原 fencing 的关系

[`assemble_with_storage`](../../crates/scap-service/src/daemon.rs) 是共同接入点，
`assemble`、`assemble_with_listings`、真实 `serve` 均经过这里。
transport、output、Options、调度额度、三个 intake、catalogue、discovery/GC 能力、
worker 数值、监听地址和缓存目录先验证，再使用原后端完成 claim，最后启动数据库/
catalogue worker 和 HTTP listener。不存在测试或生产 bypass 开关。

S3 客户端自身需要的有界 I/O runtime 在 claim 前创建；数据库执行线程与 listener
不能在 claim 前运行。claim 的 PUT/GET 共用 `Options.operation_timeout` 派生的
一次绝对期限，并继续受 S3 adapter 单次 transport timeout 约束。

登记不修改任何数据库 HEAD。新实例仍须按 fresh HEAD、原 revision/serial、权限和
owner plan 完成接管；claim 成功不意味着已经成为任一数据库的 owner。
旧实例的候选仍由原 HEAD CAS、owner epoch 和请求身份协议 fencing，不能改为用
marker 存在来授权读写。S3 不可得时也不能仅凭本地历史记录启动。

多个线程中的 `Engine` 共用同一次 daemon incarnation，不逐线程 claim。
直接装配 `Engine::new`、`Database::with_options` 等底层受信 Rust API 的嵌入程序
仍负责其顶层生命周期与身份登记；这些原语不是完整 daemon 启动入口。普通服务
调用方应使用上述公开 assembly/serve 入口，不能自行绕过它们后声称取得同等防重用保证。

discovery cursor 继续使用每次启动的新随机盐派生 AEAD key 和递增 nonce。
永久 worker marker 不替代该密码学 nonce 规则，也不把旧 cursor 变成可跨进程恢复的权威。

## 4. IAM、GC 和生命周期配置

该 prefix 与 `scap-object/v1/...` 完全分离，不进入数据库发现或任何 payload GC。
现有 `GcS3` 仅接受精确 database/storage-generation/objects 前缀，无法通过产品接口
删除 worker marker。每次启动增加一条永久小对象；长期成本中必须计入对象数量，
不能宣称所有元数据可回收。

部署必须明确配置以下权限边界，不能只给原数据库 prefix 后期待服务正常启动：

| 角色 | 精确允许范围 | 禁止 |
| --- | --- | --- |
| 普通服务 | `s3:GetObject`、带 `If-None-Match: *` 的 `s3:PutObject`，资源为 `arn:aws:s3:::BUCKET/scap-worker/v1/instances/*` | 对 marker 的无条件写、If-Match 覆盖、DELETE、DeleteObjectVersion |
| 数据 GC | 保留原 `scap-object/v1/.../storage/.../objects/*` 白名单 | worker prefix 的读取/创建不需要授予，删除必须拒绝 |
| 生命周期/运维 | 保存 marker、保留部署准入历史 | 该 prefix 的过期清理、删除 marker 后重用 ID、复制/回滚到缺失 marker 的旧 bucket |

AWS 支持用 `s3:if-none-match` 条件键约束创建；应对 worker prefix 添加显式 Deny，
拒绝缺少该 header 的 PutObject，以及 DeleteObject/DeleteObjectVersion，避免其他
宽泛角色授权覆盖边界。marker 很小，不需要 multipart upload 例外。
具体政策应与已有 bucket policy 合并并在目标后端验收；本代码不读取 IAM 政策、
不修改权限，也不能阻止有 bucket 管理权限的人删除数据或改生命周期配置。
来源：[AWS 条件写](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)、
[AWS 强制条件写政策](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes-enforce.html)。

## 5. 首次采用时的历史边界

**首次部署这段代码不能自动证明过去从未用过一个数值。** 旧版进程没有留下 marker，
历史 HEAD 中当前 owner 也不等于完整的历史身份清单；不能用一次 LIST 或当前 owner
集合推断所有历史 ID。旧版二进制不执行本协议，混合部署也不能获得全局保证。

新 authority bucket 从第一次启动就启用该协议时，登记覆盖全部服务启动。
已有环境需要先停止并禁止旧版进程再次启动，确保新配置 ID 不与过去的服务实例重用，
并保存部署者已有的发号/退休记录；若不能证明历史分配，不能宣称已完成无复用迁移。
不要为了获得空 registry 把现存数据库随意复制到新 bucket 后继续复用旧身份；
独立 authority 迁移与恢复协议不在本功能范围内。

后续可在这个永久记录约束上设计经过验收的自动编号分配器；本次不会默认采用
随机 u64、墙钟、PID、主机名或递增 Pod ordinal 来冒充持久分配。

## 6. 验证边界

单位覆盖首次创建、相同正文重用、全 u64、两个线程竞争、所有 StoreError、
丢失 PUT ACK、GET 损坏/ETag 改变、原期限，以及三个公开 assembly 入口。
所有无效本地配置必须在 marker I/O 之前失败；marker 失败不创建服务 cache/worker。
真实 S3 adapter 的单位 HTTP fixture 不计作兼容存储验收。

独立运行使用实际 `scapd` 和 pinned SeaweedFS：两个进程并发启动、正常退出/崩溃后的
重复身份、全新身份、后端接受 PUT 后丢响应、读回记录被破坏，以及无 S3 时失败关闭。
原 bounded-transport healthz 实验也必须使用真实本地后端完成启动登记，不能保留
“S3 不可达仍启动”的旧假设。AWS 条件写/IAM、恶意管理员、跨区域复制与历史迁移
验收仍然独立，不从本地通过推导。
