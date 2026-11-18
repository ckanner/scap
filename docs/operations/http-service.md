# HTTP 服务运行与原请求查证

服务入口为 `scapd`，配置类型见[config.rs](../../crates/scap-service/src/config.rs)，完整合同见 [ADR-0023](../adr/0023-authenticated-http-and-node-sdk.md)。对象凭据由指定环境变量提供，配置文件只保存这些变量的名字。API 凭据配置仅存 SHA-256，不能放在公共仓库中。

## 启动

```bash
cargo +1.90.0 build --release --locked -p scap-service --bin scapd
install -d -m 700 /var/lib/scap/cache
target/release/scapd /etc/scap/service.json
```

配置中的 `worker_instance` 是一次服务进程的身份，必须非零且从未被另一实例使用。重启使用新身份；不要让新旧进程共享这个值。`cache_directory` 为已经存在的绝对私有目录；其子目录是可丢弃缓存。配置按所有者保护，运行用户只拥有必要 bucket 前缀权限。

`GET /healthz` 只返回进程存活，不承诺 S3 可用、任意数据库已激活或数据正确。数据库接口为 `POST /v1`，命名目录为显式启用的 `POST /v1/catalogue`；HTTPS 在反向代理处终止，daemon 拒绝直接绑定非 loopback 地址。HTTP 客户端用 `Authorization: Bearer …`，不获得 S3 凭据。

普通请求、控制请求、恢复请求有独立准入。SDK自动发送对应的 `x-scap-admission`，服务核对其操作类别。普通期限与恢复期限均从本次 HTTP 接收开始，排队、读取和执行都计入；慢请求不会在每次内部步骤获得全新 deadline。

数据库执行采用显式有界 actor 配置：`active_database_actors`、`active_database_actors_per_tenant`、`actor_idle_timeout_ms`、全局 `queued_total` 与缓存 `pages_per_actor`。每个活跃 HEAD 独占一个线程并保留至多一个完整 scope Session，闲置超时自动关闭。旧 `workers`、`queued_per_worker`、`sessions_per_worker`、`pages_per_worker` 配置必须迁移，严格解析不会沿用旧语义。示例见[服务配置](../../crates/scap-service/README.md)，不变量及剩余吞吐边界见[执行隔离设计](../architecture/execution-isolation-and-throughput.md)。

## 建库与接入

使用服务配置允许 provision 的凭据，以全新不可变数据库 ID 调用 create。返回 `active: false` 后，使用同一服务的 owner 以及当前 revision 调用 activate；库存在并不表示恢复完成。并发创建同一身份只有一个条件 HEAD 创建能够成功，冲突方读取 status 核对既有库，不能换身份偷偷再建一份。

业务代码调用 SDK prepare 绑定精确的 SQL、参数和原请求 ID，并在发出请求前把 save 返回的内容写入应用自己的持久日志。不要只把这份身份存在可能一起丢失的数据库缓存目录。Node API 的整数用 bigint；`number` 表示 f64，`42n` 与 `42` 是不同请求身份。列名和行按数组返回，不把重名列覆盖成对象属性。

`open` 只预热会话，不夺取写权限；可以为独立 reader 显式准备较大的冷库。热 query/execute 每次重新读取远端 HEAD，S3 不可用时不能回退到缓存成功。HTTP body 使用 base64，会在原始字节之外产生编码和解析成本，资源实验必须按实际内存计入。

## 命名创建与删除

目录正式候选的实现与验收状态见 [ADR-0024](../adr/0024-named-catalogue-and-permanent-identities.md)。启用方式及严格字段见[目录服务接口](../../crates/scap-service/catalogue.md)；配置缺省时不启用目录，启用时必须完整提供独立队列、worker、HTTP 和期限预算。

创建前先用 `CatalogueClient.prepareIntent` 构造 prepare_create 意图，再将 `saveIntent` 的完整值写入应用的持久日志。`submit` 返回 PreparedCreate 只证明 descriptor 已保存。保存返回的 Creation，再以该原身份调用 resume_create，直到明示 Ready；随后用返回的固定 Scope 显式 activate。UNKNOWN 后先 inspect_create_operation，或显式恢复原意图重入，不改 create operation、名称或 Scope 重新创建。

| 操作结果 | 含义与处理 |
| --- | --- |
| NotReserved | 尚未占用名称；不是已经撤销未来创建的证明 |
| Reserved / Provisioning / Bound | 创建还在推进；Provisioning 不能执行普通 SQL，Bound 已不能按创建取消 |
| Ready | 名称已绑定对应库；writer 激活状态另外检查 |
| Aborting | 取消已占据名称转换，但永久屏障/证明/释放仍可能未完成 |
| Aborted | 原取消屏障与名称释放已成立；永久身份不再复用 |
| CannotAbortBound | 创建已绑定；需要当前 ADMIN 的正常 delete_name 流程 |
| Deleting / Deleted | 原正常删除正在收敛或已完成；业务结果不再因删库而可读取 |
| NameConflict / IdentityConflict | 名称或物理身份已被其他合法来源占有；原 operation 不改身份 |

abort_create 和 delete_name 都先保存完整控制意图，包括 control operation、expected revisions 和 nonce，再发送。相同 control operation 的条件一经持久准入就不能更换；412/UNKNOWN 后按保存的原意图查证/收敛。普通 `set_lifecycle(Deleted)` 不接受命名库。删除完成后按明确的 Tombstone revision 创建新名称绑定，新库使用新 Scope，旧 SQL 对象与旧操作继续指向原库。

创建/取消/操作查证要求当次认证仍允许 provision 且主体仍是 creator；Ready 等业务状态还受当前 READ 约束。正常删除只要求 fresh HEAD 的 ADMIN，管理员不必是 creator，也不把 ADMIN 当成 READ。名称解析每次重新检查绑定、HEAD 来源和当前权限，不能把缓存当授权。

## 失败后怎么处理

| 返回 | 处理 |
| --- | --- |
| Committed | 保存 receipt 和原结果；同一身份的重复 execute 返回原结果 |
| UNKNOWN／客户端超时／断线 | 保留原身份，调用 lookup；需要封闭迟到请求时调用 cancel，禁止改 ID 重发原 SQL |
| COMMITTED_BUT_UNAVAILABLE／SDK committed 错误 | 数据库已经发布；保存 receipt，查证原结果，不能按失败回滚业务状态 |
| Cancelled | 取消屏障已发布；原身份不能再执行 |
| Closed／Retired | 身份空间已关闭或结果已退休，不能解释为可用新 ID 安全重做外部业务 |
| FENCED | 当前进程不是已激活 owner；由管理员核对并显式接管 |
| STALE_SNAPSHOT | 旧会话不能继续；服务丢弃它，后续显式 open 可恢复新会话，不在失败调用中重放 SQL |
| DENIED／UNAUTHENTICATED | 核对 API 身份和当前 HEAD 权限，不能通过更换 scope 绕过 |
| BACKPRESSURE／RECOVERY_BUSY | 本次未准入；上层按原身份做有界调度，所有失败仍计入负载分母 |

控制操作同样可能收到 UNKNOWN。保存 expectedRevision 和 nonce，读取新鲜 status 核对确切 transition；不要自动刷新 revision 再提交同一控制意图。若中间已有其他转换，需由控制方重新核对状态。

## 全部计算丢失

保留对象存储和部署凭据，在空私有目录启动新实例。对每个确切 scope 先 status，再用 current revision 执行 takeover；这推进 owner epoch 并令库未激活。随后 activate 完整下载并校验数据及保留结果，成功后才能写入。恢复 API 有独立较长预算；10 GiB 的冷恢复仍是整库物化。

恢复后按独立 ACK 集合 lookup，逐项比较 scope、request、完整 receipt、原始结果和业务内容。缺失/损坏对象必须拒绝；不得用 create 或旧缓存代替恢复。对象存储本身的区域灾难和误删恢复不是这项全计算丢失测试的结论。

## 当前持续运行边界

当前已有不可变 ID、名称目录、全目录发现、静态 owner 路由和保存原意图的显式协调；有限自动 owner controller 已在 PR #57 实现候选，仍需独立真实服务/S3组合验收。专属 actor 消除跨库固定 lane 的恢复阻塞，但共享存储、网络、CPU、HTTP 解析与磁盘容量仍须单独限流和负载验收。全部计算丢失后的完整发现须遍历名称及永久 HEAD 槽位，并按[部署恢复合同](../architecture/catalogue-discovery-plan.md)核对各状态；仅按调用者已知名称恢复不能代替完整发现。请求窗口有界，管理员通过 closeFull 有序关闭满窗口；SDK 不暗中改变 request epoch。HEAD6 回收管理见[接口说明](../../crates/scap-service/docs/reclamation.md)，候选验收、自动协调及长期留存分别记录。

HEAD6/7 的完整代际复制、持久 GC checkpoint 与 Deleted 最后一代永久退休已合入。只有安全退休代且经过公平重复 sweep 的 payload 才能物理回收。HEAD9 S1 保留根与 COPY/GC 的组合仍为实现候选，新 Scope 恢复和任意时间 PITR 未交付；永久身份/证明对象和不可达 orphan 的成本仍须计入。10 GiB 配额限制当前逻辑数据库，不限制 bucket 总量。服务适合受控开发与验收；生产可用性、总成本与长时间运行仍须完成 N3/N4 的门禁。
