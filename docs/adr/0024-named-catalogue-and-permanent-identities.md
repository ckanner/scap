# ADR-0024：名称目录、固定控制意图与永久数据库身份

状态：方案已接受，正式 Rust/HTTP/SDK 已通过 [PR #31 的必要本地验收](../engineering/catalogue-actors-validation.md)并合入。前置[协议与有界模型](../engineering/named-catalogue-model.md)和真实运行分别记录；全目录发现、AWS 及完整 N2 退出仍未完成。正式验收范围见[验证规范](../engineering/validation.md)。

## 问题

已有服务以不可变 Scope 接入数据库。业务需要按名称创建、查找和删除，但 S3 没有跨对象事务：名称绑定、数据库 HEAD 和调用方看到的响应可能分别停在不同阶段。名称重复、创建响应丢失、迟到写入、取消和删除重建都不能生成第二份业务身份，也不能覆盖其他数据库。

“名字没有查到”不能证明旧创建不会迟到；“HEAD 不存在”不能允许自动建空库；“同一 database ID 的 incarnation 不同”也不能允许复用物理 HEAD key。协议必须保留明确的持久中间态，并让重入绑定原始意图。

## 决定

在正式 `scap-object` 内增加 `catalogue`，复用相同的 exact GET、原 ETag CAS、期限和严格对象校验。它可以使用 crate 私有的 HEAD 读取与发布原语；外部调用方不能提交“已完成绑定”或“已取消”的可信证明。实验只装配这些正式 API。

名称采用 1–128 字节 UTF-8，拒绝控制字符，区分大小写，不做 trim 或 Unicode 归一化。`CreateDescriptor` 以 deployment、tenant、creator 和 create operation 唯一定位，冻结名称、派生 Scope、原创建选项及首次生效的配额/留存。相同 operation 更换输入返回冲突，不另外分配身份。

派生 Scope 的编码及具体 S3 key 见[名称目录协议](../architecture/name-catalogue-plan.md)。哈希只提供确定性候选身份；永久物理 HEAD 槽位和来源核对决定是否能够使用这个身份。HEAD key 永久绑定 deployment/tenant/database，删除后也不回收，不通过更换 incarnation 或 generation 绕过。

### 创建与取消

| 持久阶段 | 能力与后续条件 |
| --- | --- |
| Descriptor 已保存 | 只证明固定意图存在；尚未占用名称，取消返回 NotReserved |
| Reserved | 名称被固定创建意图占用；创建方与取消方竞争同一 ETag |
| Provisioning HEAD | 数据库不可服务；普通 SQL、会话、查证、取消及控制入口均拒绝 |
| Bound | 名称已不可按创建取消；创建方仍须核对来源并完成 HEAD 的 Ready 转换 |
| Ready | 名称解析必须读取当前 HEAD 并检查当前 READ；写入仍需正常 owner 激活 |
| Aborting | 已赢得 Reserved 竞争，必须建立永久身份屏障及 AbortProof 后才能释放名称 |
| Tombstone | 原名称绑定已结束；新创建只能以明确的前驱 revision 占用名称，并使用新 Scope |

取消在 Reserved→Aborting 与 Reserved→Bound 的竞争中决定。Aborting 获胜后，原 Scope 的 HEAD 必须成为永久 Deleted 屏障，或以合法外来占用的不可变证明确认该物理槽位已经不可使用。外来库的字节、权限和数据不得改变。未知格式、损坏、缺失来源或无法确认的占用失败关闭；不能先释放名字再补证明。

对于带命名创建来源的外来 HEAD，合法占用证明必须 exact GET 其实际 `CreateDescriptor`，核对规范字节摘要、完整 Scope 与创建来源。不能仅因 HEAD 中填写了看似有效的来源字段就释放名字。直接创建的 null 来源仍按独立合同核对；不遍历可能重用的外来名称绑定，也不把外来数据库的数据闭包当作取消自身意图的依赖。

永久 `AbortProof` 早于名称 Tombstone，名称后来被重用也不丢失原操作终态。Bound 阶段回答 CannotAbortBound 仍核对 fresh 同来源 HEAD；404 或错误来源是损坏，Ready/Maintenance/正常 Deleted 的状态信息仍遵守当前保留策略的 READ 权限。

### 删除与固定控制意图

每个 abort/delete 在 durable admission 时保存永久 `ControlDescriptor`，绑定调用主体、操作种类、control operation、完整创建身份、expected revisions 和 nonce。之后即使目标 CAS 返回 412 或 UNKNOWN，同一 control operation 也不能换条件继续。

同一 caller/kind/control operation 的既有 descriptor 必须在访问一个被改写的新目标之前核对完整公开意图；换目标、条件或 nonce 均返回 `Conflict`，即使新目标尚不存在。新的控制意图仍须先通过当前授权再持久准入；原意图重入也不得绕过当前授权。合法外来物理身份占用才使用 `IdentityConflict`。

正常删除由当前 HEAD 的 ADMIN 决定，调用者可以不是创建者，也不需要 READ 或 provision。只从 Ready/Maintenance 发布带原控制来源的 Deleted HEAD，再把匹配的 Bound 变成 Tombstone。普通 `set_lifecycle(Deleted)` 不接受命名库，避免绕开名称协议。删除不会物理删除 HEAD、descriptor、proof 或数据库依赖对象。

读取多个对象不构成跨 key 快照。实现先读名称，再读对应 HEAD/证明，最后重读名称并比较同次 GET 的 body/ETag；期间变化返回 Conflict。412 和 UNKNOWN 立即终止本次候选，不刷新 ETag、不改 Scope，也不自动重放 SQL。

## 格式与现有数据库入口

HEAD JSON 升为 **format 3**，显式要求 nullable `creation` 与 `deletion` 字段。直接按 Scope 创建的库写入两个 null；命名库以这些字段绑定创建和删除来源。旧 HEAD、不完整字段或非法生命周期组合拒绝，不自动升级或重新初始化。

不可变数据、索引与 Result 的 `SCAPOBJ2` envelope 仍为 **format 2**，SQL 编码仍为 `SCAPSQL1`/`SCAPRES1`。HEAD 版本与不可变帧版本分别校验，不能一起批量替换。物理 HEAD key 保持原位。

Provisioning 的禁止服务规则在正式 `Database` 中实现，不依赖 HTTP 隐藏方法。命名创建进入 Ready 后仍使用已有 takeover/activate、native SQLite gate、当前权限与原结果协议，不引入第二条 SQL 提交路径。

## HTTP、SDK 与资源

服务新增 `POST /v1/catalogue`，支持 prepare_create、resume_create、abort_create、inspect_create_operation、resolve_name 和 delete_name。严格 JSON 拒绝缺字段、未知字段、重复字段和非规范整数。u64 继续使用十进制字符串；客户端 DTO 不包含 S3 key、ETag、内部摘要或可信证明。creator 与 provision 来自当次认证，不能由请求体自报。

目录配置默认不启用。显式启用时必须完整给出 worker、全局/租户/名称排队、HTTP intake、body 和绝对期限预算；单请求 body 上限 64 KiB。目录有独立 worker 池与有界队列，不借用数据库 SQL、lookup/cancel 或恢复的执行配额。未知名称的操作查证也按保守的租户/名称预算计费，不能用随机 operation ID 绕过准入。HTTP 配额覆盖响应字节仍被传输缓冲持有的时间。

Node `CatalogueClient` 使用单独 endpoint 和明确的 deployment/tenant/principal 上下文。`prepareIntent`、`saveIntent`、`restoreIntent` 保存完整固定意图；`submit` 每次只发送一个 POST。UNKNOWN 携带原意图，应用可先查证创建进度，或显式以原 abort/delete 意图重入。SDK 不暗中重试、不刷新 revision，也不因名称被重用而把已有 SQL 句柄指向新 Scope。

## 验收与后续

正式 Rust 每个生产文件须通过 unit-only 四维精确 100% 覆盖；SDK 所有生产模块须通过 Node 和原始 V8 计数检查。HEAD 3 的原网络、保留结果、生命周期、服务和 1 GiB 合同必须重新运行，不借用旧 HEAD 2 的结果认证新源码。

目录真实实验独立记录所有输入、调用/响应、ACK、exact GET body/ETag、条件写、进程与缓存事件。逐个实际 PUT 验证发送前、后端接受但响应未达、调用方已消费响应后的计算丢失；另外覆盖 bind/abort、迟到 provision/永久 tombstone 两种顺序、外来占用、损坏、原控制条件、名称重用和全计算恢复。HTTP/SDK 使用另一套真实服务实验验证认证、无损原意图、独立准入与恢复。

这次交付的目标是精确名称及固定操作身份的持久目录。**全目录发现/分页、自动 owner 路由、完整冷热隔离和预定义负载活性仍是 N2 退出条件。** 已知名称列表不能证明完整 inventory。GC、pin、PITR、长期成本收敛、AWS Standard 和生产 SLO 仍分别验收；本 ADR 不开放 bucket TTL 或物理 GC。

实现入口：[目录核心](../../crates/scap-object/src/catalogue/mod.rs)、[服务装配](../../crates/scap-service/src/catalogue.rs)、[SDK](../../sdk/node/src/catalogue.js)、[真实切点矩阵](../../experiments/object-network/catalogue-matrix.md)。
