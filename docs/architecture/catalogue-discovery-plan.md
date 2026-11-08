# 全目录发现与全计算丢失恢复：最小实施合同草案

状态：**DESIGN_ONLY / 未实施产品代码 / 未运行真实 LIST 验收**。这是 #31 之后的独立工作包，不属于 #31 或 actor 候选已通过的范围。全文基于当前 `name-catalogue-plan.md` §9、`object-storage-native-proposal.md` §§8、10、14、18，以及固定 `object_store = 0.14.2` 的实际源码；输入哈希见 [设计输入清单](../evidence/catalogue-discovery-design-inputs-2026-11-08.json)。原设计在独立工作区完成；当前仅开始独立原语/协调器开发，本文不把开发进度当作已合入或已验收能力。

## 1. 建议决策

实现真正的 deployment / tenant 全前缀发现，包含名称、创建/控制意图、取消证明及永久 HEAD；输入只需要部署配置和可信访问身份，不接收调用者预先保存的名称或 Scope 清单。LIST 只提供候选地址，exact GET 和既有目录状态机决定记录身份、生命周期、当前权限及可服务性。

第一版统一使用 S3 general-purpose bucket 的**有界、按键向前分页**。依赖已经公开安全的 `PaginatedListStore`；通过 `offset` 发出 `StartAfter`，用服务自己的受保护 continuation 保存已完成的键前沿。保留并严格验证 S3 的截断标记和下一 token，但不依赖 opaque token 在长时间中断后的有效期。S3 Express、无序 LIST 后端不在这一版合同内。

输出明确区分三项事实：

1. `traversal_exhausted`：此次全前缀遍历正常结束，全部候选均已分类，没有未解决的页或 GET。
2. `preexisting_slots_covered`：在本设计的单调键集合和有序 LIST 前提下，扫描开始前已持久化的全部权威记录槽均被处理。可以同时发现扫描期间新增的记录；不能确定这些新增项的精确出生时间，也不返回虚假的开始时刻总数。
3. `recovery_complete`：已满足指定恢复 profile 的数据闭包、native 校验、权限及中间态处理条件。仅完成 LIST 或仅取得 HEAD，不能设置这一值。

在线分页没有跨 key 快照。持续创建/删除/授权变更时，不返回“某个共同瞬间的准确可见数据库集合”。要求这个更强产品合同，需要新的持久索引/排序协议，见 §12。

## 2. 完整发现范围

`D = scap-object/v1/{deployment}/`，`T = D{tenant}/`，`P = Tcatalogue/v1/`。所有十进制 ID 必须规范编码、非零且在 u64 范围内；所有前缀在应用层显式以 `/` 结尾，避免 tenant `1` 匹配 `10`。

| 层次或记录 | 发现方法 | 权威确认与必要结果 |
| --- | --- | --- |
| deployment 的所有 tenant | 对 D 使用 delimiter `/` 的分页；逐个验证立即子前缀 | 不依赖 token 配置里出现过的 tenant 清单；发现不等于给普通用户该 tenant 权限 |
| 当前及历史名称槽 | 对 `Pname/` 做平面分页 | 候选必须是恰好 64 个小写十六进制字符；exact GET 规范 Binding，重算完整名称的摘要并核对 deployment / tenant / descriptor 来源 |
| CreateDescriptor | 对 `Pcreate/` 做平面分页 | exact GET 并核对 creator / operation 与完整 Creation；包括尚未 reserve 的已固定创建意图和旧轮次意图 |
| ControlDescriptor | 对 `Pcontrol/` 做平面分页 | exact GET 并核对 caller / kind / operation；已准入但没有成功改变名称/HEAD 的操作也必须被发现 |
| AbortProof | 对 `Pabort-proof/` 做平面分页 | exact GET 并核对创建来源、固定 abort 意图和身份屏障；不能仅依赖当前名称仍引用该 proof |
| 所有物理数据库身份槽 | 对 T 使用 delimiter `/`，从立即子前缀中识别规范 database ID；随后 exact GET `T{database}/head` | 覆盖 direct create、命名创建、Provisioning、Maintenance、Deleted 和旧名称重用留下的 HEAD |
| 数据上传产生的 prefix，但没有 HEAD | database 子前缀只构成候选 | 可以是未发布上传/orphan，不能建立空库或推断一个已存在的数据库；若 Binding 等权威记录要求该 HEAD 存在，则必须报缺失权威 |

数据库子前缀发现使用 delimiter，避免为发现一个 HEAD 而列出该库所有业务块。目录意图前缀只包含有限大小的协议元数据；任何数量仍通过 continuation 处理，不能在内存中一次 `collect` 全部列表。

`all_names` 与 `all_database_slots` 是不同集合。只扫描 `name/` 会遗漏 direct create、已重用名称的旧身份、尚未绑定的状态；只扫描 HEAD 会遗漏 descriptor-only 与 Reserved 尚未 provision 的意图。N2 的完整恢复门禁必须覆盖两类及其关系。

普通用户 API 只列出其已认证 tenant 内、当前 READ 允许的名称；deployment 全发现是可信恢复入口。全局恢复不能拿“已有凭据涉及的几个 tenant”冒充整个 deployment 的分母。bucket / deployment 的选择来自明确部署配置；本工作不枚举任意账户的 bucket。

## 3. 权威确认、权限与状态

### 3.1 每项确认

对名称候选，先 bounded exact GET 解码并验证 key 与完整名称，再使用正式目录路径的稳定视图：**Binding → AbortProof → HEAD → 同一 Binding**。末次 Binding 的 body / ETag 必须和首次一致；HEAD、descriptor、proof 及 control 的来源核对保持当前实现的严格规则。不得把 LIST 的 ETag、Size 或 LastModified 代入 CAS、权限判断、恢复版本或名称状态。

如果复用现有 `resolve`，候选读取只用于获取合法名称，后面的 resolve 必须重新执行完整权威确认；不能复用旧 HEAD 或跳过双读来省一次 GET。所有嵌套读取消耗同一个预算和 deadline。

HEAD-only 候选需要按物理 `(deployment, tenant, database)` 槽检查 body，之后取得真实 incarnation / generation。建议引入内部 `DatabaseSlot` 类型复用 `decode_head_slot` 的物理槽验证，避免伪造一个带占位 incarnation 的 Scope。外部数据库 API 继续核对完整 Scope。

### 3.2 权限

- deployment、tenant、principal 必须来自当前认证上下文。continuation 与旧页都不是授权凭据，每页重新认证；每个要返回的 Ready 名称重新检查该 HEAD 的 READ 权限。
- ADMIN 不隐含 READ；`provision=true` 不隐含全目录可见。当前 `Principal` 仅有 provision 位，没有 deployment inventory 权限，不能借用它扩权。
- 普通页面可以对已确认的应用 ACL 拒绝项不输出名称、Scope 或内部失败计数。S3 LIST/GET 的 403 则是底层访问不完整，必须失败/返回未完成，不能当作“对用户不可见而跳过”。
- Reserved、Aborting、Tombstone、控制意图等详情只能给原有合同允许的调用者或明确的恢复 capability。不得用 `Caller { principal: descriptor.creator, provision: true }` 伪装原创建者来自动续作。
- 可信恢复能力允许内部元数据分类，不自动授予 SQL READ/WRITE/ADMIN，也不更改现有权限。自动 owner 接管与授权身份分配是另一个需要明确合同的工作包。
- 一个页面内的条目在各自权威读取点授权；页面不是一笔全租户读事务。后续撤权不会追回已合法交付的数据，但下一页不能沿用旧的授权结果。

### 3.3 分类必须保留

最少区分 Ready、Maintenance、Provisioning、Reserved、Aborting、Deleted/Tombstone、descriptor-only、admitted-control-without-terminal、orphan-prefix、Denied、Conflict、Unknown、Corrupt。只有 Ready + 当前 READ 授权才能作为普通可解析名称输出。未完成创建不能变成空 Ready 库；Deleted 身份不能重建；控制 descriptor 存在不等于控制已接受或完成。

LIST 明确返回的永久 `name/create/control/proof/head` 对象随后 exact GET 404，不是合法名称删除的正常解释：这些权威键不物理删除。该项保持缺失/未确认，不能把它过滤掉后报告完整。与此不同，仅由业务对象形成的 database CommonPrefix 本来就可能没有 HEAD。

## 4. 分页与 continuation

建议新增独立只读 `Listings` port，保留事务路径使用的 `Objects` exact GET/条件 PUT port：

```rust
pub trait Listings: Send + Sync {
    fn list_page(&self, request: &ListPageRequest, deadline: Instant)
        -> Result<ValidatedListPage, ListError>;
}
```

这是接口草案，尚非生产代码。`ListPageRequest` 的字段由可信服务构造，包含固定 namespace / scan kind / 前沿 / 页大小；HTTP 不接受任意 S3 key、prefix、delimiter、ETag 或 bucket。`ValidatedListPage` 必须由严格 wire guard 构造，至少包含候选键/子前缀、明确 `is_truncated`、原始页证据摘要及是否可推进前沿。

服务 continuation 保存：版本、scan ID、endpoint/bucket 配置摘要、deployment、tenant 或 deployment-scan 模式、principal、输出视图、固定页参数、深度优先阶段栈、各层最后**已完成分类**的原始键、预算 profile 和过期时间。它不保存任何可授权的旧 HEAD。

普通用户的 cursor 必须经过认证且对内部前沿信息保密；仅签名的明文 cursor 可能泄露被过滤的名称摘要/数据库 ID。使用经审计的 AEAD 实现和轮换的服务配置密钥，限制编码和解码后的长度。密钥或 worker epoch 改变而无法恢复 cursor 时返回明确 `CURSOR_INVALID / RESTART_REQUIRED`，不能返回空页或伪造完成。cursor 密钥不是数据库权威；丢失后允许从 D/T 的第一键重新扫描。

处理一个 LIST 页时按原始 ASCII 键序逐项完成 exact GET 分类。预算用尽、名称双读冲突或 GET 未知时，前沿只能推进到最后一个已完成项；不能把 S3 页末当作完成前沿并丢掉未处理的尾项。下一次用 StartAfter 重新发现后缀，允许重读，不能漏读。深度优先扫描先完成一个 tenant 的各阶段，再提交父层 tenant 前沿；栈深固定，不能持有全部 tenant 数组。

截断但零项的响应不等于结束。若无法取得严格前进的键前沿，返回 `NO_PROGRESS / incomplete` 和原前沿，在有限预算内让调用者明确重入。不得用无限内部循环、假造 offset 或直接使用“返回项少于 page_size”结束。S3 token 失效或不可解析也不是完成。

重复项可以在当前有界页面内去重，但每个重复消耗扫描预算；跨页后退、重复前沿或原始键不满足请求范围要阻止完成。前沿顺序使用字节/字典序，不把十进制 ID 当数字排序。重放旧 cursor 只会重新读取，它没有修改数据库的效果；硬性全租户费用预算仍需独立准入和限流，不能由可重放的无状态 cursor 计数来保证。

## 5. 并发下可以证明的完成边界

设 `t0` 为首次 deployment/tenant LIST 发起之前的启动边界，`K0` 为范围内在该边界前已持久化的永久权威记录键。以下是本方案的推导，不是声称 S3 提供了跨页事务：

1. 名称槽、永久 HEAD、CreateDescriptor、ControlDescriptor 和 AbortProof 不删除、不 TTL；其键集合只增长。
2. 每次 LIST 对固定前缀和明确 StartAfter 返回按字典序排列的后续候选，所有原始键通过严格 wire 检查；S3 general-purpose 合同和后端准入测试提供这个前提。
3. 遍历从最小键开始；只在已分类键上推进；每个层次都看见有效未截断终页；无被忽略的错误或未完成候选。

因此，若全遍历终止，则 K0 的每个键都会被处理。并发新建发生在已经走过的前沿后面时，可以到下一轮才发现；发生在前沿前方时可能在本轮加入。我们不能按 LastModified 把后者从 K0 中准确分离，因为旧键的 body 也会更新。故报告的是“覆盖所有预先存在的槽，可含新增项”，不是某时刻准确的数量或快照。

**这个合同能找回全计算丢失前已 ACK 的全部数据库身份**：其永久 HEAD 和必要目录记录必须在 ACK 之前持久化，扫描开始后仍存在。扫描不需要事先知道它们的名称、Scope 或数量。测试的独立 oracle 可以从故障前 ACK/对象历史建立 K0；该清单绝不可传给恢复实现。

扫描期间持续创建大量更靠后的键可能阻止一次遍历在预算内终止。此时必须保持 incomplete，不能通过缩小范围或跳过页来制造成功。每个在足够长静止窗口前已存在的记录最终可由一轮完成的扫描找到；无限对抗性并发下没有固定完成时限。

**物理元数据删除、无序后端、错误的后端 LIST 或跳过候选都会破坏这个推导。** 该完整性收据依赖存储合同，不能检测一个恶意后端用合法 XML 永久隐瞒某个未知键。若要求在不信任 LIST 的情况下证明完整性，需要持久索引承诺，见 §12。后续 GC 也不得擅自回收这里用作单调发现依据的权威键。

## 6. 空集与未知

| 输出情形 | 可声明 | 不可声明 |
| --- | --- | --- |
| 第一次 LIST 403、超时、错误 XML、预算耗尽、候选 GET 未知 | 当前扫描 incomplete；可以返回已验证的部分项和 continuation/失败原因 | 完整空目录 |
| 页面过滤后零条，但仍有下一页或未分类项 | 此页无可返回项，扫描继续 | tenant 内不存在数据库 |
| 在线完整遍历结束，普通用户零条可返回项 | 本轮逐项检查没有返回当前 READ 允许的 Ready 名称；跨 key snapshot=false | 某个共同瞬间所有可见名称必然为空；整个 tenant 为空 |
| 完整记录扫描结束且一项权威记录也没有观察到 | 在单调发现前提下，启动边界前没有权威记录槽 | 扫描期间/扫描结束后绝对没有新记录 |
| 经过独立证明的静止窗口覆盖整个扫描，全部键和状态检查成功 | 对明确 scope/view 的完整集合；若 Ready 集合为空，可声明完整可服务集合为空 | 物理 bucket 已清空，或旧 Deleted/tombstone 成本为零 |

静止不能由“连续两次扫描相同”“等几秒”“杀掉本进程”或租约超时推导。全计算退出后仍可能有已经发出的 PUT 在途。真实恢复夹具必须记录并排空/裁决这些在途请求；产品若没有可证明的写入静止机制，应使用上述启动边界覆盖合同，不宣称瞬时 inventory complete。

## 7. 全计算丢失后的恢复流程

1. 保留必要的部署信任配置：S3 endpoint/bucket/region、受信认证配置、namespace/format 和预算版本。清空全部数据库缓存、名称路由、进程内 actor 和旧扫描状态，从固定 deployment 前缀开始。
2. 完成有界发现和元数据分类，生成新的、可丢弃的路由提示。提示不成为第二个持久权威；普通请求继续 fresh exact GET，不能凭扫描结果服务“最新读”。
3. 对每个发现的 Ready 身份，在当前授权和恢复预算下调用正式恢复路径：校验完整 data/result 闭包、完整物化、本地存储准入和 native SQLite 结构/语义检查。恢复期间 HEAD 变更按已有精确候选合同处理；不拿旧 ETag 重基，不重放 SQL。
4. 写者 takeover/activate 继续使用当前 ADMIN、准确 HEAD revision 和固定转换身份。扫描成功不等于写者获得所有权。没有当前必要权限时报告未恢复/需授权，不能伪造原主体。
5. 保留 Reserved/Provisioning/Aborting/descriptor-only 和固定 control 意图的准确可恢复状态。只有在原合同允许、并取得当前真实调用者授权后才继续控制动作；不擅自把尚未决定的创建变 Ready，或把 UNKNOWN 当作已取消。
6. 按库、tenant 和全局固定在途数调度。可以逐库恢复、校验、释放本地物化文件；不要求同时把所有冷库留在内存或磁盘。已验收的库之后仍以正式强读准入，不把旧校验收据当最新健康证明。
7. 独立报告 `metadata_classified`、`ready_verified`、`pending_intent`、`maintenance`、`deleted`、`permission_blocked`、`unknown`、`corrupt`、数据字节和实际耗时。发现结束但有未知/损坏，不设置 recovery_complete；只做元数据扫描时，数据恢复标记 NOT_RUN。

完整冷启动验收应以“所有开始边界前 ACK 的身份均恢复其由后续合法 SQL 历史决定的准确效果及仍在保留期内的原始结果，或由随后合法权限/删除/结果退休屏障明确解释；全部中间态准确分类”为合同，不以“一部分已知名字可以查询”为合同。若产品选择按需物化，仍必须另外运行遍历全部发现身份的恢复验证，不能把 lazy admission 直接当作全库数据健康证据。

## 8. 固定预算建议

以下是实施前可冻结的初版参数候选，**不是性能实测成绩**。任何调整必须版本化；不能测完再挑阈值。

| 单次目录请求资源 | 建议上限 |
| --- | --- |
| S3 LIST 页大小 | 32 个 Contents/CommonPrefixes，且不超过 S3 general-purpose 的 1000 上限 |
| 一个请求的 LIST 页数 | 4 |
| 候选处理数 / exact GET 数 | 128 / 512；所有嵌套 core GET 共享计数 |
| LIST 单页原始响应体 | 1 MiB，进入 XML 解码前流式限制；非 2xx 错误体也限制 |
| LIST 原始体总量 / 目录元数据 GET 总量 | 4 MiB / 16 MiB |
| 单条目录记录 / HEAD | 继续分别使用 64 KiB / 256 KiB |
| 在途 exact GET | 全局最多 4、每 tenant 最多 2；必须先取得预算再发请求 |
| 返回体 / cursor | 1 MiB / 16 KiB；解码前后都限制 |
| 单次总 deadline | 5 秒绝对 deadline；排队、LIST、GET、解析和生成 continuation 都计入 |
| 单次重新尝试 | 不做隐藏重试；冲突/未知按固定前沿明确返回 |

恢复作业另有冻结的总页数、候选数、metadata/data bytes、作业 deadline 与并行度；到界返回 incomplete + 已处理范围，不能无期限后台扫描。全量数据恢复使用现有按库大小相关的预算，不能塞进 5 秒目录 API 承诺。成本计量包含被过滤/重复/失败的读取和永久 tombstone/intent 增长；业务数据库配额不等于目录或 bucket 总成本上限。

发现作业使用独立的低优先级准入，建议全局最多 2 个 active scan、每 tenant 最多 1 个；不得占满当前 lookup/cancel 控制预算，不在跨页过程中持有全局调度锁。冷恢复的 native 物化另用有界恢复预算，不能借列表接口挤占热库执行 lane。

上述预算约束第一方保留的负载和请求规模，不应未经实际内存测量就声称硬 RSS 上限。XML token/depth/字符串也必须在原始体上限内设置限制，避免依赖解析器产生过量结构分配。

## 9. 固定 object_store 0.14.2 的实际 API 结论

### 9.1 可以实现，且无需第一方 unsafe

本地固定依赖源码已经核对：

- `src/list.rs` 公开 `PaginatedListStore::list_paginated(prefix: Option<&str>, opts)`；`PaginatedListOptions` 有 `offset`、`delimiter`、`max_keys`、`page_token`、`extensions`。
- `src/aws/mod.rs` 为 `AmazonS3` 实现该 trait；`src/aws/client.rs` 把参数映射到 ListObjectsV2 的 `start-after`、`delimiter`、`max-keys`、`continuation-token`，每次只发一页请求。
- `AmazonS3Builder::with_http_connector`、`HttpConnector`、`HttpService`、`HttpClient::execute`、`HttpResponseBody::bytes_stream`、从 Vec 构造响应体、请求/响应 extensions 都是公开 safe API。
- `api-probe.rs` 使用 `#![forbid(unsafe_code)]`，以当前正式 stable target 的真实依赖做 `rustc --emit=metadata -Dwarnings`，退出 0；证明这些 API 和 trait 组合在固定版本上确实可编译。它只验证接口可用性，不是产品实现或真实 S3 测试。

现在 `S3` 内部只保存 `Arc<dyn ObjectStore>`，这个已擦除的对象不能自动提供另一个 trait 的方法。创建时保留同一 `Arc<AmazonS3>`，再分别安全地转换为 exact port 与 listing port 所需 trait object，即可共享客户端/runtime；或新增专用 listing adapter。不要靠 unsafe downcast，亦不要把所有内存测试 Objects 都强制实现 LIST。

### 9.2 不能直接使用默认返回值证明完整

固定源码有三项具体不足：

1. `client/s3.rs::ListResponse` 只保留 Contents、CommonPrefixes、NextContinuationToken；未保留 IsTruncated、KeyCount、Name、Prefix、MaxKeys 和输入 token 回显。下游无法判断“截断却丢失 token”、错误 bucket/prefix、显式 false 是否真的存在。
2. `aws/client.rs::list_request` 先执行 `body.bytes().await`，再整体 XML decode；`max_keys` 只约束合规服务的项数，不约束任意响应体字节或超大错误体。
3. `Path::parse` 会剥离一个前导/尾随 `/`。若只看转换后的 Path，非法原始 key 可能已经被规范化。合法 CommonPrefix 的尾随 `/` 也会丢失，必须在边界处保留其原始语义。

因此，不可把 `page_token == None` 或 `objects.is_empty()` 直接当完整终页；也不可宣称默认 SDK LIST 已满足 SCAP 的有界原语合同。

### 9.3 建议的最小安全包裹层

为 client 安装请求局部的 HttpConnector/HttpService guard，保留 object_store 的凭据、签名与序列化，由显式配置的 reqwest client 执行已签名请求。固定版本的默认 ReqwestConnector 会跟随 redirect；实际故障代理已证明仅设置 `max_retries: 0` 不能保证一次物理请求。实现必须同时关闭 reqwest retry 与 redirect、自动代理和解压，维持绝对 deadline；原 SDK 的 `max_retries: 0` 仍保留。guard 由 LIST、GET、PUT 共用，不能只限制 LIST 而让条件写在另一条连接路径重试。实现与实际故障证据见 [LIST 合同](../../experiments/object-network/listing-contract.md)。

- 请求 extensions 携带本次规范 bucket/prefix/options、字节上限与 deadline。只有带内部类型的合法 LIST 请求走 guard；不用全局可变“当前请求”变量，不跨并发调用共享解析状态。
- 按 bytes_stream 在复制前累计并限制字节；Content-Length 仅作额外提前拒绝，不能替代流式计数。非 2xx 不伪造成功，错误体同样有界。
- 在原始 XML 上验证正确根、必需且不重复的控制字段、请求 bucket/prefix/delimiter/offset 回显（对本合同要求的字段缺失失败关闭）、真实项数及 max_keys、原始 key/prefix 规范范围、排序、截断标记与 token 一致性。可兼容明示的可选元数据字段，不能把未知控制语义默认成空集。
- `IsTruncated=true` 必须有非空、受限的 NextContinuationToken；false 与 token 的矛盾必须拒绝。零项 true 保持未完成；不把短页当终页。
- XML 中 Contents 和 CommonPrefixes 可以各自成组出现，不能要求两种元素在原文中交错全局排序。分别校验各自严格有序后按原始 key 合并；KeyCount 同时计入对象和公共前缀。
- 检验后的原始 bytes 再交给 object_store 解码；在 response extensions 附加 `ValidatedListWire` 证明。`ListResult.extensions` 会保留该响应 extension，adapter 必须核对证明存在，并比较转换后键/前缀/next token 与原始校验结果一致。
- CommonPrefix 允许且要求原始尾 `/`，仅在固定转换处移除；Contents 的权威记录键不允许前后 `/` 被静默修正。所有 scope 检查在原始键上完成。
- 缺证明、解析/键错配归 Corrupt；体超限归 Limit；403/网络/截断传输保留具体内部原因并对外返回失败或 incomplete。不得把这些异常映射成 Missing/空目录。

XML 校验器需要独立精确单元覆盖和真实故障代理负对照。可直接固定已经在 lock 中的 `quick-xml = 0.41.0`、`async-trait = 0.1.92`、`http = 1.5.0` 为新生产直接依赖；增加后重跑两个 workspace 的锁定构建与全部门禁。不要修改依赖源码或使用 coverage 排除来隐藏 guard。

## 10. 实现范围建议

| 工作包 | 主要变更 | 出口 |
| --- | --- | --- |
| A：LIST 原语 | 独立 Listings port、S3 safe guard、原始 envelope/路径校验、预算、统一错误分类 | 每个生产文件四维精确 100%；真实分页、错租户、403、截断、超限、重复/后退、token 矛盾均被区分 |
| B：全目录协调器 | typed scope/key parser、tenant/五类元数据/HEAD 发现、既有稳定视图复用、深度优先前沿、结果分类 | 全前缀扫描与 continuation；直接创建和 descriptor-only 均纳入，权限无旁路 |
| C：HTTP/SDK | 在线只读列名 API、受保护 cursor、当前鉴权、可见性过滤、明确 non-snapshot / incomplete；SDK 不自动吞页错误 | wire/types/SDK 单元、公开声明检查、HTTP 权限竞争与限额验收 |
| D：冷启动完整性 | 从 deployment 根开始的恢复命令/服务作业、正式 data/result/native 恢复、分母/原始证据、独立审计 | OT-11/14 新门禁；输入不含名称/Scope 分母；全计算退出、在途裁决和全部本地状态丢弃后恢复 |

不把产品协调逻辑写到 experiments；实验只装配正式 core/store/service。`validate.sh` 后续必须显式增加这些新 LIST/发现/恢复门禁，不能用本次已通过的 exact-name 验收替代。

## 11. 必需验收与负对照

至少冻结一个多 tenant、混合 direct/named、中间态和权限的 profile；记录既定容量、页大小和总 deadline。建议目录规模覆盖 0、1、31、32、33、1024 个名称/HEAD；实际 network 样本的页大小调为 2 或 3，以较少对象触发所有边界。另有部署层 tenant 分页，不能仅覆盖单 tenant 的 name 分页。

- 原始 LIST：0 项终页；短页仍截断；0 项截断；缺/重复 IsTruncated；true 无 token；false 有矛盾 token；错误 bucket/prefix；33 项响应到 max_keys=32；非法规范化路径；超大有 Content-Length/无 Content-Length/流式错误体；返回 200 的错误 XML。
- 传输与 continuation：LIST/GET 403、404、5xx、超时、页内失败、结束响应丢失、cursor 跨 tenant/principal/部署/视图使用、篡改、过期、服务重启、预算刚好耗尽、页尾未处理项不得丢失。
- 权限：READ 允许、只有 ADMIN、只有 provision、撤权发生在两页间、同名重新绑定为无权限 Scope、隐藏名称不从 cursor/错误详情泄露；S3 403 不能被当 ACL 过滤。
- 并发：前沿之前/之后插入新名字；创建/取消/删除/同名复用发生在候选 GET 与稳定视图之间；合法重叠返回被接受；真实 stale/missing/source 错误保持拒绝。
- 全计算丢失：建立多个用户此前未提供给恢复器的名字和 direct HEAD；包含 descriptor-only、Reserved、Provisioning、Bound+Provisioning、Ready、Aborting、Deleted、被复用的旧身份；退出全部进程，清空全部缓存/路由/cursor，再仅给部署配置启动。
- 独立完整性 oracle：从故障前原始 ACK/HTTP PUT 版本历史构造全部预先存在永久键，检查每页请求的 prefix/offset、响应原文、候选 exact GET 和最终分类。恢复代码不得读取该分母；故意漏掉一个 tenant、一页、一条 direct HEAD、一个 descriptor-only、一个未处理尾项，都必须使审计失败。
- 原数据与结果：对全部先前 ACK 的数据库逐个验证由完整历史决定的 SQL 效果和仍保留的准确原始 result；合法已退休的结果应验证既有退休/请求世代屏障，不能承诺永久返回或重放。不得只验证文件存在或总条数。插入缺权威依赖/损坏 root 的实例必须令恢复不完整，不建立空库。
- 性能/成本：在固定增长速率下测试 deadline 与 partial；无持续变化且存储在约定延迟范围内时证明最终完成。保留所有失败/慢样本与 LIST、GET、返回字节、metadata 总量，不给“无限目录固定秒数完成”的承诺。

本地兼容端点仅证明已运行的本地协议。AWS Standard 对真实 ListObjectsV2、权限策略、路径/分页及延迟合同的验收单列；未运行时明确 NOT_RUN。

## 12. 更强瞬时 inventory 的边界

如果目标是“持续并发时，对整个 tenant/deployment 返回某个共同瞬间的完整 Ready/可见集合”，只添加 LIST、两轮相同扫描、时间戳或进程内目录都不能证明它。至少需要一个持久、可选择一致 cut 的索引/排序协议。

可研究不可变分片目录页 + 条件发布的目录根，根引用所有分片版本并成为明确的成员资格权威。创建/取消/删除/名称重用必须纳入同一个发布语义；仅在现有 HEAD/Binding 更新旁边补写一个异步索引会出现漏项。全局 freeze marker 的前后 GET 也挡不住已经越过检查点的迟到写入，不能把它称为 fence。多分片一致 cut、旧候选屏障、权限在切点上的含义和 GC pin 均需单独模型及真实验收。

第一版建议先交付本草案的完整前缀发现、启动边界槽覆盖和诚实的在线 non-snapshot 合同。它保留全目录目标，并给全计算丢失恢复一个可证明、可测的分母；它不声称实现更强的持续并发瞬时快照。

## 13. 证据与资料

仓库依据（输入哈希另存）：

- `docs/architecture/name-catalogue-plan.md` §§2、3、9、10。
- `docs/architecture/object-storage-native-proposal.md` §§8、10、14、18。
- `crates/scap-object-store/src/lib.rs`、`crates/scap-object/src/catalogue/{mod,inspect,records,types}.rs`、`crates/scap-object/src/format.rs`、`crates/scap-service/src/auth.rs`。
- 固定依赖 `object_store-0.14.2/src/{list.rs,aws/mod.rs,aws/client.rs,aws/builder.rs,client/s3.rs,client/http/connection.rs,client/http/body.rs,path/mod.rs}`；crate checksum `f1796bc93603f78c5760a69f2d58badc9618d22adade0a95385bb2adbae4eb94`。

官方外部依据：

- [Amazon S3 ListObjectsV2](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html)：general-purpose 的字典序、StartAfter、opaque continuation、IsTruncated、每页最多 1000、ListBucket 权限与可能出现的无效 XML。本文不把这些单页原语扩写成跨页快照承诺。
- [Amazon S3 data consistency model](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html#ConsistencyModel)：成功 PUT 后的 GET/LIST 可见性和单 key 更新边界；跨 key 原子协调需应用自行设计。
- [PaginatedListStore 文档](https://docs.rs/object_store/latest/object_store/list/trait.PaginatedListStore.html)仅作可导航参考；具体版本判断以本地固定 0.14.2 源码及编译证据为准。

`api-probe-evidence.json` 记录实际编译器、依赖 rlib 和源文件哈希；该探针没有执行网络请求、native SQLite 或产品恢复测试。后续实施和新门禁均为 NOT_RUN。

## 14. 首版恢复状态的固定解释

元数据协调器仅设置 metadata_classified 与槽覆盖状态，data_recovery 固定为 NOT_RUN，recovery_complete 固定为 false。严格全量恢复 profile 中，permission_blocked 仍表示对应 data/result/native 未验证，不能被计入“所有数据健康”；此类身份需单列并使 recovery_complete 为 false。Catalogue::resolve 对若干中间状态统一返回 NotFound，完整分类必须复用 crate 内部的严格 typed inspect/DatabaseSlot 路径，不能冒用 descriptor creator，也不能仅靠公开 resolve 推断全部状态。
