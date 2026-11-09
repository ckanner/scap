# SCAP N3：分段请求索引、存储世代、pin、物理回收与 PITR

**2026-11-09 状态更新：分段请求索引已随 PR #35 合入；独立 storage generation、pin/freeze/drain、产品 GC 和 PITR 仍未交付。** PR #36 只增加受限条件删除传输，尚未接入数据库回收。此前记录的 generation/pin 本地候选当前不能从工作区或远端取得，不能计入当前实现。最新可验证源码与工作顺序见[实施状态](../engineering/status-2026-11-09.md)。本文后续阶段仍为设计，不是 GC、PITR 或长期成本验收报告。

编写时间：2026-11-08。代码事实固定于 [`5b4e97e276988bd10ecfd25ff7abbf2a547a6459`](https://github.com/ckanner/scap/tree/5b4e97e276988bd10ecfd25ff7abbf2a547a6459)，tree `62aa55862c2798230f43136206c1958c26cf294c`。新分段索引批次计划基于 actor 候选 `32f3369e13cd89e32521d5d371ecbfda6834322c`；不得把候选代码或已有 actor 验收当成 N3 已完成。逐文件 SHA-256、证据定位及外部资料见[设计输入清单](../evidence/storage-reclamation-design-inputs-2026-11-08.json)。

## 1. 当前事实与目标边界

| 当前代码事实 | 位置（相对于仓库） | 对 N3 的约束 |
| --- | --- | --- |
| `Scope` 包含 deployment、tenant、database、incarnation、generation；完整 Scope 进入不可变对象封装与 key | `crates/scap-object/src/format.rs:35–50,458–471` | 不能把现有 `Scope.generation` 当 GC 计数器 |
| Catalogue 从创建身份导出 Scope，`own` 要求 HEAD Scope 与创建描述符完全相等 | `catalogue/records.rs:82–132`；`catalogue/mod.rs:386–409` | 改 generation 会破坏名称、创建来源及请求所属数据库身份 |
| HEAD format 3、对象 envelope format 2；每个窗口的索引是完整 `Vec<Entry>` | `format.rs:218–277,370–399`；`lib.rs:372–418,627–652` | 现在每次 append 要读写整个窗口索引，需显式格式升级 |
| 最多保留当前与前两个已满窗口；close_full 只去掉逻辑引用 | `lib.rs:597–624` | 请求退休不等于物理回收 |
| 每次冷恢复校验数据树、所有保留窗口及原始结果 | `lib.rs:342–369,810–858` | 分段后不能只校验被查询的枝而忽略坏枝 |
| `StoredResult.data_root` 是原提交回执的一部分，读取原结果不会遍历此历史数据根 | `lib.rs:437–460`；`docs/engineering/object-runtime.md:41–58` | 结果保留不自动产生 PITR 历史快照保留义务 |
| 暖 Session 查询只做一次 fresh HEAD GET，再从本地 SQLite 镜像查询 | `lib.rs:1062–1075` | 不应给每次热查询附加 pin Add/Release CAS |
| Objects 只有 exact GET 和条件 PUT，没有 LIST、DELETE 或版本枚举 | `crates/scap-object-store/src/lib.rs:32–48,64–68,175–199` | 不能把 GC 直接装进现有 writer 对象接口 |
| 当前 `Lifecycle::Maintenance` 仍可读，没有 pin、freeze/drain 或删除授权 | `lib.rs:167–210,554–570` | 不能把现有维护状态解释成 GC 安全屏障 |

现有硬上界包括：`MAX_REQUESTS=65,536`、`MAX_HEAD_BYTES=256 KiB`、单结果不超过 `64 MiB`，默认每窗口 `4,096` 条、`256 MiB` 结果预算，最多三个窗口；默认 SQLite cache `64 MiB`，普通操作 30 秒、恢复 1,800 秒。这些是配置/格式边界，不是已测吞吐，也不是整个 S3 bucket 的物理成本上界。来源：`format.rs:12–32,112–120,197–213` 与 `options.rs:30–55`。

目标拆成六个可独立验收的批次：分段索引；存储世代和无删除模型；pin/freeze 与可重启计划；经过能力验证的物理删除；显式保留快照；新身份 PITR。每批必须保留原 ETag 发布、原始 SQL 结果及请求取消屏障，不重放 SQL，不把 UNKNOWN 当未提交。

## 2. 首批：有界的不可变请求 B+ 树

### 2.1 数据结构与格式

以完整任意 `u64 request.id` 为排序 key。叶条目保留完整 Request（包含 principal、epoch、fingerprint 等现有字段）和原 Outcome。用 ID 定位后仍逐字段校验身份；同 ID 不同请求保持 Conflict，不能用哈希碰撞或桶满冒充 WindowFull。

每个叶和内部节点都有显式类型、epoch、尺寸上界。内部孩子保存有序且不重叠的最小/最大 ID、对象 hash、精确条目数和原始结果字节聚合；节点须验证类型、层级、范围、子树聚合与父边声明。实现只允许固定高度、固定扇出、固定叶容量，插入走一条路径并按确定规则分裂，生成叶及祖先的新对象。旧根继续可读；失败候选只产生 orphan。

候选参数为每叶 128 项、内部扇出 32，但必须在实现前按最坏的规范编码尺寸、65,536 项上限和分裂后的最小占用率推导最大高度。**这些参数现在是设计候选，尚无编码尺寸或性能实测结论。** 不采用追加链表或无界哈希桶：前者使查询随历史线性增长，后者不能保证任意合法 ID 分布下的容量。

根聚合必须等于 HEAD `Window.count/result_bytes`。单次查找可以只下载路径；完整冷恢复必须遍历所有叶及全部保留结果，验证 count、结果实际字节、完整 Request/Outcome、hash、epoch、范围与原回执，不允许用父节点自报聚合替代叶和结果验证。

第一版计划显式升级 HEAD 为 format 4；对象 framing 保持 `SCAPOBJ2`，增加明确的请求索引节点类型，不改 Scope、HEAD key 或原 Result 封装。旧 HEAD format 3 严格拒绝，绝不解读成空库。仓库当前是 greenfield，按 AGENTS 不建设旧库兼容层；若部署中有业务库，迁移必须成为单独授权、冻结与验收的批次，不能悄悄增加 fallback。

### 2.2 不变的业务语义

- 保留当前加前两个已满窗口及现有 count/result_bytes 满窗口判定，不降低容量来掩盖树的限制。
- Unknown、Closed、Retired、Cancelled、Conflict 和 Committed 原结果严格区分；结果字节、result hash、sequence、transition、原 data_root 的含义不变。
- 创建空窗口、append、cancel、close_full、lookup、冷恢复共用同一索引格式；每次发布仍使用构造候选时的原 ETag。并发只允许一个合法 HEAD 胜出。
- 冷恢复不能因为目标请求在某个好叶上，就忽略另一个损坏或缺失的保留叶。
- 本批不引入 storage_generation、pin、DELETE、LIST 或 PITR；不宣称总存储成本已收敛。

### 2.3 最小隔离改动范围

生产代码限定在 `crates/scap-object/src/{format.rs,lib.rs,request_index.rs}` 及该模块实际需要的子模块、对应单元测试。`format.rs` 定义严格 codec/类型边界；`request_index` 实现独立的查找、COW 插入、全树遍历；`lib.rs` 接入创建、append、resolve 和完整历史验证。Native SQLite、SQL codec、store、service actor、SDK 的公共语义不变。

必须同步新格式说明和独立真实验收 oracle；现有 `experiments/object-service/audit_wire.py` 明确检查 HEAD 3，`service_oracle.py` 汇总也写死 3，不能在正式 gate 中放过旧解析器或简单替换数字而不验证新树。新增生产文件须进入正常逐文件覆盖统计，不借测试分类或排除规则逃避覆盖。Catalogue 的创建来源、Scope 与名称语义虽不修改，仍需跑既有回归。

### 2.4 首批必须完成的门禁

1. **独立语义模型。** 用不导入生产算法的平面映射作为参考，覆盖递增、递减、交错、稀疏与边界 `u64` ID；完整身份冲突；叶分裂、根增长；count/result_bytes 边界与溢出；取消；多于三个 epoch 后的所有解析状态。树的容量必须覆盖最大合法窗口及恶意 ID 排列。
2. **格式与坏枝。** 拒绝重复 ID、错误顺序/范围/层级/epoch/类型、错误聚合、错误 hash、损坏长度、缺失子节点、重复/循环引用及不合法空节点。查找正确不代替全树验证。
3. **精确单元门禁。** 每个生产文件 line/function/region/branch 均为精确 100%，保留真实分母；fmt、严格 clippy 和工作区既有 gate 不降级。开发运行与冻结候选正式运行分别记录。
4. **正式 native + HTTP + signed S3。** 固定输入分母，实际产生足够条目跨越分裂和根增长；随机/BLOB 原结果重复查询、取消与窗口退休；停止全部计算进程后冷恢复；在未被普通 lookup 触及的枝上注入缺失/损坏并验证失败关闭。保留全部调用、失败和原始响应。
5. **故障发布。** 在叶、祖先对象 upload/readback、HEAD CAS 前后 UNKNOWN 与 native publication 边界注入故障；成功 ACK 必须能从 HEAD 的完整依赖闭包重建；旧候选 412 后没有 ETag 刷新或 SQL 重放；trace 中没有 DELETE。
6. **可解释的 I/O 证据。** 预先固定工作负载，记录每次查找/插入的对象请求数、索引字节及树高度，验证路径增长上界。单次本地 SeaweedFS 延迟不是 AWS 承诺，也不是生产 TPS。

## 3. 独立 storage_generation，保持逻辑身份

同一逻辑 Scope 下增加物理对象空间：

```text
.../inc/{incarnation}/gen/{scope.generation}/storage/{storage_generation}/objects/{sha256}
```

同 Scope 迁移时复制原始对象字节，不把 storage_generation 塞入现有 Chunk/Result frame，因此 hash 和原回执不变。首版要求当前数据树、所有保留请求索引及原结果在一个物理世代内形成完整闭包，禁止跨物理世代的隐式边。

一次操作捕获不可变 `ObjectContext { logical_scope, storage_generation, admitted_head_serial, pin_or_attempt_identity }`，所有读写都使用此上下文。不能通过可变的 `Database.current_generation` 改写正在进行的旧候选目的 key。现有 `DataObjects for Database` 需在此批改为显式对象上下文。

HEAD 保存 `active_generation=A`、`allocated_through=M`、至多一个 `staging_generation=T`。分配只用 M+1，失败也永不复用。已退休集合可表示为 `1..=M` 去掉 A/T；模型须证明该集合单调增加。只有当前 T 可晋升，放弃的 T 永久退休。由此处理 T>A 的失败迁移，而不永久保存一条对象级或世代级零字节 tombstone。退休资格与对象已经物理消失必须分开记录。

### HEAD 技术序号

增加严格单调的 `head_serial`，每次 HEAD CAS 都增加；原业务 `revision/transition` 继续表示 SQL 与管理操作。Pin、物理迁移仅改变技术序号，业务成功仍遵守 SDK 的 expected revision + 1。否则 pin Add/Release 可以把 HEAD body 变回完全相同的内容，出现 ETag ABA；也会无故破坏现有管理 API。

Pin 可以用授予时的 serial 派生唯一身份，但 pin 表、状态字段与 ACL 在 256 KiB HEAD 硬限制内必须算清最坏尺寸。不能通过增大 HEAD 或忽略 codec 上界掩盖无界元数据。**任何已封存 SQL 候选均不得因技术 CAS 冲突而换 ETag 重绑。**

## 4. Pin 与热路径：避免把读请求变成提交竞争

| 操作 | 建议保护 | 预期额外权威写入 |
| --- | --- | --- |
| 已完整物化的暖 Session 查询 | fresh HEAD 鉴权及根/配额对齐；无远端对象读取 | 0；维持 1 HEAD GET |
| 冷恢复、完整历史验证 | 在对象读取前登记的世代 pin | 按一个有界恢复操作或批次登记/释放 |
| HEAD 已足够判定 Retired 的 lookup | fresh HEAD | 0 |
| 要读取保留索引/Result 的 lookup | 有界进程/数据库/世代批次 pin | 批次 Add/Release，而非每请求两次 CAS |
| 原 ETag 封存的写候选 | 当前世代保留到 cutover，原 CAS fence；是否另加 pin 由模型定论 | 不为追求吞吐偷偷重绑旧候选 |

每操作 Add+Release 至少增加两次 HEAD 条件 PUT，还要相应读取和校验。即使只是 pin 元数据变化，也会使同时封存的 SQL 候选 412。单库只有一个 HEAD 发布点，这些 CAS 与业务竞争；pin 不是免费的锁服务。

推荐有界批次 pin：本地 broker 按进程、完整数据库身份、物理世代合并，维护有界 refcount 与 admission gate。取得 guard 和检查 gate 必须原子；关闭 gate 后拒绝新 guard，等所有已有 guard 真正退出才释放 durable pin。不得把读者不同 scope alias 变成重复缓存或无限 pin。每个调用仍读取 fresh HEAD 校验权限，不把 pin 当 ACL 租约。全局/租户/数据库 pin 数和活动批次数要明确配置，并给 control lookup 保留配额。

Idle 计时器只可在本地 guard 数为零时主动释放；它不能证明远端暂停进程已经停止。进程暂停或崩溃且 pin 未显式释放时，最小首版报告 **GC_BLOCKED**。TTL 到期、lease 数字变化、当前时钟越过 deadline 都不能授权删除仍受 pin 保护的数据。

若未来要强制撤销 pin，必须单独建模：所有远端读和公开成功出口都检查不可复用 token；撤销后旧流程只能返回 Fenced/SnapshotExpired；输出之前原结果已完整物化；native 提交仍受原 HEAD CAS fence。不能仅在入口检查 token，再声称暂停在检查之后的执行者已经停止。本文不把此强制撤销方案算作首版已解决。

## 5. Freeze、复制、Seal 与可重启回收计划

物理回收状态独立于现有 `Lifecycle::Maintenance`，具有固定 gc_id、源 A、目标 T、根集合指纹、计划身份与有界进度。

| 阶段 | 允许的工作 | 必须满足的条件 |
| --- | --- | --- |
| Freeze / Copying | Status、完整暖镜像查询；保留配额下的短 control lookup；复制源闭包 | 固定业务根集合；阻止新写入/关闭窗口和新大恢复；允许当前 ACL 变更须在最终发布中继承 |
| Seal | Status 与完整暖查询；已有对象读取 guard 排空 | 关闭新的源世代远端 admission；既有 pin 显式释放或继续阻塞 |
| Promote | 单次 HEAD CAS 选择完整验证的 T | T 完整；源根与计划匹配；pin 安全；不恢复 Freeze 时的旧 ACL |
| Sweep | 枚举并删除永久退休的精确世代 key | 专用 GC 权限；绝不触及 A/T、HEAD、Catalogue 描述符、名称绑定或永久身份屏障 |

完整闭包包括当前数据树、所有保留请求索引、原始结果对象及显式保留快照。`StoredResult.data_root` 只是回执身份，不沿它扩张历史数据闭包。复制同 Scope 字节后全量校验，原 Result 保持完全一致。

技术维护步骤可以从新的 HEAD 构造下一步，但必须重新证明固定计划、源根及状态条件；这不是许可重绑旧业务候选。ACL 更新、takeover 等与计划的关系须在模型中逐项定义；若某操作改变被冻结根集合则 Busy 或明确终止重建计划，不能隐式继续旧计划。

恢复记录必须在执行 DELETE 前持久化，包含计划身份、精确有界 key/ETag 批次与游标；Applied、Missing、Conflict、Unknown 是不同结果。重启后可继续或重查批次，不需要重放 SQL。不得每删一个对象就永久留下一个新对象级审计 tombstone。计划可放入 staging 的少量不可变对象，HEAD 只保留有界当前批次；完成后按明确顺序让工作元数据也进入可退休世代。至多一个活跃 GC、固定并发与复制空间预算。

现有对象发布在 deadline 前后的检查只约束客户端观察。客户端超时不等于服务端取消已收到的 PUT，因而不能据此宣布旧上传不存在。

## 6. 安全与物理成本收敛是两份保证

### 6.1 可以建立的安全不变量

1. 当前与 staging 世代及 durable pin 所需闭包不被删除。
2. 永久退休的世代不再成为新的 HEAD 权威，任何旧业务候选不能绕过原 ETag。
3. 延迟 DELETE 只携带旧物理世代 key；即使新世代包含相同字节/hash，也不删除新对象。
4. Pin 暂停时保留保护；不能靠数值过期删数据。
5. HEAD、Catalogue 创建身份、名称屏障、请求完整身份及已确认原始结果不因物理迁移退回旧状态。

### 6.2 不能仅靠 epoch 或一次 LIST 保证的事

AWS 的 `If-None-Match: *` 检查当前 key 是否存在；key 不存在，或 versioned bucket 当前为 delete marker 时，旧 CreateOnly PUT 可以再次成功。因此，旧世代切换和删除后，暂停在 deadline 检查之后的旧 uploader 仍能把 orphan 写回旧 key。它不能重新成为 HEAD 权威，但确实重新占空间。来源：[S3 conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)。

S3 的强 GET/LIST 一致性和单 key 原子性不提供多 key 原子事务，也不阻止未来才抵达的旧 PUT。分页 LIST 不是全 bucket 的冻结快照。一次、两次空扫描都不证明将来永久为空。来源：[S3 consistency model](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html)、[ListObjectsV2](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html)。

因此，Sweep 必须公平地重新从退休范围起点扫描；迟到 key 可以出现在已经越过的游标之前。状态可以报告“此轮为空”“最后发现/删除时间”，不能报告无条件的永久物理完成。零字节 tombstone 仍有对象/key 成本，无界数量不构成成本有界证明；通用 bucket TTL 也不提供活跃闭包安全证明。

### 6.3 Eventual cost convergence 的必要前提

在以下前提下才可论证退休世代最终清空：旧世代操作总量有限；遵守协议的执行者不再创建新的旧世代操作；每个已发起旧 PUT 最终结束；存储持续可用；重复 sweep 公平覆盖全部退休 key；显式保留集合与数据库身份集合有界。暂停 pin 必须先通过显式释放、已证明的停止/quiescence 或未来严格撤销协议解除。工作负载停止后，当前世代的 orphan 还需要最后一次迁移才能一并退休。

持续写入时还需 GC 的有效服务能力高于垃圾产生速率、足够复制空间、可用带宽和有界并发。没有这些容量与调度假设，安全实现仍可能成本持续增长。存储侧授权 fence 可以加强前提，但必须证明已经在途的 PUT 也得到处理；不能假定 IAM 撤销完成即取消所有既有上传。

永久数据库身份屏障、Catalogue 创建/命名历史、不断新增数据库的成本不属于单库 payload GC。需另设租户创建配额或独立保留合同，不能把单库回收结果宣称为整个 bucket 无条件成本有界。

### 6.4 必做真实暂停验证

按固定顺序执行并保留原始 S3/HTTP、全部调用分母、ACK、进程和实际 binary 收据：

1. writer 读到 HEAD G，真实旧对象 PUT 已越过客户端 deadline 检查，在代理转发前暂停。
2. G 完整迁移到 H，退休 G，执行完整 sweep 并记录当时空 LIST。
3. 释放暂停 PUT，实际观察旧 key 被重建，证明测试真的覆盖迟到上传。
4. 旧候选不能发布 HEAD、不能得到提交 ACK；H 中相同内容对象与当前数据库保持可读。
5. 下一轮 sweep 找到并删除重建 orphan；再执行新写入、原结果 lookup 与冷恢复。
6. 对称地暂停旧 DELETE，待 H 发布同内容后释放，证明只影响 G。另验证 paused pin 使 GC 保持 BLOCKED，未到释放条件绝不删除。

这才分别证明“迟到对象不破坏当前权威”与“在前提成立时第二轮能收敛”。不能删掉第 3 步，只用 mock 或最终成功汇总替代。

## 7. S3 删除接口及能力边界

截至本次核对，S3 general purpose 和 directory bucket 均支持基于 ETag 的条件 DELETE。`If-Match` 是额外并发校验，不能代替不复用物理世代；相同内容重建可能具有相同 ETag。来源：[conditional deletes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-deletes.html)、[ETag 定义](https://docs.aws.amazon.com/AmazonS3/latest/API/API_Object.html)。

Versioned bucket 的默认 DeleteObject 产生 delete marker，不会物理清掉旧版本；需 VersionId 级别枚举/删除协议。现有 Stored 没有 VersionId。首版 GC 只允许已验证的 unversioned backend；versioning 状态未知、Object Lock、MFA delete 或不满足条件删除语义时禁用回收。来源：[DeleteObject](https://docs.aws.amazon.com/en_en/AmazonS3/latest/API/API_DeleteObject.html)、[Delete markers](https://docs.aws.amazon.com/AmazonS3/latest/userguide/DeleteMarker.html)。

GC 使用独立 capability/权限，不把 DELETE 暴露给普通 SQL writer。须验证精确 prefix、分页不漏项、continuation token、每页上界、错误 XML、每个对象的删除结果与重试边界。ListObjectsV2 每次最多 1,000 项，HTTP 200 也可能返回无法解析的 XML，解析失败必须停止。批量删除的 HTTP 200 不代表全部项成功。对应来源：[ListObjectsV2](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html)、[conditional deletes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-deletes.html)。

SeaweedFS 上的真实 signed S3 合同不能证明 AWS Standard 云端合同。S3 可见对象逻辑字节、Seaweed 实际磁盘占用（可能需独立 vacuum）和 AWS 计费字节分别记录；没有真实测量就标 NOT_RUN。

## 8. 显式保留快照与新身份 PITR

首先引入明确保留的快照/提交根集合、容量与保留策略，并把它们加入 pin 与 GC 闭包。首版可以支持命名快照或 sequence 目标，不直接承诺任意墙上时刻的恢复；后者还需可审计的时间映射与完整历史链。

PITR 创建新的 Catalogue 创建操作，从而得到新的 database/incarnation；现有逻辑 generation 可仍为初始值 1，因为完整身份已不同。源镜像被 pin，目标对象因 envelope 中包含 Scope，必须针对新 Scope 重新封装与验证。这与同 Scope 的物理世代复制不同。

目标有新的 ACL、owner、请求窗口与初始请求屏障；源 provenance 可记录，但不能恢复旧授权、旧所有者或旧请求身份。目标完整闭包验证后才进入 Ready/Bound；旧 HEAD、tombstone、名称与取消屏障完全保留。跨源/目标的 durable restore intent、源 pin 释放与崩溃恢复必须另行建模，不能使目标长期引用之后会被 GC 的源对象。

## 9. 后续批次与证据承诺

| 顺序 | 可声称的完成结果 | 额外门禁 |
| --- | --- | --- |
| N3.1 分段请求索引 | 有界路径读写与原请求语义保持 | 第 2.4 节；GC 仍关闭 |
| N3.2 generation / head_serial / pin 模型 | 定义并证明退休单调性、pin/冻结顺序及不重绑 | 独立状态机穷举/性质模型，dry-run，不 DELETE |
| N3.3 实际回收 | 在明确 backend 与活性前提下安全重复 sweep | 暂停 PUT/DELETE、pin 阻塞、全部重启、能力拒绝、原始云端证据 |
| N3.4 快照与 PITR | 显式保留目标、新数据库恢复、完整权限边界 | 跨身份恢复与跨 authority 崩溃模型、原结果与历史根验证 |
| N3.5 长期运行 | 给定负载和配额下观测到成本/延迟稳定 | 长跑输入账本、垃圾速率/GC 速率、恢复预算、资源与成本曲线 |

本稿初版只有代码阅读、官方接口资料和设计推导证据；分段索引后续实现及验收见[分段索引说明](segmented-request-index.md)和[发现/恢复记录](../engineering/discovery-recovery-validation.md)。删除传输合同不代表数据库 pin/退休/回收已经成立。N3 状态机、产品 DELETE、AWS 云端故障、PITR 和长期成本仍分别验证。所列不变量是必须实现和验证的要求，不是完成声明。原始结果、固定输入与失败日志均应保留；开发检查不能替代冻结源码和实际 release binary 的正式验收。
