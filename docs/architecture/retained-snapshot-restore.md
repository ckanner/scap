# HEAD9：显式保留快照与新 Scope 恢复

状态：设计与独立可执行模型候选，产品未实现。模型运行结论以带完整源码指纹的独立manifest为准；本文不预先声明通过。固定实现输入为 HEAD8 候选 `3e850357478133ae2b76007c3e0e9609d3d8ac02`；其 core 字节对应 `core-freeze-01.json` 的完整摘要 `4ef26b654748b1d21a1d483ba22c7e2f6ebeba2de4a25884d27c93cc3916927b`。HEAD8 的正式验收不认证本文的新协议。

## 1. 选择与交付边界

推荐先实现 **当前 A 内的有界 retained roots，随每次 compaction 一起复制**，再把一个明确 SnapshotRef 恢复到全新的 Catalogue 创建身份。首片是显式命名点或明确 sequence 的恢复；只能捕获当前已提交根，不声称能选择任意历史 sequence、任意墙上时刻或从 Result.data_root 恢复历史镜像。

每个 retained root 指向同一逻辑 Scope 的不可变数据树。当前数据库、全部保留快照的数据树、现有请求窗口及原结果，都必须在当前物理 A 中构成闭包。CopyBasis 固定完整快照列表；COPY 验证并复制这些数据树，之后仍按现有规则退休旧 g。保留的是数据根，普通长读仍可中止，不登记不可撤销的进程 pin。

| 方案 | 必须新增的权威 | 空间与工作量 | 首片判断 |
| --- | --- | --- | --- |
| 当前 A 内 retained roots | HEAD9 有界快照列表、accepted-snapshot proof、扩展 CopyBasis/closure、new-Scope restore recipe | 捕获只读 manifest/写少量元数据；同 Scope COW 共享对象。迁移时逐根验证，可按有界 root 集合去重 | 最接近 N3 既定闭包，推荐 |
| 每点独立 archive Scope | 永久 frozen archive 类型、发布/释放/GC 权威、独立发现与 ACL、同样的新 Scope restore recipe | 每个点都要完整跨 Scope 重封装，Scope 入 hash 导致跨 archive 点不共享现有对象 | 可做后续独立备份；普通可写 clone 不能冒充 immutable archive |

仅把一份完整数据复制成新的普通 Database 不足以实现永久 archive：其 ADMIN 仍可重新激活、修改数据和 GC 原根。若采用独立 archive，必须明确引入不可写的 archive authority 或保留根协议，不能依赖“约定不写”或旧 READ-only ACL。没有源保留点时，archive 初始复制被源 GC 中止可以安全失败，但失败后的旧点未必还能重建。

本方案不改变源 Scope、不复制源权限/owner/请求窗口，不覆盖旧 HEAD，不撤销源请求取消和退休屏障。目标以新的 database/incarnation、初始 request_epoch=1、空请求索引、sequence=0、creator 的新 ACL 开始；源 sequence 等只作为 provenance 保存。

## 2. 已核对的现有构造器与所需改动

* `format::Scope` 已进入 SCAPOBJ2 frame 及对象 hash；`data_tree::{walk,check_node,check_chunk}` 校验几何。因此同 Scope COPY 可原字节搬运，跨 Scope 必须重编码 Chunk/Node/Manifest，并自底向上重新计算父 hash。
* `closure::Cursor::new/for_copy` 当前只有一个数据 manifest，随后遍历三个 retained request windows。`complete` 对该树的 pages/chunks 和每个窗口独立对账。不能简单再累加几个 root 而继续用单个 manifest_pages 校验。
* `CopyBasis::capture/matches` 目前固定 data_root/windows/sequence/revision/quota/retention/request_epoch；必须新增完整 snapshot entries。`compact_begin/copy/promote/abort` 必须保存、验证和继承这些 entries。
* `PreparedHead::new`、`reclamation::publish_technical`、owner 私有候选都必须保持不属于自己的 snapshot/restore 字段；不得因 owner_start 当前写死 format=8 而把 HEAD9 降级。
* `Catalogue::resume_create` 当前可 Reserve→Provision→Bind→Complete；`complete` 可把已验证 Provisioning 变为 Ready。恢复 recipe 不能经过旧 empty-create Complete 而提前发布空库。
* `Catalogue::view` 的 Name 双读与 Proof→HEAD 顺序必须保留。`abort_create` 的 Aborting、FenceAbsent/FenceOwn、OwnDeleted/ForeignOccupied proof、Name tombstone 路径继续作为目标取消屏障。
* HEAD7/8 terminal seal 当前假设 retained roots 为空。HEAD9 若还有快照，不能安装 terminal seal；已有 terminal 永远不能新增 root 或 payload context。

## 3. 源 HEAD9 与永久快照身份

### 3.1 严格字段

HEAD9 新增必填 `snapshots: []`（至多 64 条）、`snapshot_limits: {max_points,max_logical_bytes}`、必填 nullable `restore_origin`。HEAD6/7/8 必须完全省略这些字段；不能把未知/缺失字段默认为空。HEAD9 的 owner_plan 可省略仅表示尚未采用 V2，显式null仍拒绝；一旦已有 owner marker，任何后继必须保留或经现有 owner V2 合法替换，legacy owner 永久拒绝。HEAD9 的普通/终态 storage 规则与现有 HEAD6/7 一致，额外要求 terminal => snapshots 为空。

限额是持久业务策略：默认 `max_points=64`、`max_logical_bytes=32GiB`；格式硬界为最多64点、总字节最多 `64 × MAX_PAGES × 4096`，可配为0以禁止新增点。当前ADMIN可在Ready/Maintenance用原HEAD/ETag更新限额，更新推进业务revision/transition及技术serial；新限额必须容纳已有live数量和gross逻辑字节。Deleted/terminal不开放这个业务更新入口，避免改变原delete/abort barrier；那里只释放旧点、保留原R/transition。服务本地copy/read预算不参与格式合法性，换一个较小预算的实例不能把原来合法HEAD判Corrupt；它只能对新复制尝试返回Budget。限额进入CopyBasis，copy期间不更新。

SnapshotEntry 建议字段：

```text
reference = { creator, operation, capture_serial, descriptor_hash }
label: 最多128 UTF-8字节，无控制字符
point = { data_root, page_count, sequence, source_revision }
```

数组按 capture_serial 严格递增；live label 不重复；完整 ref 不重复。`capture_serial` 是 capture CAS 后的 head_serial，即 descriptor 原 head_serial+1，不由客户端任选。要求 `0 < source_revision < capture_serial <= HEAD.head_serial`、`sequence <= HEAD.sequence`、`page_count <= MAX_PAGES`，hash 和所有身份严格验证。名字只是在当前 live 集合内的标签；release 后同名新点必须获得新的 serial/ref。restore descriptor 永远保存完整原 ref，不会在重启时按同名重新选点。

SnapshotDescriptor 是永久不可变控制记录，包含完整 Scope、creator/operation、原 expected revision/head_serial、label、原 HEAD canonical hash/同次 ETag、精确 point、schema 和输入摘要。与 owner prepare 相同：输入在调用前保存；响应丢失可按 operation 找回实际 first-winner descriptor；不能重新用较晚 HEAD 给原 operation 构造新 base。

从HEAD6/8首次升级时，descriptor还固定此次first-winner的初始snapshot_limits；不能在resume时用另一实例的新默认重建候选。HEAD9已有持久limits时完全沿用原HEAD策略。HEAD7 terminal不接受capture或新payload context。descriptor保存完整HEAD的SHA256和原ETag，不把最多256KiB HEAD内联到小控制记录；当前exact GET须同时匹配hash、原R/S、point和同次ETag。

prepare 对现有 descriptor 的原始 GET 结果先暂存，随后 fresh HEAD/current ADMIN+READ，之后才处理内容、缺失或输入冲突。新建还要求 Ready、没有 pending owner/copy/sweep/terminal、原 R/S 一致、有快照数/字节额度。page_count 来自原 Snapshot 下真实 manifest GET 的 hash/Scope/类型校验，不能接受客户端自报。若当前 entry 或 accepted proof 已引用同身份，descriptor Missing 是 Corrupt，不能重建。

### 3.2 capture

`snapshot_capture` 读取原 descriptor 和 fresh HEAD，检查当前 ADMIN+READ。只有 HEAD 与 descriptor 原完整 body/ETag 匹配，才能 clone 此 HEAD、升级/保留 HEAD9、增加 serial、插入该 entry，然后以原 ETag 发布一次。业务 revision/transition、sequence、owner、数据根、请求窗口保持不变。原候选遇到 412/Unknown 不换 ETag、不换点、不自动发第二次 CAS。

当前已经有同 entry 时只做稳定观察；同 identity 却不同 descriptor hash/point，先完成 HEAD2 稳定屏障，稳定才 Corrupt，变化则 Conflict。其他合法 HEAD 后继使原 admission 失效时，只能报告未来已 fence、过去未知；不能把 descriptor 存在当作 capture 已接受。

### 3.3 release 与 proof

删除 live entry 前，必须从真实当前 entry 构造并条件创建一个固定 `SnapshotAcceptedProof {version, scope, entry}`，再 exact 读回原字节。proof 不包含这次 release 的新鲜 ACL、ETag、时间或较晚 revision。它证明该 entry 曾被 HEAD 接受；**单独存在不证明 release 已生效**。

确认 proof 后，release 以当前原 ETag 移除完全相同的 entry，仅推进 serial。copy/sweep/pending owner 时拒绝 release。重启后的新 release 可在新鲜 ADMIN 下继续同一 ref；每个具体 CAS 仍固定自己的原 ETag。当前 entry 仍在 => Retained；稳定 HEAD 中 entry 不在、serial 已跨过 capture_serial、固定 proof 匹配 => ReleasedObserved；这不是过去调用的 ACK。proof/descriptor 永不进入 payload GC。

ID 防复用来自双重约束：capture ID 必须是原 S+1，具体 CAS 又绑定那个原 HEAD。release 或任意较晚 HEAD 使这个原 CAS 永久失效。新 capture 不能指定旧 ID；新同名点也不能冒充旧 ref。不存在“entry absent 就允许重注册旧 ref”的入口。

### 3.4 Deleted 与 terminal

正常删除保留 snapshots，不将备份悄悄删除。普通 status/query/lookup 仍拒绝 Deleted。专用 snapshot 元数据接口用当前 ADMIN；从仍保留的快照开始恢复必须有当前 ADMIN+READ，允许 Deleted、禁止 terminal。Deleted 上只允许 release 已有快照，不允许 capture 新点。最后一个 entry 释放前，terminal seal 必须失败；释放完毕后仍要经过既有 direct/named actual deletion source 验证才能 seal，不能只检查 lifecycle。

首片仍保持 compaction 的 Ready admission；Deleted 保留点可恢复/释放，但不新增“Deleted 压缩”调度承诺。其 A 可能携带更多历史 orphan，保留期间的成本必须如实报告。

## 4. 闭包与 GC

HEAD9 活跃闭包为：当前 data tree + 全部 live snapshot data trees + 原有 retained request-index/Result 闭包。Snapshot point 的数据树完整遍历；Result.data_root 与 restore provenance root 都不自动成为保留边。

COPY 对每个 snapshot root 单独验证 manifest page_count、节点层级/范围、chunk 起点/长度和每棵树的最终页数。不能用全部树总和掩盖一棵多页、另一棵少页。当前 quota 只约束当前数据；历史点用 capture 时固定的 page_count 和格式几何上界校验，不能因为后来缩小业务 quota 就把合法旧快照判为损坏或静默丢弃。目标 restore 必须另检查自己的新 quota 能容纳该 point。

CopyBasis 保存 snapshot entries 的完整规范列表。register/release 在复制期间 Fenced；允许的 ACL 改动不改变列表。只有当前 root、所有 snapshot roots、所有结果依赖均已复制并 exact 回读后才 Seal。Promote 保留列表并切换 A，旧 g 按现有谓词退休。当前/target/持有点的数据损坏不能降格为 SnapshotExpired。

普通 snapshot restore 的一次 source context 仍固定原 Scope/g/HEAD/期限。源切换并回收旧 g 后，未完成读取可在严格 fresh retirement 证明下得到 SnapshotExpired；新的明确 resume 可以在 fresh 权限和仍存在的同一 snapshot ref 下，从新 A 重新开始。它没有重新选择业务点，也没有重用旧 cursor/native prefix。已失败前缀不能因随后看到健康 HEAD 而续跑。

## 5. 新 Scope 目标：first-winner recipe 与最小状态机

### 5.1 不能先向一个尚未取得身份槽的目标搬大数据

目标由新的 Catalogue creator/operation 导出新 database/incarnation。先 Reserve Name，再条件创建 **自己的 Provisioning HEAD**，然后才开始大数据复制。如果在搬运后才争取 HEAD，foreign identity 可在复制中赢得同一物理 slot，留下大批无法由当前 OwnDeleted collector 证明退休的 losing-Scope orphan。先取得 slot 把这一风险限制在既有创建 bootstrap 边界。

新增严格 Catalogue Descriptor recipe：`Empty` 或 `SnapshotRestore`。现有 format1 Empty 记录保持明确解码；新的 restore 用显式新版本/带 tag 的 wire 类型，不能给旧结构静默加默认字段。两种 recipe 共用 creator/operation 的 first-winner 身份槽，不能让同一 operation 同时变成 empty create 和 restore。

RestoreDescriptor 固定：目标 Creation（name/expected-name-revision/新 Scope）、原输入 options 与 first-winner effective quota/retention、新 ACL、源完整 Scope+SnapshotRef+point、重封装版本。首片新 ACL 固定为目标 creator 的 read/write/admin；不继承源策略。后续需要变更目标 ACL，走既有正常管理操作。源/目标可在同 tenant 内，跨 tenant 不默认开放。

`restore_origin` 固定形状为 `{descriptor_hash,phase}`，phase严格为 `{kind:"copying"}` 或 `{kind:"copied",completion_hash,data_root,page_count}`。它引用真实RestoreDescriptor，不把源ACL或源HEAD内联到目标HEAD。Ready 后其 Copied 内容成为不可变 provenance。普通 SQL 只改当前 root；sequence>0 后 provenance root 不进入 GC 闭包。任何普通/owner/storage 构造器都不能改写 origin、降回 Copying 或替换源 ref。Copied阶段的Bind/Ready/恢复inspect必须exact验证已引用CompletionRecord存在且hash匹配；Missing是损坏依赖，不能重新复制伪装未完成创建。

### 5.2 状态及效果

| 可恢复状态 | 权威事实 | 下一步 |
| --- | --- | --- |
| Prepared | immutable restore descriptor 已存在 | 以原 Name 条件 Reserve |
| Reserved/无 own HEAD | Name 引用同一创建身份 | bootstrap 新 Scope，Absent PUT Copying Provisioning HEAD |
| Copying | own Provisioning HEAD，A=1，空请求窗口，active=false | 新一次受限 copy；可读取已有 CompletionRecord |
| CompletionRecord exists | 曾有一次完整验证、独立目标依赖及源授权通过 | 验证目标闭包后，用原目标 ETag 安装 Copied |
| Copied/Reserved | own HEAD 的 imported root/CompletionRecord 已绑定 | 原 Name Reserved ETag 发布 Bound |
| Copied/Bound | Name 与 own HEAD 双读稳定 | 完整验证目标，原 HEAD CAS 到 Ready/inactive |
| Aborting | 既有 Name 取消已接受 | FenceAbsent/FenceOwn、实际 barrier proof、Name tombstone |
| Aborted/Deleted | 永久目标取消或删除屏障 | 既有实际 terminal retirement，再 GC 目标 A |

从 Copying 到 Copied 只推进 target head_serial，保持 revision=1/sequence=0，替换 provisioning 的 empty root 为 imported root，绑定固定 CompletionRecord。Ready 是原创建的业务后继，revision=2，仍 inactive；没有隐式 owner activation 或 native Session 返回。原 SQL 请求身份、取消记录、结果、snapshot refs 均不导入。

旧 `resume_create` 不能将 SnapshotRestore/Copying 当 Empty/Provisioning 完成。创建 inspector、binding、discovery/recovery 和 terminal 来源检查都必须认识 recipe；未知/不匹配不能 fallback 空库。

### 5.3 CompletionRecord 的准确含义

固定记录内容：restore descriptor hash、源完整 snapshot ref/point、目标完整 Scope、目标初始 data_root/page_count、空请求根、重封装/native 格式版本。它由私有 CompleteCopy capability 构造，调用人不能提供任意 root 或“已完成”布尔值。

创建前必须已经完整读完源树、检查每条边/页数，完成 native 镜像验证，针对新 Scope 重编码并 exact 验证全部目标对象，最后再次检查源当前 ADMIN+READ。record 仅 Absent PUT，并 exact 回读。稳定内容不混入后来 ACL/HEAD counters，否则重启可能重建不相等的所谓同一 completion。

它是“这份完整且独立的数据已被授权转移”的持久事实，不是原 HTTP 调用收到 ACK。其存在时，后续新 resume 可以只依赖目标当前权限和完整目标闭包恢复进度，不再要求源 point 仍被保留。缺失 record 且目标已引用它是 Corrupt，不准从请求/磁盘重建。仅部分 target objects 不是 completion。

迟到CompletionRecord PUT分两种：若原attempt已完成独立复制和最终源授权，之后源release/terminal/GC不撤销这个已形成的候选，PUT仍可接受，目标可按自己的新鲜权威继续到Ready。若目标abort已经接受，Name/own HEAD原ETag与永久取消屏障仍会关闭Ready；迟到record可以成为永久小控制orphan，却不能让被取消的目标payload重新active。源release和目标abort不是同一个授权边界。

## 6. 两 Scope 的权限和竞争线性化

* prepare 新目标与 Reserve/Provision 要求真实目标 creator/provision admission；原 caller 输入不提供可信 principal。现有记录 first-winner 返回前仍鉴权。
* 没有 accepted CompletionRecord 的每次 copy 必须 fresh source HEAD、当前 ADMIN+READ、同一 held SnapshotRef，并 fresh 验证目标 own Provisioning/Copying 与 caller 权限。跨进程不继承旧授权或数据 context。
* copy 完成后，创建 CompletionRecord 前进行源HEAD1→实际SnapshotDescriptor/必要的accepted proof→源HEAD2的稳定屏障；HEAD1/HEAD2 body和ETag完全相同后，按该次当前ADMIN+READ处理元数据。跨读变化先Conflict，不把一个过渡组合永久隔离；稳定且完整ref/hash/point矛盾才Corrupt。若撤权已在这次检查前生效，拒绝、无completion、无Copied/Ready。当前权限不足也先Denied，不泄漏后读记录或输入冲突。
* release阻止新的source attempt/context admission。已经合法准入、尚未失败的原context可以继续GET；若在旧g仍可读期间完成完整源/目标验证，则可在当前权限仍有效且accepted-snapshot proof匹配的条件下完成。最终稳定屏障后不再补源payload GET。若旧g先被回收，该attempt失败；失败或重启且无completion时不能凭旧descriptor为已释放ref重新准入。这里没有每GET的HEAD锁，也不承诺release完成会撤回所有在途读。
* 在最后源权限观察之后发生的撤权不能撤回已经完成的授权读取。不存在跨源 HEAD 与目标记录的原子事务；不能承诺“撤权一返回，所有先前完成的数据复制都从目标消失”。
* CompletionRecord 已接受后源 ACL/GC 不再是目标依赖；继续推进必须有目标当前授权。若目标已 Aborting/Deleted，不能转为 Copied/Ready，即便原 completion PUT 后来才出现。
* copy 的 source 与 target context/预算/失败来源独立。target PUT/readback 或本地磁盘错误不通过 source retirement probe 变成 SnapshotExpired；source hash-valid semantic corruption永远不是 expiry。source attempt 失败即消费其全部局部前缀。

目标 abort 沿既有 Name CAS 和 HEAD fence：Aborting 赢得 Reserved ETag 后，旧 Bind 永远 412；copy 的 Copied HEAD 可能在 FenceOwn 之前先到，但仍 Provisioning，随后可被删除屏障覆盖。FenceOwn/Absent 之后旧 Copied/初始 HEAD CAS 均不能成功。Name 已 Bound 时沿既有 CannotAbortBound 语义，随后由正常 delete 完成，不伪造取消已绑定目标。

## 7. API 候选

```text
Database::snapshot_prepare(principal, PrepareSnapshotInput, deadline)
  -> PreparedSnapshot { full_scope, fixed_input, snapshot_ref, point }
Database::snapshot_capture(principal, SnapshotPlanRef, deadline)
  -> SnapshotObservation { current_head, Prepared|Retained|ReleasedObserved|FencedUnknown }
Database::snapshot_inspect(principal, creator, operation, deadline)
  -> SnapshotObservation
Database::snapshot_list(principal, deadline) -> bounded metadata list
Database::snapshot_release(principal, SnapshotRef, deadline)
  -> SnapshotObservation

Catalogue::prepare_restore(Caller, PrepareRestoreInput, deadline)
  -> PreparedRestore { new_creation, fixed_input, effective_options, descriptor_hash }
Catalogue::inspect_restore(Caller, RestoreRef, deadline) -> RestoreProgress
Catalogue::resume_restore(Caller, RestoreRef, deadline) -> RestoreProgress
Catalogue::abort_restore(Caller, original_restore_creation, abort_identity, deadline)
  -> existing-style AbortProgress
```

PrepareSnapshotInput 固定 creator/operation、expected revision/head_serial、label。PrepareRestoreInput 固定新 operation/name/expected name revision/options 和完整源 SnapshotRef，不接受任意对象 key/hash 代替受证明的 point。查询支持由 operation 找回 first-winner；mutation 需要完整 ref。每个 SDK 方法只派发一次请求，无隐藏重试；resume 是明确的新调用，不更新旧候选的 ETag。

control 工作与大 copy 分离。每个控制调用最多一个权威 CAS；长 copy 使用 recovery admission、隔离 worker 和同一总 deadline。先使用完整重新验证的显式 resume，不承诺崩溃后从磁盘 cursor 接着走。

权限细节首片优先复用现有 Catalogue creator/provision 的创建和取消合同；不顺带赋予其他 principal 取消未建 HEAD 的新权利。源被撤权不妨碍有目标取消资格者清理目标。若部署撤销了 creator 的 provision，怎样授予管理员接管未完成创建是现有目录权限的独立约束，不能借 restore 绕过。

## 8. 资源与计数边界

* 格式最多64个live points、label最多128 bytes；HEAD仍256KiB。新模型目录的`codec_budget.py`用当前1024条ACL、64个互不相同且全部需JSON转义的128-byte labels、完整CopyBasis副本、3窗口、owner marker、Copied restore origin、32条最大key/1024-byte ETag的sweep分别构造。候选字段布局下live COPY=164,934 bytes、live sweep=199,324 bytes、terminal sweep=157,799 bytes。进一步把互斥plan+sweep+terminal及最长enum都同时置入不可达的保守上界，得到242,467 bytes，距262,144仍有19,677 bytes。它是逐字段JSON尺寸上界，不是声称这个不可达组合能过Rust validator；真实HEAD9 codec四维单位及同字段编码仍须独立验收。任何最终字段改名/新增均重算。
* 持久gross限额默认32GiB；按每个点page_count×4096保守相加，不把共享对象扣除作为准入依据。现有live总量以上的ADMIN限额更新必须单独通过checked总量验证；本地恢复预算与此策略分开。
* 业务 quota 只约束当前库；点的页数不可随 quota 降低改变。target quota 独立设置且必须容纳完整点；target retention是新默认/选项，不是源结果保留策略。
* source GET、target PUT/readback各独立计数/字节预算，建议沿用每次最多1,048,576读、64GiB admitted bytes的安全默认，并为PUT设独立相同上限；可降低，0禁用大copy。按授予cap预留、成功且期限仍有效才退款、失败不退；本地缩窄cap的Limit映射Budget，无quarantine。不是RSS/线缆流量硬上限。
* 重封装采用有界后序栈（数据树最多4层，每层最多256 child hashes）与单Chunk缓冲，不能用全库PageBatch/BTreeMap把10GiB图片装入内存。native校验使用有额度的临时文件；recovery semaphore和临时盘预留必须分别限制并发/总逻辑空间，不能只宣称cache_bytes限制RSS。
* 一次完整copy若超总deadline/预算就失败，未得到CompletionRecord不得标完成。新resume有独立预算但会重新完整验证原点；首片不保证任意大库在固定预算内完成。
* HEAD9统一保留有限清理计数。令 `p=1` 当owner pending，否则0；`c=1` 当copy plan存在，否则0；无checkpoint时`q=0`，存在任一Pending entry时`q=2`，全部entries已终结时`q=1`；`d=1` 当尚未Deleted，否则0；`t=1` 当尚无terminal seal，否则0。所有状态均要求 `R + p + d <= u64::MAX`，`S + live_points + p + c + q + d + t <= u64::MAX`。已有terminal且idle时保留量为0，但terminal后的gc_prepare仍要为新checkpoint预留q，不能抹掉它。静态格式与每个实际候选使用同一checked helper。
* q来自真实`reclamation::gc_resume`：先在局部处理全部Pending；全部取得确定typed outcome后，最多一次HEAD CAS保存整个disposed batch，再一次HEAD CAS clear。它没有逐条entry的HEAD CAS。任一物理失败或UNKNOWN退出不会发布部分disposed；如果settled CAS已生效而ACK丢失，下一调用exact读到全部终结则只剩一次clear。释放一个点、终结pending owner、abort copy、batch settle、clear、delete、seal各消耗并减少对应有限债务。一般SQL/ACL/限额更新不能借这些余量推进；capture需publication加新增release债务至少2个serial，gc_prepare需publication加settle/clear至少3个serial。
* 上述R/S规则保证一个有限清理路径仍有计数，不保证任意晚到PUT、重复GC扫描或无限管理员竞争有计数可用。named deletion的owner_epoch+1和Name的原有计数准入约束仍要保存；采用HEAD9的具名非Deleted状态还应留一格owner_epoch以免R/S有余量却不能安装真正delete barrier。目录初始Reserve依旧预留其Abort/Release所需Name revision。大copy的完成不是清理所必需：到极限时允许明确abort、release、delete、seal。

## 9. 必须保持的安全性质

1. Retained point 的所有data对象在当前A；Sealed target包含当前根、每个point和原请求闭包。
2. SnapshotRef一经接受，point永不变化；释放后ID永久不可复用，同名新点不替换旧restore intent。
3. Proof存在但entry仍在不表示release；稳定缺失不能编造原HTTP ACK。
4. ordinary publication、owner、ACL/quota、技术维护只能保留自己不拥有的snapshot/restore字段。
5. SnapshotExpired需要真实物理失败和fresh退休证明；语义损坏/目标失败不能伪装成expired。
6. target依赖只含新Scope对象；Ready后删除全部源payload仍可冷恢复目标。
7. CompletionRecord接受前必须有完整验证和源授权；部分prefix、磁盘缓存或未回读PUT均无完成权。
8. target Empty/Copying不能Bound或Ready；旧generic create不能绕过restore recipe。
9. Name/HEAD abort barrier永久fence所有旧Initial/Copied/Ready候选；旧PUT只留下不能发布的orphan。
10. 目标使用新ACL、owner准入和空请求空间，旧请求/取消/退休身份不复活。
11. Deleted保留点不随逻辑删除清空；terminal只能在全部points释放及真实删除来源验证后安装。
12. 当前ADMIN/READ检查不由历史descriptor/proof替代；完成独立复制后的权限边界必须按第6节解释。

## 10. 实施切片与验收

建议一次完整功能分两可审查提交，但最终产品验收按组合进行：

**S1 snapshot authority + closure：** strict HEAD9/table/descriptor/proof/API，所有普通/owner/storage guard，完整逐根 closure 和 CopyBasis，Deleted/release/terminal、资源与counter预留。仅存在未发布的S1草稿时不宣称PITR完成。

**S2 fresh restore：** strict Catalogue recipe/restore origin/completion，完整跨Scope重封装和native校验，Name/HEAD状态机与取消/发现/恢复全部消费者，HTTP/Node SDK，一次调用一个CAS与明确新resume。

核心改动位置：`format.rs`、`storage.rs`、`closure.rs`、`data_tree.rs`或新有界transcode模块、`lib.rs`/Session publication、`head_publication.rs`、`reclamation.rs`、`owner.rs`、Catalogue records/types/create/inspect/control/terminal/discovery/recovery；新增snapshot/restore私有capability模块。store继续提供原exact/conditional接口，不引入任意DELETE能力。

独立finite模型先覆盖两snapshot、三source generations、两个目标身份/两个actor、有界counter与2–3页数据树。分开实现状态转移与观察器，保留正向全history和故障协议负控。模型明确抽象掉SQLite/HTTP/S3真实实现，不认证产品。

正向矩阵至少包括：两个点与当前根同时复制；snapshot后SQL并close窗口；quota降低后旧点迁移；复制期间capture/release拒绝；旧GET被promote+sweep中止后同点新A重启；release后同名新点；Deleted恢复/最后release+seal；两个restore creator争同Name；同operation不同recipe first-winner；prepare/capture/release/proof/Copied/Ready逐个Unknown；每个跨对象切点退出后全缓存丢失；源撤权前后完成边界；CompletionRecord先到/后到target abort；FenceAbsent/ForeignOccupied；目标quota/bytes/context/disk额度耗尽；同target双resume；源全删除后目标cold恢复；旧源请求在目标不能lookup成原Committed。

负控至少包括：COPY漏一个snapshot root；用current quota替代point边界；汇总页数掩盖单root错误；CopyBasis不绑列表；release不保留proof；旧snapshot ID复用；按新同名点改restore；旧g物理失败直接当Current损坏或语义损坏当Expired；原frame跨Scope直接复制；目标引用源hash；generic Empty完成Copying；部分copy制造CompletionRecord；撤权前的旧权限跨新resume；target abort后换ETag续发；source Missing伪装空库；CompletionRecord被删除后重建；snapshot被终态seal遗漏；没有计数预留耗尽清理路径；错把Missing当历史NotApplied。

产品门禁另含所有生产文件四维精确单位、真实native/HTTP/signed S3、多个snapshot重叠chunk与不同根、原SQL随机值/BLOB、暂停GET/PUT/CAS/DELETE、两Scope进程退出及全冷恢复、独立oracle和负控。实际AWS故障域/成本仍是独立门禁。以上当前均为NOT_RUN，不能由HEAD8的700单位或任何旧模型结果替代。
