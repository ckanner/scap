# HEAD7 Deleted 终态退休：真实运行验收计划

状态：**首次实际执行未完成；已修正夹具的权限前置，等待新冻结源的完整重验**。
原产品 `7b757f7` / 夹具 `430f7a3` 的 actual01 在撤回 READ/WRITE 后调用普通 status，
收到正确的 DENIED，但旧 runner 错误要求成功而停止。原失败和清理账本保留，不作为合同通过。
固定输入分母与命令见本目录 README；精确产品基线和源码清单由每次实际记录绑定。这里只装配正式 `scapd`、Node SDK、
native SQLite 与需要签名的 S3 兼容后端，不实现另一套退休或目录恢复算法。

协议依据是 `docs/architecture/terminal-storage-retirement.md`。现有 HEAD6 完整保留窗口、
COPY 闭包和可重启 GC 合同仍由 `experiments/object-reclamation-runtime` 单独承担，并在
新产品上重新验证。本目录独立验证 final-A、永久元数据、原业务屏障和迟到请求。

## 已确认的公开接口

| 入口 | SDK 调用 | HTTP 操作 / admission |
| --- | --- | --- |
| 直接终态观察 | `Client.storageStatus(options?)` | `/v1` `storage_status` / control |
| 直接显式 seal | `Client.retireStorage({expectedHeadSerial}, options?)` | `/v1` `retire_storage`，wire 为 `expected_head_serial` / control |
| 具名终态观察 | `CatalogueClient.storageStatus(creation, options?)` | `/v1/catalogue` `named_storage_status` / catalogue |
| 具名显式 seal | `CatalogueClient.retireStorage({creation,expected_head_serial}, options?)` | `/v1/catalogue` `retire_named_storage` / catalogue |

每个调用只发一次原始 POST。直接 seal 的 Unknown 保留原 `expectedHeadSerial`；具名
Unknown 保留原 `intent.action` 中完整 Creation 与 `expected_head_serial`。观察请求的
传输失败是 ClientError，不伪造可重试的退休意图。已 terminal 的 HEAD，不论传旧 serial
还是当前 serial，显式 seal 都返回 Conflict，不再发 CAS。

普通 status/query/lookup/SQL 在 Deleted 后仍返回 Lifecycle。专用 storage status 只允许
观察 Deleted 管理状态，不是新的 payload 读取凭证。Seal 本身不要求启用 GC；物理删除
仍要求显式配置、独立凭据的 Garbage 能力。

## 格式与不变量

原始 HEAD6 storage 仍精确只有 A/M/plan/sweep 四个字段，不悄悄添加 `terminal:null`。
HEAD7 必须为 Deleted、inactive、无 plan，并有非空 `terminal:{serial}`。公开 status
则另有必填的 `storage.terminal:null|{serial}`；公开 DTO 与持久化 HEAD 格式分开核验。

首次 seal 只改变 format、`head_serial += 1`、active=false 和 terminal.serial；新 serial
等于 terminal.serial。revision、transition、sequence、owner、auth、policy、quota、
retention、request_epoch、windows、data_root、creation、deletion 全部保持。其后 A、M、
terminal.serial 永久不变；checkpoint 仍只按原条件改变 serial/sweep。

静态条件包括 `M < terminal.serial <= head_serial`、`revision < terminal.serial`，有 sweep 时必须
`terminal.serial < sweep.serial <= head_serial`。旧 HEAD6 context 的退休调查还要求
`terminal.serial > 原 HEAD6 head_serial`；仅 fresh head_serial 很大不够。

## 真实场景与切点

八个主场景族如下。直接发布族另有一个健康原回执子场景，两个损坏回读 scope 只用于
明确的 fail-closed 反例。每个需要业务数据的 scope 通常只写两条带随机结果的 SQL，
不重复铺设 260 个 retained 原请求。原 SQL 输入、请求身份、原始结果与 receipt 均先后
完整持久化；被删除的库不声称仍能新 lookup，未删除的 successor/foreign 必须冷恢复。

| 场景族 | 正式前置操作与真实暂停位置 | 必须观察的结果 |
| --- | --- | --- |
| Direct late seal / final-A | 正式 create/activate/SQL；COPY+Abort 实际分配后放弃 g=2，保留 A=1/M=2。暂停原 immutable PUT 与旧 lookup GET，正式 Delete；暂停原 seal CAS 转发，原 caller 超时后由另一个进程观察 unsealed，再放行原 CAS。 | unsealed 时不能给最后 A 安装删除 checkpoint；原 Unknown 不因新 status 改写。seal 后 g=1/2 都可 GC。checkpoint ACK 后换 worker/restart，以原 batch 删除旧 GET 对象再放行，必须在原期限内经一次 fresh HEAD 证明过期。完整扫描后放行原 PUT，后端实际接受，再从头新扫。 |
| Direct 固定候选与原结果 | 两个 daemon 的 seal 都在同一原 serial/ETag 上准备并暂停，逐个放行。另有实际 SQL HEAD CAS 在 Delete/seal 前已准备并暂停。健康子场景则暂停一个已经被后端接受的 SQL HEAD PUT 成功响应，另一 daemon Delete→Seal→GC 后再放行成功响应。 | 双 seal 只有一个原条件成功，另一原请求 412/Conflict；旧 SQL CAS 也实际 412，不能换 ETag。健康子场景仍完成本地 native COMMIT，返回原已持久化的完整 receipt/result，不能变成 Expired 或重放。 |
| 正常 named delete，Release 前 seal | 真正创建、绑定、写入，并用原 delete control 删除 HEAD；暂停原 Name Release 的 If-Match PUT 转发。seal 并安装 checkpoint，重启后在 checkpoint 未 clear 时恢复同一原 delete intent。 | Name Release/Done 只依赖真实元数据，terminal sweep 不阻断。随后复用同名、建立新完整 Scope；最后放行的旧 Release 不能覆盖新 Name。 |
| 正常 named delete，名称复用后 seal | 旧 delete 完成并释放 Name；实际建立同名 successor，再以原 Creation/删除来源 seal 旧 HEAD。 | 稳定的新 Name revision 不会丢失旧删除来源；只清理旧完整 Scope，successor 的原结果和完整业务值冷恢复相同。 |
| OwnDeleted proof 已存在 | 原 create/resume 在 HEAD Provisioning 已生效、Name Bound 还未生效时暂停。执行原 abort，待真实 AbortProof Absent PUT+exact GET 后，在 Name Release 前暂停。 | seal 不改变 proof 引用的业务 transition；有 terminal checkpoint 时仍能用原 abort 意图 Release/Done；不重新物化已删 payload。 |
| OwnDeleted proof 尚未产生 | 同样通过真实 Provisioning/Reserved 状态开始 abort，在其原 AbortProof Absent PUT 转发前暂停，此时 HEAD 已 Deleted/Name Aborting。 | 另一 daemon seal/prepare 后，原 proof 仍能以同 transition/nonce 原样生效，再恢复同意图。不能靠改变产品循环次数制造阶段。 |
| FenceAbsent | 暂停真实创建的初始 HEAD Absent PUT；另一个 daemon 正式 abort/FenceAbsent，持久安装 own Deleted HEAD，然后 seal/GC。 | 旧 Absent HEAD 原请求最终真实 412；永久 HEAD 仍占用 slot，不能复活。目录 descriptor/control/proof 与原 abort 恢复完整。 |
| ForeignOccupied | 原 Creation 已 Reserved，但另一条合法 direct create 用不同完整 Scope 占据该永久 HEAD slot并写入真实数据。旧 abort 产生 ForeignOccupied proof，丢 Name Release 回复并重启恢复；尝试对旧 Creation seal。 | seal 返回 IdentityConflict，不给 foreign ADMIN 或 GC 权限；原取消仍可元数据完成。foreign 原结果、HEAD、payload 与 proof 保持。losing Scope bootstrap orphan 不借此宣称可回收。 |

OwnDeleted 切点按真实四步 `abort_create` 实现：Accept→Fence→Prove→Release；不假设
一次 HTTP 自然停在两步。Name 的 Bound/Release PUT 与 AbortProof PUT 都保留原 body、
原 ETag/Absent 和原签名传输，不在暂停后重建请求。

## 新增的诊断和静态拒绝

两个实验专用 scope 可以由明确记录的独立 operator 使用真实 GET 的原 ETag 条件替换
HEAD，用来制造坏 authority 回读；这不是正常运行设置，不是终态授权，不可用于给任何
正例补造状态。operator 只允许固定的这两个 scope 和指定字段差异，所有原始字节、条件、
后端响应与读回均归档。其余全部正例只能经正式产品 API 达到状态。

1. **过旧 terminal serial**：该专用 scope 先通过真实 COPY→Abort→Activate 形成技术 serial
   高于业务 revision 的差距；原 R context 捕获 HEAD6 serial=N 并暂停依赖 GET。正式
   Delete→Seal→GC 完成后，仅把 terminal.serial 条件改为 N；保证 `M < N`、fresh
   head_serial>N、revision<N、无 sweep，使它静态可解码但不能证明在原 context 后退休。
   释放原 GET 得到真实 NoSuchKey；原一次调查保留原 MISSING，不能分类为 SnapshotExpired。
   global quarantine 的后续同 lineage 行为由 core 精确单位承担，不把同一个 daemon
   的另一次调用未经证明地当作同一个 handle。
2. **checkpoint 早于 seal**：先通过正式 policy 撤回 principal 11 的 READ/WRITE 并保留 ADMIN。
   普通 status 必须 DENIED；删除直接使用该次 policy 成功响应的 revision，随后 seal/prepare
   仍无 READ/WRITE/provision。独立审计检查原响应版本、拒绝结果与封存前全部 HEAD 的原权限。
   正式 seal/prepare 后，仅把 sweep.serial 改为 terminal.serial。
   fresh storage_status 与原 batch resume 必须失败关闭，无 DELETE/HEAD 技术发布。

新鲜第二次 Name GET 与第一次的 body/ETag 不同，精确返回 Conflict，不能 Corrupt 或
自动 rebase。实际夹具用暂停第二个 Name GET 的转发、推进原 Name 来覆盖此边界；源
control 缺失、非当前管理员与 foreign 不能通过任何调用者自报字段补出权限。

## 原始证据和独立判定

完整记录每次 SDK 输入/保存意图、一次 POST、完整响应或原 transport error；所有 S3
exchange 的 request/forward/backend/delivery/handler 生命周期与最终 listener request
计数；scope、方法、path、body、条件、公开 payload hash 逐阶段一致。后端接收的 DELETE
与调用者收到的确定结果分别记录。当前 HEAD/ETag 必须来自同一次 exact GET。

原始 business ACK 对应的 Result Absent PUT、exact readback 与 HEAD 条件发布都要早于
该 ACK；健康延迟响应子场景用实际已发布的 Result 原件核对最终 native 返回，不计算或
猜测随机 SQL 输出。Unknown 观察保留原知识，不自动重发 SQL。

Oracle 独立解析严格 HEAD6/HEAD7、目录 descriptor/control/proof/Name、原 scope
关系、双 Name 读、全部 checkpoint 与原条件 DELETE，不复用产品 verifier 或候选构造器。
它核对 terminal 前后业务字段保持、原 OwnDeleted barrier、全部已分配代的退休边界，
以及永久 HEAD/descriptor/control/proof/Name 永远不在 payload DELETE 集合。

正向过程不得删除或替换 successor/foreign 的原对象；冷启动后逐字节回收这些仍存活库的
原 ACK，并查询全部实际业务行。已删除库的新 ordinary lookup 明确 Lifecycle，保留
外部原件只用于审计，不虚构删除后的结果查询能力。完整 raw contract 与 whole-history
负控制通过后才报告该次实际验收通过。

负控制会覆盖：缺 seal 清 A、g>M、terminal 回退/新分配、改业务 transition/proof、缺
原 control/Name 双读、foreign 当 own、永久元数据 DELETE、换原 ETag、改 Unknown、
无新鲜证明的 Expired、过旧 terminal.serial、sweep.serial 不晚于 seal、原 receipt
降级、NoSuchBucket 当 Missing、迟到 PUT 未新扫、漏完整 exchange/原结果/owned wait4。
每个变异必须同步其镜像并命中命名的语义边界；无关解析失败不算该负控制成功。

严格 JSON 重复/未知字段、native InvalidImage、所有 lineage 组合、Budget 与每个低层
I/O cut 由 core 精确单位/独立模型承担。健康已提交响应的实际子场景不冒充 native 失败的
CommittedButUnavailable；后者由新核心精准单位及独立 output/response 合同继续承接。

## 资源、源码和执行纪律

实际固定配置沿用已验证的合法 output/transport/S3 范围，增加的 catalogue admission
与所有 worker/Scope/nonce/operation 身份固定在 spec.py 与 runner 原步骤中。整个运行、每个 hold、原
read/HTTP/S3/SDK 的 deadline 先记录再运行，不在失败后续期。固定为 23 次一次 SQL、
21 原 ACK、6 冷 lookup、19 传输切点、10 seal、25 完整历史反例；完整实际验收尚未通过。

运行前验证真实 SDK prepare/restore 及所有新的 DTO 适配；owned loopback HTTP 边界
测试覆盖 binary、嵌套 response body、multipart XML/ETag。测试不代替实际 native/S3。
运行只使用独立 HEAD7 release receipt 与冻结 source manifest。进程资源不按未经证明
的 Popen PID 猜测 procfs；所有 owned children 使用原 wait4回收，proxy joined 后保存
最终分母。任何失败保留原始 public/private evidence；下一尝试用全新路径。

`aws_standard=NOT_RUN`、`production_slo=NOT_RUN`、永久 prefix 为空 `NOT_CLAIMED`。
永久元数据本来不删除；foreign losing Scope orphan、PITR/holds 和自动调度仍单独列为
剩余项，不由 final-A 退休顺带宣称解决。
