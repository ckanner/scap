# 名称目录真实 core 合同：场景与证据分母

状态：**装配中；release 编译、真实 S3 运行及独立审计均 NOT_RUN。** 本文固定实验的判定边界，不把模型、夹具自测或最终一次 resolve 作为原生合同通过。

权威算法仅来自 `scap-object::catalogue::Catalogue` 和现有 `Database`；worker 增加六个薄直通及既有 quota 控制直通。Python 不补 reserve/bind/complete/abort/delete 算法。普通 worker 的主体与 provision 权限来自私有 fixture 配置，命令不自报权限。SDK/HTTP 准入合同由 `experiments/object-service` 单独执行。

## 1. 权威 PUT 的三种边界

先在真实端点执行固定原始输入的 pilot：prepare、resume、缺失 HEAD 的 abort、已有 Provisioning 的 abort、ForeignOccupied 的 abort、正常 delete。按每次公开调用中**实际发出的全部 PUT**列出原路径类型、条件、bytes/hash 和顺序；包括空库的不可变依赖，不能只数最后一条 HEAD。独立 oracle 从原始网络历史重算 pilot 分母，再要求每个 ordinal 都有以下三种新身份的独立场景：

| 边界 | 必须保留的事实 |
| --- | --- |
| before_forward | 原请求完整 bytes/条件已经到达代理；转发前杀死实际 compute，并明确记录代理没有把该请求发给后端 |
| after_backend | 后端已返回真实 200，响应尚未交付；杀死 compute 并抑制回包；不能伪造一个已写结果 |
| after_consumed | 先交付该 PUT 的响应，再阻塞同一调用随后发出的 GET，或实际读到完整方法响应；随后杀死 compute。代理写 socket 本身不证明客户端已经消费响应 |

每个 case 都使用独立 create operation/name/Scope；cut 后清空该 case 的全部计算目录，使用持久保存的原输入显式重入。不换 operation、nonce、原 expected revisions 或 Creation。原在途条件永远保留，不能重写成新 ETag。

缺失 HEAD 的 abort 初态通过正式 resume 在 Reserved 发布后截断建立；Provisioning/Bound 初态同样在相应真实发布处截断，不能直接构造名字状态。ForeignOccupied 使用正式 `Database::create` 建立同物理 database key 的合法其他 Scope 或无命名来源的库。

## 2. 固定并发与拒绝场景

| 编号 | 场景 | 原始证据与独立判定 |
| --- | --- | --- |
| CAT-01 | 两意图争同名；两进程续作同意图 | 两个已准备候选共享原 Absent/Reserved 条件；分别放行，真实后端只有合法后继；同意图不产生第二 Scope |
| CAT-02 | bind 先胜 / abort 先胜 | 同一 Reserved body+ETag 的两条 name CAS，分别强制两个顺序。Bound 胜则 CannotAbortBound；Aborting 胜则原 complete 无资格变 Ready |
| CAT-03 | Aborting 后迟到 provision 与 absent-HEAD tombstone | 两条原 If-None-Match:* 候选；覆盖 provision 先胜和 tombstone 先胜。原取消通过显式同意图续作得到永久屏障，原迟到候选不能复活 |
| CAT-04 | 控制 descriptor 已准入，目标 412 / UNKNOWN | 对 abort/name 和 delete/HEAD 分别保存完整 ControlDescriptor，检查同 control ID 改 nonce/revisions/目标被拒绝，原记录与新目标均未被改写 |
| CAT-05 | ForeignOccupied 与永久 AbortProof | 合法其他 incarnation、generation、同完整 Scope 的直接创建；Ready/Maintenance/Deleted 外来库均不被收编。取消完成并重用名称后，旧取消只查证其永久原证明 |
| CAT-06 | 损坏、未知 HEAD 格式、错误物理 key、Bound HEAD 缺失 | 故障写入/删除单独记录为 fixture 破坏；后续 exact GET 验证原损坏/404，拒绝释放名字、空库重建或假完成 |
| CAT-07 | descriptor-only abort / Bound abort | 分别为 NotReserved / CannotAbortBound，二者不计为 Aborted |
| CAT-08 | 非 creator ADMIN 正常 delete与无权调用 | 删除保留原 Creation.creator，控制 principal 使用实际 ADMIN；无 ADMIN 删除、非 creator 取消、无 provision 续作拒绝 |
| CAT-09 | 创建/控制身份修改及名称重用 | 同原 operation 改名/选项/Scope 拒绝；创建者/租户的数字 operation 命名空间分别核对，不将合法独立数字 ID 当成旧操作。旧 reserve/bind/complete 原 bytes/条件重发得到真实 412；旧 abort/delete/SQL 不改新 HEAD |
| CAT-10 | Ready 重入保留后续业务、quota/policy | 保存真实 SQL 原请求与首次随机 RETURNING 见证；变更 current policy/quota 后原 resume 不能重设初始 descriptor 策略或空数据根 |
| CAT-11 | Provisioning 的普通入口 | status/query/execute/lookup/cancel、takeover/activate/activate_session、policy/quota/lifecycle/close_full、session_open 逐项拒绝；显式 create 不能覆盖。未能取得 Session 不冒称执行了一个既有 Session 的方法 |
| CAT-12 | 有界无效输入与调用预算 | 固定空/过长名字、零/溢出 revision 与短 deadline；精确错误及 no-PUT 保留，不把配额/权限错误合并成 UNKNOWN |

所有并发调用都先在真实 HTTP 边界暂停，再按指定顺序放行。目录续作会在第一条 PUT 后继续 GET/PUT，因此恢复被暂停调用前必须恢复它自己的观测 phase；oracle 还要按独立 call 时间区间、对象路径和完整身份绑定，不能信任 phase 标签本身。

## 3. 账本、恢复与判定

- 输入账本在发送前同步保存 catalogue action 的全部参数、受信 caller/context；SQL 另存原 SQL/参数及准备后的完整指纹身份。只记录输入中本来就有的值，不从结果反推 expected SQL。
- 调用/响应账本保存每个 call 的开始、完整 command、真实 worker incarnation、结束和完整响应；进程丢失的未回包调用单独记录。成功 mutation 响应与 SQL execute ACK 都必须在 ACK 分母，read-only inspect/resolve 单列。
- HTTP 保存 request serial、method/path、原条件、body bytes/hash/长度、真实后端 status/ETag，以及 response delivery。HEAD 明确为 v3；不可变 SQL 对象仍是 v2。目录记录原 JSON 捕获有独立 64 KiB 上限，超限直接使 fixture 失败，不能截断。
- 独立 oracle 不导入 controller 或生产状态转换；依据原始 bytes、条件和真实 HTTP 顺序重建固定 descriptor/control 与 name/HEAD 版本链。任何成功终态都必须有匹配的持久证明；不能从最终字符串 phase 猜测历史。
- SQL 原始结果严格解码 SCAPRES1、重算 SCAPSQL1 与 SCAPOBJ2 Result hash，完整 receipt/bytes 比较。随机值来自首次合法 ACK，再与后续原结果及实际业务行核对。
- 每组完成后杀死全部计算进程并删除其私有缓存，再进行新计算恢复；所有 case 完成后，实际零 compute 时杀死并重启 SeaweedFS master/volume/filer/s3 四个 owned 子进程，保留同一后端目录，再从原意图复核一次。进程 identity 包括 PID、spawn 时间、自身 proc start_ticks 与 wait4 来源，不能只核 PID 或 controller 的 live=0 标签。
- 删除、取消、名称冲突、不可访问/损坏和仍可查原结果分别统计。Deleted 不计为原 SQL 结果可访问恢复；未完成的名称或控制阶段不计为完成。

## 4. 不包含的证明

本实验仅覆盖实际记录并通过的固定本地兼容端点场景。完整目录发现、在线分页/瞬时 inventory、AWS Standard、IAM/KMS/跨 AZ、持续资源耗尽、断电、GC/PITR 与生产 SLO 仍单独未完成。通用 S3 adapter 的 403/409/412/5xx 映射以及 HTTP/SDK 错误合同按各自门禁记录；未在本轮新增目录轨迹中实际注入的状态码，不能冒称已覆盖其全部阶段组合。

候选冻结后才生成正式 build/source receipts 并开始真实运行。任何 oracle 失败保留该候选源码和完整失败证据，修复后新冻结重跑，不改写旧报告。
