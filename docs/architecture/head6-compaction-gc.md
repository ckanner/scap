# HEAD6：明确管理员压缩与退休世代清扫

状态：生产候选 `66f452ec73111f8c9dc7509883717828ba883e8a` 已冻结。workspace stable/nightly 各 632 个单位测试、全部 59 个生产文件的行/函数/region/分支精确 100% 和严格 Clippy 已通过；真实 native、HTTP/S3、回收与负载分别验收。完整进度见[HEAD6 验收记录](../engineering/head6-runtime-validation.md)，未完成的门禁不能据单位覆盖推定通过。GC 仍需专门显式配置的删除凭据。

本片实现 PR43 可中止普通操作与 PR49 handle 知识域在 live database compaction 上的生产闭环。普通读、lookup、SQL attempt 没有 durable operation pin。本片没有显式 retained snapshot roots，因此 holds 集合固定为空，格式不接受 holds。PITR/跨 Scope archive 和自动 owner 后续独立交付，不是本片已完成事项。

## 状态与不变量

HEAD format 6 保持完整逻辑 Scope 和 SCAPOBJ2 不变。Storage 保存 `active_generation=A`、`allocated_through=M`、可空的 `plan` 和 `sweep`。`1 <= A <= M <= head_serial`。plan 与 sweep 互斥；每次分配只用 `M+1`，放弃的 target 永不复用。所有 HEAD CAS 技术序号加一；纯技术维护不改业务 revision/transition。

CopyPlan 的 serial 是 Freeze 发布后的 head_serial，在完整 Scope 内唯一。它固定 source、target、phase，以及 data_root、全部 retained windows、sequence、revision、quota、retention、request_epoch。源 A 在复制期间仍为读取权威；target 仅由当前 plan 保护。复制期间禁止修改冻结根、quota、请求窗口与 owner；允许当前 ADMIN 修改 ACL。后续 Seal/Promote 使用新鲜 HEAD 的 ACL，不把旧策略从 basis 恢复。

永久退休谓词是 `1 <= g <= M && g != A && g != current_target`。不是只比较 `g < A`：A1、已放弃 G2、当前 T3 时 G2 已退休。此谓词的正确性依赖每个构造器禁止退休世代重新 active、target 或 protected。没有 lease/TTL/进程死亡推断。

本批管理接口只接收 Ready 数据库。Deleted 的最后 active generation 仍受保护，也没有为 Deleted HEAD 安装 sweep 的入口。要清理最终 namespace，需要单独的永久终态退休转移并与 Catalogue 取消/删除屏障组合；本片没有把逻辑删除自动当作这种证明。HEAD、Catalogue descriptor/name/control/proof 永不由 payload GC 删除。

## 管理接口

全部接口由受信服务 admission 提供 principal，运行在隔离工作线程。普通用户不能传任意 key、prefix 或 ETag。

| 接口 | 原始输入与结果 |
| --- | --- |
| compact_begin | expected_head_serial 必须匹配新鲜 HEAD；分配 target，固定 basis，owner inactive；返回 HEAD |
| compact_copy | plan_serial；有界内存遍历完整源闭包，每个原 frame 条件写入 target 并 exact readback；完整成功才 Seal |
| compact_promote | 当前同 plan 必须 Sealed；A 切换 target，plan 清空，owner inactive；之后沿现有完整恢复/激活合同激活 |
| compact_abort | 当前同 plan 清空，owner inactive；target 永久退休，旧具体 CAS 由原 ETag fence |
| gc_prepare | expected_head_serial、已退休 generation、可选 64 小写 hash frontier；最多一页 32 项候选，exact inspect 后安装 checkpoint，不 DELETE |
| gc_resume | 当前 batch_serial；新鲜 ADMIN/HEAD/退休检查后处理最多 32 项，持久化 disposition、exact 观察，再清除 checkpoint |

COPY 持有原绝对恢复 deadline。重启后的新调用可以从同一 plan 根重新复制，已有 immutable 目标只在 exact readback 后重用；不接受磁盘 prefix、旧内存 cursor 或旧网络 token 作为完成证据。若完整闭包不能在当前 job budget 内完成，返回失败，不偷偷延长旧期限。本片没有承诺最大数据库在固定维护预算内完成。

## 完整复制与原结果

`closure::Cursor::for_copy` 仍以实际原 Snapshot 为 authority，不伪造 target Snapshot。遍历校验当前数据树、全部 retained request-index 边和原始 Result。Result.data_root 是原 receipt 字段，不是额外的历史数据闭包边。copy basis 固定原 revision，ACL 后续增加业务 revision 不放宽原结果的 revision 校验界限。Result 和取消记录还必须满足 `transition.nonce == request.id`；点查、完整恢复、COPY 和 Node SDK 共享这项语义，哈希正确不能替代它。

源与目标是同一逻辑 Scope，因此复制原 SCAPOBJ2 frame 字节，保留 hash、非规范 JSON 字节及原始结果。每条源边通过验证后，target 只 Absent PUT 并 exact readback。只有完整源 cursor 成功且所有 target 回读成功才具备 Seal 证据。后续目标仍受当前 plan 保护，没有可授权删除 target 的并发路径。

跨 Scope PITR 不能复用这种原 frame 复制：Scope 进入 hash，必须重建目标 envelope 与父 hash，使用新请求身份。它不在本片范围内。

## 失败归属与 handle 生命周期

Database 一次构造创建本地知识谱系，clones/Session/ObjectContext 共享；独立 Database 构造不继承它。源 context 保存实际原 backend/meter、完整 Scope、物理 g、原 serial/A/M/ETag，并在入场时固定不能延长的 deadline。诊断拒绝 serial、A 或 M 回退，以及同 serial 的 body/ETag 矛盾；它们不能被解释成合法退休。

每个谱系最多 64 个 live contexts 与 64 个 generation slots。容量不足在本地失败；不静默逐出 unresolved incident。物理故障立即关闭该 context 的可执行前缀并记录到原 g。没有 active references 且严格证明退休的物理 slot 可以释放；authority/content-semantic latch 不由这一清理解除。

| 故障来源 | 处理 |
| --- | --- |
| 本地配置、聚合额度或缩小 allowance 导致的 Budget | LIMIT；没有腐坏 latch，不调查 HEAD |
| 源 immutable Missing、实际响应超格式 cap、范围/长度损坏、hash 不匹配 | 关闭 prefix；最多一次原 backend/meter/deadline 的专用 exact HEAD 调查 |
| 同 Scope 新鲜 HEAD 严格证明原 g 退休，且原 serial/ETag 已被后继 fence | SnapshotExpired；不污染当前 g |
| 调查不可得、预算耗尽、同代仍 active/target | 保留原错误/未决 incident；不能假装退休或健康 |
| hash-valid 格式、Scope、typed edge、retained SQL 或 native InvalidImage | 内容语义 latch；即使原 namespace 退休也不是 expiry |
| target PUT/readback、visitor、本地文件/内存失败 | 按实际 target/local 来源处理，不能由源 raw port 误报 source corruption |
| 已知 durable receipt 后 native/结果物化失败 | 保留 committed-unavailable 与原 receipt，不能变成 SnapshotExpired |

诊断 HEAD 只判定原失败，不暴露可供重新发布的 Snapshot。坏 Scope、坏 HEAD、逆序 serial/A/M 或用原 ETag 声称退休会失败关闭。普通只读新调用仍可用自己的新授权、完整验证成功；它不清除旧知识。最后 healthy 检查不是网络锁：之后其他操作的 latch 不能撤销已固定/已发的原 CAS，也不凭空增加 ACK 前的第二次健康检查。

## 可重启 sweep

LIST 只是候选。专用 Garbage::inspect 只从完整 bounded exact GET 取得 ETag；Missing 必须是严格 NoSuchKey，NoSuchBucket/普通404/异常响应不能据此清候选。bucket 必须符合专用 GC 能力的 unversioned/Object Lock/条件删除合同。

当前 HEAD checkpoint 保存 serial、generation、分页 frontier、exhausted 与最多 32 项完整 key/hash/原 ETag/disposition。DELETE 必须由 fresh exact 同 batch 观察授权。这是一次最多 32 项的有界操作前缀，不是每个 key 都额外读取一次 HEAD；迟到 DELETE 在 clear 后仍安全，依据是不可逆退休及其原 key/ETag。disposition 只有 pending、applied、observed_absent、condition_mismatch；Unknown 不构成 disposition。

重启可对 pending 项重新 exact inspect：typed NoSuchKey 可建立 observed_absent；存在对象时仍使用 checkpoint 原 ETag 发 DELETE，即使新 inspect 看到了不同 ETag。只能由这次原条件 DELETE 的明确 Conflict 关闭旧候选，再在新批次捕获新的 ETag。不会改写旧 UNKNOWN 调用的历史结果。

全部确定 disposition 先以原 HEAD CAS 持久化，再 exact 观察；之后才 clear checkpoint。clear 的不确定仍是不确定。旧 batch 已被清除/替换时返回 Conflict，不制造原 Applied/NotApplied。可以从 generation 起点重新开始一轮。

迟到旧 PUT 可在刚清空的退休 namespace 重建 orphan，迟到 DELETE 也可能在 checkpoint 清除后交付。两者始终绑定旧物理 key/条件，不能影响当前 A/T。公平重复从起点扫才能找到新 orphan。空页/本轮结束不证明永久为空。成本最终收敛仍需要有限旧操作、在途上传最终结束、存储持续可用、重复公平扫描及 GC 服务能力足够。

## 验收状态

本批需要 core/store/service/SDK 全消费者通过、逐文件精确单位覆盖，以及真实 native/HTTP/signed S3 暂停 GET/PUT/CAS/DELETE、重启 checkpoint、原 Result、ACL 竞争、独立 handle、预算来源、NoSuchBucket 拒绝和迟到 orphan 再清扫。缺失或失败项保留原记录，不以 PR43/49 的有限模型结果代替。

核心单位中的 36 个 reclamation 用例覆盖六个 API 的每个 Objects I/O 中断点、所有本地复制停止点、真实 SQLite 的 65 条回执跨 Cursor 步复制、完整目标字节、ACL/plan 竞争、分页与原 ETag、丢响应与 checkpoint clear 竞争、迟到 PUT、新旧谱系隔离、容量/期限/serial 边界。额外的 retained nonce 反例覆盖 lookup、activate 和 COPY，证明 hash-valid 的错误回执不能 Seal。以上是单位与本地 native 证据；真实网络暂停/退出/重启证明仍是独立门禁。
