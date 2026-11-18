# SQLite on S3：文件安全、并发、吞吐与完成标准

状态更新：2026-11-13。主线基准是 HEAD7
[`fab8ca0`](https://github.com/ckanner/scap/commit/fab8ca09aa05fdaf612cdcf47a9fce8e65373896)。
[PR #59](https://github.com/ckanner/scap/pull/59) 汇集 #56 owner plan、#57 有限 controller
和 #58 S1 retained snapshots；本轮生产基线冻结为 `b15bc45`，后续 `8a5bd65`／`642383c`
分别修复严格覆盖检查器和观测／审计工具。[PR #60](https://github.com/ckanner/scap/pull/60)
的生产候选 `fd508cc` 复用同一事务中已经验证的 Manifest，减少一次重复 GET。

本文补充[对象存储方案](object-storage-native-proposal.md)，不另建 HEAD、请求身份、
所有权或 GC 协议。环境已恢复，旧原件缺失的合同正在按精确冻结来源重新采集；
当前结果统一见[本轮代码、验证与剩余工作](../engineering/sqlite-s3-review-2026-11-13.md)。
两份 Rust 报告的已发出计数全命中，但 7 个文件的 branch 为 0/0，不能称为严格逐文件
四维覆盖通过。原检查器缺口已修复，两个 PR 继续 Draft；详见
[分支测量说明](../engineering/branch-coverage-measurement-gap.md)。

下文注明日期／源码的历史结果仍属于原候选。模型、单元、本地实际合同、AWS 与生产
SLO 分别验收；历史 checker 成功不补足未测量分支，也不自动认证后续候选。

## 1. 要完成的目标与现在的结论

SCAP 的目标是：大量独立租户／Agent 数据库共享计算资源，以对象存储保存唯一持久权威，
计算节点及全部本地缓存丢失后仍可恢复所有已确认事务、原始结果和正确性元数据。
同一数据库保持一个有效写入序列，不要求每个闲置数据库常驻进程。

**当前架构避开了跨主机共享 SQLite 活动文件的锁风险；它没有消除单库串行提交、
对象往返、整库冷恢复和共享资源的成本。HEAD6 的完整复制与有界物理 GC、HEAD7 的
Deleted 最后一代显式退休已经合入 main。PR #59中的HEAD8接管、有限controller和
S1保留快照及固定12场景controller矩阵已有明确来源的本地合同；当前组合仍按本轮验收收口。动态fleet、身份分配、
S2恢复、PITR、硬资源边界及生产性能目标
仍未完成。**
历史已合入证据见[HEAD7 验收](../engineering/head7-runtime-validation.md)，接管增量见
[HEAD8 验收](../engineering/head8-owner-plan-validation.md)，快照设计见
[HEAD9 方案](retained-snapshot-restore.md)。

| 用户关心的问题 | 当前代码的处理 | 仍有的边界 |
| --- | --- | --- |
| NFS/EFS 上共享 `.db/WAL/SHM` 损坏 | 私有本地执行镜像；文件系统准入；跨节点只通过对象 API 协调 | 可靠本地 I/O、可信挂载和固定 native 引擎仍是前提；真实网络挂载实验另验 |
| 旧容器未退出，新容器已经接管 | 同一个 HEAD 的原 ETag CAS；takeover 推进 owner epoch 并先置 inactive；HEAD8 候选持久保存接管计划及取消证明 | 探测和调度不决定写权；进程 worker identity 不复用仍依赖部署；固定多controller矩阵通过，动态fleet和真实部署故障域另验 |
| 一个热点数据库写入拥堵 | 同库 actor 串行，事务有界，支持一次事务多个 SQL 语句 | 加 pod 不会自动增加该库的有效 writer；没有多写者或 group commit |
| 一个冷库阻塞其他热库 | 不同库有界 actor，控制池和恢复准入分别设置 | CPU、网络、S3、磁盘、进程资源仍共享；不是硬租户隔离 |
| 小改动上传整库 | 128 KiB chunk、COW 数据树和分段请求索引 | 仍有多个顺序 GET/PUT、read-back 与 HEAD CAS |
| 节点丢失后重新上线 | 从 S3 完整恢复、校验，再激活；Session 保留已恢复镜像 | 当前冷恢复必须读取完整数据及保留结果闭包，没有 lazy VFS |
| 长期成本 | 逻辑请求留存边界、完整闭包复制、单调物理世代、持久 GC checkpoint；显式 terminal seal 可退休 Deleted 最后一代 | GC 默认无删除凭据；需公平重复 sweep；保留快照需保护完整闭包，永久控制记录和孤儿不受单库配额限制 |

实现映射见 [README](../../README.md)、[路线图](../engineering/roadmap.md)、
[HEAD5 基础](head5-foundation.md)和[资源预算](resource-budgets.md)。

## 2. SQLite 的真实限制，以及本项目如何避开共享文件问题

SQLite 并非只能由一个进程使用。官方 WAL 支持同机多个连接／进程，读者与写者可以
并行，但一个数据库同一时刻只有一个 writer；共享 wal-index 要求这些进程处于同一
主机。网络文件系统的问题同时涉及文件锁、同步与写入顺序，不能简化为所有 NFS
必然立即损坏，也不能只归因于 `fcntl`。[S1][S2][S3]

EFS 官方明确支持 NFSv4 文件锁，包括 byte-range advisory locks，并规定 close-to-open
一致性等 NFS 访问语义。因此不能说 EFS 没有文件锁；“advisory”本身也不是损坏证明。
但这些能力不满足 SQLite WAL 跨主机共享 wal-index 的前提，也不能替代 SQLite 对完整
文件系统语义的要求。SCAP 的部署决定仍是不共享网络上的活动 SQLite 文件。[S1][S12]

SCAP 当前执行拓扑进一步收窄为“一份私有镜像、一个受控 native 连接、所属线程串行
使用”。数据库服务可以接收多个客户端；多个数据库可以同时运行。这个选择避免了
把同一活动 WAL 在多个进程、机器或后台 checkpointer 之间共享。

### 2.1 已有防护对应的源码

| 边界 | 实际函数／模块 | 行为 |
| --- | --- | --- |
| 执行目录准入 | [`validate_cache_directory` / `validate_temporary_directories`](../../crates/scap-object-sqlite/src/storage.rs) | 对实际打开的目录查询文件系统；拒绝已知网络、FUSE 和未知类型；检查独立临时目录候选 |
| 私有文件创建 | [`ImageBuilder::create_new` / `Builder::create_new`](../../crates/scap-object-sqlite/src/file.rs) | 校验父目录与新目录，独占创建镜像，不复用已有目录或旧 sidecar |
| native 打开与配置 | [`sql::open`](../../crates/scap-object-sqlite/src/sql.rs)、[`configure`](../../crates/scap-object-sqlite/src/config.rs) | 拒绝宿主全局临时目录覆盖，关闭自动 checkpoint，保留固定 VFS 与单连接前提 |
| 活跃镜像所有权 | [`SqliteWriter`](../../crates/scap-object-sqlite/src/lib.rs)、[`Scheduler::start_actor`](../../crates/scap-service/src/scheduler.rs) | 连接在所属线程创建、使用、关闭；不同数据库拥有不同镜像 |
| 本地失败 | [`Engine::execute_using`](../../crates/scap-service/src/engine.rs) | 失败后丢弃 Session；后续创建必须重新核对对象权威，不复用失败的 native 状态 |

允许 overlayfs 不等于检查了它的所有底层挂载；管理员不能在准入后替换挂载、环境、
工作目录或 VFS。文件系统类型检查是防误配置机制，不是恶意宿主沙箱。完整部署边界见
[SQLite 执行存储说明](../operations/sqlite-storage-safety.md)。

“缓存可丢弃”也不允许缓存读错：native 算错的页如果被正常编码、哈希并提交，S3 的
CAS 不能辨认其业务内容错误。固定 libSQL/native 的 WAL-reset 补丁与拓扑审查继续见
[原生引擎评估](sqlite-wal-reset-assessment.md)；扩大到同文件读连接池或外部 checkpoint
之前必须重新验证，不能把 S3 架构视为内核补丁。

### 2.2 存储结构保持两个不同层次

本地 `.db/WAL/SHM` 用于执行，不是跨节点协议。远端不可变对象保存物理页块、树、
原结果及请求索引，单库 HEAD 引用它们。S3 从未被挂载后交给 SQLite 直接当文件使用。

当前 [`ObjectContext::capture`](../../crates/scap-object/src/object_context.rs) 绑定原后端、
完整逻辑 Scope、原 HEAD body/ETag、物理 storage generation 与原绝对 deadline，
不允许一次操作中途换地址。HEAD6 支持多世代复制与永久退休；ordinary 操作可中止，
不建立崩溃后无法解除的永久读 pin。物理读取失败后，只有一次原预算/期限内 exact
HEAD 调查严格证明原世代已退休，才可返回 `SnapshotExpired`；语义损坏仍失败关闭。
已知提交保留原 receipt，不能因为读取过期抹掉提交事实。主线 HEAD7 尚不提供显式保留快照；
HEAD9 S1候选已实现retained roots、捕获/释放、多根闭包复制及GC保护；本组合重新完成
实际合同与10项指定guard负控，原失败和夹具修正另行保留。S2的新Scope恢复和任意时间
PITR未实现；保留SQL原结果、
保留历史数据根和可用的备份恢复产品不是同一能力，见[快照方案](retained-snapshot-restore.md)。

## 3. S3 提交、fencing 与丢响应的精确边界

### 3.1 一次新写入的实际路径

1. [`Session::execute` / `Database::admit`](../../crates/scap-object/src/lib.rs) 用新 exact GET
   取得同一响应的 HEAD body/ETag，检查当前权限、请求身份、生命周期和 owner。已经保留的
   原请求直接解析原结果；同 ID 不同内容、已取消或退休的身份不能作为新 SQL 执行。
2. `AttemptContext` 固定原 Snapshot、ObjectContext、request 与绝对 deadline。
   native 执行 SQL，缓冲原结果；[`GateWal::insert_frames`](../../crates/scap-object-sqlite/src/gate.rs)
   在 native 页面发布之前调用 `CommitGate`。
3. `PublishGate::publish` 调用 `Database::commit`；`data_tree::update` 生成变化块及树路径，
   原结果与请求索引随同一候选更新。`ObjectContext::save` 对每个不可变对象条件创建并
   exact GET 比较完整字节。依赖失败不能发布新 HEAD。
4. [`PreparedHead::new` / `publish`](../../crates/scap-object/src/head_publication.rs) 捕获原 ETag、
   已编码候选和原 deadline，仅执行一次条件 PUT。冲突不能给旧物理差分换一个新 ETag。
5. 只有远端接受后才允许 native publication。当前 [`SqliteWriter::finish`](../../crates/scap-object-sqlite/src/lib.rs)
   还在成功返回前完成同连接 TRUNCATE checkpoint 和结果物化；服务再进行有界输出编码。
   客户端收到完整成功响应才成为客户端 ACK 集合的一员。

S3 提供单 key 强一致和条件写，不提供整个数据树的多 key 事务。[S4][S5]
SCAP 的原子性来自先持久依赖、再发布一个根；安全性仍依赖协议参与者不覆盖或删除
可达不可变对象。未变化子树继承原 HEAD 的闭包，热写并不每次重读整库；冷恢复、
激活和相应历史校验负责完整检查。这也是开启 GC 前必须补齐读取保护的原因。

### 3.2 接管不是靠“相信旧进程已经死了”

[`Database::takeover`](../../crates/scap-object/src/lib.rs) 先读取当前 HEAD，验证 ADMIN 和
`expected_revision`，用原条件增加 `owner_epoch`、改变 owner、置 `active=false`。
`activate_session` 完整恢复数据和保留结果，再 exact GET 核对原 body/ETag，最后按原
条件激活。Takeover 的管理 ACK 本身不表示 SQL 已可服务。

如果旧 worker 在接管前已经构造好候选，接管的 HEAD CAS 生效后，旧 ETag 就不能再
匹配。若旧写先被接受、接管后客户端才收到旧响应，那是先前提交的迟到响应，并不
构成“接管后又新增提交”。测试必须记录真实 HEAD 顺序，不能只比较响应到达时间。

HEAD5 引入、HEAD6 沿用的 `head_serial` 每次替换严格递增，防止内容恢复原样造成 ABA；业务 revision、
owner epoch 和物理 storage generation 各有用途，不能互换。特别是，尚未到服务端
准入的旧管理 HTTP 只带 `expected_revision`，单独前进技术 serial 不足以封闭它的
所有未来阶段。HEAD8 候选通过 accepted plan、phase 和取消屏障封闭这些后继，进入该
格式后拒绝旧 takeover/activate，详见[owner 计划](accepted-owner-plan.md)和
[controller 设计](owner-controller-plan.md)。

HEAD8 的后续修复还覆盖一个与 NFS 无关的合法并发时序：A 的 descriptor GET 先返回真正
Missing，B 随后创建并接受 descriptor，A 再看到引用它的新 HEAD。旧实现把前后的不同
观察拼成损坏结论。`e3bdf7b` 要求在 HEAD1 后重新读取依赖，并在 HEAD2 重新授权、核对
完整 body/ETag 后解释；后来的 accepted proof 也需要稳定屏障。这不重试 HEAD CAS，
不为旧意图换 ETag。新增三项确定性单位进入 703 项完整单元及 63 文件精确覆盖分母；
真实 signed-S3 并发证据仍单独验收。由此可见，改用对象 API 避开共享活动文件只是
架构前提，不能替代读取顺序、权限、发布和恢复协议的逐项证明。

当前 `worker_instance` guard 只比较配置中的数值，不是进程 incarnation 认证。部署必须为
每次启动分配不复用的 identity；若两个进程复用同一值，替换进程可以通过原目标 guard。
原 ETag CAS 和完整恢复仍防止两个冲突候选都成为新权威，但实例隔离、路由判断和争用
语义不再有此前提。产品尚未实现持久实例登记/分配；不能用本地 PID 或普通健康探针
声称已解决该问题，参见[计划的实例边界](accepted-owner-plan.md#33-resume)。

### 3.3 不确定与已知提交必须分开

| 观察结果 | 允许的后续行为 |
| --- | --- |
| HEAD 条件发布明确冲突 | 原候选失败；保存原请求并按现有查证协议处理，不更新旧候选 ETag |
| PUT/HTTP 响应丢失或期限耗尽 | 保持 UNKNOWN；用原身份 lookup/cancel，不能认为远端没有发生效果 |
| HEAD 已被接受，native publication/checkpoint/结果物化失败 | 保留原 receipt，返回 `CommittedButUnavailable`，停用本地镜像；远端提交不能回滚 |
| lookup 暂未找到原结果 | 不等于旧在途请求永远不会提交；需要有序取消／关闭屏障才能封闭迟到接受 |
| S3/IAM/KMS 不可得 | 新写与新强读失败关闭，不能凭本地缓存、路由或 lease 返回权威成功 |

当前 [`RoutedClient`](../../sdk/node/src/routed.js) fresh status 后最多派发一次原业务请求，
[`OwnerClient`](../../sdk/node/src/owner.js) 的恢复意图仅供 inspect；新的只读 guarded probe
验证接收 worker 数值，不产生自动接管权。候选 `OwnerPlanClient` 只推进受 HEAD 接受的
固定计划；`OwnerController` 在有界策略内调用它，仍复用 HEAD 权威。其代码与独立模型
已存在；原生产CLI/native/S3合同与15负控继续保留，新增固定12场景实际、独立oracle
和31项定向负控通过。原HTTP/S3独立证明成功或阻断，再与CLI报告核对。

### 3.4 固定controller矩阵的证明范围

11–12 日历史冻结夹具 `e64eb56` 完成23项自测（21项oracle、2项真实HTTP loopback）、12项实际
场景和31项负控。runtime仍为 `fc10287`，277项release输入相同；每个Node入口与57项
SDK/codec/观察器运行源码输入绑定原manifest/tar、实际路径及摘要。旧 `73a7140` 结果、
源码绑定审计缺口与启动失败均保留，新完整历史另行重跑，见
[矩阵机器记录](../evidence/sqlite-s3-integration-controller-matrix-local-2026-11-12.json)。
2026-11-13 又在冻结 `b15bc45` 的新正式 release 上完整执行原矩阵和全部 31 负控，
结果单独见[本轮机器记录](../evidence/sqlite-s3-revalidation-local-2026-11-13.json)。

矩阵覆盖同策略竞争、其他policy/creator及人工marker阻断、Claimed取消、Cancelling
重启、原owner仍健康、撤权、目标误绑、真实429/413、S3 UNKNOWN、probe超时、停机和
迟到原CAS；普通与恢复操作沿用各自固定期限。20个controller、108个受管scapd/Node
子进程、586 HTTP（363 controller）、1914 S3、24 ACK+12 UNKNOWN、36原lookup与12个
快照分别核对。这些分母不作为吞吐，也不推定逐进程逐tick的完整wire归属。

固定策略、地址、5秒tick和至少3次间隔失败仍是前提。动态fleet、在线策略、持久实例
身份、硬RSS/磁盘和生产SLO未交付。本轮 HEAD6 完整 23 负控／1 正控及终态合同
25 负控／1 正控已经完成；原失败与新通过分别保留。严格分支测量门禁仍未满足，PR
保持 Draft；准确状态见[本批门禁](../engineering/roadmap.md#本批合入门禁)。

## 4. 单库与多库的吞吐分别设计

标准 SQLite 的单 writer 是单库约束；SCAP 在此基础上还有单库 HEAD 发布顺序。把一个
热点库放到更多 pod，并不能将不同私有镜像产生的页面直接合并。跨库事务、离线写合并
和多区域多写不属于当前目标。

当前 [`Scheduler`](../../crates/scap-service/src/scheduler.rs) 以完整 HEAD key 注册 actor。
同一进程中同一 key 的 Starting、Running、Draining 生命周期受一个槽位约束，退出与
join 完成前不能重新占用。不同数据库 actor 可以同时执行；控制池独立，恢复 semaphore
限制冷恢复并发。空闲 actor 会回收，闲置库只留下持久元数据和对象。

这解决固定哈希 lane 中“冷库 A 阻塞热库 B”的队列问题，但同库长查询仍阻塞该 actor
中的后续写入，多个 actor 仍竞争 CPU、磁盘和对象带宽。具体调度、公平性和线程边界见
[执行隔离方案](execution-isolation-and-throughput.md)。不能把线程数上限当数据库总数
上限，也不能把多库总 TPS 当单库 TPS。

应用层优先使用短事务、索引和适量 SQL batch；一次 batch 仍是一个原子事务和一个
请求身份，不是独立事务 group commit。事务越大，变化页、结果预算、锁持有时间和
失败成本也越大，batch 大小需要通过实际负载选择，不默认放开所有执行资源上限。

## 5. 吞吐要看完整延迟与对象请求账本

### 5.1 当前关键路径

| 阶段 | 实际工作 | 应单独记录的量 |
| --- | --- | --- |
| 入口与调度 | 认证、body/解析、队列、actor 与资源准入 | 排队时间、拒绝、原 deadline、tenant/class；限流结果不丢弃 |
| 权威与原请求 | fresh HEAD、ACL/owner、请求索引查证 | HEAD/索引 GET 数、字节与延迟；热缓存命中不能省略新权限检查 |
| SQL | 私有 native 执行、物理页捕获、typed/wire 原结果 | SQL 时间、VM/变化页/结果大小与预算失败 |
| 依赖构建 | 旧树路径/块 GET，变化对象 PUT 与 exact read-back | 各类型 GET/PUT 数与字节，条件创建冲突、上传失败 |
| 发布与本地收尾 | manifest 校验、HEAD CAS、native publication、TRUNCATE checkpoint、结果物化 | CAS/本地各阶段延迟，冲突、UNKNOWN 与已提交不可用分别计数 |
| 交付 | Base64/JSON 编码、worker 交接、慢客户端发送 | 编码耗时、存活 backing、发送失败；已提交但未 ACK 仍保留 |
| 冷路径增量 | 全库恢复、历史结果校验、native integrity check、最终激活 barrier | 冷恢复总 GET/字节、磁盘峰值、首条可服务请求时间 |

端到端延迟可以按上述阶段分解。当前同库执行无流水线，单库饱和处理能力受 actor 的
平均占用时间约束；排队继续增加客户延迟。增加其他库的并行度可以提高聚合吞吐，
直到共享网络、CPU、资源池或对象服务限制成为瓶颈。不存在从“S3 可扩展”直接推导的
SCAP TPS 数字。

热强读 `Session::query` 做 fresh HEAD、当前 ACL 和已验证缓存根相等检查，然后查询
本地镜像；根变化需要重新恢复。直接冷 `Database::query` 则物化完整闭包。两者必须
分别测量，不能将纯本地 SELECT 的耗时包装成远端强读延迟。

### 5.2 已有可核对的历史请求量，不是当前性能承诺

[HEAD5 容量记录](../evidence/head5-capacity-local-2026-11-09.json)绑定
`f6c9073a924297f5cd1704fa3c677101ad451d3f` 与当时实际二进制。本地兼容端点的 1 GiB
数据中，每次点修改的业务 payload 为 65,536 bytes：

| 历史场景 | GET 次数 | PUT 次数（含 HEAD） | PUT 请求字节 | GET 响应字节 |
| --- | ---: | ---: | ---: | ---: |
| `point_1gib_beginning` | 16 | 8 | 292,837 | 593,234 |
| `point_1gib_middle` | 18 | 9 | 424,360 | 856,534 |
| `point_1gib_end` | 18 | 9 | 313,513 | 635,094 |
| `cold_recovery` | 8,338 | 2 | 1,599 | 1,084,291,629 |

点写的上传量远小于整库，说明增量树已在该负载生效；但 24–27 次对象请求也说明请求
放大仍然可观。完整冷恢复读取量约为整个物理库，不能声称已有按需页加载。上表不含
AWS 实测延迟，不认证 PR #53 的新代码，也不能与其他 HEAD 格式的字节数拼接成同轮成绩。

### 5.3 历史 HEAD6 本地基线与实际瓶颈

冻结 `66f452e` 的[独立负载验收](../engineering/head6-runtime-validation.md)已完成：八库、
两租户，185 个原 execute 全部 committed；固定 288 个测量调用无丢样、无自动 SQL 重试。
它经过审计代理和本地兼容端点，每组只有 32/64 个样本，不是 AWS 或生产 SLO。

| 场景 | 并发 | 成功请求/秒 | 单请求 p50 / p99，ms | S3 请求/调用 |
| --- | ---: | ---: | ---: | ---: |
| 单库写 | 1 | 8.795 | 112.601 / 160.354 | 18.531 |
| 单库写 | 4 | 8.750 | 455.455 / 532.210 | 19.797 |
| 四库写 | 4 | 14.376 | 268.860 / 386.995 | 18.000 |
| 单库热读 | 4 | 118.169 | 27.687 / 111.151 | 1.000 |
| 四库热读 | 4 | 124.453 | 27.378 / 83.277 | 1.000 |

表中请求时延包括服务排队、响应解码与观察记录，generator queue 另列在完整验收记录。
小样本 p99 就是各组最大值。同库并发没有增加成功吞吐，主要增加等待；四库约提高
1.643 倍，但每库写入次数、数据布局和请求放大不同，不能据此声称线性扩展或把增益
全部归因于线程。当前优先级仍是减少实测对象往返与副本、有效使用 SQL batch，以及
在固定快照和资源预算内研究独立 I/O 并发，不能靠增加同库线程解决串行提交成本。

32 MiB 冷库在 fresh process/empty compute cache 下完整恢复需 1.746 秒，含 276 ms 人为
阻塞；11 个热库和控制探针全部在解除阻塞前完成，单请求最大 108.120 ms。该轮验证
了有界恢复 permit 与热库/控制隔离，不表示 backend 页缓存已冷，也不替代 1 GiB 容量
恢复、唤醒风暴、长期过载或进程 RSS 硬限制。资源采样与 wait4 数值不一致的原始观察
同样保留，不把采样峰值当成硬上界。

后续已合入 HEAD7 的[同类完整记录](../evidence/head7-runtime-local-2026-11-10.json)
`load.result.measured` 中，单库写并发1为 **10.823 次/秒**，单库写并发4为
**10.083 次/秒**，四库并发4为 **14.707 次/秒**。这些仍是带审计代理、固定小样本、
本地兼容存储的历史观察，不能认证本次 HEAD8/HEAD9 源码，也不能用作生产容量规划。
它进一步说明增加同库请求并发没有增加串行提交能力；要提高热点库吞吐，必须减少
实际关键路径工作，或另行设计并验证新的引擎/提交协议。

### 5.4 本次组合的实际基线：热点吞吐仍未解决

以下是 2026-11-11 的历史基线，不能代替 2026-11-13 的同环境配对。
后续配对与请求分类见第 5.6 节和本轮交付报告。

当时重新执行原冻结 `object-load` 合同：runtime `fc10287`，fixture `ffff164`，正式
release/native SQLite/Node 与 SeaweedFS 4.51，871 个 POST、185 份原 execute、288 个
测量调用。actual、独立 oracle、14 个负控和3个正控全部通过，源码前后一致，详见
[11 日完整机器记录](../evidence/sqlite-s3-integration-load-local-2026-11-11.json)。

| 11 日场景 | 并发 | 成功请求/秒 | 单请求 p50 / p99，ms | S3 请求/调用 |
| --- | ---: | ---: | ---: | ---: |
| 单库写 | 1 | 5.149 | 72.772 / 772.210 | 18.531 |
| 单库写 | 4 | 2.822 | 1181.670 / 2903.984 | 19.797 |
| 四库写 | 4 | 7.206 | 241.331 / 2815.831 | 18.000 |
| 单库热读 | 4 | 217.396 | 14.067 / 57.673 | 1.000 |
| 四库热读 | 4 | 223.134 | 13.902 / 47.650 | 1.000 |

所有测量调用成功；全部871次POST中870次成功，一次是原合同要求的
`RECOVERY_BUSY`。185个原execute均查证committed，原结果和业务数据完整保留。
32 MiB 用户数据的冷恢复观察为1106.081ms，其中162.626ms是人为GET gate保持；
暂停冷恢复时的11个热库/控制探针按原时限完成。这不是GiB冷启动或生产恢复SLO。

这些结果低于部分历史写入数字；测试环境不同，未做同环境的前后配对，不能归因于
某项代码变化。测量期间没有其他构建或runtime故障合同，仍有轻量源码/Git文件操作，
CPU和磁盘未隔离，观察代理和证据写盘也有开销。每组只有32或64个样本，本组p99
等于最大值，不提供生产尾延迟置信界限。

该次原始账本中单库四并发有5个对象请求的代理观察往返超过100ms；四库写有20个，
最慢的一次HEAD PUT观察间隔为882.188ms。该间隔包含代理记录开销，不能当成纯S3服务
时间；端到端还包含SQL、本地checkpoint、编码与排队，当前资料不足以把所有尾延迟
归因到单一组件。已经确定的是每写18–20次对象请求及同库串行路径仍在；增加同库
并发没有消除这些工作，也没有形成高吞吐承诺。

### 5.5 优化的优先顺序与可测成果

| 优先项 | 可以测量的改进 | 必须保留的合同 |
| --- | --- | --- |
| 复用现有 Session、SQL batch、索引调优 | 同工作量下恢复次数、每业务记录对象请求数、actor 占用与 p99 | 每次新操作 fresh HEAD；同原请求／结果；batch 的原子边界明确 |
| 保持已通过的组合及输出池合同 | 慢客户端／大结果不会无界占用声明受保护的输出 backing；控制信用仍可用 | `/v1` 池范围、实际最后 owner 退款、CBU/UNKNOWN 与原 deadline 不变 |
| 整理每类对象的 GET/PUT 路径并减少确定的冗余 | 相同数据、结果、故障模型下减少请求数或分配副本 | 不删除规定的 immutable read-back，不缓存授权，不用 LIST 猜最新 HEAD |
| 在测量确认瓶颈后研究有界独立块 I/O 并发 | 降低冷恢复／大事务 I/O 墙钟时间，同时记录峰值内存、在途 bytes 和失败尾部 | 固定 Snapshot/ObjectContext；所有依赖完成才发布；失败不换根、不延长期限 |
| 后续 lazy VFS、跨库打包或 group commit | 另行证明冷首读、每事务请求成本或有效提交率改善 | 另立 ADR 和 native/恢复/GC 合同，不计入当前已承诺收益 |

新 I/O 并发属于待评估优化，当前顺序遍历并未自动获得它。性能优先降低实测的等待和
复制开销，不以改成异步 ACK、陈旧读或减少失败样本来换取更漂亮的数字。

### 5.6 本轮已经实现的请求减少，以及尚未证实的吞吐收益

PR #60 的私有 `VerifiedManifest` 证明只能由原 `data_tree::update` 创建；它绑定原
ObjectContext、后端与 handle lineage、Scope／物理世代、输入／输出根、页数和原 deadline。
消费时核对原 HEAD body／ETag，再执行原条件 CAS。不可变依赖的首次条件写和完整
回读、配额／健康验证、原结果和 native publication 都保留。普通 query/read 与管理发布
不使用这个快速路径。设计见
[Manifest 验证复用](https://github.com/ckanner/scap/blob/fd508cc052c21dba0e3c54b8e8e82d11c167777a/docs/architecture/verified-manifest-publication.md)。

2026-11-13 首次按 b15 → fd508 顺序运行相同固定 fixture；两版各自的 actual、独立
oracle 和原 14 负控／3 正控全部通过。五个测量阶段的对象帧按原 key、字节 SHA、类型和
请求／响应编号分类，得到下表；同阶段其他对象类型的 GET／PUT 次数全部相同。

| 测量阶段 | 调用数 | 基线全部 S3 请求 | 优化全部 S3 请求 | 少出的 Manifest GET |
| --- | ---: | ---: | ---: | ---: |
| 单库写，C1 | 32 | 593 | 561 | 32 |
| 单库写，C4 | 64 | 1,267 | 1,203 | 64 |
| 四库写，C4 | 64 | 1,152 | 1,088 | 64 |
| 单库暖读，C4 | 64 | 64 | 64 | 0 |
| 四库暖读，C4 | 64 | 64 | 64 | 0 |

这是按 phase 的聚合核验；它与代码中每次新提交省一次 Manifest GET 的设计相符，
但没有新增并发下逐 execute 的 HTTP 区间归属证明。不能把本表 160 次减少扩写成
全程所有 871 次调用逐类型受益，普通暖读仍然每次 fresh HEAD。

首次配对的速率变化混合：单库两组分别约 +5.28%／+11.35%，四库写为 -24.00%。
这些原始结果保留，不能将请求减少直接写成全面 TPS 提升。针对这个具体差异，另行
冻结一次反向顺序配对，完整实际／oracle／14 负控／3 正控也通过；三个写入阶段
再次恰好少 32／64／64 个 Manifest GET，其他对象类别次数相同。四库写仍下降
24.52%，单库两组这次也下降，不能将回退归为顺序噪声已经解决。全部数字与限度见
[性能验收](../engineering/verified-manifest-load-validation.md)和
[完整机器记录](../evidence/verified-manifest-load-local-2026-11-13.json)。不挑选更好的一次，
不唯一归因环境，也没有事后设置性能通过阈值。

两版使用相同 SQL 结构、schema、调用集合和 payload 长度；原 fixture 每次生成独立
随机 BLOB，数据字节并非逐字相同。固定小样本、执行顺序、共享宿主以及观察代理／
证据写盘都会影响时间。对象请求成本减少已有实际证据；稳定吞吐、生产 p99 与 AWS
性能仍需预先冻结负载、重复测量和目标部署验收。

## 6. Turso 可以借鉴什么

必须区分三个产品／组件层次，不能用一张“Turso 基于 S3”的标签替代协议分析。

| 路线 | 官方可确认的机制 | SCAP 的取舍 |
| --- | --- | --- |
| 开源 libSQL / Bottomless | libSQL 仍继承 SQLite 单 writer；Bottomless 按 generation 异步复制已提交 WAL 页，本地 `insert_frames` 后提交复制工作 | 可参考分批和恢复链；这条异步备份边界不能满足本项目 ACK 前 S3 权威发布 [S8][S13] |
| Turso Cloud | WAL 先写 S3 Express，成功后确认；多租户 WAL 合批；DB 分块与本地缓存、按需取块 | 借鉴远端持久化参与提交和请求摊薄；不据公开文章假定其 owner/GC 采用本项目 HEAD 协议 [S9][S10] |
| 新 Rust Turso Database | MVCC 模式下 `BEGIN CONCURRENT`、行级冲突检测和 snapshot isolation；2026-08-03 的 Cloud 公告为需显式启用的 early preview | 是独立 Rust 引擎的并发能力，冲突仍需处理；S3 不会使 SCAP 的固定 libSQL 自动具备这套能力 [S11][S14] |

本次还核对开源 `bottomless/src/bottomless_wal.rs`：`insert_frames` 在本地
`wrapped.insert_frames` 后调用 `replicator.submit_frames`，等待复制进度／snapshot 的
逻辑位于 checkpoint 路径。由此只能判断这条开源路径的确认边界，不能反推 Cloud。
固定上游比较与更详细的生命周期取舍见[已有源码复核](sqlite-s3-turso-review.md)。
Cloud 的 WAL 合批、缓存和调度属于服务架构；不能因引擎开源就假定全部 Cloud 基础设施
已经开源，或把旧 libSQL 方案和新引擎 preview 的能力拼成同一个已验证产品。

Turso/AWS 文章中的 6.4 ms 平均值属于作者的 S3 Express 环境；它既不是 SCAP 的实测，
也不是 S3 Standard、其他兼容服务或端到端 p99 的承诺。MVCC 仍需要处理写冲突，
也不等于允许多主机任意改同一份网络 WAL。[S10][S11]

## 7. S3 Standard 与 Express 的故障域不能混用

| 选项 | 官方故障域 | 对当前 SCAP 的决定 |
| --- | --- | --- |
| S3 Standard / general purpose bucket | 对象冗余跨至少三个 AZ | 继续作为主方案的目标验证后端；仍要单独验证真实云端条件写、身份与故障合同 [S6] |
| S3 Express One Zone / directory bucket | 单 AZ 内多设备冗余；整个 AZ 损坏可能丢失数据 | 不直接替换唯一持久层；若未来使用，另立 ADR 和验收其认证、端点、恢复与损失边界 [S6][S7] |
| 兼容 S3 的其他服务 | 依服务实现与部署配置而定 | API 名字兼容不等于强一致／CAS／持久性相同，每种实现独立验收 |

若最新已确认 WAL 只在 Express One Zone，隔一段时间才 checkpoint 到 Standard，
则整个 AZ 灾难下最后一次 checkpoint 后的数据并未因此取得 Standard 的多 AZ 保护。
不能把这种组合宣称为跨 AZ RPO=0。反过来，Standard 的存储冗余也不会自动给 SCAP
生成自动计算切换、跨区域晋升或应用 SLA。

当前“零已确认事务丢失”的目标条件是：原对象服务及密钥仍满足约定，全部计算／缓存
可以丢失；它不覆盖对象被管理员删除、密钥丢失、应用误写或整个区域永久丢失。
新强读和新写在线依赖 S3，因此 IAM/KMS/区域端点故障也是可用性边界。

## 8. 按现有路线完成，不另造并行协议

以下顺序是已有 N1–N4 的实施映射。各工作包可以并行研究，只有依赖合同和对应验收
闭合后才启用能力。生产文件继续进入原逐文件四维精确单位覆盖分母。

| 工作包 | 当前起点 | 下一交付与退出标准 |
| --- | --- | --- |
| 当前候选组合 | HEAD6/HEAD7 已合入；PR #59 组合 owner/controller/S1，PR #60 实现 Manifest 验证复用，分别保留冻结来源 | 本轮单位和各实际合同见当前报告；HEAD6/终态完整通过，逐文件分支测量缺口仍阻断合入，不能用历史摘要代替原件 |
| N1 权威合同 | 已有提交 gate、结果查证、取消、接管及多轮本地恢复证据 | 完整 OT-01–08、真实 AWS Standard 合同和独立并发历史审计；同 ETag 双发布、所有切点崩溃、迟到旧 owner、依赖损坏与全计算丢失分别验收 |
| N2 自动恢复 | HEAD8持久owner-plan、有限controller/fleet/CLI；本次真实重启接管、丢响应、原结果及S1保留合同与15负控通过 | 固定多controller矩阵/31负控通过；动态fleet、在线策略和持久identity分配另验，不能重放业务SQL |
| N2 资源与活性 | actor、intake、单次预算、HTTP期限和普通/v1 output Pool；本次固定单库/多库及32 MiB冷恢复合同通过 | 对当前写入尾延迟按阶段测量并减少对象请求；补跨入口decode/native heap/磁盘总账、持续过载、唤醒风暴和租户公平性 |
| N3 可持续存储 | HEAD6 copy/promote/持久 sweep 和 HEAD7 Deleted 永久终态退休均已完成对应本地验收并合入 | 在全部保留根、旧操作与迟到 PUT 的真实历史中验证回收；长期成本统计包括永久控制元数据，不把一轮清空当作永久无孤儿 |
| N3 快照与 PITR | HEAD9 S1 capture/release、多根 COPY/GC 实际／10 负控通过；b15 的 783+783 单位通过、67 文件有 map，严格分支门禁仍未闭合；当前模型 804／48+3，旧 804／47+3 属于历史候选 | 实现 S2 新 Scope 恢复、新权限／请求空间及目录完成协议；任意时间 PITR 另设计；不得把 S1 保留根当完整 restore 产品 |
| N4 发布出口 | 既有本地容量与部分故障证据 | 冻结负载及数字 SLO，测目标存储、真实部署故障域、长运行、保留/GC 成本、运维恢复；按既有流程另行启用非关键试运行 |

HEAD6 的产品回收依赖整套闭包、退休与 checkpoint 协议，独立条件 DELETE capability
本身不足以授权删除。guarded probe 不是自动 HA；普通 `/v1` output Pool 不是全进程
RSS 上限。本轮输出池、response expiry与资源专项已通过原固定合同；跨入口资源总账和
全进程硬隔离仍需完成，适用入口与边界见
[输出池设计与证据](v1-output-pool.md)。

普通操作的回收路线继续采用既定的可中止世代方案，不默认加入不可撤销永久 pin。
当前 active、复制目标和 retained hold 的损坏必须失败关闭；只有 fresh 权威证明原世代
永久退休时，才能将未完成旧读取分类为过期。局部 handle 的 quarantine 不能冒充
全系统共享的损坏知识，完整模型与生产接线必须对应。

lazy VFS、同文件并发读池、替换 MVCC 引擎、跨库 group commit、Express 唯一持久层和
多区域多写继续是独立后续决策。当前完成目标不以默认加入这些能力为前提；若真实
负载证明原串行／全量恢复路径无法满足冻结目标，再据测量重新设计相应部分。

## 9. 每个结论都对应可失败的验收

| 合同 | 必须观测到的结果 |
| --- | --- |
| 不共享网络活动文件 | unsafe cache/temp/symlink 目标在 native 使用前拒绝；真实 NFS/EFS/FUSE 挂载另测；不能用 procfs 分类测试声称真实挂载通过 |
| stale owner fence | 接管后释放暂停旧 CAS，旧候选不新生效；接管前提交的迟到响应保留其原顺序 |
| native 与远端一致 | HEAD 已接受后的 native/checkpoint/编码失败仍可查到原 receipt 和结果；无半事务，无 SQL 重跑 |
| UNKNOWN | 区分响应丢失、未发送、已接受与有序取消；完整客户端调用集合中不删除超时和迟到样本 |
| 多库隔离 | 阻塞冷库恢复时热库与控制仍按声明资源合同前进；单库严格串行；共享资源过载明确背压 |
| 全计算恢复 | 新机器无旧 PVC／目录状态，逐条核对 ACK、原结果、物理数据、目录和永久身份屏障 |
| 持续存储 | 多轮提交、留存、退休、GC 崩溃与恢复后，所有被保护根可读；对象／orphan 增长与回收开销可量化 |
| 性能与成本 | 同数据、相同保证、预定义开环负载；分别报告单库/多库、冷热、p50/p95/p99、错误、恢复时长与各对象操作/字节 |

原始源码、锁定依赖、native、实际二进制、配置、后端类别、完整调用／对象历史和
独立 oracle 绑定同一候选；单元、模型、兼容端点、真实 AWS 和故障域证据分别保存。
缺失环境记 NOT_RUN，实际失败继续为失败。不能把容量参数、历史绿色结果或 Turso
性能数据当本候选已完成验证的替代品。

## 10. 官方资料

以下外部资料于 2026-11-11 复核；采用其技术边界，不继承其产品承诺。

- [S1：SQLite — Write-Ahead Logging](https://www.sqlite.org/wal.html)：WAL 共享内存、同机与单 writer。
- [S2：SQLite — SQLite Over a Network](https://www.sqlite.org/useovernet.html)：网络文件 I/O 的同步、顺序和锁风险。
- [S3：SQLite — How To Corrupt An SQLite Database File](https://www.sqlite.org/howtocorrupt.html)：文件锁与错误访问方式。
- [S4：AWS — S3 data consistency model](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html#ConsistencyModel)：单对象一致性边界。
- [S5：AWS — Conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)：原 ETag 条件替换与条件创建。
- [S6：AWS — Storage classes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-class-intro.html)：Standard 与 Express One Zone 的 AZ 范围。
- [S7：AWS — Express directory bucket creation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-express-tutorial-create-directory-bucket.html)：AZ 故障可能不可用或丢失数据。
- [S8：libSQL Bottomless README](https://github.com/tursodatabase/libsql/blob/main/bottomless/README.md)与[实现](https://github.com/tursodatabase/libsql/blob/main/bottomless/src/bottomless_wal.rs)：开源异步复制边界；本次读取实现 blob 为 `98fd59ce16c02f8110c2b80aaa9d4fd50c16e39b`。
- [S9：Turso — Cloud durability](https://turso.tech/blog/how-does-the-turso-cloud-keep-your-data-durable-and-safe)：分块、本地缓存与远端确认。
- [S10：AWS/Turso — Transactional database with S3 Express](https://aws.amazon.com/blogs/storage/how-turso-built-a-transactional-database-using-amazon-s3-express-one-zone/)：2026-07-23 文章，多库合批与写入路径；作者测量不等于 SCAP 性能。
- [S11：Turso manual](https://github.com/tursodatabase/turso/blob/main/docs/manual.md)：MVCC/BEGIN CONCURRENT 的连接、冲突和功能限制；快速演进的 main 不替代本项目固定依赖。
- [S12：AWS — Features of Amazon EFS](https://docs.aws.amazon.com/efs/latest/ug/features.html)：NFSv4 advisory byte-range locks 与 close-to-open 一致性；不推出跨主机 SQLite WAL 支持。
- [S13：libSQL 项目说明](https://github.com/tursodatabase/libsql)：libSQL 与 Rust Turso Database 是不同项目，前者保留单 writer 限制。
- [S14：Turso — Concurrent Writes Early Preview](https://turso.tech/blog/concurrent-writes-on-turso-cloud)：2026-08-03 公告，显式启用、tursodb 数据库与行级 MVCC；相同行冲突仍需处理。
