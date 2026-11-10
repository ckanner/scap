# SQLite on S3：文件安全、并发、吞吐与完成标准

复核日期：2026-11-10。源码审查基线为
[`66f452ec73111f8c9dc7509883717828ba883e8a`](https://github.com/ckanner/scap/commit/66f452ec73111f8c9dc7509883717828ba883e8a)
（PR #54 的 HEAD6 冻结生产候选）。本文补充已接受的[对象存储方案](object-storage-native-proposal.md)，
不修改 HEAD、请求身份、所有权或 GC 协议。下文的“已实现”只表示该树存在对应代码；
历史验收只认证其原冻结输入，新候选是否通过仍以[验证规范](../engineering/validation.md)
和本候选证据为准。

## 1. 要完成的目标与现在的结论

SCAP 的目标是：大量独立租户／Agent 数据库共享计算资源，以对象存储保存唯一持久权威，
计算节点及全部本地缓存丢失后仍可恢复所有已确认事务、原始结果和正确性元数据。
同一数据库保持一个有效写入序列，不要求每个闲置数据库常驻进程。

**当前架构避开了跨主机共享 SQLite 活动文件的锁风险；它没有消除单库串行提交、
对象往返、整库冷恢复和共享资源的成本。HEAD6 已实现完整复制与有界物理 GC，正在
完成其独立真实验收；自动 owner 恢复、Deleted 最后一代退休、PITR 与生产性能验收
仍未完成，不能宣布整个目标已经交付。** 新源码与实际完成状态见[HEAD6 验收](../engineering/head6-runtime-validation.md)。

| 用户关心的问题 | 当前代码的处理 | 仍有的边界 |
| --- | --- | --- |
| NFS/EFS 上共享 `.db/WAL/SHM` 损坏 | 私有本地执行镜像；文件系统准入；跨节点只通过对象 API 协调 | 可靠本地 I/O、可信挂载和固定 native 引擎仍是前提；真实网络挂载实验另验 |
| 旧容器未退出，新容器已经接管 | 同一个 HEAD 的原 ETag CAS；takeover 推进 owner epoch 并先置 inactive | 探测和调度不决定写权；后台自动 controller 尚未交付 |
| 一个热点数据库写入拥堵 | 同库 actor 串行，事务有界，支持一次事务多个 SQL 语句 | 加 pod 不会自动增加该库的有效 writer；没有多写者或 group commit |
| 一个冷库阻塞其他热库 | 不同库有界 actor，控制池和恢复准入分别设置 | CPU、网络、S3、磁盘、进程资源仍共享；不是硬租户隔离 |
| 小改动上传整库 | 128 KiB chunk、COW 数据树和分段请求索引 | 仍有多个顺序 GET/PUT、read-back 与 HEAD CAS |
| 节点丢失后重新上线 | 从 S3 完整恢复、校验，再激活；Session 保留已恢复镜像 | 当前冷恢复必须读取完整数据及保留结果闭包，没有 lazy VFS |
| 长期成本 | 逻辑请求留存边界、完整闭包复制、单调物理世代与持久 GC checkpoint | GC 默认无删除凭据；需公平重复 sweep，Deleted 最后一代尚保护，单库配额不限制 bucket 总量 |

实现映射见 [README](../../README.md)、[路线图](../engineering/roadmap.md)、
[HEAD5 基础](head5-foundation.md)和[资源预算](resource-budgets.md)。

## 2. SQLite 的真实限制，以及本项目如何避开共享文件问题

SQLite 并非只能由一个进程使用。官方 WAL 支持同机多个连接／进程，读者与写者可以
并行，但一个数据库同一时刻只有一个 writer；共享 wal-index 要求这些进程处于同一
主机。网络文件系统的问题同时涉及文件锁、同步与写入顺序，不能简化为所有 NFS
必然立即损坏，也不能只归因于 `fcntl`。[S1][S2][S3]

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
已知提交保留原 receipt，不能因为读取过期抹掉提交事实。显式快照/PITR 的 retained
roots 尚未实现，不能把保留 SQL 原结果等同于历史数据库快照。

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
所有未来阶段，详见[owner controller 设计](owner-controller-plan.md)。

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
验证接收 worker，不产生自动接管权。任何后续 controller 都继续复用 HEAD 权威，不另建
一套绕过它的分布式锁。

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

### 5.3 优化的优先顺序与可测成果

| 优先项 | 可以测量的改进 | 必须保留的合同 |
| --- | --- | --- |
| 复用现有 Session、SQL batch、索引调优 | 同工作量下恢复次数、每业务记录对象请求数、actor 占用与 p99 | 每次新操作 fresh HEAD；同原请求／结果；batch 的原子边界明确 |
| 关闭当前组合及输出池验证缺口 | 慢客户端／大结果不会无界占用声明受保护的输出 backing；控制信用仍可用 | `/v1` 池范围、实际最后 owner 退款、CBU/UNKNOWN 与原 deadline 不变 |
| 整理每类对象的 GET/PUT 路径并减少确定的冗余 | 相同数据、结果、故障模型下减少请求数或分配副本 | 不删除规定的 immutable read-back，不缓存授权，不用 LIST 猜最新 HEAD |
| 在测量确认瓶颈后研究有界独立块 I/O 并发 | 降低冷恢复／大事务 I/O 墙钟时间，同时记录峰值内存、在途 bytes 和失败尾部 | 固定 Snapshot/ObjectContext；所有依赖完成才发布；失败不换根、不延长期限 |
| 后续 lazy VFS、跨库打包或 group commit | 另行证明冷首读、每事务请求成本或有效提交率改善 | 另立 ADR 和 native/恢复/GC 合同，不计入当前已承诺收益 |

新 I/O 并发属于待评估优化，当前顺序遍历并未自动获得它。性能优先降低实测的等待和
复制开销，不以改成异步 ACK、陈旧读或减少失败样本来换取更漂亮的数字。

## 6. Turso 可以借鉴什么

必须区分三个产品／组件层次，不能用一张“Turso 基于 S3”的标签替代协议分析。

| 路线 | 官方可确认的机制 | SCAP 的取舍 |
| --- | --- | --- |
| 开源 libSQL / Bottomless | 已提交 WAL 页异步复制，按 generation 备份与恢复；`insert_frames` 提交本地帧后提交复制工作 | 可参考分批和恢复链；它的异步备份边界不能满足本项目 ACK 前 S3 权威发布 [S8] |
| Turso Cloud | WAL 先写 S3 Express，成功后确认；多租户 WAL 合批；DB 分块与本地缓存、按需取块 | 借鉴远端持久化参与提交和请求摊薄；不据公开文章假定其 owner/GC 采用本项目 HEAD 协议 [S9][S10] |
| 新 Rust Turso Database | MVCC 模式下 `BEGIN CONCURRENT`、行级冲突检测和 snapshot isolation | 是引擎并发能力；采用 S3 不会使 SCAP 的固定 libSQL 自动具备这套能力 [S11] |

本次还核对开源 `bottomless/src/bottomless_wal.rs`：`insert_frames` 在本地
`wrapped.insert_frames` 后调用 `replicator.submit_frames`，等待复制进度／snapshot 的
逻辑位于 checkpoint 路径。由此只能判断这条开源路径的确认边界，不能反推 Cloud。
固定上游比较与更详细的生命周期取舍见[已有源码复核](sqlite-s3-turso-review.md)。

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
| 当前候选组合 | HEAD6 已冻结；632+632 单位、59 文件精确覆盖、新 native/1 GiB 已完成 | 补齐本批真实 HTTP/S3、回收、负载与独立原始历史门禁；旧失败、后续修复与新成功分别保留 |
| N1 权威合同 | 已有提交 gate、结果查证、取消、接管及多轮本地恢复证据 | 完整 OT-01–08、真实 AWS Standard 合同和独立并发历史审计；同 ETag 双发布、所有切点崩溃、迟到旧 owner、依赖损坏与全计算丢失分别验收 |
| N2 自动恢复 | 静态路由、显式 owner 意图、guarded probe | 按[owner-controller 既定决定](owner-controller-plan.md)优先完成 accepted owner-plan 独立模型、权威 phase 与新 API，再接探测/controller；跨重启同计划推进、abort 与迟到 HTTP 竞争可证明；业务 SQL 不重放 |
| N2 资源与活性 | actor、intake、typed 单次预算、HTTP 期限与普通 `/v1` output Pool；输出/慢消费实证已完成 | 运行冻结单库/多库基线，补跨入口对象 decode/native heap/磁盘总账；持续过载、冷恢复风暴、tenant 公平性与硬容量另验 |
| N3 可持续存储 | HEAD6 完整 copy/promote、共享知识域、可中止旧操作、单调退休与持久 sweep 已接通产品 | 完成[本批故障验收](../engineering/head6-runtime-validation.md)，再实现 Deleted 永久终态退休、retained hold/PITR 与长期成本收敛；不把一轮清空当作永久无孤儿 |
| N3 快照与 PITR | 方案与基础原语存在，产品未完成 | 从受保护根恢复到新数据库身份，重新建立权限和请求空间；源/目标崩溃、旧 owner/ACL/取消屏障不复活、保留根安全释放逐项验收 |
| N4 发布出口 | 既有本地容量与部分故障证据 | 冻结负载及数字 SLO，测目标存储、真实部署故障域、长运行、保留/GC 成本、运维恢复；按既有流程另行启用非关键试运行 |

HEAD6 的产品回收依赖整套闭包、退休与 checkpoint 协议，独立条件 DELETE capability
本身不足以授权删除。guarded probe 不是自动 HA；普通 `/v1` output Pool 不是全进程
RSS 上限。该池已接入并完成本批实际合同，适用入口与边界仍见
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

以下外部资料于 2026-11-10 复核；采用其技术边界，不继承其产品承诺。

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
