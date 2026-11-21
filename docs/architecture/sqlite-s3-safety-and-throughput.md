# SQLite on S3：文件安全、并发、吞吐与完成标准

更新：2026-11-20（America/New_York）。当前基线是已合入
[PR #66](https://github.com/ckanner/scap/pull/66) 的
[`b9d736b`](https://github.com/ckanner/scap/commit/b9d736b)，包含此前
[PR #65](https://github.com/ckanner/scap/pull/65) 的身份分配与 S2 恢复。
本文按主线解释当前设计；各次验证仍绑定原冻结源码，不因文档更新而重新认证。

**SCAP 已避开跨主机共享活动 SQLite 文件的风险，并实现对象权威提交、接管恢复、
独立并行强读、快照恢复和有界调度。它仍使用单库串行 writer，冷恢复仍读取完整
闭包；独立事务 group commit、按需读页、任意时间 PITR 和生产资格尚未完成。**

总目标与顺序见[交付计划](../engineering/sqlite-s3-delivery-plan.md)，合入证据见
[并发与资源交付记录](../engineering/sqlite-s3-scale-validation-2026-11-18.md)。本文补充
[对象存储方案](object-storage-native-proposal.md)，不另建所有权或提交协议。

## 1. 要完成的目标与现在的结论

目标是让大量独立租户／Agent 数据库共享计算资源，以对象存储保存唯一持久权威。
全部计算节点及本地缓存丢失后，仍能恢复已确认数据、原始请求结果和正确性元数据。
闲置数据库不需要常驻进程；活动库的资源使用、失败和恢复必须有明确边界。

| 用户关心的问题 | 当前主线的处理 | 仍有的边界 |
| --- | --- | --- |
| NFS/EFS 上共享 `.db/WAL/SHM` | 私有本地镜像；缓存／临时目录准入；跨节点只使用对象 API | 可靠本地 I/O 和可信挂载仍是前提；类型分类不能代替真实挂载验收 |
| 旧容器未退出，新容器接管 | HEAD 原 ETag CAS、owner epoch、持久 owner plan 与取消屏障 | 探测只触发决策，真正写权仍由 HEAD 排序 |
| Pod 重启复用实例身份 | 永久 claim，支持 `worker_instance="auto"` 持久分配 | 须初始化历史 high-water；身份不授予 owner，也不自动刷新业务路由 |
| 同库读被写队列阻塞 | 可选 `admission.read_pool`，各 reader 使用独立完整镜像并重新授权 | 增加读执行并发，不增加 writer；额外镜像占用资源 |
| 热点单库写入拥堵 | 单库 writer actor 串行，短事务、索引和显式 SQL batch | 无独立事务 group commit 或同库 MVCC；加 Pod 不会自动提高该库写吞吐 |
| 冷库拖住其他库 | 不同库 actor、独立控制池与恢复准入，空闲 actor 回收 | CPU、磁盘、网络及 S3 仍共享，不等于每租户物理隔离 |
| 全计算丢失 | 完整恢复数据及原结果，验证后激活；controller 推进原计划 | 无 lazy VFS；RTO 随闭包大小、对象往返、检查和排队变化 |
| 备份与误操作恢复 | S1 retained snapshots；S2 恢复成独立新 Scope | 不是任意时间 PITR，也不是只复制 root 的瞬时分支 |
| fleet 与资源边界 | 受信动态配置、永久退役、quiesce；可选 cgroup/tmpfs 实际准入 | 无全局 fleet 共识或自动扩缩容；组级边界不是每租户硬隔离 |
| 长期成本 | 代际复制／退休、持久 GC sweep、Deleted 最后一代终态 seal | GC 默认无删除权限；需重复 sweep，永久元数据和 orphan 不受单库配额限制 |

真实 AWS Standard、目标 IAM/KMS、跨故障域、长期 GC／成本和生产 SLO 仍需独立
验收，不能由兼容端点、覆盖率或 CI 成功推导。

## 2. SQLite 的真实限制，以及本项目如何避开共享文件问题

SQLite 支持同一主机上的多个连接和进程。WAL 允许读者与写者并行，但同库同一时刻
只有一个 writer；共享 wal-index 要求相关进程访问同一共享内存。网络文件系统还
涉及锁、同步与写入顺序，不能只归因于 `fcntl`，也不能说所有 NFS 必然立即损坏。[S1][S2][S3]

EFS 支持 NFSv4 byte-range advisory locks 和 close-to-open 一致性。存在文件锁
不等于满足跨主机 SQLite WAL 的共享内存前提；“advisory”本身也不是损坏证明。
SCAP 让数据库引擎使用私有本地文件，通过服务 API 提供远程访问。[S12]

### 2.1 私有文件与实际代码

| 边界 | 实现入口 | 行为 |
| --- | --- | --- |
| 目录准入 | [storage.rs](../../crates/scap-object-sqlite/src/storage.rs) | 检查实际打开目录的文件系统，拒绝已知网络、FUSE 和未知类型，并检查临时目录候选 |
| 镜像创建 | [file.rs](../../crates/scap-object-sqlite/src/file.rs) | 独占创建私有目录／镜像，不复用旧文件或 sidecar |
| native 配置 | [sql.rs](../../crates/scap-object-sqlite/src/sql.rs)、[config.rs](../../crates/scap-object-sqlite/src/config.rs) | 使用受信默认 Unix VFS 与私有连接，关闭自动 checkpoint，保留受检同步路径 |
| 执行所有权 | [scheduler.rs](../../crates/scap-service/src/scheduler.rs)、[engine.rs](../../crates/scap-service/src/engine.rs) | 连接在所属线程创建、使用、销毁；writer 和各 reader 镜像独立 |
| 失败处理 | [Engine::execute_using](../../crates/scap-service/src/engine.rs) | 丢弃受影响 Session，新恢复重新检查对象权威 |

读池使用多份完整私有镜像，不共享 writer 的活动 WAL。同一镜像仍由所属线程和
受控连接使用。前提见[存储部署要求](../operations/sqlite-storage-safety.md)及
[同库强读池](../../crates/scap-service/docs/read-pool.md)。

文件系统准入是防误配置措施，不是恶意宿主沙箱。允许 overlayfs 不表示自动核验
全部底层挂载；部署器须保持挂载、目录解析、环境与 VFS 稳定。本地缓存可以丢弃，
仍必须正确执行：native 错误页面若被正常编码和提交，hash/CAS 不会识别其业务
内容错误。固定引擎及 WAL-reset 边界见[原生评估](sqlite-wal-reset-assessment.md)。

### 2.2 本地执行与远端权威是不同层次

本地 `.db/WAL/SHM` 只用于执行。远端保存不可变页块、数据树、原始结果和请求索引，
由单库 HEAD 引用；S3 没有被挂载后交给 SQLite 当作 POSIX 文件系统。

[ObjectContext](../../crates/scap-object/src/object_context.rs) 固定后端、完整 Scope、
原 HEAD body/ETag、物理 generation 和绝对 deadline。恢复不能拼接不同根的页面，
也不能在依赖缺失时建空库。只有 fresh 权威证明原世代永久退休，才可把相应未完成
旧读取分类为 `SnapshotExpired`；真实损坏仍失败关闭。

S1 保留根参与完整复制、恢复与 GC 判断。S2 逐层重封装数据到新 Scope，完整验证
后创建独立目标，不继承旧 ACL、owner、请求和取消屏障。目标完成后不依赖源
payload；provenance 本身不永久 pin 源库。见[快照设计](retained-snapshot-restore.md)
及 [S2 HTTP 合同](../../crates/scap-service/docs/restore.md)。

## 3. S3 提交、fencing 与丢响应的精确边界

### 3.1 一次写入的确认条件

1. exact GET 同时取得 HEAD body/ETag，验证当前权限、owner、生命周期和原请求。
   已保留请求解析原结果；同 ID 不同内容不能作为新 SQL 执行。
2. 固定原 Snapshot、ObjectContext、请求与 deadline，执行 SQL、暂存页和原结果。
   `CommitGate` 位于 native publication 之前。
3. 创建变化块及树路径，保留原结果、请求索引和取消屏障；不可变依赖条件创建并
   exact GET 回读比较完整字节。依赖未完成不能发布 HEAD。
4. 用原 ETag 条件发布一个 HEAD；冲突后的旧物理差分不能换新 ETag 继续提交。
5. 远端接受后才允许 native publication，完成受检 checkpoint 和结果物化，再返回成功。
   客户端完整收到成功响应才计入客户端 ACK 集合。

代码入口：[Session](../../crates/scap-object/src/lib.rs)、
[GateWal](../../crates/scap-object-sqlite/src/gate.rs)、
[PreparedHead](../../crates/scap-object/src/head_publication.rs) 与
[SqliteWriter](../../crates/scap-object-sqlite/src/lib.rs)。当前保留普通精确 Manifest GET、
`synchronous=FULL` 和受检 TRUNCATE，没有改成异步确认或减少必要回读。

S3 提供单 key 强一致和条件写，不提供跨 key 原子事务。SCAP 用“先持久依赖，再
发布一个根”构建原子性；对象不可变性、引用完整性及安全删除仍由协议和权限
共同保证。bucket 支持 CAS 不能单独证明数据库正确。[S4][S5]

### 3.2 旧 owner 和重复进程身份

所有权变化和业务提交在同一 HEAD 排序。owner plan 的 claim 推进 owner epoch 并
进入非 active 阶段；完整恢复与 fresh HEAD 屏障通过后才激活。旧候选持原 ETag，
接管生效后不能新增权威提交。接管前已接受、接管后才到达的旧响应保留原提交顺序，
不能按响应时间误判 fence 失效。

`head_serial` 严格推进，避免正文恢复原样造成 ABA。owner epoch、业务 revision、
请求 generation 与物理 generation 各有用途。HEAD8/9 的 accepted plan、phase 和
持久取消屏障封闭迟到管理操作；该格式不再接受 legacy 接管入口，见
[owner 计划](accepted-owner-plan.md)。

主线 [instance.rs](../../crates/scap-service/src/instance.rs) 已实现永久 claim 和自动
编号。失败或退出不释放身份；不确定启动失败关闭。allocator 缺失时不自动初始化，
历史 high-water 和永久 marker 必须保留。见[实例占用](worker-instance-claim.md)及
[自动分配](worker-instance-allocation.md)。

持久编号解决身份复用，[动态 fleet](dynamic-owner-fleet.md)解决受信配置更新；二者
都不授予数据库写权。controller 依据已接受计划和固定权限／预算推进恢复，reload
先停止准入并等待原 tick/socket/DNS 结束。无跨 controller 全局配置共识，部署器
仍须协调一致配置，原业务 SQL 不因地址或身份变化自动重发。

### 3.3 不确定与已知提交必须分开

| 观察 | 必须保留的语义 |
| --- | --- |
| HEAD 明确条件冲突 | 原候选不换 ETag，按原请求查证协议处理 |
| 可能发布的写入已经发出，但丢响应／超时后没有确定结果 | UNKNOWN；保留原身份 lookup/cancel，不自动重放 SQL |
| 远端已接受，本地 publication/checkpoint/编码失败 | `CommittedButUnavailable`；保留 receipt，丢弃本地状态，远端提交不回滚 |
| lookup 暂未找到原结果 | 不证明在途请求以后不会提交；须有序取消／关闭屏障 |
| S3、IAM 或 KMS 不可用 | 新强读和新写失败关闭，不凭缓存或 lease 返回权威成功 |

排队或准入阶段已经确定尚未执行的请求可以返回相应 DEADLINE／拒绝；已取得的
确定提交结果也不因后来超时变成“没有提交”。UNKNOWN 只表示无法确定原效果。

## 4. 单库与多库的吞吐分别设计

同库 writer actor 仍串行。增加 Pod 不能合并多个私有镜像的页面；CAS 让冲突候选
无法同时生效，不会把它们变成可并行执行的合法事务。不同库 actor 可并行，退出及
join 完成后才复用槽位。独立控制池、恢复 semaphore 和队列预算减少冷库与热点
请求的相互阻塞；调度细节见[执行隔离](execution-isolation-and-throughput.md)。

可选读池每次重新 exact GET HEAD、验证 READ 权限，只查询根一致的完整镜像。
一次读可在线性化点后与写入并行；请求开始前已完成的撤权必须被看到。SQL 前的
`StaleSnapshot` 最多触发一次同 deadline 重建；执行后的错误与写入 UNKNOWN 不走
此分支。额度覆盖实际工作生命周期，不按客户端断线提前归还。

读池减少读写排队耦合，但每个完整镜像有空间成本。保留页数是操作后预算，不是
瞬时 RSS／磁盘上界。[内核资源合同](kernel-resource-envelope.md)检查真实有限
cgroup v2、普通 CPU 调度和有限 tmpfs；它提供组级约束，不认证每租户硬隔离或
普通 ext4/XFS 项目配额。未启用此可选合同不能宣称拥有这些内核边界。

| 吞吐手段 | 当前状态 | 改变什么 |
| --- | --- | --- |
| 显式 SQL batch | 已实现 | 一次请求多条 SQL，仍是一个事务／请求身份 |
| 同库强读池 | 已实现，可选 | 多份私有快照并行执行读，writer 仍一个 |
| 多库 actor 并行 | 已实现 | 提高不同库聚合能力，仍受共享资源限制 |
| 同库独立事务 group commit | 未实现 | 各事务保留身份／结果，共享一轮持久化与发布开销 |
| 跨库 WAL 打包 | 未实现 | 不同库共享上传成本，各库发布条件仍独立 |
| 同库 MVCC | 未实现 | 改变引擎、冲突与隔离协议，允许多个事务并行推进 |

后续协议见[Turso 接续设计](turso-adoption-next.md)。多语句 batch 不能报成多个
独立事务，多库总 TPS 也不能报成单库吞吐。

## 5. 吞吐要看完整延迟与对象请求账本

### 5.1 当前关键路径

| 阶段 | 应独立测量 |
| --- | --- |
| 入口与调度 | 预定到达、实际发出、排队、拒绝和 deadline，按租户／请求类别分组 |
| 权威与身份 | fresh HEAD、权限和原请求索引的 GET 数／字节／延迟 |
| SQL 与对象构建 | native 时间、变化页、原结果大小，树路径 GET、不可变 PUT 与回读 |
| 发布与本地收尾 | CAS、native publication、checkpoint、物化，冲突／UNKNOWN／已提交不可用分别计数 |
| 交付 | 编码、输出 backing 生命周期、慢客户端和发送失败；原提交仍保留 |
| 冷路径 | 全闭包 GET／字节、校验、临时空间、恢复排队和首个成功强读时间 |

单库饱和写吞吐受 writer actor 占用时间约束，排队增加用户等待。多库并行的收益
最终受共享资源限制。热强读依然需要远端授权；冷强读还要物化闭包，纯本地 SELECT
不能代表端到端强读时延。

### 5.2 当前已经取得的有限证据

[#66 组合记录](../engineering/sqlite-s3-scale-validation-2026-11-18.md)保留各自冻结
来源的 911 项 stable/nightly 单位、77 个 Rust 文件逐文件四维精确覆盖，以及独立
读池、动态 fleet、内核和开环合同。它们不是本页更新时的新测试结果。

[读池实际](../engineering/read-pool-validation-2026-11-18.md)验证同库重叠读与写／
控制进展，不认证生产 TPS；并发 GC／owner handoff 的实际覆盖仍以该报告为准。
[内核实际](../engineering/kernel-resource-validation-2026-11-18.md)验证 14 场景及压力
限制；辅助压力程序 OOM 不等于 daemon 的 SQL/S3 恢复已在同场景验证。

[开环合同](../engineering/open-loop-overload-validation-2026-11-18.md)固定 30 秒、
1,140 个预定到达与六个进展窗口，保留拒绝／UNKNOWN／迟到样本，并比较同样 64 行
的 64 个单事务与 8 个八语句事务。该场景未启用读池，不能据此推导读池提速。

[PR #66](https://github.com/ckanner/scap/pull/66) 后续记录了修正归档包装后的独立取回
复核，性能来源是 [run 44262057229](https://github.com/ckanner/scap/actions/runs/44262057229)，
不是本次文档更新的新负载；早期大 ZIP 无法取回的记录仍保留。最终记录的短样本为：

| 固定阶段 | 已提交事务 | 逻辑行 | 含 drain 耗时 | 事务/s | 行/s | S3 请求 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 单条事务 | 64 | 64 | 2.660644 s | 24.0543 | 24.0543 | 1,152 |
| 每事务 8 条 SQL | 8 | 64 | 0.368494 s | 21.7100 | 173.6798 | 144 |

固定开环阶段热点写 566 成功、394 BACKPRESSURE，quiet 120/120、control 60/60
成功；六个窗口均取得进展，生成器丢弃为零。这是本地 SeaweedFS／证据代理、固定
先 single 后 batch 的观察；173.68 行/s 不能写成独立事务/s，也没有 AWS、读池或
生产 SLO 结论。混合成功与拒绝的 p99 不能作为成功写 p99。

### 5.3 下一次性能验收如何成立

预先冻结工作集、读写比、事务边界、到达率、持续时间、拒绝策略、候选和对象服务。
分别报告单库／多库、热／冷、事务/s／逻辑操作/s、p50/p95/p99、错误及 UNKNOWN、
每成功事务对象请求／字节、恢复时间和资源峰值。不能只统计成功请求或挪动到达
时间掩盖过载，短样本最大值不能包装成稳定 p99。

相同保证下先检查短事务、SQL batch、建连复用、对象等待和分配副本。新增 I/O 并行
须固定原 Snapshot／deadline 并限制在途字节，依赖全部完成才发布。生产容量和成本
需要目标后端、故障域及长运行记录，不能继承 Turso 的数字。

### 5.4 本次组合的实际基线：热点吞吐仍未解决

本标题保留旧报告链接。“本次组合”指 **2026-11-11 至 11-13 的历史候选**，不是
当前 `b9d736b` 的新性能认证。原数值和条件保留在
[11 日负载记录](../evidence/sqlite-s3-integration-load-local-2026-11-11.json)、
[13 日配对验收](../engineering/verified-manifest-load-validation.md)及
[后续因果诊断](../engineering/manifest-proof-causal-2026-11-18.md)。

#60 的 Manifest GET 省略候选证明特定负载少一次 GET，但两个历史四库配对回退
24.00% 和 24.52%，原因仍未完成归因。后来诊断不能补造当时没有采集的剖面，请求
减少也不等于吞吐通过。该路线已按[停止采用决策](../engineering/manifest-get-elision-decision-2026-11-18.md)
退出本次产品；主线保留普通 Manifest GET，不将它列为待合入的提速成果。

## 6. Turso 可以借鉴什么

| 组件 | 官方机制 | SCAP 的决定 |
| --- | --- | --- |
| 开源 libSQL / Bottomless | libSQL 继承单 writer；Bottomless 按 generation 异步复制本地已提交 WAL | 研究布局与恢复链；异步备份不满足 ACK 前对象权威 [S8][S13] |
| Turso Cloud | 128 kB 分块／generation、本地缓存、按需取块、WAL 持久到 Express 后确认、多库 WAL 合批 | 采用存算分离和远端确认原则，继续设计请求摊薄／按需加载；不假定其 owner／GC 等同本项目 HEAD [S9][S10] |
| Rust Turso Database | MVCC、BEGIN CONCURRENT、行级冲突；0.8 增加 group commit | 独立引擎候选，需要 SQL、隔离、挂点、恢复和原结果兼容验收 [S11][S14] |

云存储层与开源引擎不是同一交付物。官方说明将新的多租户服务端与开源 libSQL
服务端区分；下载开源引擎不等于取得 Cloud 全部存储、fencing 和运维能力。[S15]
固定上游源码审查见[源码对照](sqlite-s3-turso-review.md)。

Cloud 跨库打包汇集独立数据库 WAL 上传，新引擎 group commit 属于事务提交路径，
两者不等价。MVCC 仍有冲突和热行竞争，也不允许多主机随意修改网络 WAL。上游
main 的功能和成熟度会变化，采用时须冻结具体版本；实验性多进程协调不构成共享
网络文件的生产安全证明。[S10][S11][S14]

AWS/Turso 的 6.4 ms PUT 平均值来自其特定 Express 同 AZ 实验，不是 SCAP 的
端到端提交、Standard／其他兼容服务延迟或生产 SLO。[S10]

## 7. S3 Standard 与 Express 的故障域不能混用

| 后端 | 已知边界 | 本项目状态 |
| --- | --- | --- |
| S3 Standard | 多 AZ 冗余；对象服务和权限仍是在线依赖 | 目标资格验证后端，真实云端合同仍 NOT_RUN [S6] |
| S3 Express One Zone | 单 AZ 内冗余，可用性与 AZ 灾难边界不同 | 未作为 SCAP 后端交付；若采用须独立 ADR、认证和恢复协议 [S6][S7] |
| 其他 S3 兼容服务 | 一致性、CAS、持久性取决于实现／部署 | 每种实现独立验收，接口名称相同不构成等价证明 |

最近 ACK 的 WAL 若只在 Express，随后异步 checkpoint 到 Standard，最后一次
checkpoint 后的数据不会因此取得同步多 AZ 保护；不能宣称跨 AZ RPO=0。Standard
冗余也不自动生成计算切换、跨区域晋升或应用 SLA。

“计算／缓存全丢失但不丢已确认数据”的目标，以对象服务、密钥、不可变对象及
永久元数据仍满足合同为条件。误删、密钥丢失、应用误写和区域永久损失需各自
恢复策略；S3 不可达时不能通过本地成功降级维持同一强一致承诺。

## 8. 接续实施与退出条件

| 工作包 | 当前起点 | 下一完成条件 |
| --- | --- | --- |
| 对象权威与恢复 | 提交／取消、owner plan、永久身份、动态 fleet 已实现 | AWS/IAM、真实故障域和完整原请求恢复审计 |
| 热点写吞吐 | 单 writer、SQL batch、有界准入 | 固定瓶颈与负载后实现同库 group commit，保留逐事务结果、权限和 UNKNOWN |
| 跨库请求成本 | 多库并行，独立对象与 HEAD | pack 引用、逐库发布、部分失败和跨库 GC；无隐式分布式事务 |
| 冷启动与缓存 | 完整恢复和独立读池 | lazy VFS 的页身份、缺页失败、generation／GC 保护及有界缓存 |
| 历史恢复 | S1 和 S2 独立目标 | 连续历史、时间索引、保留／GC 协议，才可提供任意时间 PITR |
| fleet 与隔离 | 受信有限配置、组级内核准入 | 另立全局配置共识、历史压缩、自动扩缩容及每租户硬隔离协议 |
| 生产出口 | 固定本地／CI 合同与既有容量证据 | 当前候选容量、长运行、多轮 GC、冷启动风暴、成本和数字 SLO |

详细方案见[Turso 接续设计](turso-adoption-next.md)。单库 MVCC 是后续引擎决策，
不能用增加线程、共享网络卷或异步 ACK 代替。

## 9. 每个结论都对应可失败的验收

| 合同 | 必须观测的结果 |
| --- | --- |
| 文件安全 | 不安全 cache/temp 路径在 native 使用前拒绝；镜像独立；真实挂载另验 |
| stale owner | 接管后释放暂停旧 CAS，旧候选不新增生效；此前接受的迟到响应保留原顺序 |
| 确认与 UNKNOWN | 各切点崩溃／丢响应后原结果可查或有序取消；不重跑 SQL、不丢失败样本 |
| 并行读 | 当前权限与固定根、同库读重叠、写与控制进展；SQL 前仅一次 stale 重建 |
| 身份与 fleet | 启动不复用 ID；旧 guard 不收养新进程；reload 等真实工作结束 |
| 全计算恢复 | 无旧目录也能核对全部 ACK、原结果、数据、目录和永久屏障 |
| 资源与存储 | 过载背压，实际释放后退款；保留／GC／迟到上传下闭包正确、成本可量化 |
| 性能 | 固定完整工作量与保证，分开单库／多库、冷热、拒绝、尾延迟和请求／字节 |

源码、依赖、native、二进制、配置、后端与原始历史须绑定同一候选。单元、模型、
兼容端点、AWS 和故障域分别记账；未运行为 NOT_RUN，原始失败保留。

## 10. 官方资料

以下技术边界于 2026-11-20 复核，外部架构或性能说明不构成 SCAP 验收。

- [S1：SQLite WAL](https://www.sqlite.org/wal.html)：同机共享内存、多读与单 writer。
- [S2：SQLite Over a Network](https://www.sqlite.org/useovernet.html)：网络文件 I/O 与部署选择。
- [S3：SQLite corruption](https://www.sqlite.org/howtocorrupt.html)：锁故障和错误文件访问。
- [S4：S3 consistency](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html#ConsistencyModel)：单 key 原子性，无跨 key 事务。
- [S5：S3 conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)：条件创建、ETag 替换和冲突。
- [S6：S3 storage classes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-class-intro.html)：Standard 与 Express 故障域。
- [S7：Express directory buckets](https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-express-tutorial-create-directory-bucket.html)：目录桶与 AZ 边界。
- [S8：Bottomless README](https://github.com/tursodatabase/libsql/blob/main/bottomless/README.md)：开源异步备份／恢复。
- [S9：Turso Cloud durability](https://turso.tech/blog/how-does-the-turso-cloud-keep-your-data-durable-and-safe)：2025-05-20，分块、按需读取和 ACK。
- [S10：AWS/Turso S3 Express architecture](https://aws.amazon.com/blogs/storage/how-turso-built-a-transactional-database-using-amazon-s3-express-one-zone/)：2026-07-23，跨库合批和特定环境测量。
- [S11：Turso manual](https://github.com/tursodatabase/turso/blob/main/docs/manual.md)：MVCC、连接、冲突和当前限制。
- [S12：Amazon EFS features](https://docs.aws.amazon.com/efs/latest/ug/features.html)：NFSv4 byte-range advisory locks 和一致性。
- [S13：libSQL README](https://github.com/tursodatabase/libsql/blob/main/README.md)：libSQL 与 Rust 引擎的区别。
- [S14：Turso 0.8](https://turso.tech/blog/turso-0.8.0)：2026-09-29，MVCC／group commit；基准不是 S3 端到端性能。
- [S15：Turso platform roadmap](https://turso.tech/blog/upcoming-changes-to-the-turso-platform-and-roadmap)：2025-01-21，Cloud 服务端与开源组件边界。
