# 串行 Raft driver 与原生存储后端

初始日期：2026-10-29；读准入与业务接合更新：2026-10-31。本页描述正式模块的接口、错误和资源边界；测试计数以 [执行证据](g0-evidence.md)为准。决策见 [ADR-0009](../adr/0009-serial-driver-and-native-backend.md)与 [ADR-0010](../adr/0010-cell-acceptance-and-raft-safety.md)。本页聚焦底层 driver；上层现已由 [正式服务](sqlite-service.md)组合，底层接口的独立实验范围仍按原证据说明。

## 1. 模块边界

| 模块 | 负责 | 调用方仍负责 |
| --- | --- | --- |
| `scap-raft-store` | 版本化镜像、恢复校验、持久状态转换与 `raft::Storage` | 合法身份与新组创建授权 |
| `scap-raft-rocks` | 独占目录与 RocksDB 句柄、镜像读取、WAL + sync 原子替换 | 目录生命周期、设备和挂载前提、阻塞执行安排 |
| `scap-raft-driver` | 一个 RawNode 的串行输入、Ready/LightReady、持久 apply、读票据与有界输出 | 认证、路由、传输、逻辑 tick 调度和完整业务状态机 |
| `scap-cell` | 纯确定性的有界业务接受、身份/owner/auth、去重和取消 | 可信准入、引擎发布、完整生命周期和服务接口 |

driver 直接持有 `RawNode<Store<B>>`，不暴露可任意修改 RawNode 的入口。注入的 `Application` 接收旧应用字节和有序条目，只计算候选新字节；不能在该回调中发布 SQLite 页面、发送业务成功或执行不可回滚外部效果。配置条目由 driver 调用固定 Raft 库处理，再和应用、applied 一起保存。当前没有公开成员变更提案入口，完整生产成员管理仍待实现。

## 2. 启动与配置

调用方先明确选择 `RocksBackend::create_new` 或 `open_existing`，再构造经过校验的 Store，最后建立 Driver。不能因重开失败就改走创建新组。

非空业务 genesis 使用 `Store::create_new_with_application`，把应用和 genesis snapshot 原子保存；同组 founding replicas 必须使用相同应用 bytes。已有 `scap-cell` 状态在恢复或 snapshot-only 安装后，以同一 Store 视图的 cell 身份和 applied term/index 执行 `decode_bound`，不能仅凭外层 applied 开放业务读取。

该 term 来自 applied 对应的 entry；若 applied 位于 snapshot 边界，则来自 snapshot metadata。不能使用当前 HardState.term 或 driver status 中较新的选举 term。

driver 从 Store 取得 node identity 和 durable applied，固定 `pre_vote`、`check_quorum` 与 `ReadOnlyOption::Safe`，关闭持久前 apply、proposal forwarding 和 append batching。传入 Raft Config 的对应字段不能覆盖这组有效配置。选举参数仍需上游校验；默认选举区间的整数溢出在调用上游前拒绝。

`boot_id` 必须非零，并且每次建立 Driver 实例都唯一，包括同一进程中的不同 cell。生成和分配 boot identity 是外部启动层职责，不能在重启后使用旧值。driver 不以墙钟时间替代 Raft 一致性判断。

输入字节、输出消息数/字节、pending read 数和 drain 的 Ready 轮数都有显式预算，Raft 的消息、未提交和每 Ready 提交字节预算也必须有限。字节预算限制已编码消息与逻辑读回执（每项 32 bytes），不等同于整个进程、第三方内部对象和 native cache 的内存上界。当前没有经过容量验证的生产默认值。

## 3. 串行运行与完成边界

输入包括 `tick`、`campaign`、已解码的 `step`、普通 `propose`、`read_index` 和传输失败/快照结果反馈。已有 Ready 或已完成但尚未交出的读结果时返回 `NeedsDrain`，调用方先执行 drain；不能在未处理的 Ready 中间穿插这些变更。

每批 drain 按以下次序执行：

1. 取得真实 Ready，保留最初的 committed entries 和读状态。
2. 同步保存 entries、HardState 和可选 snapshot，完整遵守 Store 的恢复不变量。
3. 调用 `advance_append`，保留 LightReady 的新 commit、committed entries 和 messages。
4. 对准确的已提交范围计算应用与成员配置，并将 commit、应用、完整 ConfState 和 applied 原子保存。
5. 调用 `advance_apply_to`，只交出已满足持久处理前提的消息及读屏障。

本版本保守延后普通 messages，直到本批持久应用成功才返回给调用方；这会增加延迟，是本实现的选择，上游并不要求所有普通消息都等待 fsync。driver 不执行实际网络发送，调用方必须为下一层发送队列另设总量和 deadline，并正确调用 `report_unreachable` / `report_snapshot`。

`Output.more_ready` 表示还有后续工作或可交付读结果。调用方应持续调度有限 drain，不能把一次返回当成整个 cell 已永久空闲。收到提案准入结果、消息输出或传输回执都不等于 SQL ACK。

## 4. 错误与停止语义

| 类别 | 行为 |
| --- | --- |
| 准入拒绝 | 输入超限、待 drain、非 leader 提案/读、读容量满等不等于已发生持久修改 |
| `ReadNotReady` | leader 尚未提交本 term 条目；不分配票据或占 pending 容量，保持实例可用，quorum 推进后由调用方重新准入 |
| 持久化或应用失败 | 当前 driver 停止，不返回本批成功输出；通过重新打开磁盘确定实际恢复状态 |
| 后置输出超限 | 工作可能已经持久，属于停止错误，不能按确定未提交自动重放业务请求 |
| panic 被外层捕获 | 修改开始前先设置停止标记；外层不能捕获后继续使用同一实例 |
| checkpoint 失败 | 保留 Store 的旧/新原子恢复边界，停止当前实例；不能擅自清空或重建 |

应用回调发生错误之前可能已经修改它自己的临时内存，因此停止规则覆盖整个 driver。回调不得把外部副作用当成可以靠重新读取 Store 撤销的事务。

Store 保证完整镜像的原子替换和恢复校验；它不自动决定 quorum，也不提供 SCAP 的 owner/auth fence、业务请求去重或 SQLite 可见性协议。

## 5. 读票据、取消与容量

`ReadTicket` 含 `(boot_id, sequence)`。wire context 还包含 cluster/cell/实例/node 身份。序号不复用；旧 boot 的取消不能删除新实例请求，旧 context 不能完成新票据。

准入先检查当前 term 是否已有提交。固定上游会静默忽略不满足此条件的 ReadIndex；driver 返回 `ReadNotReady`，避免创建没有后续完成路径的票据。真实三进程测试在新 leader 的 no-op 尚未 quorum 提交时检查此错误，完成提交后再验证首张 sequence=1 票据可完成。

只有匹配当前待处理票据的 Safe ReadState，并且持久 applied 已达到其 index，才返回 `ReadBarrier`。已取消或无法匹配的结果不会授权其他请求；输出暂时放不下的已完成读继续留在有界队列中。

取消外层请求不会立刻删除 Raft 内部待 quorum 的读。因此准入同时检查 SCAP 的 pending 集合与 Raft 的 pending read 数，不能通过反复“发读—取消”绕过容量限制。内部上下文由真实 Raft 在完成或状态重置时退休，driver 不重新实现其队列推进算法。

当前只开放 leader-local ReadIndex。peer 转发读/提案不能绕过本地准入。这个约束属于首版接口范围，不是一般 Raft 协议不支持 follower read。

该屏障只证明对应 Raft 请求和持久应用位置；`scap-cell` 已提供同视图中的授权、数据库 revision 和 owner 校验，调用方须显式接合。精确 SQLite snapshot-start gate 与生产查询入口仍待实现。选举与租约边界见 [Raft 安全说明](raft-safety.md)。

## 6. Native backend

创建新库先用原子目录创建预留路径，并同步父目录。已经存在的路径，包括空目录和先前失败残留，都不能被创建入口复用。打开已有库先检查路径存在且为目录，再调用禁止创建的 native 打开流程；不能仅依靠 RocksDB 的 `create_if_missing(false)` 避免目录被创建。

native 句柄、选项和专有 key 不对调用方开放。加载拒绝外来或多余 key；在复制完整 image 到 owned buffer 前检查长度。同步替换固定开启 WAL 和 sync WriteBatch，并选择 fsync。恢复显式启用 paranoid checks 和 `AbsoluteConsistency`，损坏 WAL 拒绝打开，不能悄悄退回较早的合法镜像。错误可能发生在同步前或同步后，不表示磁盘回滚。失败不会自动清理目录。

严格恢复可能拒绝崩溃留下的损坏尾部，需要通过健康副本和受控重建恢复该节点；当前没有自动重建实现。其可用性代价不通过允许旧投票或已提交位置回退来消除，具体取舍及上游依据见 ADR-0009。

调用方必须拥有并保护父目录命名空间，禁止并发替换或移动已打开目录。当前实现针对已验证的 Linux 构建与目录同步语义；它不是通用网络文件系统或对象存储 VFS。

## 7. 验证范围与代价

单元测试覆盖所有正式第一方实现；driver 只测试单实例规则，存储与应用受控，native 薄调用使用 memory Env。该 Env 的 payload/WAL 位于内存；Rust wrapper 和入口仍可能进行隔离临时目录的元数据操作，这不作为磁盘恢复证据。

[三进程实验](../../experiments/raft-cluster/README.md)使用正式模块、各自 RocksDB 和 SIGKILL，独立核对持久历史、少数派限制、恢复及真实 snapshot。父进程的 IPC 路由只提供受控消息故障模型，未实现生产 RPC/mTLS；逻辑 tick 与测试耗时不构成端到端 RTO。

本轮保持完整有界镜像布局，不降低 [原有容量与写放大限制](durable-store.md)。2026-11-01 新增[正式单 cell 网络运行时](raft-network-runtime.md)，在专用线程通过窄 RaftDriver port 驱动本模块；[真实 mTLS 三进程实验](../../experiments/raft-network/README.md)另行验证网络故障，没有改变上面旧 IPC 实验的历史范围。多个 cell 的公平性、动态成员与服务控制面仍需实现。有界业务接受与受限 SQLite 接合已经加入，G0/G1 的通用 SQL、SDK、完整生命周期和其他门禁仍须分别完成。

上游接口与来源见 [ADR-0009](../adr/0009-serial-driver-and-native-backend.md)。

## SQLite 网络提交实现更新（2026-11-02 UTC）

正式 `scap-cell-client` 与 `scap-sql-worker` 已连接 native SQLite 和固定三副本 mTLS cell，增加本请求的持久业务裁决和明确的 ClaimOwner/物理恢复/ActivateOwner 入口。具体步骤、UNKNOWN、deadline、资源与分区行为见 [SQLite 网络合同](sqlite-network.md)。调用恢复入口失败可能已经改变 owner epoch；即使 ActivateOwner 已成功，末次读失败也不会交付 writer。下一次接管必须重新读取权威状态、使用新的 worker 身份和新目录，不能沿用旧缓存或把失败当作回滚。现有 `scap-server` 已提供静态凭据映射、HTTP/Hrana 与 Node SDK，并在固定三节点 cell 内随 leader 变化自动恢复 owner；完整运行与冷生命周期见 [服务方案](sqlite-service.md)。动态成员、多 cell 调度和自动更换损坏副本仍待实现，生产性能目标未通过。
