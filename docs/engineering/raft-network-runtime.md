# 正式 Raft 网络与单 cell 运行时

实现更新：2026-11-04；原网络基线：2026-11-01。正式模块及八项真实三进程 mTLS 契约已实现，SQL/SDK/S3 服务见 [服务说明](sqlite-service.md)。固定成员边界依据 [ADR-0012](../adr/0012-bounded-raft-network-runtime.md)，本轮动态 learner/joint 扩展与验收状态见 [ADR-0016](../adr/0016-durable-membership-replacement.md)。本文说明 [运行与 RPC 设计](runtime-and-rpc.md)中的 peer transport 和单 cell 调度，完整控制面、多 cell 与生产 SLO 仍有独立门禁。

## 1. 正式边界与依赖

| 模块 | 已实现职责 | 不承担的职责 |
| --- | --- | --- |
| [scap-raft-wire](../../crates/scap-raft-wire/README.md) | 版本化 envelope、解析预检、证书属性、固定/动态模式通信授权、policy revision 与消费前复核 | listener、队列、时钟读取、磁盘、Raft 提交 |
| [scap-raft-transport](../../crates/scap-raft-transport/README.md) | 唯一 unary peer RPC、mTLS、真实 TLS identity、连接/请求限额、deadline 与回执 | Raft 成员管理、quorum、业务接受 |
| [scap-raft-runtime](../../crates/scap-raft-runtime/README.md) | 认证 mailbox、本地请求、单 owner 调度、自动 tick、读等待、有限发送和失败反馈 | SQL 解析/执行、租户入口、S3、worker 自动接管 |
| [driver / Store / RocksDB](serial-driver.md) | RawNode 驱动、Ready 持久顺序、applied、snapshot 和原子恢复 | 网络认证、公开业务 API |
| [scap-cell](cell-state-machine.md) | owner/auth、请求身份、业务接受、结果去重和取消 | TLS、线程调度、SQLite 本地发布 |

平台代码使用 Rust 1.90.0。共识为固定 raft-rs commit `ad13f3d90780f53aea2488c6a4b76c0d334bf136` 与 `protobuf-codec`，rust-protobuf 2.28.0；网络使用 Tokio 1.50.0、Tonic 0.14.6、Prost 0.14.3、`tls-ring`；策略使用 sha2 0.10.9 与关闭默认 features 的 x509-parser 0.18.0。精确直接/传递依赖和 features 以各 crate manifest 与根 [Cargo.lock](../../Cargo.lock)为准。这是 SCAP 的网络实现，不是 TiKV grpcio 服务的移植。

## 2. 启动、身份与成员模式

启动层明确选择 Initialize、受控 Join 或 OpenExisting，再构造 driver；重开失败不能退化为创建新组。每次建立 driver 都需要新的非零 boot ID。读取到的 durable identity 必须与 `Policy::scope()` 的 cluster、cell、incarnation、node 一致。`Policy::new` 保留原固定模式：durable ConfState 必须与固定 voters 一致，不包含 learner、joint 或 auto-leave。`Policy::with_trusted_peers` 显式开启动态模式，通信目录受通用 limits 约束；server profile 将预注册身份限定为 3–16 个。持久 ConfState 可以包含合法 learner/joint，投票资格始终由真实 ConfState 决定。

`Runtime::new` 验证上述身份、配置和时钟后返回串行 owner 与可 clone 的 `Handle`。调用方在 Tokio runtime 中建立 `NetworkWorkers`，提供恰好覆盖其余受信 peer 的 endpoint 集合；重复、缺失、额外节点、错误 cluster、非法 HTTPS origin 和越界配置都会拒绝。没有启动时连接全部 peer 的要求，一个不可达端点不会阻止健康多数派尝试形成 quorum。预注册 peer 不是 voter；按本机已应用 ConfState 判断为未加入、learner 或已移除的节点不能 campaign、提出业务写或提供强读。替换前离线的旧盘可能仍按旧配置发送选举消息，不能因此取得当前 quorum 的 SQL 服务权；重开不意味着它已经获知新的配置。

两种模式都只允许受信 peer 间的复制、投票/预投票、心跳、snapshot 及直接 TimeoutNow。持续准入拒绝：

- local-only 的 Hup、Beat、Unreachable、SnapStatus、CheckQuorum；
- peer 转发 Propose、ReadIndex、ReadIndexResp 和 TransferLeader；
- 旧式 ConfChange V1 entry；固定模式同时拒绝 ConfChangeV2；
- 重复/零/未注册 ID、未知 enum、非法角色关系和越界配置；固定模式还拒绝与原 voters 不同的非空 snapshot。

动态模式在有限 protobuf 预检后接受合法 ConfChangeV2 和 learner/joint snapshot；本地管理只开放 AddLearner、JointExplicit ReplaceVoter 和 LeaveJoint，并要求完整配置 CAS、单调新 ID、追赶和精确持久完成。操作步骤见 [成员管理](membership-operations.md)。TransferLeader 在上游可能保留原 from 转发，与逐跳证书来源绑定不兼容，因此没有开放该 API。普通 snapshot 的 metadata 与持久恢复合法性仍由 Store 再检查。两种 policy 的限制都持续作用于运行期间。

这些检查把未授权输入挡在 RawNode 修改 term/vote 之前。合法 voter 仍属于可信共识参与者；本设计采用 Raft 的故障模型，没有增加 Byzantine 共识。

## 3. 编码与双向认证

唯一 RPC 是 `/scap.raft.peer.v1.Peer/Deliver`。外层 [peer.proto](../../crates/scap-raft-transport/proto/peer.proto)中的 `Packet.data` 承载完整 wire envelope，响应只有版本化 `Received`。不直接把不同版本 Prost 的类型拼接起来。

`SCAPRPC1` envelope 有固定 80 字节头：magic、version、codec、两个 u128 的 cluster/cell ID、incarnation、from/to node 和 payload 长度，整数为 little endian；当前 version/codec 均为 1。解码拒绝错误 magic、版本、截断、尾随和超限。内层 raft-rs bytes 保持原样；零分配预检先限制字段和 entries 数，再调用固定 protobuf decoder。未知普通 protobuf 字段可保留，未知消息/entry enum、非法结构和本阶段禁止的消息不能通过授权。

身份检查分为两条路径：

| 路径 | 认证与授权 |
| --- | --- |
| 服务端验证调用者 | rustls 验证显式 client CA、证书链和客户端身份；transport 从已验证 TLS metadata 提取 leaf DER；wire/runtime 每次核对证书日期、leaf SHA-256 → node 映射、受信 peer 和完整 cell 路由 |
| 客户端验证服务端 | 显式 server CA，精确 DNS SAN 为 `node-{node_id}.cluster-{cluster_id:032x}.scap.internal`；连接地址可为 IP，验证名不能换成通用 localhost；正式 sender 可按 lane 有界复用，RPC 前后重新验证实际链/DNS/日期/current pin |

外层 from 必须等于证书绑定 node，内层 from/to 必须等于外层 from/to；证书不能来自自报 header。x509-parser 在 wire 层只提取 DER 指纹与有效期，不承担 TLS 签名、证书链、用途或 DNS 验证。Unix 秒数由运行时显式提供；单调时钟承担 deadline 与 tick，墙钟只用于证书日期，不能替代 Raft quorum。

## 4. 轮换、撤销与排队复核

`Handle::replace_bindings` 是可信的本地管理接口，不是未鉴权的网络管理服务。完整候选 allowlist 校验成功后原子替换并推进 revision；节点集合不能借此改变。一个节点可临时配置多个 pin，支持先增加新证书、完成切换、再移除旧 pin 的重叠轮换。空 allowlist 表示撤销全部 peer。

已授权消息保存私有的 revision、通信目录与成员模式摘要、limits 和证书属性。入队时与消费时都检查当前策略；只要 revision 改变，旧队列消息就丢弃，即使新列表仍含原 pin。这样避免旧授权在队列中继续穿透，代价是一次轮换可能丢弃尚未处理的正常消息，由 Raft 自身重传。固定与动态 policy 不能复用彼此的授权结果。

准入、policy 替换、消费前复核与有界的 `driver.step` 使用同一把 mailbox 锁建立顺序。磁盘 Ready 不在这把锁下执行。已经先于撤销完成 handoff 的 Raft 消息不会被“回滚”；保证的是撤销之后不能再凭旧队列授权开始新的 handoff。

transport 的独立 `PeerClient` 可以串行复用连接。正式 `NetworkWorkers` 按 [ADR-0015](../adr/0015-incremental-blocks-and-isolated-execution.md)在每个 ordinary/snapshot lane 有界复用，并在每次 RPC 前后重新验证实际证书链、DNS、时间和当前 pin。入站即使复用旧长连接，后续 RPC 仍会检查当前 pin 和证书日期；队列消费时也再次检查日期。

pin policy 与 revision 当前保存在进程内；调用方必须在重启时提供最新可信授权。证书签发、CA 轮换、授权持久化和跨节点配置分发尚无生产控制面实现。改变 server 身份/CA 需重建 server，改变 worker 的 client 身份/CA 需重建 workers；单纯替换入站 pins 不会替换 TLS 配置。

## 5. 资源预算与物理持有量

| 资源 | 准入限制与持有期限 |
| --- | --- |
| accepted socket | accept 前取得全局 permit，覆盖 TLS 握手与完整连接生命周期；用尽时给 listener 背压 |
| in-flight RPC | body 解码前取得全局 permit，另有每连接请求、HTTP/2 stream、header 和消息上限；压缩关闭 |
| runtime inbound | 条目与累计保守内存成本双限额，外加 `max_inbound_age`；full 或授权失败直接拒绝 |
| 本地请求 | 条目与字节双限额，`Request` 与 `Pending` 共享 RAII reservation；出队、转入 pending read 或响应仍在内部等待领取，都不提前归还预算 |
| runtime outstanding | 限制未完成 delivery 的数目/字节，保留本地 attempt ID、peer、term、snapshot 类型与原始 deadline |
| sender 实际 payload | 所有 sender clone、peer 与两类通道共享独立 count/bytes RAII；队列元素和整个网络 future 都释放后才归还 |
| pending read / read view | pending 数量与最大 application view 字节受限；读准入预留最大响应成本 |
| 单次 owner 工作 | `max_poll_rounds`、driver Ready 轮数、输入/输出和应用大小均有界；不同 cell 的公平调度未实现 |

inbound 同时持有原始 bytes 和已解析 Message，不能只按 wire 长度计费。当前保守成本为 `2 × payload + 128 × min(max_fields, payload) + 256 × min(max_entries, payload / 2) + HEADER_BYTES + 512`，算术溢出即拒绝。fields/entries 的预检限制配合这个预算约束解析膨胀。它不是精确 RSS 公式；allocator、TLS/HTTP2 缓冲、RocksDB cache 和应用侧持有的结果仍属于各自容量边界。

出站尤其区分“逻辑 attempt 已超时”与“网络任务已经释放 payload”。慢连接还占内存时，即使 owner 已把该 attempt 判为失败，新的发送也不能借此绕过物理配额。队列满、未知 route、通道关闭均明确返回错误；不启用无限 channel 或无限等待。

每个 peer 的普通与 snapshot 任务独立，但节点 CPU、总网络带宽、全局连接数和共享预算仍可能竞争。当前 snapshot 是完整有界消息；没有大文件分片或无界放大消息上限的路径。

## 6. 串行调度、读与回执

owner 运行在调用方提供的专用阻塞线程。它串行 drain Ready、发布允许发送的消息、交付读屏障、处理失败反馈、推进 tick，并在本地请求与 inbound 之间轮流调整优先顺序。网络任务只入队或反馈，不直接持有 RawNode，不执行同步 RocksDB 写入。

运行时通过窄 `RaftDriver` port 调用 drain、tick、step、status/view、propose、read、checkpoint 和传输反馈；`Runtime<D: RaftDriver>` 的正式装配使用实际 `Driver` 完整委托实现。这个边界隔离调度策略与共识/持久实现，允许单元测试用包裹真实 Driver 的 decorator 在一个指定调用上注入错误，验证关闭与错误传播，不需要损坏真实对象的内部状态，也不替换整个 Raft adapter。委托代码同样属于正式覆盖分母。

磁盘阻塞后不会按错过的全部 tick 突发重放：下一次调度按当前单调时间重新安排 tick。慢盘仍可能推迟所属 cell 的选举与请求；拆出网络线程并不消除这一延迟。Ready 的实际持久顺序继续遵守 [driver 合同](serial-driver.md)。

| 返回值 / 事件 | 能证明的状态 |
| --- | --- |
| `Network::try_send -> Ok` | 本端有限 sender 已接收该 attempt |
| gRPC `Received` | 对端已完成认证、授权并接收进有限内存队列 |
| `Answer::Admitted` | 本地 driver 接受了 proposal；它可能尚未被 quorum 提交 |
| `Answer::Read(ReadView)` | 当前请求自己的 Safe ReadIndex 已完成，且持久 applied 达到屏障；返回绑定 identity、applied term/index 的 application |
| `Answer::Membership` | 当前请求独立 Safe ReadIndex 后取得持久 ConfState 和复制进度；远端 matched 只证明日志复制，不等于应用完成 |
| `Answer::MembershipChanged` | 本次精确配置条目及其应用、ConfState/applied 已原子持久化；超时/取消不会撤销已经提出的变更 |
| cell `Lookup::Committed` / Accepted | 有序业务状态机中的确定结果；还必须按 SQLite 提交合同完成本地发布才能成为 SQL 成功 |

读使用 driver 强制的 `ReadOnlyOption::Safe`，票据绑定 boot 和递增 sequence。当前 term 尚未提交返回 `ReadNotReady`，非 leader 返回 `NotLeader`，请求过期或取消不会被旧 read context 完成。本阶段没有 lease read、follower 转发读或直接 SQL snapshot 查询服务。调用方仍需使用同一 durable view 执行 cell 的授权和 `decode_bound`；`ReadView` 不是公开的 SQLite 结果集。

发送回执只对应本地 attempt：重复、未知、旧 term 或迟到的反馈不能完成新 snapshot attempt。snapshot 反馈按 peer、attempt ID、term 对照后调用 driver；超出原始 deadline 的 Received 按失败处理。它只影响 Raft 的发送进度反馈，不产生伪造的 append acknowledgment，更不会给业务提交 ACK。

每个 ordinary/snapshot lane 至多复用一个 mTLS channel，并在 RPC 前后重新校验证书链与当前授权；必要的建连、握手、readiness 和 RPC 使用同一个排队前分配的绝对 deadline。失败、取消或达到最大龄期后丢弃缓存；连接配额需为正常 lane 与故障重连分别预留容量。已经到期的工作不发起连接；future 完成后还会检查实际完成时间，防止不让出执行权的步骤迟到却被判为成功。协作式取消不构成硬实时 CPU 抢占保证。

## 7. 分区、故障、重启与停止

| 情况 | 当前行为与边界 |
| --- | --- |
| peer 拒绝连接、断连或黑洞 | 有限 attempt 到期/失败并反馈；其他 peer 通道继续；重传由 Raft 决定，adapter 不隐藏重试 |
| leader 位于少数派 | check_quorum 最终使其退位；退位前即使 proposal 获得 Admitted，也不能替代 durable quorum；新的 Safe ReadIndex 不因普通 RPC receipt 成功 |
| 同一连接上的旧 pin 或过期证书 | 后续 RPC 当前授权拒绝；旧队列还要在消费前复核，不能依靠既有 TLS 会话继续使用旧权限 |
| inbound、请求或发送预算耗尽 | 明确拒绝或丢弃该网络 attempt；不降级为本地写或陈旧读 |
| driver/存储/应用 fatal error，或 poll panic | 关闭入口和等待请求；panic 清理后继续向外传播，实例不能捕获后恢复使用 |
| leader 进程退出 | 健康多数派可以按 Raft 继续；具体恢复时长需要独立测量，不由“支持选举”推导秒级 SLA |
| 原节点重启 | 明确重开原持久目录、校验身份/历史、分配新 boot；通过正式 peer 网络追赶，必要时安装有界 snapshot |
| 本地镜像损坏或目录丢失 | 严格恢复拒绝不可信历史；有健康多数派时，operator 可经新身份 Join、learner 追赶和显式 joint 替换；自动故障探测/采购/调度未实现 |
| 全组重启 | 保留本地磁盘的测试场景可以恢复；无 quorum 时不切换到旧 S3 状态，不把进程 SIGKILL 等同于设备断电 |

关闭由调用方编排：先通过 `Handle::stop` 关闭新准入并处理尚在队列的等待请求，停止 server 接收，按绝对 deadline 等待 `NetworkWorkers::shutdown`，再确认 serial owner 线程退出。owner 中尚未完成的读在下一次 owner 调度或销毁时关闭。已经开始的 proposal 仍可能提交；`Closed`、超时、取消和断连都不能证明事务回滚。

network shutdown 取消发送 future，超时或任务错误时 abort 剩余 async worker；Drop 也执行取消。未开始的排队消息释放物理配额，不产生成功回执。这个有限等待只针对网络 worker，不能强制中断同步 fsync、应用回调或 SQLite FFI，也不承诺整个进程在同一个 deadline 内完成持久关闭。必要的进程监督、故障接管及 UNKNOWN 解析属于服务层后续工作。

## 8. 真实组合暴露的 NODELAY 缺陷

真实三进程网络测试曾在健康链路中出现小消息延迟累积，读请求在原定 deadline 内无法完成。原因是自供 incoming listener 的 accepted socket 没有显式设置 `TCP_NODELAY`。Tonic 0.14.6 [官方文档](https://docs.rs/tonic/0.14.6/tonic/transport/struct.Server.html#method.tcp_nodelay)明确说明 `serve_with_incoming` 不应用 builder 的该项设置；不能把 builder 的默认开启理解为传入 socket 已配置。文档与锁定源码核对日期：2026-11-01。

正式 transport 现在在交给 TLS/HTTP2 前对每个 accepted socket 调用 NODELAY，设置失败就拒绝连接，并以真实 socket 与失败注入单元覆盖；故障代理两端也明确设置该选项，使故障模型不混入未定义的 TCP 延迟。修复后八项网络契约在原有读 deadline 下通过。具体记录见 [实验结果](../../experiments/raft-network/README.md)，没有用提高超时来隐藏缺陷。

此修复证明了这条实际实现缺陷已经覆盖，不证明新建连接策略达到生产吞吐或尾延迟目标。每 delivery 的 TLS 握手、socket 数、TIME_WAIT、取消残留、snapshot 干扰和证书轮换下的容量仍需专门测量。

## 9. 验证层次与性能边界

正式模块的单元 profile 只验证单组件协议、策略、执行顺序、资源生命周期与错误路径；RaftDriver 故障 decorator 保留真实 driver 的其他行为，必要的 native mTLS 测试验证真实 adapter 参数和回传，未把三节点持久历史混入单元覆盖。100% 精确 line/function/region/branch 门禁适用于全部正式源码，最终计数由 [覆盖率策略](../../contracts/coverage-policy.json)、[quality workflow](../../.github/workflows/quality.yml)和 [执行证据](g0-evidence.md)统一维护。

[八项真实网络契约](../../experiments/raft-network/README.md)使用三个独立 OS 进程、各自 RocksDB、正式 sender/server/runtime 和六条有方向的透明 TCP 故障代理，验证以下范围：

1. 自动选主、业务结果、幂等重复、新 ReadIndex 与断连后的副本追赶。
2. 黑洞少数派不能增加提交或完成新强读，后续由有序 ResolveOrCancel 解析 UNKNOWN。
3. leader SIGKILL 与全组 SIGKILL 后在原目录重开，保留已确认 cell 历史。
4. 落后副本通过真实网络安装 snapshot，再次重启仍保留该持久快照。
5. 无证书、错误 CA、过期/未授权 leaf、伪造 node、错误 incarnation、本地 Raft 消息被拒绝。
6. pin 轮换同时撤销既有连接的新请求与未消费旧队列，合法新 pin 可使用。
7. inbox 数量/字节、发送 deadline 与 Received 不等于持久化的崩溃反例。
8. 单向分区下，普通 RPC 路径存在也不能授权新的 Safe ReadIndex。

这些用例复用正式 `CellApplication`，物理数据是合成 opaque payload，没有执行 SQLite SQL。原生 SQLite 的提交/恢复由 [SQLite adapter 实验](../../experiments/sqlite-engine/README.md)独立证明；两套实验分别通过不能替代完整组合验收。

本轮未提供生产 p95/p99、RTO、30 天可用性或多 AZ 容量结果。[性能目标](performance-slo.md)中的单 Raft leader 故障 p95 ≤ 2 秒、p99 ≤ 5 秒仍是特定前提下的待验目标；fixture 的 tick、选举区间、读 deadline 和测试总耗时都不是该目标的实测值。后续测量必须从故障发生计到稳定窗口起点，并保留失败、超时和 UNKNOWN 分母。

SQL/Hrana/Node SDK、同 cell owner 接管和有界 S3 生命周期已有 [正式服务](sqlite-service.md)；受控成员替换见 [ADR-0016](../adr/0016-durable-membership-replacement.md)及其独立真实实验。跨 cell 调度、自动坏盘运维、跨 AZ 和掉电/丢盘验证、可证明 GC、大 snapshot 流式协议和长期容量仍待完成。不能以放宽提交条件或隐藏未覆盖源码来把有界阶段描述成完整 HA 产品。

## 10. SQLite tracked 提交扩展

[ADR-0013](../adr/0013-tracked-sqlite-network-commit.md)增加 `Input::ProposeTracked` / `Answer::Applied`：Runtime 等待实际 Entry 对应的持久应用裁决，不将 `Admitted` 作为 SQL 成功。driver 的 pending 数量/字节与 runtime 的 result/waiter 限额分别生效，取消只退出等待、不撤销 command。正式 `scap-cell-client` / `scap-sql-worker` 和真实三进程 SQLite 组合见 [SQL 网络合同](sqlite-network.md)。旧八项网络实验继续保留合成 payload 范围。
