# ADR-0012：有界 mTLS Raft 网络与单 cell 运行时

- 日期：2026-11-01。
- 状态：正式 wire、transport、runtime 模块与八项真实网络契约已实现；完整 SQL/SDK 网络服务、S3 生命周期、自动接管与生产性能仍待验证。
- 关联：[ADR-0007](0007-tikv-stack-and-rpc-boundaries.md)、[ADR-0009](0009-serial-driver-and-native-backend.md)、[ADR-0010](0010-cell-acceptance-and-raft-safety.md)、[ADR-0011](0011-bounded-native-sqlite-adapter.md)。
- 补充范围：落实此前待实现的 peer transport 与单 cell 调度边界；不改变 durable quorum、业务 Accepted、SQLite 发布和 UNKNOWN 合同。

## 背景

已有正式 driver、持久后端、cell 状态机和 SQLite adapter。此前三进程故障测试由父进程路由 Raft 消息，编码实验也没有包含共识与持久化，因此都不能证明真实 mTLS 连接、网络分区、动态撤销和有限调度下的正确性。

本阶段需要把可复用运行逻辑放进正式 crate，使独立实验只装配组件、注入故障和观察结果。同时必须防止普通 RPC 成功被误认为 Raft 或 SQL 提交，防止已撤销连接或排队消息进入 RawNode，并为慢连接、慢存储和取消后的实际内存占用设置有限边界。

## 决策

1. 拆分三个有实际职责的正式模块：`scap-raft-wire` 负责格式与纯授权策略，`scap-raft-transport` 负责 Tonic/mTLS 与传输资源，`scap-raft-runtime` 负责 mailbox、串行 owner 和有限 sender。共识继续复用固定 raft-rs，持久顺序由既有 driver/Store 负责，不在网络层重写 Raft。
2. 外层 unary RPC 只携带有界 `Packet.data`。其中 `SCAPRPC1` envelope 采用固定 80 字节头，绑定协议/codec、cluster、cell、incarnation、from/to 以及 opaque Raft bytes。接收前校验长度、版本、身份和解析预算；内层 bytes 不经无意义的 decode/encode 转发。这个正式格式与旧编码实验的测试 envelope 分开。
3. 本阶段只接受固定 bootstrap voters。启动时验证 durable identity/ConfState 与 policy 完全一致；网络持续拒绝 ConfChange/ConfChangeV2 entry，以及改变固定成员集的 snapshot。证书 allowlist 与 Raft ConfState 分开维护。动态成员变更、learner、joint consensus 与领导权转移管理 API 不属于本阶段。
4. mTLS 使用显式私有 CA。入站 leaf DER 只能取自已验证的 TLS connection metadata；policy 以完整 DER 的 SHA-256 映射节点，并核对当前证书日期、cell、incarnation、内外层 from/to。出站验证精确的 cluster/node DNS 名称，不能使用通用 localhost 身份。证书属性解析不能代替链、签名和用途验证。
5. 每次 RPC 都使用当前授权。allowlist 替换先完整校验再推进 policy revision；消费前在同一把锁下重新核对 revision、证书日期和当前绑定，并把消息交给 driver。旧 revision 的排队消息丢弃，由 Raft 重传。准入与消费不能依赖握手时缓存的权限。
6. Tokio 任务只执行有限网络工作与入队，单 cell owner 在专用阻塞线程通过窄 `RaftDriver` port 串行调用真实 driver。正式 Driver 的委托实现保留原共识/持久行为；测试可在单个调用边界注入错误。队列同时限制条目与字节；入站计入 raw/parsed 的保守成本，本地请求用共享 RAII reservation 覆盖请求、pending read 和待取响应，出站用独立 RAII reservation 覆盖真实排队/发送中的 payload。逻辑 delivery 超时不能提前释放仍被 sender 持有的物理预算。
7. 每个固定 peer 配置普通消息和 snapshot 两个独立 worker。每次 delivery 新建 mTLS channel，建连、握手、readiness 与 RPC 共用排队前分配的绝对 deadline；没有隐藏重试。这个选择用额外连接成本换取明确的逐次出站证书验证，后续连接池优化须重新证明有效期、撤销、取消和容量行为。
8. `Answer::Admitted` 只表示本地提案准入，`Received` 只表示远端已认证并入有限内存队列。它们都不证明持久化、quorum、业务接受或 SQLite 发布。选举与读继续遵守 driver 的 PreVote、check_quorum 与 Safe ReadIndex 合同；本阶段没有启用租约读，也不开放网络转发 ReadIndex/Propose。
9. fatal driver/存储/时钟错误以及 poll 中的 panic 关闭当前 runtime 的入口和等待请求；失败后通过明确的重开与恢复处理。network shutdown 可以取消并 abort 异步 worker，但不能强行中断已经开始的同步 fsync、应用回调或 native 调用。进程监督和 owner 自动恢复编排仍由后续服务层实现。

## 取舍与实际修复

固定成员集使授权与持久配置边界可审查，但不能将本地配置改成另一组节点来实现扩缩容。allowlist 的 revision 与 pin 更新目前是进程内策略；启动层必须提供最新可信授权，不能声称撤销已经获得跨重启的控制面持久化。

新建连接增加握手 CPU、网络往返、socket/TIME_WAIT 和 server 连接预算压力。普通与 snapshot 分离降低通道相互阻塞，但二者仍共享节点 CPU、网络和全局配额。当前发送完整有界 snapshot，不提供大 snapshot 分片、多 cell 公平调度或跨 AZ 容量保证。

真实三进程网络组合发现了 accepted socket 未显式启用 `TCP_NODELAY` 的问题。锁定版本 [Tonic 0.14.6 的文档](https://docs.rs/tonic/0.14.6/tonic/transport/struct.Server.html#method.tcp_nodelay)明确说明，`serve_with_incoming` 忽略 builder 的对应 TCP 设置（核对日期：2026-11-01）。正式 transport 现逐连接设置 NODELAY，失败就拒绝该连接，并补充真实 socket 与错误注入单元测试。修复后在原有读 deadline 下通过网络契约；没有把延长超时当成修复。

## 验证与重新评审条件

正式源码分别接受精确 100% 单元行、函数、region 和分支门禁。窄依赖注入验证错误、取消与预算；隔离 native mTLS 单元验证真实 adapter 委托。真实三节点历史、磁盘和进程故障在独立 [网络契约实验](../../experiments/raft-network/README.md)报告，不用于补单元覆盖率。最终精确计数、环境和执行状态统一由 [执行证据](../engineering/g0-evidence.md)及覆盖率报告维护。

八项网络契约验证了自动选举和业务读写、黑洞少数派、leader/全组 SIGKILL 后重开、真实网络 snapshot、非法身份拒绝、旧连接与旧队列 pin 撤销、有限准入与非持久回执、单向分区的新强读限制。实验使用正式 cell 的合成 opaque payload；不执行 SQLite SQL，不等于 mTLS、SQLite、Hrana/Node SDK 的完整组合验收。

以下变化必须重新评审：动态成员或转发语义、可复用连接池、异步 Ready、快照分片、跨 cell 共享调度、pin/CA 控制面持久化，以及将此 runtime 接入 native SQLite 提交 gate。生产延迟和 RTO 继续按 [性能验收口径](../engineering/performance-slo.md)测量；本次契约通过不表示目标达标。

详细行为、启动与关闭顺序见 [正式网络运行时](../engineering/raft-network-runtime.md)。
