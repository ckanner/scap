# 有界 mTLS Raft peer transport

本模块只接收和发送内部 Raft 消息，不提供 SQL、成员管理或提交确认 API。运行入口使用固定 Tonic 0.14.6、Tokio 1.50.0、Prost 0.14.3 与 `tls-ring`；未启用系统或公共根证书、匿名客户端认证、压缩、自动业务重试。完整解析依赖以根 Cargo.lock 为准。

## 协议与准入

`/scap.raft.peer.v1.Peer/Deliver` 是唯一 unary RPC。外层 `Packet.data` 承载 [scap-raft-wire](../scap-raft-wire/README.md) 的完整有界 envelope，内层 raft-rs bytes 原样保留。外层 protobuf schema 记录在 [peer.proto](proto/peer.proto)。服务路由与 Prost 派生消息直接声明在正式源码中；本模块没有 build.rs、额外生成器或覆盖率排除。

服务端从 Tonic 的已验证 TLS connection extensions 读取 leaf DER，不读取调用者自行声明的身份 header。`Ingress::admit` 必须同步完成当前授权校验和有限队列预留；只允许有界工作。运行层负责校验证书有效期、leaf SHA-256 pin、node、cell 身份、内层路由、消息种类及队列条目/字节，并在消费前再次验证。成功 `Received { version: 1 }` 只说明入队，绝不表示持久化、多数派或数据库提交。

## 双向身份与连接寿命

服务端配置显式身份和私有 client CA，缺失或无法解析的配置在启动阶段失败；`client_auth_optional(false)` 始终开启。客户端显式提供自己的身份和私有 server CA，URI 必须是 HTTPS origin。SNI/验证名称从 cluster/node 生成：

```text
node-{node_id}.cluster-{cluster_id:032x}.scap.internal
```

证书必须具有该精确 DNS SAN。连接地址可以是 IP，但不能把验证名称改成通用 localhost。这里信任给定 CA 正确签发此命名空间；不把“同一个 CA”本身当作完整节点身份。

服务端收到的客户端证书仍由 Ingress 在每次请求和消费时重新检查有效期及当前 pin。出站 `PeerClient` 通过固定 Tonic 的 `tls_config_with_verifier` 接入 Rustls 原生 `WebPkiServerVerifier`：链、DNS、时间以及 TLS 1.2/1.3 握手签名均委托给原生验证器，没有跳过证书验证。客户端保存本次 TLS 握手实际验证的有界证书链，在每次 RPC readiness 之后、发送之前重新验证链、名称和当前时间，收到合法回执后再复核一次。

正式运行层使用 `connect_authorized` 并提供实时 `PeerAuthorizer`，在握手以及每次 RPC 前后核对当前 cluster/node、leaf pin、有效期和关闭状态；任何历史握手或 policy revision 都不授予继续发送的租约。独立 `connect` 入口保留显式私有 CA/DNS 的验证模式，供不持有运行层 pin policy 的直接 transport 调用者使用；正式 runtime 不使用该入口。保存的证书链和 OCSP 数据合计至多 1 MiB，中间证书至多 32 个；pin 撤销仍由当前策略决定，不依赖在线 OCSP。

`max_connection_age` 与 `connection_grace` 限制服务端已有连接寿命；运行层在下次使用前也淘汰超过该年龄的缓存 channel，失败或取消立即丢弃缓存。修改 TLS 身份/CA 需要重建对应 client/server；当前 pin 的轮换和撤销无需重建连接。

## 有限资源与 deadline

- `BoundedIncoming` 在接受 socket 前取得全局 permit；permit 持续覆盖 TLS 握手和连接整个生命周期。容量用尽后对 listener 施加背压，不创建无界用户态等待队列。
- 正式 listener 对每个 accepted socket 显式设置 `TCP_NODELAY`；设置失败即拒绝该连接。Tonic 的 builder TCP 配置不作用于自供 incoming stream，不能依赖该默认值避免小 Raft 消息受到 Nagle/delayed ACK 延迟影响。
- 全局 in-flight RPC permit 在 gRPC body 解码前取得；服务端同时设置每连接请求与 HTTP/2 stream 上限、header 上限及 request timeout。per-connection 限额不替代全局限额。
- 外层 gRPC 最多 `max_wire_bytes + 6` 字节，wire 层再次限制确切 envelope 长度；响应最多 16 字节。压缩关闭。每次请求的解码缓冲、原始 envelope 和 payload 可能同时存在，部署预算须计入这些副本及 TLS/HTTP2 开销。
- `PeerClient::connect` / `connect_authorized` 设置整个连接尝试 deadline，TLS handshake 和连接子步骤也有界。`send` 接受运行层在排队前分配的绝对 `std::time::Instant` deadline，readiness 与发送共用预算，无自动重试。
- 运行层必须限制客户端/发送任务总数、排队字节和每对端预算；单个 `PeerClient` 不负责跨实例的全局出站调度。

当前是有界完整消息协议；没有大 snapshot 分片或多 cell 公平性实现。限制范围不是部署推荐默认值或已经测得的安全容量。

连接复用的变更理由、安全边界与独立验证要求见 [ADR-0015](../../docs/adr/0015-incremental-blocks-and-isolated-execution.md)。每节点 `max_connections` 至少容纳 `2 × (trusted_peers − 1)` 条稳定 peer lane；固定成员模式下 trusted peers 就是 bootstrap voters，动态模式则包含预注册 learner/替换候选。这个值只是启动下界，不包含旧半开连接、连接重建、身份轮换和运维流量需要的余量，不能当作故障恢复容量已验收。

transport 不根据 Raft 的当前 voters/learners 自动授予或撤销 TLS 身份。可信 peer 目录、V2 配置 entry 及 joint snapshot 的验证由 wire policy 完成，实际 membership 的持久应用由 driver 负责。peer 角色变化不延长证书有效期，也不跳过每 RPC 的当前 pin 检查。

## 验证范围

正式单元测试覆盖参数、配置、路由、错误转换、全部 IO 委托、连接 permit 生命周期、解码前全局准入、绝对 deadline 和 receipt 校验；新增复用验证覆盖原生链/DNS/有效期拒绝、实时 pin 撤销、每 RPC 前后复核及 TLS 1.2 签名委托。可控依赖端口注入 readiness、native 完成和 HTTP/2 调用失败；一次隔离 native mTLS 往返只验证实际连接 metadata 到有界 Ingress 的委托，不运行 Raft、不使用持久数据、不构成 quorum 或分区证据。

真实三节点、多进程、分区和恢复证据由独立契约测试记录，不补单元覆盖率。精确最终计数由仓库覆盖率门禁和执行证据统一维护。
