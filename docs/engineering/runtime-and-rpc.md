# 运行、RPC 与依赖接合契约

初始日期：2026-10-29；正式 peer 网络与单 cell 运行层更新：2026-11-01。状态：完整运行栈契约与部分正式实现。`scap-raft-wire`、`scap-raft-transport`、`scap-raft-runtime` 已实现固定成员单 cell 的有界 mTLS 传输和自动驱动，并有独立三进程网络证据；外部 SQL/Hrana/SDK 和单 cell 自动 writer 接管已由后续 [ADR-0014](../adr/0014-sqlite-service-and-cold-lifecycle.md)装配，多 cell 调度与生产规模仍未完成。技术方向见 [ADR-0007](../adr/0007-tikv-stack-and-rpc-boundaries.md) 与 [TiKV 参考审计](../research/tikv-rust-stack.md)，本轮实现决策见 [ADR-0012](../adr/0012-bounded-raft-network-runtime.md)。

## 1. 采用方向与边界

平台完整栈方向为 Tokio、Axum/Tower、Tonic；诊断采用 tracing 和 Prometheus，OTLP exporter 按信号成熟度及资源预算验证。当前正式 peer 路径固定 Tokio 1.50.0、Tonic 0.14.6 和 Prost 0.14.3，不表示 HTTP/SQL 入口与观测服务已交付。共识复用 raft-rs，SQLite 继续使用固定 libSQL C 内核。所有这些组件都不能替代业务状态机的提交裁决。

TiKV 的主服务使用 grpcio C Core，状态 HTTP 使用 Hyper，部分云 SDK 又使用 Tonic。SCAP 选用 Tonic 是自己的工程决定，不能称为复用了 TiKV 的主 RPC 实现。Tonic 的 [transport][tonic]建立在 Tokio、Hyper、Tower 上；[Axum][axum]提供 HTTP 路由与 Tower 中间件，保留它与借鉴 TiKV 的 Hyper 使用并不冲突。

`scap-core` 不引入 HTTP/gRPC 请求、具体 Raft 消息或 telemetry 类型作为领域接口。边界 adapter 负责认证、编码、错误与完成事件转换；状态机只处理确定性命令。不要为每种库建一层没有实际责任的抽象。

正式模块职责为：wire 负责有限格式、消息预检和对端授权；transport 负责真实 mTLS、gRPC 和连接/RPC 资源；runtime 负责有限队列、串行 owner、自动 tick、读请求和发送反馈。运行入口和故障边界详见 [单 cell 网络运行层](raft-network-runtime.md)，三个正式模块不依赖实验中的代理、父子控制通道或进程编排。

## 2. 资源与执行分工

| 工作 | 执行安排 | 必须限制与观察 |
| --- | --- | --- |
| HTTP/gRPC、连接、定时与控制 | Tokio 异步任务 | 连接、流、请求数、字节、deadline、队列等待 |
| 一个 cell 的 RawNode | 串行有界 driver | Ready 未完成前的状态变更约束、tick 迟滞、控制消息预算 |
| SQLite FFI 与 SQL 执行 | 有界线程/worker 执行池 | 单库 writer、CPU/内存、语句时间、interrupt、结果大小 |
| RocksDB sync 与 snapshot 文件 | 按 cell 有序的受控 I/O 路径 | 未完成写数/字节、sync 时间、磁盘 reserve、错误 |
| 归档、压缩、恢复 | 独立并发与带宽预算 | 每库和每节点任务数、对象字节、临时磁盘、取消与保留 |
| 管理、健康、metrics | 与重 SQL/恢复工作隔离的资源预算 | 不能被热点租户完全饿死，也不能无限消耗资源 |

参考 TiKV 的任务准入和专用池，不在首版直接增加 yatp。Tokio 自身不提供跨租户公平性；`spawn_blocking` 也不会自动限制任务数或安全取消已开始的阻塞调用。[官方说明][tokio-blocking]要求对这类调用另做并发与取消管理。

队列同时限制条目数与累计字节。满时明确拒绝或在既定 deadline 内等待，不能使用无限 channel 把问题转成内存耗尽。控制消息与恢复操作可有独立预算，但不能越过已经建立的 Raft 顺序，或在未持久 Ready 期间任意调用 RawNode。

多个 cell 共用节点时，某个 cell 的磁盘等待不能占住整个网络线程。首版同步 Ready 可以暂停所属 cell 的驱动，必须记录因此造成的选举和尾延迟。批处理限制数量、字节与等待时间，且不改变每个事务的 ACK 条件。

当前 `Runtime` 在调用方提供的专用阻塞线程串行驱动真实 `Driver`，网络任务只入队或报告 attempt 结果。单调时钟推进 tick；磁盘停顿后不会突发补齐所有遗漏 tick。`RaftDriver` 窄 port 的正式委托也纳入生产覆盖率分母。多 cell 公平性、SQL 执行池和慢盘下的生产容量仍须单独实现与测量。

## 3. RPC 服务、编码与回执

### 3.1 三种协议入口

| 接口 | 使用者 | 契约与当前状态 |
| --- | --- | --- |
| Hrana / 对外 SQL | Node.js SDK 与应用 | 已实现自包含闭合 HTTP v2 pipeline、参数/整数/BLOB、batch、稳定 ID 与 UNKNOWN；交互会话/cursor 不支持 |
| SCAP 内部业务 RPC | gateway、worker、cell、controller | 自有版本化服务定义、服务身份、明确的提交/查询结果；完整装配尚未实现 |
| Raft peer transport | 合法 cell 成员 | 已实现 `/scap.raft.peer.v1.Peer/Deliver`；版本化 envelope 与内层 Raft 消息，不对租户开放 |

采用 gRPC 并不等于实现 TiKV 的 `kvproto::Tikv` 服务。SCAP 没有与 TiKV 服务直接互通的产品需求，也不因同用 Raft 就复用其 Region/MVCC 业务协议。

### 3.2 内层与外层编码

固定 raft-rs 的 [proto manifest][raft-proto]中，`prost-codec` 依赖 Prost 0.11；当前实验使用的 Tonic 0.14 配套 [tonic-prost][tonic-prost]依赖另一代 Prost。不同版本的 Rust trait 和生成类型不能直接互换。

初始契约实验采用：

- 外层：Tonic + 配套 Prost 生成 SCAP 测试 envelope。
- 内层：raft-rs 的 `protobuf-codec` 序列化字节。
- envelope：独立协议/codec 版本、cell 实例、发送/接收节点和 opaque bytes。

2026-11-01 的正式实现使用 Prost `Packet.data` 包裹 `SCAPRPC1` envelope：80 字节固定小端头包含版本、codec、cluster、cell、incarnation、from/to 和 payload 长度，后接原始 raft-rs bytes。完整字段和拒绝规则见 [wire 合同](../../crates/scap-raft-wire/README.md)，实际 unary schema 见 [peer.proto](../../crates/scap-raft-transport/proto/peer.proto)。最小 Tonic service 和消息派生直接位于正式源码中，没有 build.rs 或新增生成代码排除；旧实验 `.proto` 仍只描述其历史探针。

接收方验证外层版本、长度、实际 TLS 对端权限和有限 protobuf 结构，再解码内层。内层 from/to 与外层必须一致；未知 envelope/codec 版本明确拒绝。本阶段仅允许指定的 peer 消息种类，拒绝网络注入本地事件、proposal、转发 ReadIndex 和未交付的 leader transfer；固定成员变更不通过这个 RPC 开放。

传输层保留内层原始 bytes。Protobuf 的可解码等价不表示重新编码后字节相同；未知字段或非规范但可解析的表示可能改变。不要通过 `decode → encode` 实现无意义的转发，也不要把外层序列化结果当作稳定业务幂等指纹。日志命令、业务指纹与传输 envelope 分别定义版本和校验规则。

实验采用的 protobuf 2.x 构建组合与 TiKV 的 PingCAP fork 不同，必须明确记录并独立测试。采用相同 raft-rs commit 不能证明整棵依赖图相同。

### 3.3 接收成功与提交成功分开

| 结果 | 最多能说明什么 | 不可推出什么 |
| --- | --- | --- |
| transport 写入 socket / 入队 | 本端已接受发送工作 | 对端收到、落盘或 quorum |
| gRPC `Received { version: 1 }` | 正式接收端完成认证、授权并准入有限内存 inbox | 已交给 driver、持久完成、业务接受、SQL 可见 |
| `Answer::Admitted` | 本地 driver 接受 proposal | quorum 提交、业务接受、SQL 可见 |
| Raft append response | 按锁定库和真实 adapter 规则表达复制进展 | 单靠一个响应即可给 SQL ACK |
| SCAP Accepted + SQL 原子发布 | 满足 [一致性协议](../architecture/consistency.md)规定的完整条件 | 未声明的区域零丢失、跨库事务 |

`Received` 返回时消息可能仍未被 owner 消费；消费前还会复核当前 policy revision、证书有效期和消息年龄，撤销或超时的排队消息会丢弃。何时发送 Raft 持久依赖响应由 [Ready 契约](raft-rs-integration.md)决定。不得在收到 gRPC 请求时伪造 append 成功；即使返回 receipt 后进程退出，这条消息也可能从未持久化。

Raft 消息的重复/丢失由共识重传流程处理。业务 SQL RPC 则遵守稳定请求身份和 UNKNOWN 规则，不能套用同一种通用自动重试中间件。`DEADLINE_EXCEEDED`、`CANCELLED`、断连和 HTTP 503 不证明事务未提交。

## 4. 消息、超时与背压

Tonic 允许设置收发消息上限，其[默认值][tonic]不构成 SCAP 的容量合同。生产实现必须明确配置客户端和服务端的编码/解码上限、内层 payload 上限、条目数、并发流和全局/单对端预算；每连接限额不能代替进程总限额。

需要分别约束 wire 字节、解压后消息和被解析后的对象/条目数量。正式实现关闭压缩；未来开启前须测试高膨胀比、解压 CPU 与失败路径。当前 snapshot 使用有界完整消息，大快照分块尚未实现，不能靠取消消息上限来发送任意大小的文件。

正式 `NetworkWorkers` 为每个 peer 分别保留 ordinary 与 snapshot worker，各 peer 相互独立；所有队列和正在发送的 payload 仍共享有限数量/字节预算。owner 的逻辑 attempt 到期不会提前释放 worker 仍持有的 payload 预算。大 snapshot/restore 与普通流量仍共享节点 CPU、网络和连接总量，不能从 worker 分离直接推导生产隔离已达标。

正式 delivery 的绝对 deadline 从 owner 创建 attempt 开始，包含排队、建连、握手和发送，adapter 没有自动重试。Raft 后续决定的重传是新的显式 attempt，不能被包装成业务 SQL 重放。取消仅撤销尚未不可逆的工作，已提交或结果未知的写继续按身份查证。

服务端在 accept 前取得全局连接 permit，在 body 解码前取得全局 RPC permit，同时设置每连接 stream、header、消息和时间上限。inbox 计费覆盖 raw bytes、解析对象及 fields/entries 的保守开销；这不是精确 RSS 公式。单元与真实网络测试验证指定的满队列、取消和截止时间路径，完整内存、吞吐和高负载退化仍需容量测试。

`serve_with_incoming` 不应用 Tonic builder 的 TCP_NODELAY 设置，[固定 0.14.6 官方接口](https://docs.rs/tonic/0.14.6/tonic/transport/struct.Server.html#method.tcp_nodelay)明确说明这一点。正式 accepted socket 在交给 TLS 前显式设置 NODELAY，失败即拒绝连接；真实网络组合曾发现此遗漏导致小消息延迟积累，修复后在原读 deadline 下通过契约，详见 [网络运行层记录](raft-network-runtime.md)。

实验里的字节常量是测试夹具参数，不是生产事务上限，也不修改 [性能合同](performance-slo.md)的小事务负载定义。生产限制必须与最大物理事务、snapshot 布局、内存预算和恢复目标一起验证后固定。

## 5. TLS、服务身份与健康

正式 peer RPC 强制 mTLS，Tonic 0.14.6 显式启用 `tls-ring`，只信任配置的私有 CA，禁止匿名客户端。服务端从经过 TLS 验证的 connection extensions 获取 leaf DER，由当前 policy 绑定 SHA-256 pin、node 和 cell，并在每次准入及消费前检查有效期。证书链、节点身份映射、cell 成员权限和外层字段一致性是不同步骤；字段写了正确 node ID 不代表调用者被授权。

出站验证名称固定为 `node-{node_id}.cluster-{cluster_id:032x}.scap.internal`，不能用通用 localhost 身份替代。正式 worker 每条 delivery 建立新 `PeerClient`，因此每次消息重新完成服务端证书链、DNS 和日期检查；独立 `PeerClient` 的串行复用仍只在握手时验服务端证书，不能宣称每请求验时。每条消息的 TCP/TLS 建连、socket/TIME_WAIT 和 CPU 成本尚未通过生产吞吐与 p99 验收，后续池化必须保留明确的过期/撤销边界。

当前 pin policy 由可信调用方提供并在进程内替换，重启必须重新提供最新授权；签发、CA 轮换、持久分发和动态 Raft 成员管理尚无生产控制面实现。替换 pins 不会自动替换 server 或 workers 的 TLS 身份/CA。

测试必须覆盖无证书、错误 CA、错误身份、证书过期、轮换、现有长连接与新连接、已移除成员和旧 cell incarnation。缺配置不能静默退化为明文。诊断管理接口仅向受控网络和主体开放，不因 `/metrics` 或 `/config` 是 HTTP 就省略权限边界。

健康检查分别表达：

- 进程存活：可以响应基础探针，不能推导 quorum。
- 节点就绪：本地存储、身份、队列等达到承担所属职责的条件。
- 数据库操作可用：由对应 cell 的 quorum、owner、权限、恢复水位和实际请求协议决定。

不要把少数派无法写入变成无限重启全部节点的探针策略，也不要把一个 `/status` 的 200 响应宣传成所有数据库都可用。上面的健康接口仍是服务层设计。正式关闭先停止准入并取消异步发送，worker 等待有绝对 deadline；同步 fsync 或已开始的应用/SQL 回调不能被这个 deadline 强制中断。实验退出成功不代表设备卡死下固定时限的 graceful shutdown、成员退出或 SQL drain 已获证明。

正式 [scap-sqlite adapter](sqlite-engine.md)是线程受限、私有连接的阻塞模块，直接调用固定 `libsql-sys`。它的同步 gate 已通过 `scap-cell-client` / `scap-sql-worker` 接入正式身份、请求与网络共识路径；VM 指令预算不涵盖网络、fsync 或整个 wall-clock deadline。早期 adapter/cell 与 opaque 网络实验保留原范围；后续 [真实服务合同](../../experiments/service-network/README.md)已经在三个独立 daemon 上通过同一正式 native/HTTP/SDK/mTLS/S3 组合，生产规模仍需独立测量。

## 6. sqld 与平台依赖树

固定 libSQL commit 的 [server manifest][sqld-cargo]仍声明 Axum 0.6.18、Tonic 0.11、Prost 0.12 和 `Tokio =1.38`；其 workspace 使用 Hyper 0.14 / Tower 0.4。平台 Tonic 实验通过不能证明完整 sqld 与现代 Axum/Tonic 组合已合编通过。

G0 必须实际决定并验证 fork、模块抽取或独立构建/进程边界。跨不同框架版本的 Router、Request、Body、Message 不能仅靠同名类型拼接。若暂时通过独立服务协议接合，记录额外的网络、身份、超时与故障成本；若升级上游依赖，记录集中 patch 并重跑 Hrana/SDK 事务与取消测试。不能为了统一依赖版本忽略 SQL 兼容风险。

## 7. 日志、指标、配置和故障注入

tracing 作为平台诊断入口；raft-rs 的 slog Logger 在 adapter 边界处理。桥接必须单向，避免 `log → slog → tracing → log` 环路或重复输出。队列溢出、丢弃计数、脱敏、采样与 shutdown deadline 明确；诊断日志不是持久业务审计，日志出口故障不能改变已提交事务结论。

Prometheus 指标围绕本项目阶段拆分：准入、Ready、fsync、quorum、apply、SQL 发布、冷恢复与 owner 激活；保持有界标签，不把租户/数据库 ID 放进全部指标。OTLP、profile 与 debug 出口设置资源预算，不以观测系统故障阻断数据库正常提交。

采用 Serde/TOML 的类型化配置方向，记录构建标识、原始输入来源、最终生效配置、静态/动态范围和校验结果。未知字段、越界或把有限预算变成无限的设置明确处理；关键路径、cell/node 身份、磁盘格式、成员和 owner 权限不能通过本地配置静默改变。

fail-rs 可用于测试注入，借鉴 TiKV 的暂停 I/O、网络过滤与恢复观察。生产业务逻辑与注入控制分开，测试注入状态必须清理/隔离；不能用 feature 或覆盖率配置藏掉生产错误路径。真实故障测试独立报告，不借它们提高单元 profile 的覆盖率。

## 8. 构建与证据门禁

引入组件时记录 upstream repo、完整 commit/tag、Cargo.lock、features、代码生成器/protoc、native 版本及 submodule、编译器/平台、许可与 patch。不能把 README 中的旧版本、manifest 的范围下界或 lock 里的传递包当成已验证的主服务配置。

| 验证 | 必须证明 | 当前证据边界 |
| --- | --- | --- |
| codec/transport 实验 | 实际 RPC 往返、字节保持、语义字段和拒绝行为 | 见 [独立实验](../../experiments/raft-rpc/README.md)，非 quorum/持久化 |
| 正式 mTLS 与固定成员权限 | 对端身份、cell 授权、轮换、旧 pin/旧 incarnation 拒绝 | [八项真实网络契约](../../experiments/raft-network/README.md)；动态成员和证书控制面仍未实现 |
| Ready 与存储 | 持久响应、commit/applied、snapshot 与重启 | 既有存储/受控集群合同，加正式网络下的进程恢复与 snapshot；不等于设备断电或丢盘证明 |
| 运行资源 | 过载、慢盘、大流、队列满、取消与恢复干扰 | 已有有限队列、资源生命周期和 deadline 单元/契约；真实多 cell、公平性和 SLO 压测仍待完成 |
| Hrana/SDK | 固定 sqld/平台组合的真实事务、返回与错误行为 | 不由 RPC 编码实验替代 |
| 产品单元覆盖 | 所有第一方生产代码 100% 精确行/函数/分支/region | 包含 wire、transport、runtime 及正式 driver 委托；精确最终计数见 [G0 证据](g0-evidence.md) |

独立实验没有 library target，不可被运行服务依赖。若复用其中的校验/协议/transport 逻辑，必须迁移到生产模块并补齐单元覆盖、认证、持久化与错误契约；不是把实验目录加入例外就能绕过门禁。

[tonic]: https://docs.rs/tonic/0.14.6/tonic/
[tonic-prost]: https://docs.rs/tonic-prost/0.14.6/tonic_prost/
[axum]: https://docs.rs/axum/0.8.9/axum/
[tokio-blocking]: https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html
[raft-proto]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/proto/Cargo.toml
[sqld-cargo]: https://github.com/tursodatabase/libsql/blob/d8bc862d20bedc72945a1da27c8b7045414c0261/libsql-server/Cargo.toml
