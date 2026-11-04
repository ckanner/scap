# 有界单 cell Raft 运行时

正式第一方 crate，负责把 `scap-raft-driver` 接到认证 mailbox、真实 peer transport 和有限发送任务。它提供可装配的 Rust library，没有公开 SQL/SDK 服务 binary，不实现 S3 或 SQLite writer 自动接管。设计与边界见 [工程说明](../../docs/engineering/raft-network-runtime.md)及 [ADR-0012](../../docs/adr/0012-bounded-raft-network-runtime.md)。

## 接口与执行分工

| 接口 | 职责 |
| --- | --- |
| `Runtime::new` | 验证配置、持久身份与固定 voters；返回串行 owner 和可 clone 的 Handle |
| `Runtime::poll / run` | 在专用阻塞线程 drain Ready、tick、处理请求/入站消息/反馈与 Safe ReadIndex |
| `RaftDriver` | 调度层依赖的窄 port；正式 Driver 完整委托，保留原共识与持久行为 |
| `Handle::submit` | 本地可信准入 Propose、Read、Status、Checkpoint；返回有取消和绝对 deadline 的 Pending |
| `Handle: Ingress` | 从 transport 接收已验证 peer leaf DER，每 RPC 授权并预留有界 inbox |
| `Handle::replace_bindings` | 原子替换固定成员的 leaf pins、推进 revision；消费前复核旧排队消息 |
| `NetworkWorkers::start` | 在 Tokio runtime 中为每个固定 peer 建立独立普通/snapshot 发送任务 |
| `NetworkSender: Network` | 立即返回准入结果；满、关闭、未知 route 明确失败 |
| `Handle::stop / NetworkWorkers::shutdown` | 关闭 owner 入口与有界等待网络任务；调用方负责停止 server 和 join owner 线程 |

网络任务不直接操作 RawNode，也不执行同步存储。owner 的持久顺序仍由正式 driver/Store 保证；固定 PreVote、check_quorum、Safe ReadIndex 的行为见 [Raft 安全说明](../../docs/engineering/raft-safety.md)。

## 必须保留的语义

- `Answer::Admitted` 是本地 proposal 准入，`Received` 是远端认证并入内存队列；二者都不是 durable quorum、业务 Accepted 或 SQL 成功。
- `ReadView` 绑定当前请求的 boot/sequence、Safe ReadIndex 与 durable applied；它是 application 视图，不是公开 SQLite 结果集或完整 SQL 读授权。
- runtime 只接受固定 bootstrap voters；endpoint 必须完整覆盖其他 voters。ConfChange、joint/learner snapshot、网络转发 Propose/ReadIndex 和 TransferLeader 在 wire 边界拒绝。
- allowlist 撤销在每次 RPC 与队列消费前检查，握手成功不缓存后续授权。policy 本身不持久化，重启时最新可信配置由调用方提供。
- 每个 peer 的普通/snapshot lane 各缓存至多一个 mTLS channel，超过 `max_connection_age` 时下次使用前淘汰；TLS 链/DNS/时间验证与当前 pin、node/cluster 授权在握手及每 RPC 前后执行。接收端仍在入队与消费前核对当前 policy/revision。失败、取消或超过原始 deadline 均丢弃缓存，不隐式重试该 delivery；后续 Raft 消息可以重新建连。
- 排队、连接、握手、readiness、认证复核和发送共用原始绝对 deadline；到期或取消不会证明业务未提交，也不触发隐式业务重放。缓存 channel 在 await 前移出，只有成功且未过期的回执才允许放回，shutdown/drop 同时释放缓存。
- 每 peer 两类通道独立，但共享有限 count/bytes 预算。本地请求的 RAII 覆盖未领取响应；出站 RAII 持续到 payload 真正离开队列/发送 future，逻辑超时不能提前退款。
- driver/时钟 fatal error 和 poll panic 关闭入口及等待请求。同步 fsync/native 调用不能被 async shutdown 强制中断；网络任务退出不等于完整进程持久关闭。

没有经过生产容量验证的默认参数。调用方必须显式设置 inbox、请求、pending delivery/read、view、poll rounds、tick、delivery deadline 和 inbound age，并与 driver、wire、transport 限额一起校验。消息计费是保守资源预算，不是进程 RSS 上界。

连接复用的变更理由、安全边界与独立验证要求见 [ADR-0015](../../docs/adr/0015-incremental-blocks-and-isolated-execution.md)。每节点 `max_connections` 至少容纳 `2 × (voters − 1)` 条稳定 peer lane；这只是启动下界，不包含旧半开连接、连接重建、身份轮换和运维流量需要的余量，不能当作故障恢复容量已验收。

## 验证

从仓库根目录执行：

```bash
cargo +1.90.0 test -p scap-raft-runtime --lib --locked
cargo +1.90.0 clippy -p scap-raft-runtime --all-targets --locked -- -D warnings
```

单元测试包含真实 mailbox、受控时钟/存储/网络端口，以及隔离 native Tonic/mTLS 委托，验证授权、轮换、停止、读等待、物理配额、deadline 和任务取消。`RaftDriver` 的故障 decorator 包裹真实 Driver，只对指定调用注入错误；正式委托方法同样计入覆盖分母。真实 native sender 测试以 TCP accept 计数核对同 lane 的连接复用，并验证旧连接上的入站拒绝、出站 pin 撤销、下一次新握手拒绝、恢复授权后的重新连接、连接年龄淘汰与取消；没有用 fake 替代整个 adapter。正式源码接受精确 100% line/function/region/branch 门禁，最终计数由仓库报告统一记录。

三进程的持久历史、真实网络分区、SIGKILL、snapshot 和权限攻击由独立 [raft-network 实验](../../experiments/raft-network/README.md)验证，不计入单元 profile。当前八项契约通过，不等于完整 SQLite/SDK/S3 服务验收；生产延迟和故障恢复仍按 [性能合同](../../docs/engineering/performance-slo.md)测量。
