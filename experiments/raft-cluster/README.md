# 三进程持久 Raft 故障契约实验

记录日期：2026-10-29。状态：**5 项真实三进程契约测试已执行通过**，包括真实 snapshot 投递失败后的重试安装，以及真实 WAL 损坏的严格拒绝。本目录只提供独立 test target，没有产品 library 或服务 binary；不能作为可部署节点使用。

## 验证对象

每个 voter 是一个独立 OS 子进程，使用自己的真实 RocksDB 目录。子进程直接装配正式的 `scap-raft-driver`、`scap-raft-rocks` 和 `scap-raft-store`；没有在实验目录另写一份 Ready driver 或磁盘后端。Raft 使用固定 `ad13f3d90780f53aea2488c6a4b76c0d334bf136` 的真实 RawNode。

应用是按顺序保存 `(token, delta)` 的合成历史。每个非空普通条目携带两个大端 u64，应用只是追加，**没有去重逻辑**。因此，重复 apply 会直接造成历史重复，不会被测试应用自动掩盖。测试在持久应用视图中核对完整序列、commit/applied 和快照位置；`propose` 成功只表示准入，不计作提交成功，更不代表 SQL ACK。

## 传输与故障模型

父进程通过 stdin/stdout IPC 发送受限控制命令，收取 driver 释放的原始 protobuf 消息，然后根据 from/to 路由到另一个真实子进程。消息只是为确定目标而解析，转发时保留原始字节。

这是**受控消息分区模型**，不验证实际 TCP/gRPC 的断连、重连、mTLS、网络栈拥塞或跨 AZ。原有 Tonic 实验是另一层证据，不能与本实验的通过记录相乘后宣称生产 transport 已完成。

- 隔离一个 voter 时，父路由器丢弃它与另外两个 voter 之间的双向消息，模拟没有及时反馈的黑洞。
- 对已经被杀死的进程，路由器通过正式 `report_unreachable` / `report_snapshot(Failure)` 反馈可观察的发送失败。
- 实际交付 snapshot 后，接收方先执行正式 driver 的持久安装，再由路由器报告 `report_snapshot(Finish)`；同时继续转发真实 Raft 响应。
- snapshot 用例对第一次实际发出的 MsgSnapshot 注入一次明确的投递失败，调用正式 `report_snapshot(Failure)`，随后要求真实重传和持久安装。不会用一条人工合成的 snapshot 状态回调冒充失败传输证据。
- 故障使用 `Child::kill`，在 Linux 上检查确切 SIGKILL 退出状态。没有用正常关闭或数据库析构充当崩溃。
- WAL 损坏用例只修改一个已 SIGKILL 的合成副本：查找包含实际 image 和已同步操作的非空 WAL，核对物理 record header 后翻转一个 checksum 字节并 sync。正式后端必须报告明确的 native `Corruption`，保留原目录、数据库身份、CURRENT 指向和坏 WAL；另外两个副本继续提交。该用例证明主动介质损坏注入后的拒绝行为，不是物理断电或自动修复证明。
- 重启调用正式 `open_existing`，使用同一个数据库路径和节点身份、新的 boot ID。不会重建数据库目录、修改成员数量或把日志尾部强行设置为 commit。

每条命令之后执行正式 driver 的有界 drain。每个响应都检查 `snapshot <= applied <= commit <= last`。Safe ReadIndex 使用正式的 `(boot_id, sequence)` ticket；完成回执必须来自相同实例并且 index 不超过持久 applied。这里的屏障没有绑定 SQLite 快照或用户授权。

## 五项场景

| 测试 | 故障与必须观察到的结果 |
| --- | --- |
| leader 退出与整组重启 | 先隔离 node3，仅在 leader1 与 node2 的多数派持久应用后杀死 leader1；剩余的 node2 和落后 node3 选主并继续应用；旧 leader 重开追赶；全组三进程 SIGKILL 后重开保持原历史，并能继续提交和完成读屏障 |
| 1 对 2 分区 | 旧 leader 仍自认为 leader 时先准入新提案和读请求；少数派不增加持久 commit，不完成新读屏障；多数派选主继续；旧 leader 失去 quorum 后降级，恢复连接后收敛 |
| 未提交后缀重启 | 隔离 leader 并生成持久但未提交的后缀；杀死并重开后保留后缀，不提前 apply；其他两节点提交新 term 的冲突前缀后，恢复节点正确对齐 |
| 真实 snapshot 恢复 | 杀死一个落后副本；另外两节点继续应用；leader checkpoint/compact 的位置越过落后节点日志末尾；重开后第一次实际 MsgSnapshot 投递失败，后续必须真实重试并持久安装；再次重开保留快照和应用，并继续接收新提交 |
| WAL 损坏拒绝 | 已确认应用后 SIGKILL 一个副本，损坏其真实 WAL record checksum；严格恢复必须报告 Corruption，不能静默回退到更早 image；原目录与坏数据保留，剩余 quorum 继续应用和完成读屏障 |

分区与后缀用例只在**多数派已经提交冲突前缀**的特定历史中断言原未知提案被覆盖。一般 UNKNOWN 提案可能在后续合法共识中提交，不能由本实验推出“未知就是回滚”。

## 固定构建与有限预算

完整依赖解析与 registry checksum 由实际生成的 [Cargo.lock](Cargo.lock) 固定。

| 项目 | 设定 |
| --- | --- |
| Rust / protobuf | Rust 1.90.0；protobuf 2.28.0 |
| raft-rs | `ad13f3d90780f53aea2488c6a4b76c0d334bf136`，protobuf-codec |
| native 存储 | 正式 scap-raft-rocks；rust-rocksdb 0.24.0 / native RocksDB 10.4.2，WAL + sync，AbsoluteConsistency + paranoid_checks |
| 进程和成员 | 3 个 voter，初始 index/term 为 1；每次进程启动使用新的非零 boot ID |
| 时间 | 显式逻辑 tick；heartbeat=1、election=10、随机选举区间 30–31 tick |
| Raft 预算 | 每消息目标 1024 bytes、16 个 inflight、未提交预算 8192 bytes、每 Ready 提交预算 4096 bytes |
| Driver 预算 | 输入 1536 bytes；每轮最多 64 条 / 32 KiB 输出；最多 16 个 pending read、32 个 Ready round |
| Store 预算 | image 8 MiB、entry 4096 bytes、4096 entries、application 64 KiB |
| 控制协议 | 请求帧 4096 bytes，响应帧 128 KiB；每个发送/读取 channel 容量为 1 |
| 路由与历史 | 待路由队列和单次 pump 各最多 4096 条；事件历史最多 20,000 项 / 8 MiB |
| 等待 | 每条命令的写入和响应共用一个 20 秒绝对 deadline；启动 20 秒；场景协议工作总预算 120 秒；退出和清理最多 10 秒一阶段 |

较长的随机选举区间用于让显式 campaign 在旧 lease 失效后确定地发生，避免该实验依赖真实 sleep 或随机 leader 碰巧被选中。**逻辑 tick 和测试运行时间都不是 RTO 证据。** 对退出状态的有限轮询使用短暂停顿，启动、消息和持久完成均依靠实际响应，不靠暂停猜测已经就绪。

## 复现与原始证据

构建要求与正式 RocksDB 后端一致：C/C++17、libclang 18 和固定 Rust 工具链。与其他原生任务共享构建目录时由 Cargo 锁串行构建；资源受限环境建议 `CARGO_BUILD_JOBS=2`。

```bash
cargo +1.90.0 fmt --manifest-path experiments/raft-cluster/Cargo.toml --all -- --check
cargo +1.90.0 clippy --manifest-path experiments/raft-cluster/Cargo.toml --all-targets --locked -- -D warnings
cargo +1.90.0 test --manifest-path experiments/raft-cluster/Cargo.toml --locked -- --test-threads=1
```

子进程复用同一个 test binary，通过精确测试名称和专用环境变量进入服务循环，没有额外的默认空跑 helper test。每个用例成功后生成一份有界 `.log`，包括固定版本/参数、请求与故障顺序、各节点 term/commit/applied/last/snapshot、完整应用序列、读屏障和 snapshot 路由。默认位置为实验工作目录下 `target/evidence/raft-cluster`；可用 `SCAP_CLUSTER_EVIDENCE_DIR` 指定 CI artifact 目录。失败时事件历史也打印到 stderr，并清理子进程。

## 结果与范围

Linux x86_64、Rust 1.90.0、GCC 13.3、libclang 18.1.3 环境，使用实际生成的锁文件与 `--locked --offline`：**5 passed，0 failed，0 ignored**。格式检查与 Clippy `-D warnings` 均通过。首次 Clippy 指出的整除写法已改为标准 `is_multiple_of`，没有新增 lint 豁免。

本地最终验证使用独立构建目录，通过 `ROCKSDB_LIB_DIR` / `ROCKSDB_STATIC=1` 复用本轮由同锁文件、同 features 源码编译的 RocksDB 静态缓存，并显式追加 `RUSTFLAGS='-C link-arg=-lstdc++'`。常规 CI 按锁文件重新构建 native 源码。实际运行始终使用正式 driver、正式 backend 和真实磁盘，五项测试均产生成功证据日志。

snapshot 日志包含同一 `1 → 3, index=5` 的真实投递失败、正式 Failure 回调、重试安装与 Finish 回调；少数派日志没有对应新读 ticket 的完成回执。WAL 用例实际找到含已同步操作的 2635-byte `000004.log`，首 record 类型 1、长度 180，修改 checksum 后得到明确的 `Corruption: checksum mismatch`。目录、数据库 ID、CURRENT 和原 WAL 其余字节保持，剩余两副本继续提交新操作。这些具体文件号和大小是本次样本记录，测试会检查实际文件内容和结构，不把固定文件号当作寻找 WAL 的依据。

本实验属于真实依赖、进程和受控分区契约层，**不计入正式模块单元覆盖率**。它不覆盖：SQLite 物理事务/可见性、owner/auth、业务幂等与 UNKNOWN 查询、SDK、真实 RPC 安全与背压、多 cell 公平性、S3、设备掉电/丢盘、跨 AZ 及端到端性能。不能据此将整个 G0/G1 或自动 SQL writer 接管标记为完成。

## 相关合同

- [Raft 接合与验收](../../docs/engineering/raft-rs-integration.md)
- [持久镜像与恢复](../../docs/engineering/durable-store.md)
- [运行与 RPC](../../docs/engineering/runtime-and-rpc.md)
- [性能和恢复口径](../../docs/engineering/performance-slo.md)
- [固定 RawNode 源码](https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/raw_node.rs)
- [固定 RocksDB binding](https://github.com/rust-rocksdb/rust-rocksdb/blob/v0.24.0/Cargo.toml)
- [固定 native WAL record header](https://github.com/facebook/rocksdb/blob/410c5623195ecbe4699b9b5a5f622c7325cec6fe/db/log_format.h)
- [固定 native WAL checksum 写入](https://github.com/facebook/rocksdb/blob/410c5623195ecbe4699b9b5a5f622c7325cec6fe/db/log_writer.cc)
