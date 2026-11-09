# 2026-11-09：继续实现资源隔离与结果内存边界

## 远端基线与目标

主线 `c5ed0c2ff1b3dfa1fd200edcf3a055d64e711e16` 已合入 PR #35。
本轮从 PR #36 的 `03287e6b8d1beaeea705a584d96da01022616013` 继续，
完整 345 文件的 Git blob 与 tree `ae75de876175a7f9297629d79f43261073ad6d72` 已核对。
这是包含受限 GC 传输的开发基线；产品 GC 仍关闭。

[上次交接](continuation-2026-11-09.md)列出的 owner、pins、intake 等本地检查点
不在当前工作区，也无法按记录 SHA 从远端读取。本轮不能继承它们的源代码或验证结果。
继续沿用 S3 唯一持久权威，不恢复旧 Raft/NFS 方案。

## 已确认的缺口

1. 当前 HTTP 入口使用全局 semaphore；请求超时后，尚未结束的后台 Job 可能不再
   持有入口额度。持续超时请求因此可能让实际执行工作超过该入口声称的数量边界。
   租户级原始 body 字节与请求数量也需在读取 body 之前一起预留。
2. SQL 结果的 wire 字节上限不包含 `Vec<Vec<Value>>` 的容器、容量空余、列名及
   扩容期间新旧分配共存。大量 NULL 和短行会放大 Rust 内存。
3. 历史结果格式有效，但当前机器无法物化其 typed graph 时，必须保留提交证明。
   不得将本地资源不足标为 Corrupt、污染 handle 健康状态或重放 SQL。

## 本轮实现协议

### HTTP intake

data、control、recovery、catalogue 使用各自的资源池。鉴权得到可信主体后、读取
body 前，原子预留全局与 `(deployment, tenant)` 的请求数及最大原始 body extent。
完整读取之后才缩减未用字节。额度绑定原 Job，并延续到实际工作结束和最后响应
Bytes 持有者释放；HTTP timeout/drop 不代表 worker 已经结束。

沿用现有全局请求数与 max_body_bytes；新增可选版本 1 profile 明确每租户数量及
全局/租户 body 字节边界。默认值及兼容行为随实现文档固定，拒绝无效组合。
不同 principal 不能绕过同 tenant 额度；拒绝的 tenant 不得污染无限增长的 map。
discovery 保持自己的受限池，不把它计入其他入口的总量。

本轮 intake 只说明原始 body extent 与请求数；它不等于响应内存、解析图、TCP
buffer 或进程 RSS 预算。后续能力必须按[资源设计](../architecture/resource-budgets.md)
逐项接入，不能用一种计量单位代替另一种。

### typed result

新增独立 `result_memory_bytes`，默认 128 MiB；保留 SCAPRES1、64 MiB 历史结果格式
和当前新执行默认 50 MiB wire 结果上限。shared ResultMemoryBudget 在分配前核对
checked arithmetic、Vec/String/Blob 容量及替换分配的旧新重叠，使用可失败分配。
native collection 与历史 decoder 采用相同计量，不把 NULL 当作只有一个字节内存。

该预算约束一次 typed materialization 的已归属 Rust 分配，不是全进程 allocator
或 RSS 硬上限，不包含 SQLite heap、allocator 元数据、编码工作区及其他并发结果。
native 编码后应释放旧 graph，避免随后 decode 时两份 graph 同时驻留。

提交前资源不足走明确资源限制出口。已经有合法原提交证明但无法物化时，返回
`CommittedButUnavailable` 和原 receipt；raw lookup/cancel 仍保留完整原始 bytes，
降低本地预算不损坏历史结果。格式校验与资源准入分开。

## SQLite、S3 与 Turso 的边界

SQLite 官方 WAL 要求访问同一数据库的进程在同一主机；WAL 允许读写并行，但普通
SQLite 仍是每库一个 writer。SCAP 的多个数据库可以并行，增加 pod 不自动增加单库
写吞吐。运行中的 `.db`/WAL/SHM 和临时文件继续只在受支持的私有本地目录中使用。

S3 上 immutable 对象和同一 HEAD 的 ETag 条件发布是跨节点权威边界。旧 owner
即使暂停后恢复，也必须通过原 ETag 的发布；租约超时本身不构成 fencing。
ACK 仍晚于依赖持久化、HEAD 接受与 native publication；不确定响应仍按原身份查证。

Turso 的 libSQL/bottomless 异步备份、新 Rust 引擎 MVCC 与 Cloud 的同步 S3 WAL
架构应分开。可借鉴按需分块加载、批量持久化和故障验证；不能据此宣称 SCAP 已有
lazy VFS、group commit、多 writer 或 Turso 的吞吐指标。S3 Express One Zone 的
故障域也不能当作多 AZ 的同步持久性。

官方依据：

- [SQLite WAL](https://www.sqlite.org/wal.html)
- [SQLite 网络文件系统](https://www.sqlite.org/useovernet.html)
- [S3 条件写](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)
- [Turso Cloud 持久化](https://turso.tech/blog/how-does-the-turso-cloud-keep-your-data-durable-and-safe)
- [bottomless README](https://github.com/tursodatabase/libsql/blob/main/bottomless/README.md)
- [Turso 0.8 并发写](https://turso.tech/blog/turso-0.8.0)
- [AWS 与 Turso 的批量 WAL 设计](https://aws.amazon.com/blogs/storage/how-turso-built-a-transactional-database-using-amazon-s3-express-one-zone/)

## 验证计划与状态

本文件首先提交设计和真实远端基线；此时新实现的 stable/nightly、四维覆盖和真实
HTTP/native/S3 回归均为 **NOT_RUN**。环境已重新准备固定 Rust 1.90.0、nightly
2025-09-18、libclang 18、Node 22.16.0 和 SeaweedFS 4.51；安装成功不等于产品通过。

新增单元需要验证零预算、溢出、真实 NULL/短行、所有容器与 payload、扩容重叠、
保留结果不可物化时的原 receipt、租户公平性、超时后 worker 持有、最后 Bytes clone
释放以及失败后的额度归还。冻结源码后分别运行严格 Clippy、workspace 单元与
unit-only 精确覆盖，以及受影响的真实 native/HTTP/S3 合同。

自动 owner、storage generation/pins、安全 GC、PITR、lazy recovery、全局响应/对象
解码/SQLite heap/磁盘预算，以及目标 AWS、长期成本与吞吐 SLO 仍有后续工作。
本轮不将这些未实施项目标为完成，也不以历史候选的通过记录认证新源码。
