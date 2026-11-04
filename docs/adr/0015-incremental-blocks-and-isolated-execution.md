# ADR-0015：增量磁盘块、按库执行隔离与可重新授权的连接复用

日期：2026-11-04。状态：实现；精确验证结果以 [执行证据](../engineering/g0-evidence.md)为准。

本记录替代 ADR-0008/0009 的 native 单 key 全镜像布局、ADR-0012 的每 delivery 新连接策略，以及 ADR-0014 的单 SQL actor 调度方式。逻辑格式、ACK、fencing、ReadIndex、UNKNOWN、归档覆盖与资源拒绝合同继续生效。

## 1. 问题

有界服务已经能够完成真实 SQL、三副本持久提交、自动 owner 恢复、归档和冷唤醒，但三个实现选择妨碍进一步验证：

- 每个 Ready 或 applied 更新都同步写整个 Store 镜像，未变化的日志、snapshot 和其他库历史被重复写入。
- 一个前景 cold hydrate 等待 S3 时，共享 SQL 线程无法服务其他数据库。
- 每个 peer delivery 都重新握手，无法摊薄 TCP/TLS 成本。简单缓存连接又会把握手时的证书有效性误当成长期授权。

## 2. 增量物理布局

`scap-raft-store` 的 `SCAPRAFT` v1 逻辑字节保持不变。正式 `scap-raft-rocks` 对这些字节采用内容确定边界的块，最小 4 KiB、最大 32 KiB，末块可以更小；固定 gear 表和分割规则纳入物理版本。边界哈希只决定分块，块身份及完整性仍使用 SHA-256。

磁盘 namespace 由一个 `scap/g1/0-manifest` 和它引用的 `scap/g1/1-chunk/<sha256>` 组成。清单包含 `SCAPBLK!`、u32 version 1、完整逻辑字节数、按顺序的块摘要/长度、完整镜像摘要和清单摘要。重复块可被多次引用；存储只保留一份。加载先检查清单长度、数量、每块长度和完整覆盖，再分配有界 image buffer；逐块核验摘要，最后核验完整镜像和上层 Store 结构。

一次更新的清单、新块和不再被引用的旧块删除都在**同一个开启 WAL、sync 和 fsync 的 RocksDB WriteBatch**中完成。未变化块不重复 put；不会在旧视图仍可能恢复时单独删除其唯一数据。后端只有在成功读取并识别独占 namespace 后允许更新，未知/多余 key、缺块、坏摘要和读取失败均拒绝继续。同步写结果不确定后，句柄停止，不允许原地重试。

旧 `scap/g0/atomic-image` 仍可只读加载。首次合法写入在同一 WriteBatch 中发布完整新布局并删除旧 key；读取不会迁移、自动修复或初始化。旧二进制不认识新 namespace，必须拒绝打开，不能把它当成空库。升级需要保留 quorum，回退不能直接用旧二进制读取新布局。

该实现减少 native 持久化的重复字节，**没有消除完整状态编码、校验和候选复制的 CPU/内存成本**。它也没有把存储改成逐页远读对象存储，未修改 S3 对象格式或放宽数据库/历史上限。后续仍需逻辑分段、恢复基线和有序保留政策。

## 3. 按库执行与生命周期

全局 dispatcher 只处理路由和有限 catalogue 维护。每个实际需要服务或恢复的数据库按需取得一个串行 lane；该 lane 的线程独占创建、调用和销毁 SQLite writer，连接不会跨线程移动。同库顺序和 owner fencing 保持不变，不同库可以分别等待本地引擎、quorum 或 S3。

catalogue 扫描仍在 dispatcher 上执行有界同步元数据检查，活动 lane 也定期维护；因此本次不声称 dispatcher 完全无阻塞。单库配额限制单个数据库占用，不是任意数量租户间的加权公平调度。

当前最多 32 个活动/退出中 lane。HTTP 到 SQL 的总准入仍最多 32 个请求、8 MiB，单库最多 8 个请求、2 MiB；排队和执行中的 reservation 持续计入总数。满额拒绝请求，原绝对 deadline 与取消信号不重新计时。一个库不能独自占满全部请求额度。

休眠且队列为空的 lane 退出，冷库不保留专用 SQL 线程。退出判断与请求入队共用同一锁；已停止准入的旧队列不接受新请求。dispatcher 在原配额内保留这些尚未执行请求的 FIFO、ID、deadline、取消标志和 reservation，旧线程成功 join 后才整体交给新 lane；不重放已经执行的请求，也不等待 native 析构阻塞其他库。退出未完成时继续清除过期/取消的等待请求；异常退出不自动重启，关闭先取消全部等待再 join。每次重建使用新的 boot/worker 身份，并通过既有 Claim → recover → Activate → ReadIndex 流程取得权限。后台扫描不会打开 SQLite 或前景 hydrate 一个冷库。

节点公开的 `/readyz` 只由 catalogue 维护，停止信号优先于 readiness hint。每库 worker 保存自己的观察状态，单库 deadline 失败或新线程第一次观察 term 不得更改节点公共提示。ready 仍不是 SQL 授权；每条请求继续执行自己的领导权、权限、ReadIndex 和有序提交检查。

后台归档继续使用一个有界 job owner，各 lane 只在入队/取结果的短临界区共享队列；对象网络 I/O 不在该锁中执行。关闭、构建失败和 panic 都取消排队/活动请求，保留句柄直到 join 完成，不 detach 仍可能写入的线程。

## 4. 连接复用与当前授权

每个固定 peer 的 ordinary/snapshot 发送 lane 各至多缓存一个串行 client。连接年龄和原始 delivery deadline 有明确上限；失败、取消、迟到或过期都会丢弃缓存，不在 transport 内重发 Raft 消息，更不会自动重执行业务 SQL。

Tonic 的 verifier 接口委托 Rustls `WebPkiServerVerifier` 完成证书链、DNS、时间和 TLS 签名校验。保存的是实际握手验证的服务端证书链，RPC 前后重新使用当前时间验证链和名称，并通过 runtime 当前 policy 复核 leaf pin、node 和有效范围。验证失败不把旧连接继续视为授权。入站请求及 driver 消费时的证书、policy revision、成员 scope 校验保持原有路径。

连接复用改善握手成本，不能代替证书控制面或证明动态成员已经实现。当前仍是静态三 voter 单 cell；CA/身份更换的部署流程需要遵循既有生命周期。

## 5. 验证与发布范围

- 单元 profile：覆盖新块布局的边界、拒绝、引用复用/回收、迁移、I/O 停止；lane 的配额、顺序、退出/入队竞争、取消、spawn/join；复用通道的链/DNS/有效期/current pin、超时和丢弃。
- 独立存储 profile：正式 native 后端的磁盘重开、旧格式迁移、同步后进程退出、缺块/损坏/外来 namespace 拒绝。
- 独立服务 profile：真实三 daemon、Node SDK 和 S3 黑洞；记录冷库等待中的热库读写及满额拒绝，再执行 ACK 保留、分区、全组重启和既定 360 请求测量。
- 生产 Rust 源码继续逐文件检查行、函数、region、branch 的精确 100%；真实故障 profile 不并入该分母。

单机结果不能证明三 AZ、真实设备断电、GiB 级恢复或生产 p99。10,000 cold/100 hot、长期请求身份回收、动态成员、多 cell、GC/PITR/DR 和性能验收依然需要后续实现或环境证据；不能把本记录的布局与隔离改进解释成这些门禁已经通过。
