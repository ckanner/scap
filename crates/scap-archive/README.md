# 不可变对象归档与有界冷生命周期

该正式模块将可信 `scap-cell-client` 与 S3 兼容对象存储连接。调用方在独立的阻塞线程执行维护任务；模块不创建后台线程、无界任务队列或独立的数据库权威。

## 已实现的协议

1. `Controller::suspend` 读取新的 Safe ReadIndex，提交绑定当前 owner 与 revision 的 `SuspendDb`。cell 对已有 owner 增加 epoch、撤销执行权限；已经休眠的库及从未认领 owner 的旧版库保持同一 epoch。
2. `publish` 从同一权威视图生成单库完整恢复对象。对象包含 cell/database incarnation、placement generation、源应用位置、请求世代与退休前缀、当前保留事务回执与原结果、恢复基座和其后的物理尾部。对象 key 另绑定 cluster ID 和内容 SHA-256。
3. S3 使用签名的 `PUT If-None-Match:*`。创建成功或已存在后，都必须执行有界 HEAD/GET，校验完整长度和 SHA-256；ETag 不承担内容校验职责。
4. `PublishArchive` 在有序 cell 状态机中再次检查数据库身份、原 owner token、休眠状态、前序归档摘要、revision、commit hash、源位置，以及对象与当前完整历史的精确对应。对象已上传而命令尚未被接受时，不会推进权威恢复指针。
5. `prune` 只在当前 head 已由已发布归档完整覆盖且原 owner token 未改变、数据库仍休眠时，清除应用状态中的基座镜像及物理尾部字节。基座 revision、请求身份、回执、原始结果、取消记录、owner/auth fence 和归档指针继续保留。
6. `hydrate` 只从新权威视图选定的精确 key 读取。命令校验完整对象摘要、每条 receipt/fingerprint/result/hash、请求世代与退休前缀、恢复基座与物理 payload 摘要，只装回缺失的恢复数据，不覆盖现有权限和元数据。归档后新增的 AuthFence、取消记录及显式结果确认不会被旧对象覆盖。完成后才允许调用既有 `Writer::recover`。

Cold 库不能 ClaimOwner、ActivateOwner 或产生新成功写。结果未知、S3 不可用、对象缺失/损坏或 deadline 到期时保持原有权威状态，不以同名空库或较旧对象降级恢复。维护请求超时后，提交可能已生效；下一次维护先读取当前状态，不能推断回滚。

Cold 可通过原身份确认已知终态，但拒绝请求窗口退休；必须先精确 hydrate。热态窗口退休先保证存在的 SQL 历史由准确 head 的物理基线覆盖，再释放已确认结果，并清除当前 live archive 引用，不删除旧对象。纯取消且从未提交 SQL 的窗口不创造虚假基线或 revision。归档即使摘要正确，缺失退休 SQL 前缀所需的基线也必须在相对 tail 索引和安装前拒绝；不能把空的保留事务表解释为空数据库。

## 有界后台维护

服务的 `archive_jobs` adapter 将归档放在一个受 supervisor 管理的后台线程执行。目录维护与每库 SQL lane 通过短临界区 enqueue/poll，共享队列锁内不执行对象 I/O 或 cell RPC；S3 故障时后台维护不会以同步对象 I/O 占用热 SQL 执行线程。

- 任务和完成通知各最多 8 个；每个 database ID 同时最多一个 pending。任务仅保存固定大小的 `DatabaseView`、原 `RequestContext` 和 operation IDs，队列不保存对象正文。
- 重试登记表最多包含配置中的数据库数量，不能随错误累积增长。失败后到该次原 deadline 加 5 秒前不再排队；下一轮维护重新检查状态、获得新的请求身份，并不自动重放旧的未知结果。
- `publish_bound` / `prune_bound` 在读取、对象 I/O 和最终有序命令之间保留排队时的身份、owner、head、auth epoch 和前序归档。即使 I/O 期间发生相同 head 的唤醒再休眠，旧 token 也不能发布或卸载。
- 成功 prune 的通知触发服务请求正式的全 cell checkpoint；完成通知自身不能删日志。后台线程异常退出通过 oneshot 通知 supervisor，panic 由 join 报告；关闭会取消当前任务并回收线程，不把停止解释成命令已回滚。

冷请求的 `hydrate` 在该库独占的 SQL lane 内，以原 deadline 同步执行。每次前景恢复构造独立 Controller，不占后台队列锁；一个库等待对象读取时，其他库的 lane 可继续服务。服务最多保留 32 个活动或退出中的 lane，全局 SQL 准入为 32 个请求 / 8 MiB，每库为 8 个请求 / 2 MiB，排队和执行中的请求都计入预算；冷库空闲时不保留专用线程。实现及退休/join 合同见 [ADR-0015](../../docs/adr/0015-incremental-blocks-and-isolated-execution.md)。

这些边界隔离单库的 SQL/对象等待与请求占用，但不提供加权公平调度、独立恢复带宽或容量预留。目录扫描仍同步访问 cell 元数据，lane 也定期维护；共享 cell、磁盘与 CPU 的压力仍可能影响其他库。

## 资源与恢复边界

- 对象长度加 192 字节必须装入同一个 `max_command_bytes`，以保证有序 hydrate 可执行。超限库保持原物理历史，拒绝发布/卸载；尚无分块 hydrate 协议。
- 所有 S3 操作受原始绝对 deadline、配置请求超时与对象大小上限约束；自动网络重试关闭。stream 逐块复核上限，S3 返回成功后仍检查 deadline/取消。
- 目前永久保留全部对象，没有自动 GC、对象生命周期删除或备份保留期协议。桶策略不得自行删除这些恢复根。
- 单库 `prune` 不授权截断共享 Raft 日志。实际日志空间回收仍需包含完整当前状态、membership 和 applied position 的持久 Raft snapshot。旧 Raft 日志或旧 snapshots 仍可能保存原物理字节。
- 未退休请求结果和审计元数据仍占用 cell 空间；服务 profile 每库窗口最多 128 条请求，确认全部终态后可显式退休。cell 4096 条行政记录尚不退休，状态镜像和完整编码成本仍受原有上限约束。请求退休不会回收 S3 对象，该实现不等于无限规模或冷库零成本。
- 普通数据归档不是 S3-only 灾难恢复入口。多数副本永久丢失时，不能仅靠扫描 bucket 复活原 owner；完成态 DR checkpoint、迁移、删除与安全 GC 仍需各自协议。

## 格式与升级

正式服务依次完成物理历史和请求退休两个独立有序 activation，确认后 Cell state 与新 `SCAPARC!` 对象写入 v4。epoch 1 的旧业务命令仍为 v2，新世代或确认/轮转命令为 v3；普通结果仍为 v2，确认、轮转和 Retired 结果为 v3。物理 `SCAPIMG!` 保持 v1。reader 读取绑定相同身份、位置和 limits 的合法 v1/v2/v3 状态及精确旧 v2/v3 归档；旧前缀在对应 activation 前保留原编码、PublishArchive/Hydrate 与容量裁决，解码本身不升级。服务目录在对外业务及后台归档开始前确认 phase 4。

history activation 对旧热历史逐条采用与新提交相同的物理算法和折叠阈值，原子得到规范的基座与尾部；不足阈值的历史仍保留为尾部，不能按各副本当前 head 无条件全部折叠。独立 retention activation 验证 v4 格式与全部未确认结果的确认空间预留，不提高原容量。已发布的旧归档保留原精确内容身份，epoch 1 且零退休前缀的旧 Cold 状态可以核验原 v2/v3 对象后恢复，不覆盖当前确认标记。v1 热状态没有归档引用和已卸载数据；从未认领的旧版库保留 `(epoch=0, worker=0)`，休眠不会创造虚假 owner。原行政 intent bytes 不包含 envelope version，升级后相同 operation ID 仍返回原 receipt。对象 key 的 `scap/v1/` 是独立路径布局版本。

旧 v3 二进制不能读取 v4 状态，禁止直接降级启动。当前 Raft peer envelope 3 与旧 1/2 隔离；升级必须先停止写入和全部原 voter，再统一使用新版本 OpenExisting，保留原目录并完成全副本验证，没有混版本滚动协商。归档格式升级不授权删除对象；请求结果仅通过 [ADR-0019](../../docs/adr/0019-explicit-request-result-retirement.md)的显式确认与有序退休释放，与对象 GC 分开。真实升级和故障的最终验证状态以执行证据为准。

## 技术与证据

固定 `object_store = 0.14.2`、`reqwest = 0.13.2`，禁用默认 AWS-LC 特性，使用 ring 和 rustls。凭证、endpoint、region、bucket 都由显式配置提供，不使用实例元数据或环境凭证发现；HTTPS 为正常方式，明文 HTTP 仅在显式允许的测试配置下使用。

上游来源核对日期：2026-11-02。

- [object_store 0.14.2 Cargo 与特性](https://github.com/apache/arrow-rs-object-store/blob/v0.14.2/Cargo.toml)
- [S3 条件 PUT 与 builder](https://github.com/apache/arrow-rs-object-store/blob/v0.14.2/src/aws/builder.rs)
- [reqwest 0.13.2 TLS provider](https://github.com/seanmonstar/reqwest/blob/v0.13.2/src/async_impl/client.rs)
- [独立 S3 契约实验](../../experiments/archive-s3/README.md)

单元测试包含真实本机 HTTP 签名请求、精确错误与超时路径；独立 SeaweedFS 进程实验不进入单元 coverage profile。两者都不能替代真实目标对象存储、跨 AZ 或设备断电的生产验证。
