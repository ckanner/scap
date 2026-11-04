# 不可变对象归档与有界冷生命周期

该正式模块将可信 `scap-cell-client` 与 S3 兼容对象存储连接。调用方在独立的阻塞线程执行维护任务；模块不创建后台线程、无界任务队列或独立的数据库权威。

## 已实现的协议

1. `Controller::suspend` 读取新的 Safe ReadIndex，提交绑定当前 owner 与 revision 的 `SuspendDb`。cell 对已有 owner 增加 epoch、撤销执行权限；已经休眠的库及从未认领 owner 的旧版库保持同一 epoch。
2. `publish` 从同一权威视图生成单库完整物理历史对象。对象包含 cell/database incarnation、placement generation、源应用位置、事务回执、物理变更与原结果。对象 key 另绑定 cluster ID 和内容 SHA-256。
3. S3 使用签名的 `PUT If-None-Match:*`。创建成功或已存在后，都必须执行有界 HEAD/GET，校验完整长度和 SHA-256；ETag 不承担内容校验职责。
4. `PublishArchive` 在有序 cell 状态机中再次检查数据库身份、原 owner token、休眠状态、前序归档摘要、revision、commit hash、源位置，以及对象与当前完整历史的精确对应。对象已上传而命令尚未被接受时，不会推进权威恢复指针。
5. `prune` 只在当前 head 已由已发布归档完整覆盖且原 owner token 未改变、数据库仍休眠时，清除应用状态中的物理事务字节。请求身份、回执、原始结果、取消记录、owner/auth fence 和归档指针继续保留。
6. `hydrate` 只从新权威视图选定的精确 key 读取。命令校验完整对象摘要、每条 receipt/fingerprint/result/hash 和物理 payload 摘要，只装回缺失的物理字节，不覆盖现有权限和元数据。完成后才允许调用既有 `Writer::recover`。

Cold 库不能 ClaimOwner、ActivateOwner 或产生新成功写。结果未知、S3 不可用、对象缺失/损坏或 deadline 到期时保持原有权威状态，不以同名空库或较旧对象降级恢复。维护请求超时后，提交可能已生效；下一次维护先读取当前状态，不能推断回滚。

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
- 原请求结果和审计元数据仍占用 cell 空间；单库请求数量、管理操作数量、状态镜像和完整历史成本仍有原有上限。该实现不等于无限规模或冷库零成本。
- 普通数据归档不是 S3-only 灾难恢复入口。多数副本永久丢失时，不能仅靠扫描 bucket 复活原 owner；完成态 DR checkpoint、迁移、删除与安全 GC 仍需各自协议。

## 格式与升级

Cell state/command/outcome 写入 v2。v2 reader 可读取 v1 热状态和旧命令/结果；v1 热状态升级时没有归档引用和已卸载数据；从未认领的旧版库保留 `(epoch=0, worker=0)`，休眠不会创造虚假 owner。新生命周期命令与结果不能塞入 v1 envelope。原有 Create/Claim/Activate/AuthFence 的 intent bytes 不包含 envelope version，升级后相同 operation ID 仍返回原有 receipt，单元测试直接验证这一点。对象 envelope 使用 `SCAPARC!` v2；对象 key 的 `scap/v1/` 是独立的路径布局版本。

旧二进制不能读取 v2 状态，禁止直接降级启动。升级时必须先停止写入并保留旧版本备份，完成新版本全副本验证；本模块没有滚动混合版本协商。

## 技术与证据

固定 `object_store = 0.14.2`、`reqwest = 0.13.2`，禁用默认 AWS-LC 特性，使用 ring 和 rustls。凭证、endpoint、region、bucket 都由显式配置提供，不使用实例元数据或环境凭证发现；HTTPS 为正常方式，明文 HTTP 仅在显式允许的测试配置下使用。

上游来源核对日期：2026-11-02。

- [object_store 0.14.2 Cargo 与特性](https://github.com/apache/arrow-rs-object-store/blob/v0.14.2/Cargo.toml)
- [S3 条件 PUT 与 builder](https://github.com/apache/arrow-rs-object-store/blob/v0.14.2/src/aws/builder.rs)
- [reqwest 0.13.2 TLS provider](https://github.com/seanmonstar/reqwest/blob/v0.13.2/src/async_impl/client.rs)
- [独立 S3 契约实验](../../experiments/archive-s3/README.md)

单元测试包含真实本机 HTTP 签名请求、精确错误与超时路径；独立 SeaweedFS 进程实验不进入单元 coverage profile。两者都不能替代真实目标对象存储、跨 AZ 或设备断电的生产验证。
