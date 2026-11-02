# ADR-0013：按尝试关联的持久裁决与 SQLite 网络提交

日期：2026-11-02（UTC）。状态：有界正式实现；证据与剩余门禁见 [G0 执行记录](../engineering/g0-evidence.md)。本记录扩展 ADR-0010、0011、0012，不改变同步多数派、CP、单 owner、物理复制和未知结果不自动重放的合同。

## 背景

正式 SQLite adapter 与正式 mTLS cell runtime 原先分别验证。直接把 `Handle::submit(Propose)` 接到 native WAL gate 会产生错误：`Admitted` 只表示本机准入，不能证明日志已提交或业务已接受；一个 Ready 批次可以包含多个不同业务裁决，`CellState::last_outcome` 不能代表任意等待者。猜测 `last_index + 1` 也不能在选主、批量、覆盖未提交后缀和重启后关联请求。

长寿命 SQLite writer 还需要每次请求独立的身份、原始 deadline 和取消信号，以及正式的 owner 恢复顺序。把这些规则写在实验 harness 中不满足生产源码和单元覆盖率要求。

## 决策

1. `scap-raft-driver` 增加 `propose_tracked` 与独立 `ProposalTicket`。Entry context 绑定 cluster、cell/incarnation、node、boot 和单调序号；driver 还核对原 command bytes 和真实 Entry term。普通 `propose` 拒绝使用保留前缀。票据表示一次本地尝试，不替代业务 `request_id`。
2. `Application::apply_with_results` 对本批实际匹配的 Entry indices 按序捕获结果，保留默认普通提案适配。`CellApplication` 在每条命令执行后立即编码对应 `AppliedOutcome`。结果数不符、结果超限或持久化失败均停止 driver，不能作为业务拒绝。只有整批应用状态成功持久化后，driver 才交付 `ProposalResult`。
3. `SCAPOUT!` version 1 对裁决单独封装，限制为 512 bytes；包含实际应用位置和校验摘要，不复制完整 SQL 结果。这个 codec 本身不证明共识；调用者必须从对应的可信 tracked attempt 接收它。已有 command、cell、SQLite 物理格式不因此升级。
4. runtime 提供 `Input::ProposeTracked` / `Answer::Applied` 和有界等待表。等待者数量、命令/结果内存与输出都受限；过期或取消只撤销等待，不撤销已进入 Raft 的命令。旧 boot、不同 attempt、迟到回执和 snapshot 安装均不能伪造本请求结果。同步 I/O 无法强制中断，资源直到实际持有者释放才归还。
5. 新 `scap-cell-client` 实现可信 `Client`、`CellPort`、真实 `RuntimePort` 和 native `CommitGate`。完整固定 replica identity 在构造及每次 I/O 前核对，read 必须将新 ReadIndex 与同一 Store view 的 actual applied term/index 绑定。事务 preflight 同时要求当前 READ、WRITE、owner 和前序 revision；不能把位掩码的“任意权限”误用为“全部权限”。
6. 每个 `Gate::begin` 返回独占 RAII invocation，绑定本次 Admission、原始绝对 deadline、取消和零摘要 ticket。一次 invocation 最多完成一个 lookup 和一个 proposal，不允许覆盖活跃请求或沿用上次权限。`Accepted` 才允许本次页面发布；`AlreadyCommitted` 必须取回当前权限下原 receipt/result，丢弃新暂存；异常或绑定不明为 UNKNOWN。
7. 新 `scap-sql-worker` 正式装配 `ClaimOwner → fresh view → Image::recover → 新目录 native writer → ActivateOwner → fresh authority check`。owner token、恢复 revision/hash 和当前权限全部匹配才返回 writer。任何步骤失败都不会交付可服务 writer；已创建的引擎随错误关闭。每次执行失败、历史回放或 deadline 后完成都退休该 writer，已知提交保留 receipt。
8. SQLite 对象及 gate 保持 `!Send/!Sync`，必须在专用 SQL 线程构建、调用、销毁。cell runtime 在另一个专用线程推进；gate 不自己 tick/pump Raft，也不阻塞 Tokio 网络线程。入口仍为可信 Rust API，暂不增加外部业务 RPC 或 SDK。

## 取舍与边界

该实现把本地 native SQL 和固定成员 mTLS 共识链路连接起来，但没有新增故障检测、自动路由或 leader 之外的业务请求转发。调用方选择当前 leader 的固定 Handle，明确调用恢复入口；恢复失败后不能悄悄改用旧本地文件。完整自动接管需要后续控制面、worker admission 队列、服务入口和调度协议。

预检与提交之间仍可能发生 owner/auth 变化；预检只是减少无效 SQL 执行，最终接受权始终属于有序 cell 状态机。新 leader 可以合法提交旧 term 的 Entry；结果位置用该 Entry 的 term/index，不要求它等于当前 leader term。

快照可以包含已经接受的请求，但不提供旧进程的 volatile waiter 结果。重启后用新的 Safe ReadIndex 查询持久历史；Lookup 未找到不是确定未提交，需要确定终态时提交有序 `ResolveOrCancel`。没有内部无限重试或 UNKNOWN SQL 重执行。

本阶段继续使用完整有界镜像和完整接受历史。SQL transaction API 中 SELECT 也记录一次 quorum 结果，尚无独立 ReadIndex-only SQL 读接口。Hrana/Node SDK、凭证验证、动态成员、多 cell、S3 生命周期、spill/大事务、生产性能与自动接管仍有独立门禁。

## 验证

新增代码全部进入第一方 unit line/function/region/branch 分母。窄端口测试覆盖裁决关联、单次身份、取消、资源约束、恢复阶段和 native/Runtime 委托；不能用真实集群 profile 补齐。

[SQLite/network 实验](../../experiments/sqlite-network/README.md)独立运行三个 OS 进程、各自 RocksDB、真实 mTLS/TCP 故障代理和正式 SQLite writer，验证真实 RETURNING/DDL 去重、owner/auth fence、quorum 丢失、迟到 Accepted、提交后发布前 SIGKILL、跨进程物理恢复、snapshot 和整组重启。夹具只配置输入、调度故障和观察结果，没有另一套生产 gate 或恢复算法。

进一步引入外部请求转发、自动 owner 调度、异步 SQL、SDK 重试、增量恢复或修改裁决/内存格式时，必须重新评审本记录的身份、次序与故障合同。
