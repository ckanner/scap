# scap-sql-worker

线程内的正式 SQLite owner 恢复和执行装配，不创建外部 SQL 服务或后台调度器。

`Writer::recover` 依次执行新 scope 读、tracked ClaimOwner、新 ReadIndex、物理 Image 恢复、NativeFactory 新目录创建、tracked ActivateOwner、最后的新权限/owner/head 校验。整条路径沿用同一个 deadline，任一步失败都不交付可服务 writer。`EngineFactory` 只隔离 native 文件系统创建效果；默认实现委托正式 `SqliteWriter::create_new`。

每次 `Writer::execute` 接收新的 `RequestContext` 和稳定业务 request ID，为当前本地 head 构造完整 ticket，并在 invocation 生命周期内调用正式 native writer。错误或历史回放后停止 writer；已经提交但不能按时完成响应时保留 receipt，禁止当作回滚重试。

请求原 `request_epoch` 始终随 context 进入 Gate，不能从后来的目录读取中刷新。Gate 经当前权限和新鲜视图确认请求已退休时，worker 明确返回 `Error::Rejected(Reject::Retired)`，包括预检查后发生轮转而由最终 cell apply 拒绝的情况；不会将该状态改写为 UNKNOWN 或重执行旧 SQL。退休只封闭请求身份，不能证明旧请求从未提交。独立强读继续按当前权限、owner 与物理 head 授权，不因请求世代变化失去读取能力。

`Writer::query(context, statements)` 是独立只读接口，返回 `ReadCompleted { result, position, revision, commit_hash }`。每次调用取得新的 Safe ReadIndex，按同一视图验证 READ 权限、数据库身份和当前 active owner；只读主体不需要 WRITE 权限。随后以该视图的恢复基座、有界物理尾部和精确 commit hash 重建校验镜像，完整比较本地 `Head` 的身份、revision 和 image digest，再进入单线程私有 SQLite `BEGIN DEFERRED` 快照。查询不提交 Raft proposal、不保存结果、不增长数据库 revision。

原生查询同时使用只读 authorizer 和 `sqlite3_stmt_readonly`；拒绝写入、事务控制、PRAGMA、附加库、虚表和不受支持的函数。输入、VM 指令、结果行数和编码字节继续受限。原 deadline 和取消检查覆盖 BEGIN 之前、语句之间、VM 执行、COMMIT 与结果交付；时钟/检查回调失败或 panic 中断读取。所有结果完整缓冲，通过最终检查才返回；失败退役 writer，成功可以继续读写。原生引擎的 `SqliteWriter::query` 不单独授予访问权，对外服务必须使用这一已绑定权威的 worker 入口。

恢复和强读调用同一正式 `Image::recover`：严格绑定权威位置、身份、revision、commit hash，先校验恢复基座的完整镜像和摘要，再重放其后的物理尾部。基座由 cell 在 Commit 或显式请求退休的候选状态中用同一物理算法构造；它不能由本地旧 SQLite 目录或独立 sidecar 取代。物理校验成本随完整镜像与保留尾部增长；未退休请求元数据、行政记录及世代屏障仍在整份状态中编码和校验，未据此宣称达到低延迟目标。已取得合法读屏障的有限快照可以在随后发生 owner/auth 变更时完成；下一次调用必须取得新屏障。无 quorum、过期 owner、恢复数据缺失或本地 head 不匹配时不开始新的强读。

对象为 `!Send/!Sync`，应在单独 SQL 线程构建、使用和销毁。调用方仍负责有界 worker admission、故障检测、leader 路由、唯一 worker start ID 和新目录分配。这个入口不等于已经实现自动跨节点接管。

具体合同见 [SQLite 网络设计](../../docs/engineering/sqlite-network.md)；独立真实故障见 [sqlite-network](../../experiments/sqlite-network/README.md)。
