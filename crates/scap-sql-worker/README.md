# scap-sql-worker

线程内的正式 SQLite owner 恢复和执行装配，不创建外部 SQL 服务或后台调度器。

`Writer::recover` 依次执行新 scope 读、tracked ClaimOwner、新 ReadIndex、物理 Image 恢复、NativeFactory 新目录创建、tracked ActivateOwner、最后的新权限/owner/head 校验。整条路径沿用同一个 deadline，任一步失败都不交付可服务 writer。`EngineFactory` 只隔离 native 文件系统创建效果；默认实现委托正式 `SqliteWriter::create_new`。

每次 `Writer::execute` 接收新的 `RequestContext` 和稳定业务 request ID，为当前本地 head 构造完整 ticket，并在 invocation 生命周期内调用正式 native writer。错误或历史回放后停止 writer；已经提交但不能按时完成响应时保留 receipt，禁止当作回滚重试。

`Writer::query(context, statements)` 是独立只读接口，返回 `ReadCompleted { result, position, revision, commit_hash }`。每次调用取得新的 Safe ReadIndex，按同一视图验证 READ 权限、数据库身份和当前 active owner；只读主体不需要 WRITE 权限。随后以该视图的完整物理历史和精确 commit hash 重建校验镜像，完整比较本地 `Head` 的身份、revision 和 image digest，再进入单线程私有 SQLite `BEGIN DEFERRED` 快照。查询不提交 Raft proposal、不保存结果、不增长数据库 revision。

原生查询同时使用只读 authorizer 和 `sqlite3_stmt_readonly`；拒绝写入、事务控制、PRAGMA、附加库、虚表和不受支持的函数。输入、VM 指令、结果行数和编码字节继续受限。原 deadline 和取消检查覆盖 BEGIN 之前、语句之间、VM 执行、COMMIT 与结果交付；时钟/检查回调失败或 panic 中断读取。所有结果完整缓冲，通过最终检查才返回；失败退役 writer，成功可以继续读写。原生引擎的 `SqliteWriter::query` 不单独授予访问权，对外服务必须使用这一已绑定权威的 worker 入口。

该版强读的物理校验开销为 O(保留历史)，没有将其描述为已达到低延迟目标。已取得合法读屏障的有限快照可以在随后发生 owner/auth 变更时完成；下一次调用必须取得新屏障。无 quorum、过期 owner、历史缺失或本地 head 不匹配时不开始新的强读。

对象为 `!Send/!Sync`，应在单独 SQL 线程构建、使用和销毁。调用方仍负责有界 worker admission、故障检测、leader 路由、唯一 worker start ID 和新目录分配。这个入口不等于已经实现自动跨节点接管。

具体合同见 [SQLite 网络设计](../../docs/engineering/sqlite-network.md)；独立真实故障见 [sqlite-network](../../experiments/sqlite-network/README.md)。
