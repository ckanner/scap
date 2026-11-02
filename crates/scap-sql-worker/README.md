# scap-sql-worker

线程内的正式 SQLite owner 恢复和执行装配，不创建外部 SQL 服务或后台调度器。

`Writer::recover` 依次执行新 scope 读、tracked ClaimOwner、新 ReadIndex、物理 Image 恢复、NativeFactory 新目录创建、tracked ActivateOwner、最后的新权限/owner/head 校验。整条路径沿用同一个 deadline，任一步失败都不交付可服务 writer。`EngineFactory` 只隔离 native 文件系统创建效果；默认实现委托正式 `SqliteWriter::create_new`。

每次 `Writer::execute` 接收新的 `RequestContext` 和稳定业务 request ID，为当前本地 head 构造完整 ticket，并在 invocation 生命周期内调用正式 native writer。错误或历史回放后停止 writer；已经提交但不能按时完成响应时保留 receipt，禁止当作回滚重试。

对象为 `!Send/!Sync`，应在单独 SQL 线程构建、使用和销毁。调用方仍负责有界 worker admission、故障检测、leader 路由、唯一 worker start ID 和新目录分配。这个入口不等于已经实现自动跨节点接管。

具体合同见 [SQLite 网络设计](../../docs/engineering/sqlite-network.md)；独立真实故障见 [sqlite-network](../../experiments/sqlite-network/README.md)。
