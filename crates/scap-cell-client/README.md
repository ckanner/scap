# scap-cell-client

可信 Rust cell client、`RuntimePort` 与 SQLite `CommitGate`。所有路径核对固定 cluster/cell/incarnation/node，使用新 Safe ReadIndex 绑定同一 durable view，等待本次 tracked proposal 的持久业务裁决。

`Gate::begin` 为每次 SQL 调用绑定独立 Admission、原绝对 deadline、取消信号和 ticket，返回独占 RAII invocation。当前 READ+WRITE、owner 和前序校验在 SQL 前执行，最终 cell apply 再次裁决。新 Accepted 才允许新页面发布；历史结果保持原 receipt/result；未知结果不自动重试。

`Client::read` 仅供可信内部恢复和授权代码使用，不是租户数据接口。调用方负责真实凭证验证。Gate/Invocation 在专用 SQL 线程使用，真实 Runtime 在另一个线程推进，禁止在 gate 中泵 Raft。

正式模块纳入全部单元覆盖率指标；真实组合故障证据独立见 [sqlite-network](../../experiments/sqlite-network/README.md)。完整接口次序、资源与限制见 [SQLite 网络合同](../../docs/engineering/sqlite-network.md)及 [ADR-0013](../../docs/adr/0013-tracked-sqlite-network-commit.md)。
