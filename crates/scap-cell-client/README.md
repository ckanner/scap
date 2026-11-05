# scap-cell-client

可信 Rust cell client、`RuntimePort` 与 SQLite `CommitGate`。所有路径核对固定 cluster/cell/incarnation/node，使用新 Safe ReadIndex 绑定同一 durable view，等待本次 tracked proposal 的持久业务裁决。

`Gate::begin` 为每次 SQL 调用绑定独立 Admission、原绝对 deadline、取消信号和 ticket，返回独占 RAII invocation。当前 READ+WRITE、owner 和前序校验在 SQL 前执行，最终 cell apply 再次裁决。新 Accepted 才允许新页面发布；历史结果保持原 receipt/result；未知结果不自动重试。

历史结果通过 `CellState::lookup` 的保留请求记录查证，不从物理恢复尾部重建。物理前缀已经折叠为恢复基座，或物理数据已经归档并裁剪，都不改变尚未退休的原 receipt、结果、指纹和取消记录。回查仍需要当前权限，并核对精确的原 `CommitResult`；恢复基座不是绕过鉴权的新结果入口。

每次 invocation 同时保存原 `Admission.request_epoch`。已确认终态由客户端显式确认、管理员完成有序世代轮转后，旧 epoch 的 lookup 和提交均返回明确 `Retired`；不能把它当成 NotFound、未知结果或自动换新 epoch 重执行 SQL。Gate 在检查当前权限之后才暴露退休状态，且覆盖 lookup 前、lookup 与 proposal 之间、历史提交结果与再次查询之间的轮转竞态。这个拒绝不表示原 SQL 从未执行。

`Client::read` 仅供可信内部恢复和授权代码使用，不是租户数据接口。调用方负责真实凭证验证。Gate/Invocation 在专用 SQL 线程使用，真实 Runtime 在另一个线程推进，禁止在 gate 中泵 Raft。

`Client::activate_history` 与 `Client::activate_retention` 仅供可信服务目录循环发起格式升级，不属于租户 command 或公开 HTTP 管理面。两者使用固定 bootstrap administrator 的独立内部条目，核对本次 tracked proposal 的 cell、term/index 和持久结果，再在同一原 deadline 内取得新的 Safe ReadIndex。前者要求 phase 至少为 3，后者要求 phase 4，且均不得早于对应条目。不能用物理历史激活的结果确认请求退休已激活。未知结果、拒绝、错误绑定或确认读取失败都不能开启服务；目录下轮先查询持久阶段，已激活时不重发升级条目。

正式模块纳入全部单元覆盖率指标；真实组合故障证据独立见 [sqlite-network](../../experiments/sqlite-network/README.md)。完整接口次序、资源与限制见 [SQLite 网络合同](../../docs/engineering/sqlite-network.md)及 [ADR-0013](../../docs/adr/0013-tracked-sqlite-network-commit.md)。
