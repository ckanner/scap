# scap-core

正式共享类型与纯物理图像算法。模块不访问网络、磁盘、SQL、对象存储或时钟，不把本地计算当成 cell 接受或 quorum 证明。

`CellIdentity`、`DatabaseIdentity`、`CommitTicket`、`CommitReceipt` 和 `PreparedWrite` 表达同一数据库世代内的物理提交身份。`physical` 提供固定 SCAPIMG v1 的 4096-byte 页面布局、受限页面批次、prepare/accepted、receipt 重放和 image digest 校验。

`physical::Snapshot` 仅包含完整 image bytes 和 `Head`。`Image::from_snapshot` 检查身份、limits、页面对齐、大小、SQLite header、revision 与摘要。一个合法 Snapshot 本身不授予任何读取或写入权限，也不能单独证明它覆盖了 quorum 提交；上层必须绑定原 source position、逻辑 commit hash 和当前授权。

状态机在同一持久应用中建立物理基线，engine 在新鲜授权视图中从基线与有限 tail 恢复；两者使用此处同一个算法，详见 [ADR-0017](../../docs/adr/0017-bounded-physical-history.md)。所有源码进入第一方精确单元覆盖率分母。真实 native SQLite 与网络故障测试独立于这些纯函数单元测试。
