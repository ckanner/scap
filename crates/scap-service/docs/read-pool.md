# 有界同库强读池

`admission.read_pool` 显式启用同一数据库的并行 `query`。已有配置省略该字段时保留
原来的单 actor 路径；启用会增加线程和私有镜像，所以不静默消耗部署资源。

```json
{
  "workers": 4,
  "active_per_tenant": 2,
  "active_per_database": 2
}
```

这三个字段都必填且非零，库上限不大于租户上限，租户上限不大于 worker 数。
writer actor、control worker 和 query worker 的总槽数不超过 255。

## 调度与资源

仅 `query` 使用读池；`execute`、`open` 和恢复继续按原 actor／恢复准入执行，
管理操作继续使用原 control 池。读池不可用返回 `UNAVAILABLE`，不会回落到写 actor
或重新发送 SQL。线程在所属线程中创建和销毁 `Engine`、SQLite 连接与完整私有镜像，
同一数据库的不同 reader 不共享 `.db`、WAL 或 SHM。

共享读队列按租户、库轮转；已达到活跃读额度的租户／库暂时跳过，其他队列继续。
排队使用已有 global／tenant／database 预算和 control 保留额度；HTTP intake、原始
绝对期限、输出预算及 recovery semaphore 都继续生效。活跃读额度独立于排队额度，
在请求过期、客户端断线后仍由正在运行的工作持有，直到执行与请求资源释放。
panic 展开先销毁 worker／native/cache，再释放当前请求的 intake/output 与活跃读额度。
当前 Job 由 worker owner 保留，HTTP 已断开也不提前归还实际工作的额度；最后一个 reader 退出后
排队请求失败，新的 query 拒绝。关闭会排空队列并 join 所有在跑的 reader。

每个 reader 的 `Engine` 操作后最多保留一个数据库镜像，页数受现有
`cache.pages_per_actor` 的保留预算约束。`workers × pages_per_actor` 是额外的
**操作后缓存保留上界**，不是磁盘峰值、SQLite heap 或进程 RSS 硬上限。冷恢复中的
临时镜像、解码、输出仍有各自原有预算；峰值物理资源需另用部署资源隔离保证。

## 强读时序

每次 `Session::query` 都重新 exact GET HEAD，并在本次 HEAD 上校验当前 READ 权限。
只有完整已验证私有镜像的根和 quota 与该 HEAD 相同时才运行用户 SQL。该快照选择
位于请求开始和响应之间，因此允许请求期间并发写、owner 交接或撤权：一次已经按
旧授权选定的读可线性化在这些并发操作之前。已在请求开始前完成的撤权会被新 GET
看到并拒绝；S3 不可用不会使用本地缓存继续提供强读。

已完整物化的私有镜像不再依赖 S3 中的旧 payload，所以运行中的只读事务不会因
后续 GC 删除旧对象而读取一半新、一半旧页面。仍在恢复中的镜像继续执行现有
generation／缺失／损坏判定；缺页不能补零或回退旧权威。

读池允许 **最多一次、严格在用户 SQL 之前**的 stale-cache 重建：

1. `Session::query` 的 `align()` 返回 `StaleSnapshot`；该检查先于用户 SQL。
2. 丢弃该 reader 的旧镜像，用同一个原始 deadline 和 recovery 准入创建全新镜像。
3. 再做新鲜授权的 `query`。若又发生根变化，直接返回错误。

SQLite 执行错误、GET 失败、结果限额、中断以及任何已经开始执行 SQL 的失败都不会
进入这个分支。写请求的原身份、UNKNOWN、原 HEAD CAS 和 ACK 顺序保持原合同。

## 能力边界与验收

该能力提供同库并行强读，以及私有读快照和写 actor 的并行执行。读池本身不实现
group commit；可以与独立可选的 `admission.group_commit` 写 actor 路径同时启用，
详见[独立事务组提交设计](../../../docs/architecture/independent-group-commit.md)。
两者都不增加同库并行 writer，也不实现共享 WAL reader、lazy VFS 或新 MVCC 引擎。

单元验证覆盖真正重叠的同库读、写／control 独立进展、tenant／database 活跃上限、
公平跳过、启动失败、panic 后资源析构、shutdown join、fresh HEAD、stale-cache
重建和错误不重试。真实 HTTP／SDK／签名 S3 合同见
[read-pool 实验](../../../experiments/read-pool/README.md)，与 unit profile 分开。
