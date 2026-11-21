# SQLite on S3：主线复核、参数绑定优化与剩余工作

日期：2026-11-20（纽约）。本轮直接读取远端 main、最近 PR、Actions job 状态和正式
源码，不以旧会话进度推断当前完成情况。代码改动及接续文档在
[PR #67](https://github.com/ckanner/scap/pull/67)，首个远端提交为
[`33c1f789`](https://github.com/ckanner/scap/commit/33c1f78991637bcceac3880b0556d11047484382)。

## 1. 已经提交并合入的基线

主线是 [`b9d736ba`](https://github.com/ckanner/scap/commit/b9d736ba563b615004d35204e970ca5895ad618c)，
完整 tree 为 `8c1a7b2fc0d584c1247513561b6ce9ddf9fb08f3`。

| PR | 远端状态 | 已交付范围 |
| --- | --- | --- |
| [#65](https://github.com/ckanner/scap/pull/65) | 已合入 `02476c8` | owner/controller、S1/S2、永久启动身份及有界 S3 连接复用 |
| [#66](https://github.com/ckanner/scap/pull/66) | 已合入 `b9d736ba` | 同库独立读池、受信动态 fleet、内核资源准入和四项实际合同 |
| [#60](https://github.com/ckanner/scap/pull/60) | 已关闭，未合并 | Manifest GET 省略候选归档；保留普通精确 GET，不宣称历史吞吐回退已归因 |

本轮逐项重新读取 main 的以下六个 run 及其 jobs：全部 `completed/success`，
共 24 个 jobs，均为 attempt 1。它们认证既有主线，不认证 #67 的新代码。

| 工作流 | Jobs | 原始 run |
| --- | ---: | --- |
| Repository checks | 1 | [44268903583](https://github.com/ckanner/scap/actions/runs/44268903583) |
| Concurrent reads, fleet reload and kernel resource contracts | 4 | [44268903524](https://github.com/ckanner/scap/actions/runs/44268903524) |
| Node codec exact unit coverage | 1 | [44268903683](https://github.com/ckanner/scap/actions/runs/44268903683) |
| Node SDK exact unit coverage and HTTP contracts | 1 | [44268903502](https://github.com/ckanner/scap/actions/runs/44268903502) |
| Owner, snapshot, restore and worker identity contracts | 9 | [44268903529](https://github.com/ckanner/scap/actions/runs/44268903529) |
| Object-native quality and independent evidence | 8 | [44268903542](https://github.com/ckanner/scap/actions/runs/44268903542) |

此前 #66 的 911 项单位、77 个 Rust 文件四维精确覆盖及其实际历史继续归属于
[原交付记录](sqlite-s3-scale-validation-2026-11-18.md)和 PR。不会把当前代码、旧
coverage profile 与不同时间的实际历史拼接成一个新的完整通过结论。

## 2. 针对用户关切的代码审查

本轮分别审读 native 存储/提交层与服务调度/资源层，再交叉审查参数绑定变更。
在下表所列实现和受信部署前提内，没有确认新的 NFS/WAL 或发布顺序阻断缺陷。
这是代码审查结论，不等于执行了真实网络挂载或 AWS 故障实验。

| 问题 | 代码中的处理 | 必须保留的边界 |
| --- | --- | --- |
| NFS/EFS/FUSE 上活动文件 | 实际目录描述符文件系统允许列表；父目录与新私有目录分别准入；全部临时回退路径也检查 | overlay 底层、准入后的特权 mount/环境/VFS 变更由受信部署器约束 |
| 同一 WAL 被不同进程写 | 每份镜像一个线程专属连接；reader 使用不同完整文件；独占创建且不复用 sidecar | SQLite 服务当前仅 Linux；没有跨主机共享 WAL |
| 旧 owner 迟到提交 | 原 HEAD body/ETag 与 owner epoch；接管、撤权、取消和提交在同一 HEAD 排序；启动 ID 永不复用 | 仍需目标对象存储真正满足条件写和读一致性合同 |
| S3 已写但回执丢失 | 保留原请求身份，lookup/cancel 查证；UNKNOWN 不自动重跑 SQL | 数据持久存在与当前可访问性是两个条件，S3 故障时新强读/写失败关闭 |
| 并行读与资源归还 | 可选固定 query worker、独立镜像、当前授权、SQL 前最多一次 stale 重建；超时不提前归还仍占用的资源 | 读池增大完整镜像预算，未提供 lazy VFS 或同库并行 writer |
| 热点写与长尾多租户 | 每库 writer actor 串行，跨库有界并行；有排队、租户预算、控制预留和背压 | 单库写吞吐不会因增加 pod 自动提高；没有独立事务 group commit |
| 内存与磁盘 | 可选 cgroup v2/CPU/tmpfs 实际准入；`--check-config` 在占用身份和监听之前执行 | 整组资源边界不是每租户硬隔离，普通文件系统项目配额不在此合同内 |
| 快照、恢复与 GC | HEAD6/7 回收、S1 retained roots、S2 独立新 Scope 已合入 | 任意时间 PITR、长期存储增长/成本仍需独立工作 |

实现入口：[私有镜像](../../crates/scap-object-sqlite/src/file.rs)、
[文件系统与临时目录](../../crates/scap-object-sqlite/src/storage.rs)、
[提交 gate](../../crates/scap-object-sqlite/src/gate.rs)、
[权威协议](../../crates/scap-object/src/lib.rs)、
[调度器](../../crates/scap-service/src/scheduler.rs)、
[执行器](../../crates/scap-service/src/engine.rs)、
[资源准入](../../crates/scap-service/src/resource_envelope.rs)。

## 3. 本轮代码变更：减少参数绑定的中间副本

原 `sql::native_value` 为 Text/BLOB 克隆一个拥有数据的 Rust `Value`，然后固定
rusqlite 在 native bind 时再把该参数复制到 SQLite。旧迭代器逐参数惰性消费，
并不是同时创建整个参数列表的第二份副本。

现在适配器返回 `ToSqlOutput::Borrowed(ValueRef)`，借用原请求已拥有的参数，
直到同步 bind 完成。每个 Text/BLOB 少一次中间 Rust 分配与 payload 复制；SQLite
取得其必要的独立副本，原 SQL、结果、类型、权限、期限和提交协议保持不变。
这不是端到端零拷贝，也没有据此推导 TPS 或 p99 的提升比例。

两轮独立源码审查核对了固定 libSQL revision
`d8bc862d20bedc72945a1da27c8b7045414c0261` 的绑定行为：

- [`ToSqlOutput::ToSql`](https://github.com/tursodatabase/libsql/blob/d8bc862d20bedc72945a1da27c8b7045414c0261/vendored/rusqlite/src/types/to_sql.rs)
  保留借用值，不增加 payload 克隆。
- [`Statement::bind_parameter`](https://github.com/tursodatabase/libsql/blob/d8bc862d20bedc72945a1da27c8b7045414c0261/vendored/rusqlite/src/statement.rs)
  对非空 BLOB 使用 `SQLITE_TRANSIENT`，空 BLOB 仍为 `zeroblob(0)`。
- [`str_for_sqlite`](https://github.com/tursodatabase/libsql/blob/d8bc862d20bedc72945a1da27c8b7045414c0261/vendored/rusqlite/src/lib.rs)
  对非空 Text 使用 `SQLITE_TRANSIENT`，空 Text 使用永久静态空串，仍区别于 NULL。

新增三项[回归](../../crates/scap-object-sqlite/src/parameter_tests.rs)：原参数缓冲区确实
被借用；绑定后覆盖并销毁输入仍读取原值；正式 writer 的 RETURNING、持久原结果和
私有镜像恢复在请求销毁后仍完全一致。覆盖五种类型、空 Text/BLOB、Unicode 和内嵌 NUL。

### 本页冻结时的本轮验证台账

| 门禁 | 当前结果 |
| --- | --- |
| 两轮源码审查、固定上游绑定语义 | 通过；没有已确认阻断项 |
| Rust 格式、diff whitespace、严格 Clippy | 通过；stable 1.90.0 workspace/all-targets/all-features，`-D warnings` |
| 完整 stable Rust 单元 | 914/914 通过，0 failed/ignored；487 core、84 native、46 store、259 service、1 binary、37 SQL；包含三个新增参数回归 |
| nightly 单元及逐文件四维精确覆盖 | nightly-2025-09-18 的 914/914 单位通过；77 个生产文件全部具有正分母且精确 100%，没有混入集成 profile；首次清单遗漏及修正见下文 |
| Node SDK 基线单元及 V8 精确计数 | 182/182 通过，22 模块精确计数及检查器负控通过；SDK 源未改；本地 Node 24.22.3，与固定 CI Node 22.16.0 分开记录 |
| 仓库与工具检查 | 76 项 tooling 单元通过；818 个文本文件、872 个本地链接及设计合同检查通过 |
| 本轮远端完整 CI、真实 native/HTTP/S3 合同 | 本页冻结时 IN_PROGRESS；#67 的首个代码提交已触发工作流，清单/文档提交后的精确 head 单独判定；最终结论由 PR 记录 |
| 真实 AWS、NFS/EFS/FUSE 挂载、生产负载/SLO | NOT_RUN；未创建云资源，也未声称本地兼容端点等价 |

本轮 fresh unit-only 原始计数：lines **16,357/16,357**、functions **1,452/1,452**、
regions **25,170/25,170**、branches **3,374/3,374**；全部 77 个生产文件各自通过，
这些数字来自本次 profile，而不是复制 #66 的旧报告。参数适配改动没有增加生产文件。

首次严格 checker 退出 1：新增的纯测试模块 `parameter_tests.rs` 漏登
`contracts/coverage-policy.json` 的逐文件 `rust_test_sources`，因而被 fail-closed
检查器当作生产文件，其断言失败分支没有被执行。修正只登记这个通过 `#[cfg(test)]`
测试模块引入的纯测试文件；没有降低 100% 要求、改动 checker、排除任何生产代码或
加入通配规则。实际生产适配器 `sql.rs` 始终在分母内，四项指标全部命中。
Rust/test 源码与原 profile 未变化，修正分类后重新运行同一严格 checker 成功；
首次失败日志保留，远端最终候选仍重新采集自己的完整结果。

本地首个 commit `6defe8e` 与远端代码提交 `33c1f789` 的完整 tree 均为
`4fb2d81cec266eec6fc7a4404f1759df96109548`。后续本轮清单/文档提交不修改生产或
Rust 测试源码；最终远端状态以 [PR #67](https://github.com/ckanner/scap/pull/67) 的
追加验证记录为准。所需门禁未完成时保持 Draft；“已提交”不表示“已合并”或
“生产验收完成”。

## 4. 文档与后续设计

修正 README、交付计划、安全/吞吐和执行隔离文档的过时“未实现”表述，明确 #65/#66
已经交付的 S2、永久身份、读池、动态 fleet 和内核资源合同。旧日期的原报告保持不变。

[Turso 接续设计](../architecture/turso-adoption-next.md)区分四项独立工作：

1. 同库独立事务 group commit：逐请求结果和顺序保持独立，共享一次安全发布；需改造
   native 提交挂点、批次限额、逐事务失败及取消竞争。现有一次事务多条 SQL 不等价。
2. 跨库 WAL 聚合：共享上传对象但保持各库 HEAD 独立；需解决不可变 extent 定位、共享
   对象生命周期与 GC，不能凭 S3 单 key CAS 推导跨库事务。
3. lazy VFS：按已授权的固定根加载并验证页面，约束缓存和 I/O，避免不同快照页面混读。
4. PITR/新 MVCC：前者需要连续历史和时间选择，后者涉及执行引擎与冲突语义，分别验收。

这些后续设计不标为已实现。真实 AWS/IAM/故障域、长期 GC 成本、全局 fleet 共识和
自动扩缩容仍在[交付计划](sqlite-s3-delivery-plan.md)的独立出口中。
