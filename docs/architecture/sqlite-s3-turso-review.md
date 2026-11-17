# SQLite、S3 与 Turso：实现边界和可借鉴的机制

源码对照的冻结日期为 2026-11-09，SCAP 当时生产切片为 `3b93b9a`；
后续 `4456fc4`、`586e11b` 只修正测试或实际验收夹具。
本文是设计判断和源码比较，不是 Turso Cloud 内部实现审计，也不把上游性能数字
当作 SCAP 的 AWS、可用性或成本验收。

2026-11-17 重新核对官方 WAL、S3 和 Turso 文档：
[libSQL README](https://github.com/tursodatabase/libsql) 将自身单写者模型与新 Rust 引擎区分；
[Turso 0.8](https://turso.tech/blog/turso-0.8.0) 描述 MVCC、`BEGIN CONCURRENT` 和 group commit；
[Cloud 平台说明](https://turso.tech/blog/upcoming-changes-to-the-turso-platform-and-roadmap)
明确新的多租户服务端闭源，而开源引擎保留。下方固定 commit 的源码分析仍认证原切片，
不冒充最新 Cloud 服务端源码审计。SCAP 最新三份 PR、修复和边界见
[2026-11-17 review](../engineering/sqlite-s3-review-2026-11-17.md)。

## 1. 为什么本方案避开共享 NFS 文件锁

[SQLite 的网络存储说明](https://www.sqlite.org/useovernet.html)指出，网络文件系统
上的锁、缓存与同步语义可能不满足 SQLite 的要求；[WAL 说明](https://www.sqlite.org/wal.html)
要求共享 WAL 数据库的进程位于同一主机。问题不能概括为“SQLite 只能一个进程”，
也不能断言每个 NFS 实现都会立即损坏。实际部署应避免让跨节点 SQLite 实例共同
修改同一个 `.db/WAL/SHM`，尤其不能把共享卷当作跨节点数据库协调协议。

SCAP 采用私有本地 SQLite 镜像，通过网络 API 提供服务。跨节点顺序由固定 HEAD
的原 ETag 条件发布决定；不可变依赖先持久化并读回校验，再发布 HEAD，最后完成
native publication 才返回 SQL 成功。AWS 提供的是[单 key 条件写](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)，
多对象依赖关系、旧候选 fencing、UNKNOWN 查证和回收安全仍由数据库协议负责。

因此，本地文件锁只协调本地执行，不承担跨节点所有权。S3 不通过挂载后冒充 POSIX
文件系统；本地 cache/temp 路径继续遵守[存储准入规则](../operations/sqlite-storage-safety.md)。

## 2. “Turso 基于 S3”必须区分三个层次

本次固定的开源输入：

- Turso Rust 引擎：`4b374b409b3c1765cc6dc6594a86fffcc8c21df7`。
- libSQL：`a1d031cb602fedefbcf55c568e98e998a2274400`。
- Cloud 持久化：以 Turso 与 AWS 的公开架构文章为依据，不从开源备份组件反推整个 Cloud 协议。

| 组件 | 可验证的机制 | 对 SCAP 的意义 |
| --- | --- | --- |
| [libSQL bottomless README](https://github.com/tursodatabase/libsql/blob/a1d031cb602fedefbcf55c568e98e998a2274400/bottomless/README.md) | WAL 页持续异步上传，按 generation 保存快照与后续帧 | 可研究批量上传与恢复链；“本地 COMMIT 后备份”不满足 SCAP 的 S3 确认边界 |
| [Turso Cloud 持久化](https://turso.tech/blog/how-does-the-turso-cloud-keep-your-data-durable-and-safe)与 [AWS 架构说明](https://aws.amazon.com/blogs/storage/how-turso-built-a-transactional-database-using-amazon-s3-express-one-zone/) | WAL 写入 S3 Express 后确认，定期 checkpoint 到 S3；本地缓存服务读取 | 借鉴对象持久化后确认和日志合批；S3 Express One Zone 的产品与故障域不能替代 AWS Standard 的实测 |
| [Turso Rust 引擎](https://github.com/tursodatabase/turso/blob/4b374b409b3c1765cc6dc6594a86fffcc8c21df7/README.md)及 [MVCC 说明](https://github.com/tursodatabase/turso/blob/4b374b409b3c1765cc6dc6594a86fffcc8c21df7/docs/agent-guides/mvcc.md) | 不同连接可用 `BEGIN CONCURRENT`；共享行版本索引、逻辑日志、提交冲突检测与 snapshot isolation | 这是执行引擎的并发协议。当前 SCAP 使用 libSQL/native gate，不会因采用 S3 自动获得这套 MVCC 能力 |

上游 README 将 `.tshm` 多进程 WAL 协调列为实验特性；
[手册](https://github.com/tursodatabase/turso/blob/4b374b409b3c1765cc6dc6594a86fffcc8c21df7/docs/manual.md)
也明确其启用条件和限制。它不是“在任意共享网络卷上安全多主写”的证明。
不同页面对快速演进功能的成熟度描述可能不同；本项目不据此替换已经冻结的引擎或降低门禁。

## 3. 具体源码中可复用的边界

### 发布可见性前的持久化挂点

Turso 的 [`DurableStorage`](https://github.com/tursodatabase/turso/blob/4b374b409b3c1765cc6dc6594a86fffcc8c21df7/core/mvcc/persistent_storage/mod.rs)
把 `log_tx`、`sync`、提交后 offset 推进、丢弃未完成写入和 checkpoint 事件分开。
`on_log_write_complete` 允许额外持久化工作在事务发布可见之前完成。
这支持一个直接的设计判断：远端持久化必须参与引擎提交协议，不能只观察一个已经
成功返回的本地 COMMIT 再异步上传。该接口本身仍不定义 S3 owner、条件发布、GC 或 PITR。

SCAP 已有的 native CommitGate 承担这一类边界；后续每次改造都必须保留
“远端已提交但本地原生发布失败”的单独结果，保留原 receipt，并禁止自动执行原 SQL。
不能把本地失败解释成远端回滚。

### 批次与并发上限必须覆盖完整生命周期

[`bottomless/src/replicator.rs`](https://github.com/tursodatabase/libsql/blob/a1d031cb602fedefbcf55c568e98e998a2274400/bottomless/src/replicator.rs)
显式配置每批帧数、批次间隔和 S3 上传并发，并维护 generation 与帧进度。
同份固定源码也使用 unbounded channel 接收待上传工作，上传子任务的 JoinSet 在接收
循环结束后集中回收。因此不能只看到上传 semaphore 就推导整个队列、磁盘副本和
任务记录的内存都有上界。这是对该源码边界的推论，不是对 Turso Cloud 资源行为的结论。

SCAP 已按实际 Job、HTTP body 和最后一个 Bytes 持有者保存 intake lease；TCP 任务
完成但尚未 join 时仍计数。后续 response、对象 decode、native heap 和临时盘还必须
接入共享预算，不能用一个新 semaphore 代表整个进程资源已经有界。

### 分块、日志合批和按需读取分别验收

Cloud 的分块缓存与日志持久化说明了降低冷启动读取量和小事务请求开销的方向。
SCAP 当前已使用 128 KiB chunk/COW 数据树和分段请求索引，但冷恢复仍完整下载
所需闭包。新源 1 GiB 合同观察到冷恢复 8,338 次 GET、1,084,291,337 字节 GET，
这一结果直接说明按需恢复仍有工作，不能把“本地可丢弃”当作“冷启动已经很快”。
该观测属于[本地组合证据](../evidence/captured-context-local-2026-11-09.json)，不是 AWS 延迟样本。

跨事务或跨库合批还会改变等待时间、故障归属、确认分母、权限和回收闭包。
初版不依赖尚未实现的合批计算成本收益，也不为降低延迟而提前 ACK。

## 4. 当前选择和后续实现顺序

1. 保留单库串行提交和固定原 ETag；不同数据库通过有界 actor 并行。热点库不能仅靠增加 pod 获得多 writer 吞吐。
2. 以捕获的 ObjectContext 固定每次操作的后端与地址；在其上建立独立 storage generation、单调 head serial 和原条件 metadata-only CAS。
3. 独立验证世代 fence、原始字节复制、永久退休及 UNKNOWN 后再接入物理 GC。普通操作候选不写永久 pin，完整验证的旧快照可按原观察返回；不完整读取只有在 fresh 权威证明退休后才能 scoped 过期。保留快照根与当前复制计划分别保护，不能将真实 active 数据损坏当成过期。
4. 显式快照/PITR 恢复到新的数据库身份，重新建立权限和请求空间；不能复活旧 owner、ACL 或取消屏障。
5. 总体资源预算、自动协调与真实目标后端的数字 SLO 分别完成；逐阶段报告请求数、字节、延迟分布和完整失败分母。

详细实现标准仍由[主方案](object-storage-native-proposal.md)、[资源预算](resource-budgets.md)
和[回收方案](storage-reclamation-plan.md)约束。HEAD6 代际复制／GC 与 HEAD7 终态 seal
现已合入 main，HEAD9 S1 保留根位于 #59 候选；不能沿用 11 月 9 日“尚无产品 GC”
作为当前状态。lazy VFS、同库多 writer、group commit、S2／PITR 和生产 SLO 仍未交付。

## 5. 原生引擎补丁不能由存储架构代替

2026-11-09 另行核查了 SQLite 官方 WAL-reset 修复：当前 SCAP 固定 libSQL 与
核查时官方 main 均尚未包含。当前私有文件/单连接调用图排除了其多连接触发条件，
但这不等于引擎已修补。精确版本、源文件身份、官方补丁和保留 publication hooks
的升级门禁见[独立评估](sqlite-wal-reset-assessment.md)。未来引入同文件读池或
后台 checkpoint 前必须重新证明这条边界。
