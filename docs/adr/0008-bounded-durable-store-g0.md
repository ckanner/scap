# ADR-0008：用有界持久状态镜像验证 Raft 存储与恢复

- 日期：2026-10-29
- 状态：G0 实现决策；验证结果以 [执行证据](../engineering/g0-evidence.md)为准
- 关联：[ADR-0006](0006-raft-rs-consensus-library.md)、[ADR-0007](0007-tikv-stack-and-rpc-boundaries.md)

## 背景

RPC 编码实验已证明固定 Raft 消息可以经过 Tonic 传输，但尚未证明日志、投票、应用状态或快照可从磁盘恢复。下一步需要把真实 `RawNode` 与同步存储连接，同时遵守第一方代码 100% 单元覆盖率、真实依赖契约独立报告的规则。

固定 raft-rs 的 `MemStorage` 是内存实现。其 snapshot 根据 commit 构造并假设这些记录已经应用，`commit_to` 还会设置 HardState.term，均不能直接作为本项目显式持久 applied 策略的实现。启动校验也必须在创建 RawNode 前完成。源码及顺序依据见 [Raft 接合契约](../engineering/raft-rs-integration.md)。

## 决策

1. 在正式 `crates/scap-raft-store` 中实现 `Store<B: AtomicBackend>`：持久编码、身份与恢复校验、日志替换、HardState、应用与快照原子发布，以及 `raft::Storage` 查询行为均计入第一方生产代码分母。
2. 把最后的原子同步 I/O 设为窄端口。单元测试控制成功、写入前失败、已经写入却返回错误等结果；真实 RocksDB 与 RawNode 在独立 `experiments/raft-store` 中验证相同端口。研究夹具目前不是产品后端或运行 driver，生产服务不得依赖它。
3. G0 使用有明确大小上限、格式版本和身份绑定的完整状态镜像，由后端以一个原子同步写发布。这个布局便于校验崩溃时只能恢复完整旧状态或完整新状态；暂不作为大 cell 的生产布局。
4. 显式区分 `create_new` 与 `open_existing`。固定 genesis checkpoint 的 index/term 为 1，并一起持久保存初始配置、HardState、applied 与空应用状态。遗失目录、未知内容或身份不匹配不能通过自动初始化绕过。
5. 只有真实同步成功才更新可供 Raft 查询的内存视图。写入错误使当前实例停止；即使磁盘可能已经写入，也只能重新打开、校验后恢复，不能在旧内存视图上继续运行。
6. 保持 `snapshot <= applied <= commit <= last_index`、连续日志和单 term 投票不反悔。LightReady 推进 commit 时保留当前 term/vote；应用状态、完整 ConfState 与 applied 在同一个原子边界发布。
7. `Storage::snapshot` 只返回已经发布的完整 checkpoint。checkpoint 与压缩基于持久 applied，不能根据 commit 猜测应用状态；未提交后缀不会被当成业务效果恢复。

## 代价与后续工作

每次持久修改重写完整镜像会带来写放大、序列化、校验和内存复制成本。明确限制 image、entry、日志数量和 application 大小；达到限制须拒绝，不能无限增长。checkpoint 把当前应用复制进 snapshot，仍可能保留当前应用和日志后缀，因此不保证缩小镜像，也可能触发总预算限制；失败必须保留旧镜像，不能声称总能靠压缩恢复容量。部署大规模 cell 前，需要实现增量键值或其他布局，并重新证明相同原子性和恢复合同。

应用状态在本阶段是调用方给出的不透明数据。store 保证它与日志应用位置的原子关系，不替代 SCAP 的 owner/auth、请求去重、数据库 heads 或 SQL 页面发布状态机。

RocksDB fixture 明确启用 WAL 和同步 WriteBatch。进程退出后重开可以验证对应恢复路径，不能代替断电、设备缓存、磁盘丢失、三进程 quorum 或跨 AZ 验证。生产 driver、RocksDB 装配、mTLS、SQL 接合、调度与性能仍分别受后续门禁约束。

精确 API、格式和测试范围见 [持久 store 契约](../engineering/durable-store.md)与 [真实存储实验](../../experiments/raft-store/README.md)。
