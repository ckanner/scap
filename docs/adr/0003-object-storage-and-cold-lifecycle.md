# ADR-0003：对象存储、归档发布与冷库

- 日期：2026-10-27
- 状态：设计基线；恢复链与 GC 待 G3 验证

## 背景

多数数据库长期空闲，需要降低热盘和计算占用。S3 适合承载不可变数据与历史，但不自动提供数据库提交、跨对象事务或写者管理。

## 决策

热提交依赖 cell durable quorum，S3 异步归档。快照和增量对象不可变，上传并校验后由 cell 发布 manifest；只有恢复证明成立才回收持久日志或对象。

首版采用完整本地数据库执行与完整恢复唤醒。关闭 worker 可以先保留 committed tail 在 cell；真正卸载持久热数据必须归档完成。只有完成态 DR checkpoint 才可用于丢失原集群后的独立灾难恢复。

区分 SQLite 单库快照与 cell 状态机快照。后者必须包含 membership、last-applied、全部数据库控制状态、去重、tombstone、seal，以及必要的数据或可靠引用。

## 代价

冷启动需要下载和重放；对象请求和历史保留有费用；S3 中断会阻塞冷恢复和归档，随后可能因日志空间不足而阻塞热写。必须有背压和可观测恢复水位。

## 替代方案与后续优化

Bottomless / Litestream 提供有价值的备份机制参考，但其普通异步上传不作为同步提交权威。按页远读、跨库对象打包和差分格式可在恢复正确性稳定后加入，不先引入额外回收复杂度。

## 重新评审条件

如果目标数据库体积使完整恢复延迟不满足实测需求，评估按页懒加载，并新增缓存版本、页校验、读屏障和恢复可用性设计。

参考：[存储生命周期](../architecture/storage-lifecycle.md)、[Bottomless](https://github.com/tursodatabase/libsql/blob/main/bottomless/README.md)、[Litestream](https://litestream.io/how-it-works/)。
