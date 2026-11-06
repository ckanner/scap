# ADR-0020：按 greenfield 重新设计 S3 原生提交权威

- 日期：2026-11-05。
- 状态：**目标架构已合入；greenfield 范围已由用户明确；首个单库实现候选见 [ADR-0021](0021-object-native-runtime.md)，完整目标尚未验收**。逻辑协议的研究模型见 [N0 工作](../engineering/object-authority-n0.md)，不等于整个 N0 或真实对象合同通过。
- 完整方案：[S3 权威持久化与可丢弃计算](<../architecture/object-storage-native-proposal.md>)。
- 历史背景：[ADR-0002](https://github.com/ckanner/scap/blob/4cd99eb3ce404dfa26a8df2536d881f078c9c809/docs/adr/0002-shared-quorum-cells.md)、[ADR-0003](https://github.com/ckanner/scap/blob/4cd99eb3ce404dfa26a8df2536d881f078c9c809/docs/adr/0003-object-storage-and-cold-lifecycle.md)、[ADR-0011](https://github.com/ckanner/scap/blob/4cd99eb3ce404dfa26a8df2536d881f078c9c809/docs/adr/0011-bounded-native-sqlite-adapter.md)、[ADR-0019](https://github.com/ckanner/scap/blob/4cd99eb3ce404dfa26a8df2536d881f078c9c809/docs/adr/0019-explicit-request-result-retirement.md)。

本 ADR 的旧实现事实以 2026-11-05 的 PR #16 文档提交为基准；下文所称原型及其代码属于该历史背景。当前实现范围与限制以 [ADR-0021](0021-object-native-runtime.md)及[对象运行时](../engineering/object-runtime.md)为准，不能将实现候选视为目标架构全部验收。

## 1. 范围变更

用户明确说明现有原型尚未投入使用，没有存量业务；允许完全推翻当前实现，按长期有效的方案设计。因此：

- **不做旧方案迁移、回退、旧数据格式、旧 SDK 或旧 API 兼容。**
- 不设计 Raft/Object 双后端，也不要求保留现有 Raft/RocksDB 组件。
- 现有代码、测试与文档是经验和事实来源，不是新目标的接口约束；可选择性复用或删除重写。
- 新系统仍须具有备份、PITR、故障恢复、长期格式演进和严格验证；它们不是旧系统兼容工作。

## 2. 目标架构

S3 保存全部数据库及正确性权威，计算节点上的 SQLite 文件、临时日志与缓存可全部丢失。大量独立用户／工作区数据库共享按需计算，不为每库常驻持久节点。

候选协议：先持久化不可变物理变更、结果和恢复依赖，再通过**每库 HEAD 的条件替换**原子发布。所有权、权限、请求去重／取消／退休、维护与删除在同一个单库权威序列内排序。

初版采用一个区域的 AWS S3 Standard。Express One Zone 如承载唯一近期已确认日志，会改变 AZ 故障合同，须独立设计；其他 S3-compatible 实现逐一验证。HEAD/CAS 是拟验证的 SCAP 协议，不声称是 Turso Cloud 的闭源实现。

## 3. 现有实现的处理

PR #16 提交时的源码采用三副本 Raft/RocksDB 提交、S3 冷归档；当时的文档合并没有改变运行时。**目标架构将取代该方向，而不是增加可选后端。**正式重写可重新组织 workspace、API、SDK、回执和对象格式，删除 cell/term/index 依赖。

原生 SQLite precommit gate、物理页面捕获、明确 UNKNOWN 与原结果查证是可复用经验，但不得为了保留旧类型而扭曲新接口。不将 RocksDB 的 AtomicBackend 简单替换为 S3 PUT，也不复制旧原型的 whole-cell 状态布局。

PR #16 只提交方案与关联文档，没有实现对象运行时。实现 PR 须同步重定义机器设计清单、工程约束、故障/性能合同及验证脚本，建立新的可执行门禁；旧 quorum 测试不能作为对象协议证据，覆盖率和独立验证要求不降低。

## 4. 必须成立的安全属性

1. 全部依赖对象已持久化且 HEAD 发布成功后，才能确认事务；本地 COMMIT、单独上传、路由或 lease 都不是提交权威。
2. 旧 writer、旧请求、删除和恢复身份由同一库的权威转换隔离，禁止 ABA 和旧状态复活。
3. CAS 冲突不允许给旧页面差分换新 ETag；UNKNOWN 不换请求身份、不盲重跑 SQL。
4. 数据与原请求结果由同次 HEAD 更新发布；结果保留有明确合同，关闭身份空间的屏障永久防止旧操作重新接受。
5. 全部计算和本地盘丢失后，仅凭 S3 与必要部署配置可恢复确认集及控制状态。
6. GC 保护当前、历史、读者、恢复和未发布操作；未证明时原型禁用并限制容量，生产必须验证长期回收。

## 5. 代价与替代路线

S3 从后台依赖变成在线提交/强读依赖，数据库可用性受对象服务、IAM/KMS 和共享入口影响。计算仍有费用；请求、恢复、保留、缓存、观测和运营都计入总成本。每用户独立库不消除共享故障域。

成熟托管 SQLite、共享托管关系数据库、现有原型和异步备份可作为实验对照，但不是必须支持的运行时后端。Turso 可作为对象存储与多租户合批的参考，不提供本文协议的正确性或成本证明。

## 6. 实施与评审门禁

按完整方案的 **N0–N4** 从零推进：协议/模型 → 小规模真实 S3 提交 → 多库平台 → 可持续存储及 GC/PITR → 容量、故障域、长运行与首发验收。不存在旧库迁移阶段。

新请求留存合同、格式、数值性能目标和客户端责任在实施前冻结；旧 128 请求窗口及管理员轮转不是新产品的操作要求。全部正式代码进入严格单元覆盖门禁，模型、真实依赖、故障及性能证据独立报告。

PR #16 提交时没有 object 运行时、真实事务/GC 验收或成本收益证明。当前单库实现候选及其独立验证范围见 [ADR-0021](0021-object-native-runtime.md)与[验证规范](../engineering/validation.md)；完整 N1、GC 与成本收益仍须各自验收。无法证明关键协议或成本不成立时停止或重评，不通过异步 ACK、陈旧读或删除失败样本宣称成功。
