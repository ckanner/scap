# SQLite on S3：当前状态、目标与接续交付

更新：2026-11-11（America/New_York）。这是按当前代码与验收证据维护的交付计划；
具体运行结果仍以[组合验收](sqlite-s3-integration-validation.md)中的冻结提交和原始记录为准。
主线基准 `fab8ca0`，组合 [PR #59](https://github.com/ckanner/scap/pull/59)
当前检查点 `3b1d50c`。检查点之后的文档提交不改变已有运行时二进制的真实构建来源。

## 1. 要交付的产品

目标是面向大量独立租户／Agent 的 SQLite 服务：应用使用 SQL 与明确的请求身份，
S3 中的 HEAD 和不可变对象保存唯一持久权威，计算实例和本地镜像可以全部丢失。
多实例通过同一 HEAD 的条件发布排序；每个数据库当前仍由一个 actor 串行执行。

验收目标按行为定义，不能把“SQLite on S3”当作已满足的性能或运维承诺：

| 目标 | 必须保持的可观察结果 | 当前证据与缺口 |
| --- | --- | --- |
| 持久提交 | ACK 前数据、原结果、请求身份与屏障已共同发布；断线后不重新执行 SQL | native gate 与原结果合同已有实现及本地证据；本组合完整回归正在补齐 |
| 安全接管 | 旧实例迟到候选不能覆盖新 HEAD；controller 不把权限、忙或配置错误当成死亡 | 持久 owner 协议、有限 controller 已实现；核心接管／重启实际通过，多 controller 和其余故障矩阵待补 |
| 无状态计算 | 清空全部计算和缓存后，从真实对象闭包恢复原数据与原结果 | 小库组合实际通过；本组合 1 GiB、完整发现／目录和资源合同待重新执行 |
| 明确保留与恢复 | 显式快照永久身份、完整 retained roots、释放与 GC 不误删；恢复生成全新数据库身份 | S1 专项实际通过；S2 新 Scope 恢复未实现，任意时间 PITR 另有协议 |
| 可控资源与成本 | 有界准入、期限、请求和输出预算；长期回收可观测；失败不提前归还仍被占用的资源 | 已有逻辑预算与 GC；持续过载、公平性、硬 RSS／磁盘和长期 metadata 增长尚未闭环 |
| 可用吞吐 | 预先冻结工作负载和后端，再报告成功率、排队、p95/p99、恢复和每事务成本 | 已有本地固定基线；单库热点写吞吐仍低，尚无生产容量结论 |

本地 SQLite 活动文件必须在准入后的私有本地文件系统内。S3 不挂载为 `.db/WAL/SHM`，
不同节点不共享这些活动文件；跨节点 fencing 依赖对象条件写。相关实现和官方依据见
[安全与吞吐](../architecture/sqlite-s3-safety-and-throughput.md)及
[部署要求](../operations/sqlite-storage-safety.md)。这消除了方案对网络文件锁的依赖，
没有消除本地 I/O 故障、错误部署或单库串行的边界。

## 2. 已完成、当前在做、尚未完成

当前代码已组合 HEAD8 owner plan、生产 controller 和 HEAD9 S1 retained snapshots。
新执行的 Rust stable/nightly 各 783 项单位、67 个生产文件四维精确覆盖、157 项 SDK
单位／21 模块精确覆盖、19 项 HTTP/TLS/CLI loopback，以及 owner、自动接管、S1 和
固定负载专项已有绑定源码的证据。数字表示这些具体门禁，不代表完整产品的完成率。

固定本地基线中，单库 C1 写 5.149 次／秒、单库 C4 写 2.822 次／秒、四库 C4 写
7.206 次／秒，每写约 18–20 个 S3 请求。它包含观察开销、样本有限，也没有同环境
旧候选对照。当前不能声称已经解决热点吞吐或给出生产 p99 承诺。

当前优先完成 PR #59 的必要组合验收，不先扩大它的产品格式范围。以下两类出口分别维护：

| 工作 | 是否阻断 #59 合入 | 交付判据 |
| --- | --- | --- |
| 新组合单位、精确覆盖、Node／类型、原二进制来源 | 是；本轮已完成的输入继续逐项核对 | 原构建 receipt 与实际生产输入相同；新夹具只报告自己的源码身份 |
| native／schema／retained results／生命周期／目录／发现／1 GiB | 是；正在重新执行 | 固定完整场景、原始 ACK／BLOB／对象账本和独立审计；失败不能被 summary 掩盖 |
| HTTP／隔离／资源／输出／GC transport／HEAD6／终态退休 | 是；正在重新执行 | 原实际入口、独立 oracle、指定负控与资源归属全部完成 |
| 多 controller 与剩余自动推进故障 | 是；需补充实际夹具 | 真实生产 controller 调用，所有 HTTP／S3 事件可重建；不能以手工 owner RPC 冒充自动推进 |
| S2 restore、任意时间 PITR | 否，#59 明确只交付 S1 | 后续独立候选，不能将未实现的 restore 字段提前开放 |
| 动态 fleet、worker 身份分配、硬资源隔离 | 否，保持现有固定 fleet 与部署身份前提 | 后续独立设计、实现和压力验收 |
| 真实 AWS、长运行成本、生产 SLO | 不作为本地 S1 有限交付已完成的声明；阻断相应生产承诺 | 目标后端／权限／故障域和负载先固定，再实际执行 |

维护者已授权完整本地验证作为合入依据。远端 CI 的失败和无法取得的日志仍原样记录，
不把本地结果改称远端 CI 通过，不修改分支保护。所需本地门禁缺失时保持 Draft；
门禁齐备后重新读取 PR head/main，用精确 head 合入并核对最终 tree。

## 3. 严格接续顺序

### 第一阶段：收口 owner、controller、S1 组合

先补齐上表的既有组合回归，并增加 controller 独立真实矩阵。该矩阵至少分开证明：

1. 相同 policy／同一 S 的多实例竞争和 first-winner；prepare 丢 ACK、无本地输入
   重启，以及 Missing 读取与迟到 immutable PUT 的相遇。
2. 不同 policy／creator 与人工 marker 的阻断；当前 authority、accepted 历史阶段、
   当前 HTTP 回执分别解释，不能仅信 CLI 的 active 报告。
3. Claimed 与 Cancelling 的重启收养，abort 前后旧 CAS 到达和 UNKNOWN 后的新一步。
4. 权限撤回、目标替换／误绑、429、S3 不可用和 wire 错误不会触发无条件接管。
5. 原 deadline、停机及 owned 资源归属；controller 全程不 execute，原业务仅用原
   lookup／cancel 查证，保留非确定 SQL 的原结果。

可复用低层 owner 真实合同的前提是注明其精确覆盖范围；模型、手工 owner 客户端、
生产 CLI 和服务资源合同互不代替。新增夹具先固定场景与负控，再提交冻结，实际执行
使用新的证据目录。任何产品缺陷另提交修复，并重跑受影响门禁。

### 第二阶段：S2，从一个保留点恢复到全新 Scope

[HEAD9 设计](../architecture/retained-snapshot-restore.md)的 S2 是一个完整协议切片，
不能只提供 copy 按钮，也不能先允许非 null 的 `restore_origin`。至少共同实现：

- 固定 source SnapshotRef 与 target creation recipe，永久 first-winner 身份和严格格式。
- 全部 Catalogue create／inspect／discovery／recovery／abort 消费者识别恢复阶段；
  普通 Empty 创建路径不能把 Copying 目标发布为 Ready。
- 有界后序遍历，自底向上重封装 Chunk／Node／Manifest；每个目标对象都属于新 Scope，
  逐个条件创建和回读。完整 native 校验之前不得形成 completion。
- CompletionRecord 固定已授权、独立完成的复制；没有它的重启需要重新验证源，
  有它的合法续进不再依赖已释放源 payload。保留最终源权限检查的明确时序边界。
- Name 与目标 HEAD 的永久取消屏障。迟到对象／completion 不能复活已取消目标；
  Ready 使用新 ACL、owner 准入、sequence 和空请求空间。
- 认证 HTTP／SDK、明确 resume 和 recovery admission；单次控制调用最多一个权威 CAS，
  长 copy 的源 GET、目标 PUT／readback、本地临时文件和总期限独立计账。

交付出口包含 source 撤权／释放／GC、同 target 双 resume、逐切点 UNKNOWN、全缓存
丢失、target abort 与迟到原请求，以及删除源全部 payload 后目标独立冷恢复。
未完成这些消费者之前保持 S1 的 `restore_origin = null` 拒绝边界。

### 第三阶段：资源与吞吐，先量化再改协议

先沿现有提交语义做可复现改进：固定逻辑事务和成功结果，拆分 actor 排队、native、
对象上传／回读、HEAD CAS 和响应等待；对比相同环境下单语句与已有 SQL batch。
独立报告事务数／秒与逻辑操作数／秒，不把批量更多语句写成独立事务吞吐提升。

随后根据账本选择减少重复读取／副本与对象往返，补持续开环过载、热点公平性、
冷启动风暴、资源归还和重复 GC 的实际合同。每项优化同时保留正确性回归和同环境
前后对照，不能省掉必要 readback 或延后 ACK 后才上传来换取表面吞吐。

group commit、lazy VFS、同库读池或 MVCC 引擎改变提交／可见性／恢复关系，必须独立
立项；现有跨库并发和短 SQL 事务不能宣称已经实现这些能力。Turso 的公开实现与
Cloud 路径只作设计参考，不能借用其基准作为 SCAP 实测。

### 第四阶段：目标后端与试运行出口

明确目标 S3 产品、IAM／KMS／版本与删除策略、区域／故障域、对象配额和成本口径；
执行实际条件写、并发、撤权、故障恢复和长运行。根据预先冻结的工作负载报告成功率、
p95/p99、恢复时间、对象请求数与存储增长，再判断非关键业务试运行条件。
没有 AWS 环境的项目保持 NOT_RUN；不以本地兼容端点或单 AZ 服务推导跨 AZ 保证。

## 4. 提交与证据维护

每个能独立审查的协议、产品、夹具或文档改动及时提交；运行前固定提交和源码清单。
原始失败保留在原目录，新候选使用新目录和完整场景，机器记录只摘录必要哈希、计数、
退出码与边界。生产变更重新构建并执行受影响精确覆盖和实际合同；纯夹具变更可以
在逐文件构建输入相同的前提下复用原二进制，但必须同时写明两份来源。

每次交付更新本页、[路线图](roadmap.md)和相关验收记录，明确哪些已经合入、哪些只是
候选、哪些已经实际验证。当前不以测试数量、设计文档长度或默认容量表示产品完成率。
