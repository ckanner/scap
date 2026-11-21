# 同库独立事务 group commit

更新：2026-11-20（America/New_York）。本实现承接
[Turso 接续设计](turso-adoption-next.md)，基于已合入 #67 的 `68246fd6`。
实现、单位、实际服务合同与目标后端性能分别记录，完整验收状态见
[本轮验证](../engineering/group-commit-validation-2026-11-20.md)。

## 1. 交付目标和范围

同一数据库已经排队的多个 `execute` 可以共用一次原 HEAD 的条件发布。每个请求仍有
独立 SQL 事务、原输入、原结果、请求身份、sequence、revision 和 receipt。后一事务
可以读取前一成功事务的私有暂存效果；请求之间不共享失败或回滚的 SQL 事务边界。
默认关闭，只收集已入队的请求，不为等待凑批增加计时器。

实现保留单库一个 writer、私有本地 SQLite 镜像和对象存储唯一持久权威。不同库可以
并行，同库 reader pool 可以独立读取已发布快照；组内 SQL 仍顺序执行，没有引入
并行写者、共享网络文件、跨库原子事务或 MVCC 引擎。显式 SQL batch 仍是一个请求
中的多条语句、一个事务；不能按语句数统计成独立事务数。

| 层 | 代码入口 | 职责 |
| --- | --- | --- |
| Native | `crates/scap-object-sqlite/src/group.rs`、`gate.rs`、`sql.rs` | 真实逐成员 BEGIN/COMMIT，私有页增量捕获、受检回滚和最终 checkpoint |
| 权威协议 | `crates/scap-object/src/group.rs`、`head_publication.rs` | fresh-only 资格、同一原 HEAD/ObjectContext、每成员结果和根、受限多步发布 |
| 服务 | `crates/scap-service/src/group.rs`、`scheduler/group.rs`、`engine/group.rs` | 显式配置、有界队列组批、实际工作生命周期、逐请求输出 |
| 客户端 | 现有 `Client.prepare/save/execute/lookup/cancel` | HTTP/SDK wire 不增加批次请求；保留原请求身份，不新增自动 SQL 重放 |

## 2. 配置和调度

在现有 `admission` 中显式加入：

```json
{
  "group_commit": {
    "version": 1,
    "max_members": 4,
    "max_input_bytes": 65536,
    "max_changed_pages": 2048,
    "max_result_bytes": 1048576
  }
}
```

这是实际正确性合同采用的有限配置，不是生产推荐值或 SLO。字段全部必填；省略整个
`group_commit` 或设置为 `null` 保留单请求执行。`max_members` 范围 2–64，且不得超过
`queued_per_database - reserved_controls`。输入上限不超过 64 MiB，结果上限不超过
持久格式的 64 MiB；变化页必须为正且在 SQLite 页号范围内。core 还将三个聚合预算
与该数据库当前 `Options` 取更小值。配置在领取永久 worker 身份和启动线程之前校验。

writer actor 仅从普通队列头取连续的 `Execute`。完整五元 Scope、完整认证 Principal
必须相等；不能只比较 HEAD 路径或 principal 数字。遇到 Query/Create/恢复操作、优先
工作、不同身份、过期或已断开的请求，或可预先计算的成员数/输入上限，立即结束收集。
变化页和结果字节由 native 在执行阶段累计检查。没有新计时器，
低负载队列仍可直接执行单请求；已有 priority 公平性和 control 保留额度继续生效。

组的总期限是成员中最早的原绝对 deadline，再受既有 Options 截止时间约束。排队、
恢复、SQL、对象 I/O、checkpoint 和输出不会获得新的计时预算。较早截止的成员可能
使整个尚未发布的组失败；这是显式开启组提交时需要评估的延迟耦合。

## 3. 在 SQL 之前确认资格

core 使用一次 fresh exact GET 得到原 HEAD body/ETag，校验当前 READ/WRITE 权限、
owner、待处理计划、生命周期、quota、请求窗口和 Session 对齐。一次尝试只持有一个
`ObjectContext`；任何依赖故障都不能通过新建上下文或更换 ETag 继续旧候选。

首版组只接受同主体、当前 epoch、完整指纹正确且互不重复的**全新请求**。存在已提交、
已取消、关闭、退休、身份冲突、重复 ID 或不满足输入资格的成员时，整个优化在任何
SQL 之前 `Fallback`。服务只对原队首运行现有单请求路径，后缀保持原顺序和原身份；
既有 lookup/原结果语义不在组内另造一套规则。过期缓存也只能在确认未开始 SQL 后
丢弃，由原队首的普通路径恢复；不能重试已经开始的组。

当前请求窗口必须有全组的 entry 空间，且满足：

```text
window.result_bytes + effective_group_result_cap + MAX_RESULT_BYTES
    <= retention.max_result_bytes
```

最后一项保留普通单请求的最大结果准入余量。因此不需要为 k 个成员预留 k×64 MiB；
同时任一中间成员仍满足原 `Window.full` 规则。接近满窗时先回退单请求路径，不能在
一个组内部轮转 epoch。revision、sequence、head_serial 的溢出和 HEAD9 必需的清理
计数余量也在 SQL 前保守预检，发布前继续执行既有格式与清理余量校验。

## 4. 真正独立的 native 事务

普通单事务路径的 `CommitGate` 在 native COMMIT 的页发布边界等待远端权威。
组提交新增明确的**私有 staging 模式**，绝不向普通 `CommitGate` 伪造 `Accepted`：

1. 独占 `&mut SqliteWriter` 并将 writer 置为 stopped，禁止普通 Session 使用暂存图像。
2. 每个成员执行真实 `BEGIN IMMEDIATE`，执行自己的语句，编码并保存自己的原结果。
3. 每个成员执行真实 native COMMIT。页回调只捕获本次私有增量，不在此时 ACK；
   deferred foreign key 在该成员自己的 COMMIT 边界检查。
4. 只有 native COMMIT 确实成功后，才把该成员计入成功暂存前缀。其后截止时间中断
   不能把已进入私有镜像的成员从前缀中删掉。
5. 首个可恢复 SQL/约束错误必须完成受检 ROLLBACK 并证明回到 autocommit。到此停止
   该组；此成员返回自己的错误，后续尚未开始的成员继续留队。

SAVEPOINT 套一个外层事务不会保留这些语义：例如先插入缺少父行的 deferred FK，再由
后一个请求补父行，不能让第一个独立事务“借用”后一个事务获得成功。实际合同分别在
首、中、末成员制造该错误，还检查跨事务 DDL 可见性、重复修改同一数据页和只读/no-op
成员的独立结果。

变化页预算统计**每个捕获版本**；同一页在两个事务中变化就计两次。结果预算累计原始
编码字节；当前正在执行的成员仍受单请求 SQL/结果内存/VM/page 等预算约束。组上限
触发可以终止成员或使候选失效，不承诺任意单请求负载在任意小组预算下都能成功。
应按请求大小设置上限，资源不够时不能无限扩展 staging 或偷偷重放失败事务。

## 5. 一次 HEAD 发布和每成员版本

设基准 HEAD 为 `(revision=r, sequence=s, head_serial=h)`，成功前缀长度为 k。
成员 i 的 StoredResult/receipt 保存：

```text
sequence = s + i
transition.revision = r + i
transition.nonce = original_request.id
data_root = root_after_member_i
```

按顺序构造各成员的数据根、原结果对象和请求索引。依赖继续条件创建并完整 exact GET
回读校验，最终 Manifest 的普通精确 GET 保留。每个 StoredResult 都有独立内容 hash，
原随机结果不会在发布或恢复时重新生成。

最后一次原 ETag CAS 发布：

```text
revision = r + k
sequence = s + k
head_serial = h + k
transition = last_member.transition
data_root = last_member.data_root
windows[0] = index containing all k original outcomes
```

`VerifiedGroupTransition` 是唯一授权多步发布的封闭入口，限制候选只能修改上述字段和
当前 window。Scope、ACL、owner/epoch、quota、其他 windows、storage、snapshot、restore、
生命周期字段全部必须与原 HEAD 相同。普通管理和单请求 `PreparedHead` 仍严格要求
`head_serial + 1`；没有把通用校验改成“大于即可”。

HEAD6–9 和 object v2 的字段格式不变。**head_serial 是消耗的协议序号，组提交开启后
不能再当作物理 PUT 次数。** 每成员逻辑 revision 仍唯一、连续；管理 CAS 和快照仍以
观察到的最终 HEAD 值作为预期值。旧的单请求实验仍按原 profile 严格验证 +1，新实验
只在完整证明 k 个新增原结果、顺序和保护字段后接受 +k，不能统一放宽旧观察器。

组是一个可见性/权威发布单位。并发 reader 可观察发布前或发布后的完整根，不能看到
未发布的中间状态；组内后续事务可读取私有前缀。receipt 的中间 data_root 表示该成员
完成时的来源，并不自动成为长期数据 pin。GC 继续保护当前根和显式 retained snapshots，
以及所有保留的原结果对象；没有显式快照的中间页面可以回收，原 receipt/结果仍可查回。

## 6. ACK、失败和取消

成功顺序是：**独立私有 native 事务 → 依赖持久与回读 → 原 HEAD CAS → 受检本地
checkpoint/镜像收养 → 逐成员 ACK**。组内 private COMMIT 位于 S3 之前，客户端成功确认
仍严格位于 S3 之后。不能把私有暂存完成当作持久提交。

| 边界 | 处理 | 是否自动重新执行 SQL |
| --- | --- | --- |
| SQL 前资格不满足 | 只回退原队首，后缀保持排队 | SQL 尚未执行 |
| 首个普通 SQL/约束失败、受检 rollback 成功 | 此前成功前缀可以发布，失败成员返回错误，后缀留队 | 否 |
| 页发布后错误、I/O/分配/损坏/未知失败、rollback 失败 | 丢弃整个私有候选，禁止发布成功前缀 | 否 |
| 依赖上传/回读失败 | 同一 context 失败关闭，依赖可能成为 orphan | 否 |
| 原 HEAD CAS 返回 412 | 所有已暂存成员保留 CONFLICT，候选不换 ETag | 否 |
| HEAD 响应丢失 | 保留 UNKNOWN，丢弃本地候选 | 否；逐原身份 lookup/cancel |
| S3 已接受，native/checkpoint/完成检查失败 | 每个已提交成员返回带自己 receipt 的 COMMITTED_BUT_UNAVAILABLE | 否 |
| 部分 HTTP 响应丢失或输出失败 | 远端原结果仍独立可查，其他成员响应不被改写 | 否 |

原生 `GroupRun` 保证 `staged <= attempted <= supplied` 且差至多为 1。core 的
`Completed.results` 恰好表示已消费前缀；任何开始过 SQL 的错误只在其中返回。
外层 Err 和 Fallback 只能在 SQL 前出现，服务不得将 Completed 成员重新放回队列。

取消、撤权、owner 切换、维护、配额和 storage 转换继续与组发布竞争同一 HEAD。
取消先赢，旧组整个 CAS 失败；组先赢，取消返回原提交结果。不能从已经执行的组中
去掉一个中间成员，再把依赖其暂存效果的后续结果发布到新 ETag。

## 7. 资源、关闭和 panic

收集出的成员保持各自 queue Usage、intake lease、output context 和实际工作 hold。
它们执行期间仍占原 global/tenant/database 队列额度，不能先退款后重新入队制造超额。
结果明确后只退款已消费前缀；未开始的后缀在调度锁内按原顺序放回新到达请求之前，
额度从未撤销，也不再次 `Usage.add`。

Engine 逐成员解码、交给既有输出预算，不同时构造全组 typed result 图。原始结果总量
已受 core 上限约束；各响应自己的序列化、发送和 deadline 保持独立。生产 RSS、SQLite
heap、同时保留的 raw/JSON/backing 和临时文件仍需要既有部署/输出隔离，聚合上限不等于
进程硬内存上限。

panic 时 `ActorWorker` 先析构 worker/native/cache，再析构 active batch 和其剩余额度。
没有可信消费边界时关闭响应，不自动回队。shutdown 排空尚未执行工作，运行组仍等待
真实工作结束；正常失败也在向调度器归还结果之前销毁不可用 Session。

## 8. 验收和仍未解决的事情

单位门禁覆盖 native 真实约束/DDL/no-op、逐阶段失败、封闭发布、counter/window、全元数据
竞争、快照/压缩/S2 消费者、queue/principal/scope/priority、关闭/panic 和逐成员输出。
新增生产文件全部进入逐文件行、函数、region、branch 精确 100% 分母，纯测试源码显式登记。

独立 [group-commit 实验](../../experiments/group-commit/README.md)包含有限协议模型及
真实 HTTP/SDK/签名 S3/进程退出合同。审计从原始 GET/PUT、正文、ETag、对象闭包和原结果
证明一次发布覆盖哪些独立事务；同时检查取消竞争、响应丢失、缓存全丢后的冷查证。
模型、synthetic 负控、native unit、本地兼容后端和 AWS 证据分别计数。

本实现降低可合组请求的重复 HEAD 发布与部分固定检查成本，仍需逐成员构造持久结果和
数据树，逐成员真实 COMMIT 继续保留 FULL 同步，最终 Manifest GET 与受检 TRUNCATE
保留；不能声称已经摊薄全部本地 fsync。它没有承诺 k 倍 TPS，也没有解决
热点 SQL 自身 CPU/锁争用、全库冷恢复、跨库对象上传、任意时间 PITR、无限历史/长期 GC
成本、跨 controller 共识、自动扩缩容或新 MVCC 引擎。目标 AWS、长期成本和固定负载
p50/p95/p99 的生产收益必须单独测量，不能用少一次 CAS 推导吞吐或 RPO。
