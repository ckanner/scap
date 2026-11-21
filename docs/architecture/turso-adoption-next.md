# Turso 实践的接续实现决策

更新：2026-11-20（America/New_York）。当前实现基于已合入 #65／#66／#67 的 `68246fd6`。
本页区分已交付能力与后续协议设计；后续条目没有对应实现和验收时不标为完成。
背景见[安全与吞吐](sqlite-s3-safety-and-throughput.md)，固定上游源码对照见
[Turso 实现比较](sqlite-s3-turso-review.md)，当前证据见
[并发与资源交付记录](../engineering/sqlite-s3-scale-validation-2026-11-18.md)。

## 1. 当前已经采用的实践

| 实践 | 当前主线实现 | 必须保留的约束 |
| --- | --- | --- |
| 对象持久化参与确认 | 依赖条件创建／回读，原 HEAD CAS，native publication，再 ACK | 不改为本地 COMMIT 后异步备份；UNKNOWN 保留原身份 |
| 分块和可丢弃计算镜像 | 128 KiB chunk／COW 数据树；Session 复用私有完整镜像 | 缺页失败关闭；当前仍完整恢复，不是 lazy VFS |
| 有来源的快照恢复 | S1 retained points，S2 新 Scope 完整复制与取消／完成证明 | Scope 绑定对象须重封装；不继承旧 ACL、owner、请求与取消屏障 |
| 非复用计算身份 | 永久 marker 与可选自动分配器 | 初始化必须尊重历史 high-water；marker 不删除、不回滚，身份不授予 owner |
| 读与 writer 解耦 | 可选有界 read pool，各 reader 独占完整镜像，每次 exact HEAD 授权 | SQL 前只允许一次 stale 重建；没有共享活动 WAL 或并行 writer |
| 动态部署配置 | 受信 version=2 fleet、完整有限历史、永久退役、quiesce／SIGHUP | 不提供全局共识、自动扩缩容或旧业务请求重投 |
| 实际资源准入 | 请求／队列／恢复／输出预算，可选 cgroup v2 与有限 tmpfs 检查 | 资源按实际生命周期归还；组级约束不等于每租户硬隔离 |
| 有界负载验证 | 固定开环、过载拒绝及原请求收敛；相同逻辑行数的 SQL batch 比较 | 事务数与逻辑操作数分别报告，测试计划值不是性能读数 |

当前保留 `synchronous=FULL`、受检 TRUNCATE 和普通精确 Manifest GET。#60 的
GET-elision 优化已按[决策](../engineering/manifest-get-elision-decision-2026-11-18.md)
退出产品，历史约 24% 回退仍未归因；不能通过删除回读或降低同步来“修复”该结果。

Turso Cloud、libSQL/Bottomless 和新 Rust Turso 引擎各有边界。开源 Bottomless 的
异步复制不等于 Cloud 的 ACK 前持久化；Cloud 多库打包也不等于 Rust 引擎 MVCC
或 group commit。官方来源列于[安全与吞吐第 6、10 节](sqlite-s3-safety-and-throughput.md#6-turso-可以借鉴什么)。

## 2. 三种批处理必须分别实现和计量

| 机制 | 事务与发布单位 | 当前状态 |
| --- | --- | --- |
| 显式 SQL batch | 客户端一个请求／身份，多条 SQL，整体一个原子事务 | 已实现；适合业务本来就允许共同提交的工作 |
| 同库独立事务 group commit | 多个原请求保留各自 SQL、结果与逻辑顺序，合用一次 HEAD 发布 | 本轮已实现可选有界路径；逐阶段验收见[本轮记录](../engineering/group-commit-validation-2026-11-20.md) |
| 跨库 WAL／对象打包 | 多个数据库共享一次不可变对象上传，各库仍独立发布 HEAD | 未实现；需要对象 pack 格式、独立可达性和回收协议 |

同库 group commit 优先降低单库小事务重复等待；跨库打包优先摊薄多租户对象请求
成本。两者都不自动引入 MVCC 或跨库原子事务。不能把 8 个八语句事务统计成 64 个
独立事务，也不能因为一次 PUT 包含多个库就把所有库的成功合成一个提交结论。

## 3. 同库独立事务 group commit：实现决策

本轮将前一方案落实为 native staging、core 发布和 writer actor 调度，完整协议见
[独立事务组提交](independent-group-commit.md)。具体取舍已经明确：

- 默认关闭；仅组合已经排队、完整 Scope/Principal 相同的连续 Execute，不增加凑批定时器。
- 每成员真实 BEGIN IMMEDIATE/COMMIT；普通 CommitGate 不收到假的 Accepted，private
  staging 不对普通 Session 或 reader 可见。首个可恢复 SQL 错误结束该组，保留成功前缀。
- 首版仅组合全新、互不重复的当前 epoch 身份。已有结果、取消、冲突或窗口空间不足
  全部在 SQL 前 fallback，只让原队首走既有单请求路径。
- 成员 i 分别占用一个 sequence、revision 和 head_serial 序号；一次原 ETag CAS
  将最终 HEAD 推进 k 步，并引用 k 个独立结果和最后根。通用发布校验仍严格 +1。
- 原始 deadline、聚合输入/结果/变化页和原队列/output 额度全程保持；失败上下文不能
  重建为新 ETag，已开始 SQL 的成员不能自动回队。
- HEAD 已接受但本地收养失败，逐成员保留 CommittedButUnavailable receipt；丢失部分
  HTTP 响应后，仍按各原身份 lookup，不能重新生成随机结果。

真实合同覆盖成功、首/中/末 deferred constraint 失败、重复请求回退、取消先赢、
单成员响应丢失和 SIGKILL/全部缓存丢失后的原结果恢复。模型与原字节审计入口见
[group-commit 实验](../../experiments/group-commit/README.md)。这完成的是独立提交协议和
可选服务能力；目标后端固定开环性能、p95/p99 和长期成本保持独立验收，不从 CAS
数量下降推导 k 倍 TPS，也不引入新的 MVCC 引擎。

## 4. 跨库 WAL／对象打包的独立设计

Turso/AWS 的公开方案把多个数据库的 WAL 聚合上传，说明高密度多租户可以摊薄
请求成本；没有公开足够信息证明其 owner／GC 与 SCAP 一致。SCAP 当前每个 object
frame/hash 绑定 Scope，不能直接把已有对象拼在一起而保持所有读取和删除假设。

建议在同库协议稳定后再建立独立版本的 immutable pack：

1. 聚合器限制窗口、成员库数、总字节、每租户额度和在途上传；全程保留各请求的
   原 deadline。冷库或慢库不能无限拖住其他库，也不能提前 ACK 等待中的成员。
2. pack index 固定各成员的 Scope、generation、对象类型、范围、长度与 digest。
   对象存储只负责 pack 原子持久化；读取须验证 index 和成员内容，不能靠未经
   校验的 range bytes 提供数据库页面。原条件创建／回读保证需要等价实现证明。
3. pack 持久后，各库分别用原 ETag 发布自己的 HEAD。A 成功、B 冲突、C UNKNOWN
   是合法的部分结果，分别保留；没有跨库原子事务或“一次 PUT 全部成功”的语义。
4. 初版禁止通过 pack 跨越不同租户的授权边界，除非认证、加密、可见性、删除及
   成本归属已经独立设计。相同上传批次不能扩大任一数据库的读取权限。
5. 共享 pack 的物理删除必须证明所有成员均不再可达。现有按库／代际退休不能
   直接删除跨库 pack；需明确持久引用目录、保守保留或重新打包的协议。内存
   refcount、一次 LIST 或某一个数据库的终态 seal 都不是全局删除证明。

验收除独立发布／丢响应外，还要覆盖 A 保留快照、B 删除、C 正在恢复时的共享 pack
生命周期，以及跨租户读拒绝、部分回读损坏、压缩／重打包中断和迟到上传。
必须同时报告请求成本下降与回收粒度增大产生的存储成本；不能只统计 PUT 数。

## 5. lazy VFS / 按需恢复的设计边界

目标是减少大库冷启动和小工作集强读的下载量。当前 S2 和 reader pool 均使用完整
物化镜像，不具备此能力。新接口需接入 native pager，并保留现有完整恢复路径。

- 每次读固定经授权 HEAD 的 body/ETag、Scope、generation 和根；通过有限层树将
  逻辑页映射到 chunk，验证 frame/hash／范围后才交给 SQLite。
- 缺页或坏 hash 不填零、不建空库、不退回旧 root。缓存只存已验证不可变页，并按
  Scope、generation 和 digest 隔离。不能把新 HEAD 的一部分页面拼进旧快照。
- 完整读池镜像不再依赖源对象，而 lazy reader 仍依赖旧对象；因此必须重验退休／
  GC 与读操作的关系。沿用当前可中止 generation 原则时，被证实退休的未完成读
  可以返回过期，但不能宣称任意长读永不受 GC 影响。
- 全局／tenant 的在途 GET、解码、页缓存、native heap、输出和后台预取都要预算。
  缓存命中不跳过新授权；失败和中断等待实际 I/O 结束后再归还额度。
- writable pager 仍把 dirty pages 和原结果接入提交前 gate。按需读页、checkpoint
  和 WAL-reset 需要固定 native 回归，不能把普通文件 read 拦截当成完整 VFS 协议。

验收使用固定工作集 1%、10%、100% 的访问集，分别量首个成功强读时间、下载量、
GET 数、CPU 和空间；加缺页／坏块／撤权／退休／对象超时／全缓存丢失故障。
若提供快速 clone，须区分目标拥有全部独立数据和仍依赖源对象的持久性，不能沿用
完整 S2 的独立性承诺。

## 6. MVCC、PITR 和 fleet 的独立出口

### MVCC 执行引擎

Rust Turso 的 `BEGIN CONCURRENT`、行级 MVCC 和引擎 group commit 值得研究，但
替换固定 libSQL 会改变 SQL 支持、隔离、约束、冲突、日志和挂点。先冻结具体版本，
核对业务 SQL/schema/类型与 native 提交接口，再做非确定性结果、冲突、恢复及全部
故障切点验收。MVCC 仍有写冲突和热行瓶颈，不等于分布式多主或共享网络 WAL。

仅当目标热点写负载证明单 writer 已是主要瓶颈、前述请求摊薄不足且兼容性满足时，
再决定切换。按租户分库的并行收益与单库 MVCC 收益必须分别测量。

### 任意时间 PITR

S2 从显式 retained point 恢复。任意时间 PITR 还需连续提交历史与完整日志链、时间
到提交序列的映射、保留／GC 保护、历史完整性校验和新 Scope 恢复入口。墙钟可以
跳变，不能只按对象 Last-Modified 或 LIST 结果猜提交顺序；应定义目标时间落点、
时钟来源和最大可证明范围。缺少连续历史不能把 S2 命名为 PITR。

### fleet 与资源隔离

[动态 fleet](dynamic-owner-fleet.md)已支持受信配置的在线更新、退役、旧计划收养和
quiesce；它没有跨 controller 全局 epoch、持久全局成员共识、无限历史压缩或自动
扩缩容。部署器验证新 readiness identity 后发布配置，旧 guard 继续拒绝新进程。
扩展这些能力需要自己的持久状态迁移和重启协议，不能靠自动刷新旧请求地址完成。

[内核资源准入](kernel-resource-envelope.md)已检查真实 cgroup/tmpfs；其组边界、
启动时信任前提和 daemon OOM 恢复的验收范围保持不变。每租户硬隔离、普通磁盘
配额认证、长期多轮 GC 和唤醒风暴仍是独立交付，不能用一次采样峰值证明。

## 7. 实施顺序与交付口径

同库 group commit 已进入本轮完整实现与验收；接下来在目标后端配对测量对象请求、
排队与 native 成本，按实际瓶颈继续 lazy VFS 或跨库打包。跨库打包在独立发布及共享回收协议
明确后实施；PITR 和全局 fleet 各自推进，不借用其他模块的成功替代自己的验收。

每项交付包含固定源码、单元／覆盖、真实 native/HTTP/S3、进程故障、独立原字节
审计和反例。生产代码继续纳入原逐文件精确覆盖分母；设计完成、代码完成、本地
合同通过、目标 AWS 通过和生产 SLO 达成分别报告。没有目标环境或原始读数时明确
NOT_RUN，不把上游基准、旧候选或配置值当成新的实测结果。
