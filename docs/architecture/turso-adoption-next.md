# Turso 实践的接续实现决策

更新：2026-11-17。依据与固定上游源码在[Turso 对照](sqlite-s3-turso-review.md)。本页
描述 SCAP 的实现选择，不把 Turso Cloud 的源码可见性或上游性能数字当成 SCAP 的证据。

## 1. 本轮采用的做法

优先完成 S2 和启动身份这两个可独立使用的产品行为，再按正式服务剖析处理吞吐。

| 上游实践 | SCAP 本轮落实 | 必须保留的约束 |
| --- | --- | --- |
| 对象存储持久化后确认 | 保留依赖回读、原 HEAD CAS、native publication，再 ACK | 不改为本地 COMMIT 后异步备份；UNKNOWN 保留原请求身份 |
| 分块存储与一次性计算镜像 | S2 逐层重封装源 chunk/node/manifest，在一个私有 native 镜像中验证 | hash/frame 绑定 Scope，不能只引用源 root 冒充独立 clone |
| 快照有明确来源和生命周期 | Restore descriptor 与 Empty 共享原编号槽；完成证明、Copying/Copied、取消、删除全部接入 | 不恢复旧 ACL、owner、请求和取消屏障；provenance 不永久 pin 旧数据根 |
| 后台工作有独立资源边界 | 长恢复单独 worker/queue/intake、每租户 staging、分方向 S3 I/O 预算 | HTTP 超时不能提前归还实际工作资源；逻辑额度不等于 OS 硬隔离 |
| 先分析实际数据路径 | 分开 native 发布/检查点、对象等待、CPU、分配和建连计数 | 正式正确性、诊断、性能结论各自保存身份，不为提速省略校验 |

本轮评估了本地 `synchronous=FULL`。NORMAL 在当前“提交后立即检查 TRUNCATE”结构下
仍保留检查点同步，但几种实测负载结果方向不一致；OFF 又会减少正在运行时的本地
写入错误观察。生产实现继续 FULL 和受检 TRUNCATE。固定有界 S3 keep-alive 池的调整
另行验证，它只影响连接重用，不改变重试、校验和 ACK。

S2 的具体实现与完整 HTTP 语义见[恢复合同](../../crates/scap-service/docs/restore.md)。
性能数字、失效样本和源码身份以性能 PR 的独立报告为准。

## 2. group commit 的实施边界

目标是摊薄小事务重复对象请求与 HEAD 发布开销。当前 CommitGate 在一个 native 事务
的发布点等待，不能直接在该连接上执行下一事务。需要先明确批次执行与发布的新协议，
再决定改造现有 libSQL gate 还是使用新引擎接口。

1. 单库 actor 收集有界 batch：事务数、SQL/输入/结果字节、最大等待和 tenant 额度
   都明确。批次满或收集期限到即结束，不建立无界等待队列。
2. 每个事务保留原 request identity、结果和逻辑 sequence。顺序确定，不能依据后来
   HEAD 为先前 SQL 刷新权限或条件；冲突后的旧候选不换 ETag。
3. 一个 HEAD 原子引用批次数据根、所有原结果和取消屏障。ACK 按逐事务 receipt 返回；
   HEAD 已发布但只有部分响应送达时，其余请求只能查证原身份。
4. 分别验收批内 SQL 失败、结果限额、权限变更、cancel 竞争、提交响应丢失、native
   发布失败与进程退出。失败事务之后是否继续批次须明确，不能默认“全部回滚”。
5. 比较固定负载的成功分母、p50/p95/p99、排队、GET/PUT/字节/每成功事务、控制延迟
   和保留结果增长。一个批次一个 HEAD 的请求数减少不自动证明尾延迟改善。

只有当远端等待占主导且业务接受收集等待时进入该阶段。不同库已经可以并行；多库
并发数字不证明单库 writer 并行。首版必须同时保留可禁用的单事务路径与相同故障语义。

## 3. lazy VFS / 按需恢复的实施边界

目标是减少大库冷启动和小工作集强读的成本。现有 S2 完整镜像验证仍是完整恢复。
下一版必须通过独立读页/VFS 边界接入 native pager：

- 每次读先固定经授权 HEAD 的 body/ETag、Scope、storage generation 和根；逻辑页
  经有限层内容寻址树映射到 chunk，验证 frame/hash/范围后才交给 SQLite。
- 缺页或坏 hash 不能填零、转空库或回退旧 root。新强读重新检查权限；缓存只保存
  已校验的不可变页，按 Scope、代际和对象 hash 隔离。
- 不能把最新 HEAD 的部分页面拼入旧快照。退休和 GC 用原 lineage 及 fresh 屏障
  区分合法过期与真实损坏；正在进行的不完整恢复保留取消路径。
- 全局/tenant 的请求、在途 GET、解码、page cache、结果和 backing 生命周期均有
  明确预算。下载量下降不能靠无界缓存换取。
- writable pager 仍将全部 dirty pages 与原结果接入提交前 gate；启用 reader pool
  或后台 checkpoint 前先完成固定 native WAL-reset 补丁及回归。

验收使用冷工作集 1%、10%、100% 的固定访问集、错误注入与缓存全丢失，分别报告首个
成功强读时间、下载量、GET 次数和 CPU。若提供快速目标可用，还须区分“目标已有全部
独立数据”和“目标仍按需依赖来源”两种持久化语义；不能沿用完整 S2 的独立性承诺。

## 4. MVCC、动态 fleet 和 PITR 的独立出口

Turso Rust MVCC 属于执行引擎协议。替换当前 native 引擎需要完整 SQL/schema/类型、
提交挂点、恢复和原结果兼容验收；它与网络文件系统锁是否可靠没有等价关系。

自动 worker 编号解决启动身份复用，不更新静态 controller route。新的 readiness ID
需要由部署控制器验证并注册；旧 guard 继续 TARGET_MISMATCH，不能盲目刷新后重投 SQL。
动态成员的可信注册、退出、重载、有界 fleet 和旧 UNKNOWN 收敛是另一项实现。

S2 从显式 retained point 恢复，不提供按墙钟时间任意选点。PITR 要定义连续历史、时间
索引、保留策略、日志链完整性、跨时间权限和 GC 保护；没有连续历史不能把 S2 命名成 PITR。

以上项目都不能仅凭设计文档标为已交付。它们分别需要固定源码、单元、实际 native/
HTTP/S3、进程退出、独立错误判定和目标后端的验收；真实 AWS、故障域和成本另行认证。
