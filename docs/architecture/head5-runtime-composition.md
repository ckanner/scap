# HEAD5 运行时组合候选

本候选基于 `7c1f8e4`，把三个已独立提交的生产切片与受限 HTTP 观测夹具放到
同一源码树。当前为静态组合，**完整 workspace 和全部新实际合同尚未运行**。
各切片的既有单元、真实故障和容量结果只对各自冻结输入成立。

`052fbbd` 的首次全 workspace 门禁在 fmt 发现一处行折叠差异，编译与覆盖采集
尚未进入；原失败保留在[格式失败回执](../evidence/head5-runtime-format-failure-local-2026-11-09.json)。
后继候选只按该原输出修正表达式排版，仍需完整重新验收。

## 组合内容

| 来源 | 当前加入的行为 | 原有证据范围 |
| --- | --- | --- |
| PR #44 / `c516ceb` | 从原 Snapshot/ObjectContext 出发的有界 raw closure cursor | 252 core 单元、21 core 文件精确计数 |
| PR #46 / `2ce579d` | Takeover/Policy 只发布封闭管理字段，保留原条件和两次 healthy | 242 core 单元、20 core 文件精确计数 |
| PR #45 / `67bffa8` | 移动 Base64 String，owned/borrowed success envelope 避免重复 Value 图 | 已冻结并静态审阅；单独运行门禁未执行，由本次全 workspace 验证覆盖 |
| 受限 Fetch 观测 | 原 request 身份、fetch/header/body 阶段、安全错误枚举和 socket 事件 sidecar | 11 个 fake Fetch/stream/channel 单元；真实连接根因未证明 |

三份生产补丁按其实际父提交做三方应用，没有手工选择覆盖整份文件。唯一共同修改的
生产文件为 `scap-object/src/lib.rs`。独立静态审阅确认，直接 `Database::activate`
和 named Complete 仍先完成闭包，再执行原 fresh HEAD body/ETag equality barrier
和原条件发布；Takeover/Policy 的 metadata 路径没有成为其他动词的快捷入口。
HTTP Engine 的 Activate 仍调用 `activate_session`，走原 restore/verify_results
和完整原生物化；不能把 owner HTTP 验收独立称作新 cursor 的实际验证。

管理 ACK 只证明管理 HEAD 已发布。局部 healthy 仍是 handle/clones 的知识，
不是跨进程健康协议，也不能撤销最后检查之后已经获准的原条件 PUT。

## 验证与集成

先在本树一次完成 canonical stable/Clippy 和 fresh unit-only 四维 workspace
覆盖，逐文件保留真实计数和编译器零分母。旧 f6 的实际 ELF/native/140 profiles
已经逐成员完整封存并读回；其完整依赖缓存可独占复用。采集前清空或隔离所有已
归档的旧 profiles，不能把多个切片的计数拼成组合覆盖。

之后用本树的新 release 输入运行所需 native/S3/HTTP、冷恢复、owner、资源及
发现合同；直接 activate/named Complete 由相应 network/catalogue 路径覆盖。
需要专门证明管理操作没有 immutable 读取时，必须使用原 trace 可证明的请求归属，
不能从并发请求的重叠时间窗猜测哪一次 GET 属于管理调用。

[f6 的新部署恢复](../evidence/head5-deployment-local-2026-11-09.json)已通过实际、
外部 oracle 和 23 负/1 正对照，保留原输入身份；新 core 组合仍需新的验证。
[4329 discovery actual01](../evidence/head5-discovery-failure-local-2026-11-09.json)
继续是 FAILED。新增观测不重试请求，不扩大成功集合，也不改变原 timeout。
若观测有 overflow、缺失停止标记或未关联事件，不能宣称完整的连接证明。

本组合单独保留草稿，由其完整门禁决定是否转向 main 承接生产栈。旧 PR 和冻结
版本的未执行项不被改写成通过。PR #43 的回收模型及后续 handle 细化独立于本
生产组合；当前仍只接受 storage active/allocated=1，没有 copy/promote、retained
hold、SnapshotExpired、产品 DELETE、PITR、全局输出池或自动 owner controller。

精确来源与当前门禁状态见[组合冻结记录](../evidence/head5-runtime-composition-local-2026-11-09.json)。
