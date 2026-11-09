# HEAD5 运行时组合候选

本候选基于 `7c1f8e4`，把三个已独立提交的生产切片与受限 HTTP 观测夹具放到
同一源码树。冻结版本 `778a4d2` 已通过完整 workspace 单位门禁和 23 项辅助检查；
**这一组合的新实际 native/S3/HTTP 合同仍待验收**。各旧版本的真实故障和容量
结果保留各自冻结输入身份，不能替代本次实际验收。

`052fbbd` 的首次全 workspace 门禁在 fmt 发现一处行折叠差异，编译与覆盖采集
尚未进入；原失败保留在[格式失败回执](../evidence/head5-runtime-format-failure-local-2026-11-09.json)。
后继 `778a4d2` 只按该原输出修正表达式排版，并已完成下述完整单位验收。

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

`778a4d2` 的 canonical fmt、strict workspace Clippy、stable 与 fresh nightly
单位运行均已通过。两次各 538 个单位；56 个生产 Rust 文件共覆盖
10180/10180 行、899/899 函数、15570/15570 regions、1882/1882 个实际产生的分支。
五个文件由编译器产生的分支分母是 **0/0**，逐项原样记录，不把它写成百分比。
23 项 SDK、工具及夹具辅助检查通过，见[完整单位回执](../evidence/head5-runtime-workspace-local-2026-11-09.json)。

采集前确认零 raw/merged profiles；保留 93 个新 raw profiles、原合并列表与单一 merged
profile，没有混入旧版本或集成 profile。12 个实际单位 ELF、真实 native/ffi 依赖链、
全部 profiles、原覆盖映射及 433 份源码已完整归档，177 个成员逐字节 SHA-256
读回通过。原 f6 归档不变；本次单位使用原完整依赖缓存，不宣称重新编译了 native C。

新 release 构建 attempt01 在 Cargo 之前被原资源 builder 的空 target 前置条件拒绝，
[原失败已保留](../evidence/head5-runtime-build-precondition-local-2026-11-09.json)。
attempt02 使用独立空 target 与未修改的原 builder，六个 release 构建全部通过；
四个 Rust 夹具的 fmt/strict Clippy 也全部通过。首个 resource 构建在空 target
编译 native C，随后复用完整依赖；GC 使用另一个空 target。见[构建回执](../evidence/head5-runtime-release-local-2026-11-09.json)。

原 23 项辅助检查没有调用 TypeScript 编译器；回执中 `SDK V8/types` 的概括已更正。
冻结 `778a4d2` 的 SDK 后来独立通过 TypeScript 5.9.3 严格检查，保留实际命令、
工具摘要和原包含运行的失败状态，见[独立类型检查回执](../evidence/head5-runtime-types-local-2026-11-09.json)。

之后用本树的新 release 输入运行所需 native/S3/HTTP、冷恢复、owner、资源及
发现合同；直接 activate/named Complete 由相应 network/catalogue 路径覆盖。
需要专门证明管理操作没有 immutable 读取时，必须使用原 trace 可证明的请求归属，
不能从并发请求的重叠时间窗猜测哪一次 GET 属于管理调用。
新增[metadata-only 实际合同](../../experiments/object-metadata/README.md)以专用 M listener
的完整生命周期证明这一点。冻结夹具 `8fda16b` 与本运行时 release 已通过固定
41 POST、独立实际 oracle、九个语义投影负控及完整复制正控：M 的 13 次 HEAD GET、
4 次原条件 PUT、零 immutable I/O 均由其完整 listener 生命周期证明。见[实际回执](../evidence/metadata-head-actual-local-2026-11-09.json)。
原 `3ca5acd` 的 observer 失败与 41+10 单位修正继续分别保留；管理 ACK 不证明 payload/native 健康。

本 `778a4d2` 的 discovery 实际、独立外部 oracle、29 个负控及原样复制正控也已通过：
418 次 HTTP、25,305 次签名后端请求、全部 33 个 owned child wait4，见[发现验收回执](../evidence/head5-runtime-discovery-local-2026-11-09.json)。
这是发现合同，不替代数据库完整冷恢复；其余 network/capacity/deployment/service/owner/resource
门禁仍须分别完成。

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
