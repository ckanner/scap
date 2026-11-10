# HEAD5 统一运行时：本地组合验收

本记录绑定 PR #54 的冻结生产提交 `d60ea98eab8d073cfe118f3176c41ba6e2a4ab02`，
tree `012651c75d2b768ebe32c671da9738c113a4212d`。实际执行与正向独立审计均已完成；
owner/discovery 的负对照构造修正在独立提交 `6e107a1` 中验收。它没有改变实际运行的
生产代码、SDK、fixture runner 或 oracle 的正向判定条件。没有将 HEAD6 开发代码或
旧候选的 profile 拼入本次验收。

**后续独立审查发现原核心 retained-result/cancelled 校验缺少 nonce 与原 request.id
的语义绑定。因此 d60 不是完整 fail-closed 合同的最终交付，PR #54 仍保持草稿。**
HEAD6 中的共享校验修复必须使用新冻结源码、新单位覆盖和受影响实际合同验收；
本记录不能替代那一轮结果。

构建回执、精确计数、原始报告摘要、失败来源与范围分别保存在
[机器记录](../evidence/runtime-completion-local-2026-11-10.json)。原始 unit profile、
对应测试 ELF/native archive 和工具日志另有带逐文件摘要的完整验收档案；不能只靠
表格中的百分比复核覆盖。

## 输入与单位证据

候选清单 497 个文件，源码内容指纹
`490f03062f59dbebcfa6dc725d191f3ca2ab883b87c328594024bac39465e738`。
Rust 1.90.0，覆盖工具链 nightly-2025-09-18、cargo-llvm-cov 0.6.21；
Node 22.16.0，SeaweedFS 4.51。正式服务和各独立 harness 均保存单独 release
构建回执、精确输入清单、native archive 与实际可执行文件摘要。

| 门禁 | 本批结果 |
| --- | --- |
| stable/nightly Rust 单元 | 各 580 项通过 |
| Rust 四维逐文件覆盖 | 57 个生产文件全部精确覆盖；10,889 行、987 函数、16,542 regions、1,968 branches 全部命中；零分支分母如实为 0/0 |
| 格式与严格 lint | workspace fmt、Clippy；原生 harness 和 discovery Clippy 通过 |
| Node 与类型 | SDK/codec 每个生产模块的原始 V8 计数、真实 Fetch、TypeScript 5.9.3 严格检查通过 |
| 工具与 fixture | 脚本精确覆盖、开发工具 280/280 statements 与 36/36 branches、相应 Python/Node fixture 单元通过 |
| 协议模型 | 原对象权威和名称目录的固定模型与历史审计通过；不作为真实网络或 GC 的证明 |

unit profile 独立新采集，没有排除生产源码、混入集成运行或合并旧源码 profile。
新 `.github/workflows/quality.yml` 将 guarded-status、输出池及响应期限的单位、
实际执行、独立 oracle、负对照和证据保留接入 CI。

## 新实际运行

正式 `scapd` SHA256 为
`4df4fc1b951fff62aba78194c49360f0fa015b7313e7fef790268c964d1943b3`；
native worker SHA256 为
`8e6655cf8deb21aa08058c020ac495f18018fbf005fc4b466eadfa40d53e7229`。
以下数量来自本批实际账本与独立审计，不是设计规模或模拟请求数。

| 合同 | 已完成的实际检查 |
| --- | --- |
| 原生提交与故障 | 真实签名 S3、依赖发布与响应丢失、native publication、schema、全计算丢失；原 ACK 无错配 |
| 保留结果 | 12 类场景、72 个入口检查；30 份原 ACK 无错配 |
| 生命周期 | 12 个场景、78 次 ACK 响应、30 个原身份；保留结果/Deleted/Retired 分类一致，独立审计通过 |
| 原生目录 | 116 个场景、1,000 次 ACK；原创建/取消/删除意图、两轮恢复与永久身份屏障逐项核对 |
| 部署全目录恢复 | 从 deployment 根枚举；九个永久 HEAD 槽位、五个需要数据的数据库完成；13 个原输入、11 个原 ACK、154 个完整对象、1,480 个 LIST 页，独立 oracle 与 23 负/1 正对照通过 |
| 资源生命周期 | 25 次 HTTP、50 次 signed S3、3 次 backpressure；唯一未知执行不重放，取消证明与最后持有者释放有效，14 负/1 正对照通过 |
| GC 传输能力 | 42 个实际场景、115 个签名产品请求、136 个独立对象检查；13 负/1 正对照通过。此项没有启用产品物理 GC |
| 输出池竞争 | 18 次 POST、17 个完整响应、4 个持有输出；全局/租户各一次 LIMIT，控制预留仍有效；一个业务 SQL，原结果 33,554,650 字节一致，9 负/2 正对照通过 |
| 响应与关闭期限 | 11 次 POST、4 次服务端 EOF 截断、3 次慢 body 滴流；一个业务 SQL，原结果 16,777,340 字节一致；受控 SIGINT 后退出 0.517729133 秒，10 个负对照通过 |
| 原有 HTTP 接入 | 基础 HTTP/SDK、8 个连接/header 场景、目录接入、冷热隔离均通过各自实际合同与独立审计 |
| 分段请求索引 | 2,145 次 HTTP、2,114 个保留条目、在 129/2,113 处的实际 split；两份原 SQL 结果、完整冷闭包和全部对照通过 |
| Guarded status | 30 个原操作、29 个 POST、46 次 S3、五次 HEAD 发布、一个 SQL；实际 oracle、31 负/1 正对照通过 |
| Owner 协调 | 144 个 POST、626 次 S3、15 份原 SQL ACK；原候选冲突、计算丢失与 12 个子进程账本通过；修正构造后的 24 负/1 正对照通过 |
| Metadata 路径 | 41 个 POST，原 HEAD/ACL、resident quarantine 和全部子进程退出通过；9 个语义负对照通过 |
| HTTP discovery | 426 个 POST、25,222 次 S3、129 个自然名称与 11 个真实页；原实际账本和独立 CLI 正向审计通过；修正后的 29 负/1 正对照通过 |
| 1 GiB 容量恢复 | 39 份原 ACK、16,384 个独立 BLOB、1,073,741,824 字节全部核对无差异；失去全部计算和 backend 进程后仍可恢复；热缓存不能绕过不可用的新鲜 HEAD |

HTTP discovery 修正后的 29 负/1 正对照已经通过；原实际源码与独立控制源码清单均
在执行结束后重新核对一致。门禁执行成功、后续发现的语义缺口与修后验收分别记录，不能互相覆盖。

## 修复与原始失败

guarded-status 首轮实际运行完成，但旧 oracle 错把凭据数组顺序当作身份条件；随后又
发现 create 的 admission 分类和 listener 顺序预期错误。修正保留完整记录、重复次数、
主体/租户、token 和全部字段检查，并增加针对性的拒绝对照。各失败原件继续保留。

旧响应实现的专用反例确认：非读取客户端等待 2.3009 秒后仍能读取完整 22,369,821 字节
响应。加入绝对发送期限和关闭 drain 期限后，新的服务端截断合同通过；这份反例没有
被修改为成功，客户端也没有用主动 RST 冒充服务端期限生效。

1 GiB 首轮在 `/tmp` 可用空间 4,262,961,152 字节时触发原 4 GiB 保护；当时仅装载
436,207,616 字节，没有完成 ACK/BLOB 总审计。新运行使用空间充足的本地 TMPDIR，
保留相同源、二进制、30 秒操作预算、30 分钟恢复预算和 4 GiB 保护，279.034 秒后
完整通过。没有删除原失败或把默认 10 GiB 配置当成本次容量实测。

owner/metadata 首轮的实际动作完成后，被原 oracle 的 `/tmp` 私有路径前提拒绝。
新的运行只调整证据目录，不改变原操作、原断言或 oracle；两组原失败保持原样。

owner 的旧负对照改了 If-Match，却保留了与其不一致的 HEAD serial/revision/transition，
先撞到格式检查，未达到预定的“缺少同调用原 GET”边界。修正只构造内部一致的恶意
候选，并同步 raw body、摘要与签名镜像；它仍缺少所要求的原 GET，正向 oracle 未改变。
修正后的全部 24 个负对照和原样副本正对照通过。一次输出跨文件系统导致的 EXDEV
也单独保留，该次尚未执行任何语义反例或产品调用。

discovery 的旧负对照在一个已用满 512 GET 的真实页追加 GET，先触发数量上界。
修正复用原末尾两个 GET，只更改相关时序，保留原 key、响应、ETag 和请求分母，
以检查声明的期限因果关系。正向 verdict 函数没有修改；两组修正有 232 项 fixture
单位验收，不改变原实际 S3/HTTP 历史。

后续 retained nonce 缺口需要能重写对象、索引和权威依赖，或同等语义损坏才触发；
普通 SQL/BLOB 输入和合法产品 mutator 不生成该矛盾，随机损坏通常先被 digest 拒绝。
但 core 曾可能把这种 hash-valid 错误内容当作 Committed/Cancelled 或允许 activation，
而 SDK 会拒绝。共享 verifier 将同时封闭 lookup、恢复和 COPY，不能仅依赖客户端检查。

## 结论限制

GitHub Actions 当前报告 failure；查看的质量 job 没有任何执行 step。远端状态不记为
通过，本地门禁按仓库已有规则单独判断。此记录不修改分支保护，也不覆盖原 CI 结果。

所有实际运行均使用私有本地签名兼容端点。AWS Standard、真实网络文件系统挂载、
生产吞吐/长尾/成本 SLO、自动 owner controller、PITR 与产品 GC 不由这些结果代替。
容量、资源与恢复的测量只说明本候选的具体合同，不是生产 SLA。
