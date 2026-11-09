# Handle 知识域：下一组有界模型的小方案

状态：**方案已获审核；正在冻结展开程序，尚未进行状态探索或验收。**

初审版本保存在 `/tmp/scap-handle-knowledge-proposal01`，未改写。当前版本明确纳入
已批准的 K06 合法 hold 前史、K15 两层语义边界和 K16 独立抽象结果查询。展开
输入单独冻结并再次审核后才探索；本文件不是已通过的验证报告。

本目录是独立的新模型。工作树基于已发布的
`d158b44f18475038eee1a904af2cf0ba0722ecf4`，不修改其中已冻结的
`experiments/object-reclamation-abortable-model` 十四个文件，也不修改旧 PR41。
生产 generation、错误码、quarantine、HTTP 和任何 DELETE 开关均不改变。

## 1. 本次只回答哪个问题

PR43 模型的 `health[g]` 和 `authority_corrupt` 对所有模型 actor 共享。其 README
已经把这称作尚待落地的抽象；它不是现有多进程产品的共享健康状态证明。真实
Database 的 clones、Session 和 ObjectContext 共享本地 Arc；独立 Database::new、
Catalogue 临时 Database、RecoveryJob 可以在同一 worker 中创建另一条知识谱系。

新模型移除全局健康知识假设，独立检查原始对象验证、失败作用域和原条件发布的
安全义务。它允许一些被旧模型全局 latch 禁止的安全读，因此**不声称新旧模型
具有逐条 trace 等价性，也不把旧模型的通过分母加到本模型。**

## 2. 已选合同：阻止发布，不把所有读取一概关掉

- 原失败 attempt 的可用前缀已经结束；后来的 GET、物化、重建 handle 或成功调查
  都不能使这个原 attempt 恢复公开成功。原 UNKNOWN 也是已经发生的历史观察。
- 同 lineage 的 generation incident 或 authority latch 阻止新的相关 publication
  取得最后健康检查许可。现有代码没有“所有 read 都先 healthy”的合同。
- 同 lineage 的**新**只读操作可以重新取得 fresh 授权并自行完整验证后返回；该
  成功不删除旧 latch。独立 H2 也按自己的 fresh 授权和原始对象证据工作。
- 已完整验证/物化的原授权读可在 ACL/fence/退休后返回，不新增 closing HEAD GET。
  其自身失败、stop/detach 的出口约束仍然独立检查。
- 这不是恢复或清除 quarantine 的 API。独立 handle 的成功不能修改 H1 的知识。

### 最后健康检查有自己的时间点

两次 healthy 不是覆盖网络的锁。模型将构造与最后检查分成显式步骤：

1. 从原 Snapshot 构造不可变候选，保留原 backend/key/body/ETag；业务依赖须先验证。
2. 通过最后健康检查，产生**仅用于这一原候选的一次性 publication permit**。
3. 消费 permit，发原条件 PUT；请求进入独立网络 token。

若同 lineage 的另一个 clone 在步骤 2 后才观察到坏对象，不能撤回既有 permit，
也不能撤回已发 PUT。关闭 local operation gate 仍阻止新的 dispatch；这与知识
latch 的作用不同。已经 dispatch 的 token 始终保留 apply/discard 边。

允许的已知 durable/native ACK 由原调用的知识和公开出口决定；稍后出现 latch
不能追溯否定早先 ACK，也不把已经生效的原 CAS 改成失败。尚未通过最后检查的
新 publication 则必须拒绝。该划分不增加 rebase、重发 SQL 或新的重试。

## 3. 最小知识域与不可搬运的内容

知识域固定为 `(authority_domain, full Scope, handle_lineage)`：

| 身份 | 含义与限制 |
| --- | --- |
| authority_domain | 一个可信物理 bucket/prefix/endpoint 配置域；不是 Arc 地址，不是请求方自报字符串。模型使用两个独立后端 map。meter wrapper 保留同一个域。 |
| full Scope | deployment/tenant/database/incarnation/logical generation 全部字段；永久 HEAD slot 相同不代表 Scope 相同。 |
| handle_lineage | 一次真实 Database 构造及其 clones/Session/ObjectContext 的谱系。两个同 worker 的独立构造也不同。 |
| attempt | 固定原 lineage、Snapshot/ETag、generation、根、principal、deadline/gate 和 purpose。失败后不换谱系继续。 |
| image / materialization | 属于原 attempt/Session 的已验证本地值；不能直接重绑为另一 handle 的 cold 验证证据。 |
| network token | 固定原 domain/key/body/condition/保护身份；原 caller 结束后仍能交付。另一 handle 不能认领其 UNKNOWN 或私有 receipt。 |

lineage 中分别记录 generation incident 与 authority/semantic latch。所有知识只能
由本 lineage 实际观察过的对应原请求更新。fixture 后端故障与 client 已知故障
分开：消除后端注入故障不自动清除任何 client latch。

新的独立 handle 可以合法执行**新的结果查询**，从 fresh 授权 HEAD 和自己的
retained-result 证据获得一个查询结果。它不把 H1 的原 UNKNOWN 改成 ACK，不能
把结果查询伪装为再次执行 SQL。K16 单独纳入这种合法的新查询；它不声称验证真实
B+ tree 或 SCAPRES1，也不得写出“不同 handle 永远不能取得相同 receipt”的错误规则。

## 4. 失败调查保持原物理身份

一次未完成的源物理 Missing/hash/截断故障最多发一次专用 exact HEAD 调查，仍走原 domain/
meter、完整 Scope 和原绝对 deadline。模型仅把 deadline/gate 当显式停止状态，
不证明实时钟预算。

退休仍要求 `1 <= g <= M && g != A && g != current_target && no_hold(g)`，以及所有
转移对已退休世代不复用、不重新 active、不新加 hold 的单调限制。G2 被 Abort 后
A1/T3 的情形必须保留。错误 backend、同 slot 外来 Scope、坏 HEAD、Unknown、
预算不足都不能构成退休证明。

调查只决定原失败的作用域，不产生新的可 rebase Snapshot 或新的 READ/admin。
target 错误使用 target generation；旧 plan 的 source G1 仍 active 时不能借
PlanExpired 免除源损坏。旧 plan 的成功响应也不能进入另一个 plan 的 evidence。
visitor、目标 PUT、本地预算和已经 known durable 后的 native 失败不冒充源缺失。

原始 hash 已验证后的 Scope/type/typed-edge/retained-wire 语义矛盾，以及 native
InvalidImage，不因 namespace 退休自动成为 expiry；相同坏内容可能已复制到新 g。
首片模型将内容语义 latch 独立保留，不声称 MODELFRAME 的检查证明真实 SQLite
或 SCAPRES1 语义。物理 allowance 与本地资源不足也不能只凭一个 Limit 混为一类。

## 5. 有限场景清单（程序展开前的审查版）

下列清单尚不是已枚举的程序。审核后才把初态、actor program、barrier、故障注入、
网络选择和 mandatory witness 展开成冻结输入。参数分支届时拆成独立 profile。

| 编号 | 场景与必须可达的结果 |
| --- | --- |
| K01 | H1 Missing + 调查 Unknown；clone-H1 的新 publication 拒绝；原失败 attempt 不能继续。H1 的 fresh 完整新只读可成功但保留 latch。 |
| K02 | 同 worker 的独立 H2 以自己的 HEAD/完整 GET 成功；H1 的 Unknown/incident 不变。后端重新完整的原因必须是显式原字节恢复 fixture 或原先已发的 Absent PUT，不能由 H2 自动修复。 |
| K03 | 不同 worker 的独立 H2 同样成功；不能把 worker ID 错当知识共享边界。 |
| K04 | 后端缺失持续存在时，H2 必须由自己的 GET 失败；“新 handle”不能跳过验证。 |
| K05 | H1 的不完整 G1 读遭退休/移除，H2 的 G2 读成功；H1 仅经自己的 fresh 调查得到 expiry，不污染 H2。另保留 H1 已完整物化后跨 fence 返回的正例。 |
| K06 | 已 abandoned target G2，active G1、新 target G3；G2 可 expire。受保护的反向情形从合法 hold 当前 G1 的 CAS 开始，再 Promote 到 G2；held G1 的受控 Missing/hash 故障不得 expire。不以无法通过合法转移到达的 held-G2 初态冒充前史。 |
| K07 | 旧 copy plan 已废弃，但其 source G1 仍 active 且真的坏；必须保留 G1 source corruption，不能仅用 plan 更换降格。 |
| K08 | H1 观察 malformed 或 foreign-Scope HEAD；只 latch 本 lineage。独立 H2 的 fresh 正确读成功；H1 的后来成功读或 ACL/serial 更改不清 authority latch。 |
| K09 | D1 上长得相同的 HEAD/世代不能为 D0 的原失败提供退休证明。另从合法 Promote 前史出发，原 D0/slot 的专用失败 probe 得到 foreign Scope 或 malformed HEAD，不能借看似已退休的数值 expire；请求 token 始终绑定原物理域。 |
| K10 | H1 原 writer CAS UNKNOWN 后 caller/handle 结束，H2 新建；旧 CAS 仍能在 fence 前/后交付，保留原条件和 UNKNOWN；H2 不能 adopt 旧 prefix/permit/native 状态或重放旧 SQL。 |
| K11 | 在 H1 原读已有部分 frame 或完整 Session/image 时构造 H2；H2 不能把 H1 的本地值冒充自己的 cold 验证。H1 原合法物化结果仍可正常完成。 |
| K12 | 最后 healthy 之前出现同 lineage latch，阻止新 permit；最后 healthy 之后、dispatch 之前出现 latch，原 permit 仍可发出。两种顺序都有 witness。 |
| K13 | 已发原 CAS 后出现 latch，后端 Applied/Conflict/UNKNOWN 与 native commit/fail 分别保留其真实意义；新 ACK 只看原公开 gate，不用后来的 latch 撤回已发请求。 |
| K14 | 完整成功以后再 latch/stop/detach，不能追溯否定历史成功；新调用与旧历史区分。 |
| K15 | K15a 的 hash-valid typed-edge 坏图保持 active，两条 lineage 各自检测，不声称坏图可合法 Seal。K15b 的 raw 图完全有效、另有声明的抽象 native/content 失败谓词；原字节经合法 raw-copy Promote 后仍语义无效，不因退休或新 handle 变成 expiry/成功。 |
| K16 | H1 原 writer UNKNOWN 后，H2 新操作从 fresh READ HEAD 和自己的 index/Result 原始 GET 证明旧 durable receipt。H1 的 UNKNOWN 不变，H2 不 adopt 私有 token、不执行/重放 SQL。另有未提交时无 receipt 的完整合法结果。 |
| K17 | writer/takeover/policy 分别覆盖 permit 后 stop 阻止新 dispatch，以及 dispatch 后 stop 不取消原网络效果。已发 token 的 apply/discard/UNKNOWN 均保留；已知 durable 的 native commit/fail 可收尾，但不能新增公开 ACK，UNKNOWN 不能被迟到 delivery 改写。 |

K12/K13 同时覆盖普通 writer 和立即有真实调用方的纯管理候选；管理候选只允许
takeover/policy 的固定字段差异，不能改变 immutable roots。普通 writer 的 ACK
必须晚于其 own known durable CAS 和 native commit；native fail 是 committed-unavailable。

## 6. 明确的范围选择与待审项

建议第一轮独立程序只实现新 cold read、普通 write、窄 metadata publication 和
用于上述竞态的受限维护 fence/retirement。已验证 raw frame 的只读返回也纳入。

不在第一轮假装完整实现 warm Session SQL、retained lookup 的 B+ tree/SQL wire、
Catalogue Name/Control/Proof 多 key 协议或真实 RecoveryMeter 资源计数。它们需要
保留的合同是：自己的 fresh 授权、原本要求的依赖验证、正确知识域与不搬运 prefix；
现有 receipt 读取不因本模型而被禁止。K16 的独立 profile 只验证新 handle 自有的
抽象 request/principal/sequence/revision 绑定、原始对象来源与历史知识不改写；不把
它折进 K10，不把这一抽象查询称作真实 codec/请求索引算法验证。

退休场景可从一个已经验证/封存的 copy plan 起步，以实际原条件 HEAD CAS 做
Promote/Abort/再分配。此前复制完整性是声明的初态假设，不重新取得 PR43 的复制
证明分母。物理移除只由显式 fixture 在退休谓词已成立后产生；本模型不重做
checkpoint/DELETE 传输协议。所有普通 HEAD/immutable tokens 仍逐一枚举 apply/
discard/known/UNKNOWN，不能通过 fixture barrier 删除已经 enabled 的交付边。

## 7. 计划采用的上界与独立检查

每 profile 至多 4 actors、3 lineages、2 workers、2 authority domains、2 full Scopes、
3 physical generations、1 hold、1 plan、8 小 raw frames、48 network tokens；每个
actor 至多 96 显式步骤。每图 50,000 states /150,000 edges /120 秒是资源 cap，
超过即 INCOMPLETE，不能删除 witness 来“通过”。展开后若需要调整，先再冻结清单。

独立 oracle 不导入 producer。它直接检查原 token 条件、原始 frame hash/引用边、
每个实际 lineage 的知识来源、最后健康许可、历史公开出口和完整 enabled-edge
集合。allowed-delta 必须禁止跨 lineage 写知识、伪造 fresh view、重绑 label/permit、
复活 failed attempt、篡改 backend fault 或用新 success 清旧 latch。

负控从原图可达 prefix 上构造：跨 lineage poison/clear、false global block、绕过
最后检查、撤回已发 CAS、旧 UNKNOWN 补 ACK、跨 backend/Scope 借证明、搬运 frame/
image、native 重放、停止后新成功、迟到响应续 failed prefix，以及漏掉 pending
delivery/截断图。正控至少包含独立 H2 的完整成功与最后检查后才 latch 的原发布。
源、展开输入、原失败、图、witness、oracle 与所有 controls 必须独立绑定。

第一份已冻结程序 `/tmp/scap-handle-knowledge-programs01` 包含 38 profiles，未探索。
根审阅发现 K09 专用失败 probe 和 K17 stop 时间点缺口，第二份程序新增八个 profile；
原 38 个 profile 输入对象保持逐字节规范化相等，原程序快照不覆盖。增加的是已声明
核心 gate/证明来源的覆盖，不是把 global latch 加回去。

## 8. 生产尚未解决的事项

本模型即使通过，也不为生产选择 unbounded health HashMap、不增加 durable health
字段、不证明跨进程 incident 广播、不证明真实时钟或任意数量 handle 的内存界限。
生产开启多世代前仍要把 bounded local knowledge 的生命周期、所有 admission/API
出口、error mapping、RecoveryMeter provenance 和 authority-unavailable 处理接通。
目前 storage 1/1 的 metadata 小片保持既有 handle/clones 行为。
