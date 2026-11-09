# 发现 HTTP / Node SDK 真实合同

这是 N2-C 的独立实验装配。服务、目录逻辑、签名 S3 客户端、游标加密和
Node SDK 均从同一冻结源码构建或导入，实验不提供替代目录实现。

本文件加入时只有 Python 语法编译及 Node `--check` 开发检查完成。
**真实运行为 NOT_RUN，不能把本夹具存在视为全目录功能验收通过。**
正式运行必须保存独立 release build receipt、原始 HTTP/S3 字节和拥有的子进程
`wait4` 收据。AWS Standard 云端合同、生产 SLO 与整个数据闭包恢复不由本实验证明。

## 覆盖合同

- 129 个同租户 Ready 名称超过固定 4 × 32 LIST 页预算，保证真实续页，不依赖
  每个候选的内部 GET 数量；首尾名称只授予
  reader READ。首个部分页之后撤回末尾名称的 READ，保留 ADMIN，使用原游标
  继续扫描，检查新 exact GET 权限与原始 Name → Proof → HEAD → Name 顺序。
- 正常页也可能在原始 4 秒读取预算内返回 `UNKNOWN`、部分结果与认证游标。
  每个正常完整扫描最多 128 次明确的 SDK 调用，首个页也计入此上限；每次调用
  只发送一个 POST，使用上一页的原始游标。独立审计从下一次真实 LIST 的
  `StartAfter` 判断物理进展，并要求被跨过的每个名称在上页完成 descriptor 与
  Name → Proof → HEAD → Name 的完整分类。这些 exact GET 都必须发生在本次实际
  列出该候选的原始 LIST 交付之后，不能借用后来才到达的 LIST。普通用户看不到的 READ-denied 名称
  同样计入此证明，撤权后的新 HEAD 决定后续可见结果。加密文本变化不构成进展。
  首个 LIST 或候选 GET 也可能一直在网络中，截止时尚未完成任何候选。这种页必须
  有一个未分类、明确断开的最终请求和截止附近的终止观察，或满足下文独立推导的
  逻辑端口截止分支；下一次调用必须复制
  原认证游标，并重复完全相同的 prefix、delimiter、StartAfter 与 LIST 参数。
  可以连续出现这种页，也可以重复同一游标文本，但仍计入原来的 128 次总上限，
  不能凭 `UNKNOWN` 或游标字段虚构进展。首个有 READ 的名称必须在整个扫描中恰好
  返回一次；不要求它出现在首个截止页。原先注入的截断零进展 LIST 仍必须是 `CORRUPT`。
  最后必须有真实耗尽的 LIST、完整固定候选集合且没有重复；`UNKNOWN` 空页不能
  被当成完成。有效游标正控、释放名额后的成功页、重启前新游标也明确续页到结束。
- 另一个租户、另一个部署、只含 descriptor 的创建与不可变 control 记录构成
  独立候选集合。operator 能完成所属部署的元数据遍历，但该能力不给 SQL READ，
  provision 也不给 inventory 权限。库存记录的 control 投影必须来自实际 GET。
  库存续页还按真实的 tenant、name/create/control/abort-proof/slot 次序核对物理
  下界；空阶段的切换必须有对应耗尽 LIST，已分类的原始记录与累积计数必须一致。
  每个记录的来源证明绑定到本次实际列出它的 LIST，以及从该候选的 exact GET 到
  下一候选或下一 LIST 之间的区间。同一 creation 出现在 create/head 阶段，或出现在
  相邻的两个 control 记录中时，各自必须有完整的新证明，不能借用同页较早记录的
  Name → Proof → HEAD → Name。已返回记录的最终分类 GET 因而不能被误列为未决退款。
- 六个有明确原始后端响应的故障：LIST 403、404、缺少 `IsTruncated`、截断零进展，
  以及已分类一个条目之后的 exact HEAD 404 / 损坏。错误必须保留不完整游标与
  停止原因；恢复必须使用它并从最后已分类条目继续，不能跳到网络页末。
- 所有 exact GET 持续增加 30 ms 延迟，LIST 不延迟。逐次明确提交上页游标，
  至少两个达到扫描期限的部分页必须带 `UNKNOWN` 与有效游标，在原始 5 秒 HTTP
  期限内交付，最终完成同一名称集合。独立审计核对每次实际延迟、单调的原始
  LIST lower bound，以及它跨过的每个名称在上页的 Name → Proof → HEAD → Name
  与 descriptor 来源证明；同下界页须通过上述未消费尾请求证明，不能只凭加密
  游标文本改变推断有进展。这个额外延迟场景保留 16 次总调用上限。
- 游标篡改、principal / tenant / deployment / view / daemon 交叉使用必须拒绝；
  同时保留有效游标正控。重启前重新取得未过期游标，销毁全部计算和缓存，再验证
  新进程拒绝旧游标；显式新扫描能找回相同永久元数据，并通过原始结果 lookup 与
  SQLite 查询验证一个实际数据库。
- 第一个 LIST 持有期间，客户端真实超时；同租户被拒绝，第三租户能利用剩余
  全局槽位得到有真实空 LIST 证明的完整空页。第二个 LIST 持有期间，客户端主动
  abort；两个任务仍占用 global=2 / tenant=1 的运行名额。持有前先明确查询预热，
  持有期间的 query 必须恰好读取一个新 HEAD、下载零个数据对象；query、lookup、
  cancel 都必须在释放 LIST 之前完成。客户端断开本身不能释放正在运行的名额。

这里的 403 / 404 错误页是代理在收到真实签名后端响应后，明确记录的故障注入。
它们检验服务如何处理 S3 HTTP 结果，不能替代 AWS IAM 或云端 S3 的验收。
所有原始后端页都另与此前条件 PUT 成功的完整候选集核对。在线分页仍不是快照；
本场景没有用 LIST 来代替名称、HEAD、权限或控制意图的 exact GET 权威。

`usage.metadata_bytes` 按正式 B 层的逐次 reservation / refund 合同审计：canonical
目录记录预留最多 64 KiB，HEAD 最多 256 KiB，均再受本页剩余额度限制；成功返回
完整对象才退还未使用额度，404 等失败保留整个预留值。它不是实际 HTTP 错误文本
与协议开销的字节和。共享 connector 对错误体另有 64 KiB 上限，最后元数据剩余
额度更小时，这两个数值仍不得混为一谈。原始后端和交付响应体字节独立记录、求和；
审计器既不放宽元数据预算，也不把保守预留误认为实际下载量。
自然截止时，代理把响应写入 TCP 并不能证明对象客户端在期限前接受了完整响应。
每次调用至多有一个尚未参与分类的最终 GET 或 LIST；前面的每个成功请求必须精确
退款。若最后的响应直到“首个可见 S3 请求加 4 秒”之后才开始交付，它必须保留
全部预留：目录 GET 为其本次真实 allowance，LIST 为 1 MiB。若最后响应更早开始
交付但无法从外部确定是否完整消费，才允许两个独立推导的精确结果：保留该预留，
或按实际完整响应长度退款。GET 与 LIST 不能同时成为模糊尾部，不能把多个请求
设为模糊状态，不能接受任意中间计数，也不能依据服务报告的计数反推允许值。
未消费的 LIST 不提供分类证明；后续调用必须重发原始 LIST 查询及认证游标。
库存也可能已经消费一个空阶段或 tenant LIST、完成相应游标进展，然后在下次
发起 I/O 前达到原截止。只有完整物理前缀证明实际跨过那个 LIST 的阶段或候选，
它才进入已分类边界，按完整原始长度精确退款；不能再当成模糊的最终 LIST。
库存用量比较因此位于整页记录及阶段进展证明之后，已消费响应仍必须满足原来的
外部 4 秒界限。没有进展的未消费 LIST 保留原先的断开与完全相同查询重发要求。

### 逻辑端口预留与实际请求

`DiscoveryUsage` 的五个字段是一次调用的保守逻辑计费，不能直接等同于代理观察到
的 HTTP 请求数。正式 `catalogue/discovery_budget.rs` 的 `Meter.get` 先增加
`exact_gets` 并预留本次 allowance，再调用对象端口；`Meter.page` 也先增加
`list_pages` 并预留 1 MiB，再调用 LIST 端口。两个下层端口都使用原绝对期限，可能
在检查期限、进入运行时或等待响应时返回 `UNKNOWN`，代理没有观察到该次请求。
此时计数和完整预留仍然存在。**未被代理观察不等于已证明没有内部 dispatch。**

审计器生成完整的 `(list_pages, candidates, exact_gets, list_bytes, metadata_bytes)`
元组，再检查服务报告是否属于该有限集合。不能分别从互不兼容的分支选择计数和
字节值。除原先唯一已观察尾请求的精确退款/完整预留分支外，只允许以下另一条
互斥的可行分支：

1. 仍是原始 `UNKNOWN`、3.5 秒至不足 5 秒的 HTTP 往返，原认证游标没有跨过
   未完成候选。所有已观察请求及响应交付开始都在原来的外部 4 秒必要上界内，
   全部原始响应体、ETag 与成功写入历史一致，没有断开的已观察尾部。
2. 在“这些已观察响应全部被客户端消费”的同一执行假设下，所有成功体都精确
   退款，正常缺失 proof 等失败仍保留完整预留。`delivery_finished` 只表明该假设
   没有明显的断开反证，不能直接证明客户端已消费或内部检查的时刻。
3. 根据原始 LIST、实际下一页物理 frontier、当前候选的完整类型化依赖顺序，
   独立确定最多一个尚未被观察的下一端口尝试。服务报告的 usage 不参与推导它。
   GET 只预留其类型上限与本页剩余额度的较小值；LIST 只预留原来的 1 MiB，
   不退款、不虚构返回体，也不附带 candidate 增量。
4. 当前候选已经开始时，其后续 GET 不再增加 candidates。未观察到的首个 GET
   只有在该候选还可被原 candidate 预算接纳时，才对应恰好一次 candidate 预留。
   已观察完整 GET 链但游标仍未越过当前候选，不足以假设它已完成；此时不能借此
   给下一候选增加 GET 或 candidate 预留。原先“尚未进行下一次预留就达到期限”
   的零额外预留分支仍保留。
5. 未观察的 LIST 只能来自已经完整分类的物理前缀及真实空阶段/tenant 进展。
   下一次明确调用必须重用原认证游标，首个 LIST 的 prefix、delimiter、StartAfter
   与其它参数逐字段等于唯一应当发生的查询。响应之后到下一次明确调用前，不得
   有同 scope 的无归属工作观察。

固定夹具的依赖顺序如下。`N` 是名称 Binding，`D` 是创建 Descriptor，`P` 是该
Creation 的 AbortProof，`H` 是数据库 HEAD，`C` 是实际 LIST 返回的 Control key。
`N/D/P/C` 上限为 64 KiB，`H` 上限为 256 KiB；每个成功体仍须逐字段绑定原
Creation/Scope、对象 key、descriptor hash，以及必要的稳定 Name body/ETag。

| 原始候选 | 类型化 GET 顺序 |
|---|---|
| Ready name | N, D, N, D, P, H, D, N |
| Ready create | D, N, D, P, H, D, N |
| 创建已 Ready 的 control 类型路径 | C, D, N, D, P, H, D, N |
| named Ready slot | H, D, N, D, P, H, D, N |
| 固定 dormant create | D, N404, P404, H404, N404 |
| 固定 dormant control | C, D, N404, P404, H404, N404 |

这个顺序模型仅用于固定夹具最后逻辑预留的可行性证明；完整分类、当前权限、
游标前缀和最终集合仍由原独立语义审计负责。夹具没有已发布的 AbortProof 候选，
不为它编造 Ready 路径，也不将该有限模型宣传为任意并发目录历史的证明。
本 HTTP 运行的实际 control 引用 dormant 创建；上表引用 Ready 创建的 control
依赖分支仅有合成单位见证，不另声称真实控制操作已经执行。

GET 与已接受 PUT 的 bytes/ETag 一致，只能证明同一版本，不能证明这个版本能被
目录解码器合法接受。因此预算推导之前还核对一个有限的固定输入 profile：

- 从原认证 caller 与 prepare 输入独立推导 132 个完整 Creation/Descriptor；
  Scope 使用固定 named-ID 推导后再与响应核对，不从被审计响应借用预期身份。
  本夹具的配置固定为 default quota 10 GiB、retention 4,096 项及 256 MiB 原结果。
- 用实际 Descriptor 字节的 SHA-256 及完整 Creation 派生 Origin 的四个字段，
  核对 131 个名称实际产生的 Reserved/Bound 完整字段和确切 key。
- 唯一 dormant abort Control 的全部字段、format、nonce、期望 revision 与 key
  均由原 `control_dormant` 请求和认证 caller 派生；其结果必须保留原意图。
- 对每个已接受 catalogue PUT 和成功 GET 比较完整字段、声明字段顺序的紧凑
  canonical 原字节及原 64 KiB 上限，拒绝缺失、未知、错误类型、字段重排、额外
  空白或不属于本场景的成功 Proof。每个声明的永久源和 Bound
  名称都必须确实发布。HEAD 继续使用组合源码已有的严格 wire 格式与权限见证。

这只描述本固定场景的源，不重新实现通用 catalogue codec 或产品状态机。
逻辑元组仍硬性检查 4 LIST、128 candidates、512 GET、4 MiB LIST 字节和
16 MiB metadata 字节，不能把 `+1` 或额外 64 KiB 当作普遍误差范围。
匹配额外预留的报告使用 `CONSISTENT_NOT_OBSERVED`，内部 dispatch 始终记录为
`NOT_OBSERVED`。

最后一个已分类数据库的 GET 也不意味着整个 Slots LIST 已消费完。若末尾的
`catalogue/` ignored entry 尚未被游标跨过，下一次调用仍应从同一 Slots frontier
继续；它可能尚未接纳这个本地候选，也可能在 candidate++ 后的期限检查处停止。
这只产生零新增端口、candidates 为原完整前缀或多一次的两条分支，绝不能据此
虚构下一 deployment LIST。只有实际 cursor 与完整物理前缀共同证明已经跨过
ignored entry 和阶段结束，才考虑下一 LIST 的唯一完整预留。

## 自然截止与吞吐假设

原夹具的 `normal()` 只接受 `null` / `LIMIT`，隐含假设了没有注入故障时，
固定候选数总能在 4 秒内分类完毕。这不是产品的协议承诺。两个保留的 3b93b9a
原始失败在同一个 `reader_first` 断言退出：

| 原始运行 | HTTP 耗时 | LIST | name GET | descriptor GET | proof GET | HEAD GET | 完成分类 |
|---|---:|---:|---:|---:|---:|---:|---:|
| 与其它验证并行的 01 | 4,139.466 ms | 2 | 101 | 101 | 34 | 33 | 33 个 |
| 停止其它重负载的 02 | 4,044.630 ms | 1 | 89 | 89 | 29 | 29 | 29 个 |

两个真实 HTTP 响应都包含 `discovery-034`、`UNKNOWN`、非空游标和
`traversal_exhausted=false`。前者的下一候选为 `discovery-017`，后者为
`discovery-038`，均在原始读取截止处留下未完成的 GET 链。所有后端响应都有原始
字节见证，只有正常缺失 abort proof 的 404，没有注入故障或延迟。第二次失败撤销了
“仅由并行负载造成”的解释；两个失败不会因本次修复被重新标记为通过。

当前 Ready 候选路径通常执行 8 次 exact GET，因此 512 GET 额度本身也可能先于
128 candidate 额度耗尽。代理每条证据都执行 `fsync`；上述数值包含记录、代理与
本地兼容后端的开销，不能作为生产吞吐或 AWS SLO。修复只让实际期限产生的部分页
进入完整进展证明，原始 5 秒 HTTP / 4 秒读取期限及全部资源额度保持不变。
冻结的生产源码把读取期限设为服务端接收时刻加 5 秒再减去 1 秒。代理没有观察这个
内部接收时刻，也没有观察对象客户端的内部 dispatch 时刻。原始网络证据对每个
**使后续请求能够发生的非最终请求及其响应交付开始**，检验“首个可见 S3 请求加
4 秒”的必要上界：同步扫描必须先消费前一个响应、通过原期限检查，才能发出
下一个请求。同时检验前一个交付开始先于下一请求。最终已发出的请求可能在截止后
才到达或写入代理日志，取消不能撤回它；不能对最终请求套用相同的到达时间断言。

允许的最终迟到观察必须是原 HTTP 5 秒以内返回的 `UNKNOWN`、保留原游标、明确
断开、没有贡献任何已完成分类的唯一 GET 或 LIST。GET 必须属于下界之后的第一个
未分类候选，并有原始 admitting LIST 和该候选的 exact GET 链；LIST 必须在下一次
调用以同一查询重发。原响应之后、下一次明确 HTTP 调用之前，不能出现同 scope
的新增 S3 请求观察。下一次授权调用开始后的归属不能仅凭时间区间确定，因此该
断言不声称排除了所有更晚的在途到达。所有这些都是外部观察合同，内部 dispatch
仍为 `NOT_OBSERVED`；没有引入宽限时间，也没有把更早的客户端发送时刻当作服务端
接收时刻来暗中收紧期限。

正常 `UNKNOWN` 的观察档位为 3.5 秒至不足 5 秒的 HTTP 往返；使用已观察尾请求的
同下界页另外要求其断开终止观察位于该调用 3.5 秒之后。使用逻辑端口分支的同下界页
则必须证明完整原始前缀与唯一下一 GET，原查询和认证游标也必须完全不变。
这是夹具的截止见证，不是内部
超时原因或请求发出时刻的直接测量。首个 GET / LIST 可以很早发出，不要求其代理
请求时间靠近截止。持续不进展只能消耗有限调用次数，最终完整集合证明仍不可省略。

### 保留的修正前失败

09cfc0d 候选在正式 actual 开始前发现同一 creation 的库存记录可能借用前一个
阶段的证明，已保留为验收器缺口；4834434 通过将每条记录绑定到它自己的原始 LIST
和候选区间修正该问题。随后 4834434 actual03 完成全部真实阶段并清理进程，但原
审计拒绝了三个最终 GET 的迟到代理观察，分别超出其外部 4 秒界限 1.722244 ms、
26.946848 ms 和 0.517331 ms。三个 HTTP 往返仍分别为 4,013.925 ms、4,043.416 ms
和 4,022.841 ms，最终响应均明确断开，原 HTTP 返回后没有继续发起工作的观察。
这个运行仍为 **FAILED**，不能用修订后的诊断结果重新标记。

同一原始历史还显示一个最终 LIST：请求在首个 S3 请求后 3,999.015 ms 被观察，
交付到 4,010.551 ms 才开始；原 HTTP 在 4,011.208 ms 返回 `UNKNOWN`，该 LIST
随后断开，没有候选由它完成分类。因此本次明确加入独立 LIST 尾部计费和原查询
重发证明。新的正式结论必须来自修订源码冻结后的另一场运行；自然 GET / LIST
迟到或同下界页是否实际出现，不是允许反复运行直到满足的通过条件。

bda5ad4 actual04 完成全部 26 个真实阶段并清理了 33 个拥有的子进程，原验收仍
因 `restart_inventory_2` 的预算比较而 **FAILED**，该结论永久保留。该页原 HTTP
耗时 4,019.685083 ms，返回 19 个记录、`UNKNOWN`、20 个 candidates 与原游标：

| 字段 | 原始代理记录逐次重算 | 原始 HTTP usage |
|---|---:|---:|
| list_pages | 1 | 1 |
| exact_gets | 154 | 155 |
| list_bytes | 9,957 | 9,957 |
| metadata_bytes | 1,311,864 | 1,377,400 |

154 个已观察 GET 恰为 19 个完整 Name 候选各 8 次，再加下一候选的原 N、D。
最后 D 的原始响应为 368 字节，在该 HTTP 开始后 4,007.297201 ms 开始交付，
4,008.589117 ms 记录交付完成。原首个 S3 观察在 15.225020 ms，因此它仍满足原
外部必要因果界；不能用这两个时间反推出内部消费或 dispatch 时刻。原下一页
LIST 的 StartAfter 仍在前一个已分类名称，随后重新读取同一候选 N、D、N。
唯一下一类型化 GET 是当前候选的同一个 N，完整 allowance 为 65,536 字节，
恰等于预算差值；candidate 已经接纳，不应再次增加。这个解释只证明一条与原
证据一致的逻辑预留分支，不会把 actual04 改成通过。修正后的结论必须来自另一次
冻结源码实际运行、默认外部审计和全部原始历史负控。

预算修复开发稿 `a6626cad…` 的独立审查另保留了一个全版本一致负例：把唯一 dormant
Control 的已接受 PUT 及同 opaque ETag 的所有 GET 副本由 `format:1` 改为
`format:2`，同步 raw SHA/base64，7 份字节见证长度、key、计数与版本关系均不变。
旧的完整语义审计仍接受了这个内存副本，正式目录解码器则会在执行任何后继之前
拒绝该格式。这说明仅证明发布版本一致和后续分类不足以成立解码前置条件。
有限 metadata profile 与新的全版本负控针对这个缺口；原 actual04 和原反例记录
均保留，后续修正不会改写它们的原始结论。

## 运行

从包含最终 DiscoveryClient 与控制记录投影的冻结 checkout 执行；不要从旧 SDK
目录混合导入。构建器的输入清单覆盖这些夹具文件，因此构建开始后不得再编辑。

```sh
python experiments/object-service/build.py \
  --target-dir /absolute/new-release-target \
  --evidence /absolute/new-build-evidence

python experiments/object-service/discovery_contract.py \
  --server /absolute/new-release-target/release/scapd \
  --weed /absolute/pinned/weed \
  --node /absolute/node-v22.16.0/bin/node \
  --build-record /absolute/new-build-evidence/build.json \
  --evidence /absolute/new-discovery-evidence

python experiments/object-service/discovery_oracle.py /absolute/new-discovery-evidence
python experiments/object-service/discovery_oracle.py /absolute/new-discovery-evidence --controls
```

开发运行可显式传入 `--diagnostic`，只会产生 `diagnostic_passed`，不会生成 release
验收结论。`--keep-private` 仅用于本地失败诊断；默认清理临时凭据和私有数据库目录。
证据目录不可重用，原始失败记录不得覆盖。

独立审计器不导入 controller、SDK 或生产发现代码。它解析原始 HTTP、JSON、XML、
条件 PUT / GET 的版本链和原生结果格式。实际历史负控在内存深拷贝中篡改完整空集、
游标结果、已完成库存的遗漏项、释放时序、wait4、原始结果回读、CAS 条件和缓存损失；
每次必须拒绝，原始证据文件的哈希前后不变。
新增实际历史负控还会丢弃延迟部分页的游标、把续页输入改回 `null`，以及把实际
预热阶段的数据 GET 移入持有期间的查询窗口，分别验证进展和驻留查询的断言。
自然续页修复增加九个实际历史负控：部分页假完成、物理下界跳过未分类 key、
把已经有进展的页伪造成无证明的同下界续页、5 秒 HTTP 期限续期、非最终请求的
4 秒读取截止续期、512 GET 额度续期、
早期 GET 不退款、多个模糊退款以及任意中间计数。新的负控必须在指定语义边界拒绝，
原始证据副本须通过正控；不能靠其它无关失败让负控通过。
本次再增加六个实际历史负控：迟到 GET 已参与分类、迟到但没有断开、多个迟到尾部、
已迟到的前一个响应却触发新请求、原 HTTP 返回后的无归属新请求，以及已完成 LIST
虚构全额退款。它们从每次有效扫描必有的已完成原始请求构造不同的反事实历史，
保留实际请求和对象字节，不依赖本次运行恰好观察到某种自然迟到尾部。完整的 LIST
截止、连续同下界、错误 scope / phase / token / cursor 与错误退款分支另有聚焦的
合成审计器测试；这些测试不冒充真实 daemon 或 S3 执行。
逻辑预算修复继续保留原 26 个负控的语义，另外在每次有效运行必有的已完成库存
调用上分别伪造一个未观察 GET 与 LIST 预留，必须拒绝；不依赖新运行恰好出现
未观察端口尝试。完整依赖前缀、错误类型/余量、双重尾部、五字段分支混拼、
candidate 重复计费、完整 GET 链未推进游标、错误阶段/查询和所有硬上限另有
聚焦的合成正反例。还增加一个完整版本一致的非法 Control format 负控，全部原
字节副本与 hash 同时改变时，仍须由固定认证输入派生的 profile 拒绝，不能只依赖
版本比较碰巧失败。合计 **29 个实际历史负控和 1 个原始副本正控**。
