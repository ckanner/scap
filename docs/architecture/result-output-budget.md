# 结果编码与服务输出预算

当前状态：**编码基础已实现。`d012dc5` 已通过严格 Clippy 及两轮各 546 项单位，但精确四维检查发现两个不可达错误传播出口，保持 FAILED。两处内部不变量窄修已冻结待新门禁。后文的全局/租户输出池仍是设计，尚未实现。**
基础实现叠在 guarded-status 的 `5604126f7677188dd1b35dd3d596747d4bf95002` 上；
原资源推导以运行时 `778a4d2` 的路径为依据。源码、独立审阅和精确边界见
[基础切片冻结回执](../evidence/output-encoding-foundation-local-2026-11-09.json)、[首个 Clippy 失败与窄修](../evidence/output-encoding-clippy-correction-local-2026-11-09.json)和[精确覆盖失败与不变量修正](../evidence/output-encoding-invariant-correction-local-2026-11-09.json)。
本文接续[HTTP 结果去副本](http-result-copy-reduction.md)和[资源预算](resource-budgets.md)。

## 0. 已实现的编码基础（先于下述输出池）

当前基础切片修改六个文件：
`scap-sql/src/lib.rs`、`scap-sql/src/tests.rs`；
`scap-object-sqlite/src/lib.rs`、`scap-object-sqlite/src/tests.rs`；
`scap-service/src/wire.rs`、`scap-service/src/wire/tests.rs`。
只实现第2节的一份 canonical count/fixed-slice emitter 与 fallible one-allocation
wrapper、native query 的纯验证分离，以及第6节的两个精确 ResourceExhausted 映射。
不创建 pool、配置、Worker 新方法或 HTTP 新类型，不声称具有 aggregate output budget。

新 plan 是被 native query 与现有 encode_result 实际使用的接口；下一 commit 可以先
为 plan.encoded_len() 取得 credit 再 write_exact，不必再次改编码器。保留现有 Invalid/Limit/
Malformed 行为和验证顺序，新分配失败使用已有 ResourceExhausted。容量失败测试可以
对真正的 fixed-buffer allocator helper 输入 `usize::MAX` 触发 TryReserveError，
不制造真实系统 OOM，也不使用进程级 global allocator 故障开关。实际 encode 的
原 invalid/limit 仍走原 rollback，资源分类用精确 helper regression 核对。
基础实现保留七项新增单位定义，已通过静态审阅和限定文件 rustfmt。
修正后的完整 workspace、strict Clippy、逐生产文件四维单位覆盖及实际合同仍待运行；
两处私有失败注入边界使用借用的 dyn FnMut，不分配回调、不使用进程全局开关。
它们仍各调用一次。原泛型候选只存在静态覆盖聚合风险，没有实测失败。
当前窄修明确声明：不可变 plan 已完整验证，wrapper 的目标长度由该 plan 确定。
这两处内部不变量使用 `expect`；公开 wrong-size Invalid、计数 Invalid/Limit 与
分配 ResourceExhausted 仍正常返回，不通过构造非法私有 plan 或覆盖豁免填补计数。

## 1. 下一片：服务编码缓冲预算与边界

先交付 **普通 `/v1` RPC 的编码缓冲全局与租户预算**：同一 daemon、所有该路由的
data/control/recovery 工作共用一个 manager，原子检查全局及可信 `(deployment, tenant)`。
覆盖新建 SCAPRES1 wire Vec、Base64 backing、最终 JSON backing，以及预留的小型
公开 Value/receipt/error 投影与 owner 开销。小信用先于派发，大信用按实际长度先于分配。
不为每个 INSERT 预占 64 MiB 或 213 MiB。

这片不把整个 Engine 的公开返回类型改掉，不改 SCAPRES1、SDK 字段、HEAD/receipt、
CAS、SQL 次数或现有 durable limits。它必须包含真实 daemon 接线，不能只实现一个
没人使用的 pool。`/v1/catalogue`、`/v1/discovery` 暂不计入该池；配置/文档必须称其
为 `/v1` 编码缓冲预算，不能声称整个 HTTP 服务或进程 RSS 已有全局上限。

另有三个明确排除项：

- native/core 在 publication 前构造的 wire result、S3/frame 读取与副本、lookup/cancel
  已经取得的原始 retained Vec，不因后来被 service 看见就变成“申请前已计费”。
- `TransactionResult` typed graph 的 128 MiB 默认本地预算仍独立；它不是该全局池，
  与 wire/Base64 同时存活时必须在容量说明中另外列出。
- libSQL VM/页缓存/参数复制、allocator rounding/元数据、HTTP header/内核/TLS 缓冲
  及固定小型 infallible Arc/Map/Bytes owner 分配失败，不受大 Vec 的 fallible 保证覆盖。

这是可单独审核的真实收益：很多不同数据库的小结果可以并发；慢 body 的最终大 backing
仍占账；仅因为输出转换缺额而失去结果时，不会把一个已提交 SQL 改称未提交。

## 2. 先把一份 canonical encoder 变成两种 sink

原 `778a4d2` 的 `scap-sql/src/lib.rs` 中，`Encoder::put` 使用 `extend_from_slice`，
len 上限不能限制几何 capacity 或增长期间的新旧 backing。不要在 service 另写一个
“大致估算 SCAPRES1”的函数。把原来的唯一字段/验证顺序抽成 `write_result(result,
limits, sink)`，其 value emission 继续复用现有 `write_value`。

基础切片已加入 opaque、只读借用的 `ResultEncoding<'r>`，前三步已实现；第四步仍属于后续池：

1. `plan_result(&TransactionResult, SqlLimits)` 用 checked counting sink 跑原 emitter，
   返回借用原 graph、limits 与精确 `len` 的 plan；计数不复制 String/Blob。
2. `plan.write_exact(&mut [u8])` 对恰好 `len` 的固定 slice 跑同一 emitter；不能增长。
   plan 的原 graph 保持不可变借用，避免计数和写入之间换一个结果。
3. 现有 `encode_result` 保留 API，内部变成 plan + 空 Vec 的一次
   `try_reserve_exact(len)` + `resize(len, 0)` + 固定 slice 写入。reserve 失败为
   `SqlError::ResourceExhausted`。不添加第二套编码规则，不调用 `shrink_to_fit`。
4. service 使用 plan 获取 R，**先取得 R 的 credit**，再调用同一固定缓冲写入能力。
   不能先调用普通 `encode_result` 得到 Vec，再申请 R 追账。

保持原限制验证和错误优先次序，包括 12-byte header、row/column/value 限制、finite
float、row width、metadata footer；非法输入计数阶段就失败。写入长度不符是内部
不变量错误，不是额度容差。固定字节 golden、所有 Value 类型、边界限制及原 decode
round-trip 都要核对；不能只比较两个共享同一错误算法的结果。

原 `778a4d2` 的 `scap-object-sqlite/src/lib.rs` 中，Writer::query 生成完整 wire Vec 仅为了
验证，然后丢弃。基础切片改用 `plan_result` 完成同一验证，不新增编码。execute 的
publication 前 wire 仍需要实际 Vec，使用改后的原 `encode_result`；它的分配暂不归
service pool。已有 native rollback 路径必须收到新的 ResourceExhausted，而不是伪装
为 durable corruption。

### capacity 保证的准确前提

标准库 API 文档只保证 `try_reserve_exact` 至少取得请求量，不能脱离工具链证明把
len 当 capacity。已读固定 Rust 1.90.0 的原始源码：`RawVecInner::grow_exact`
计算 `len + additional` 并把这个 cap 写回；Global 的分配返回请求 Layout 的大小。
对 **新建、空的 Vec<u8>** 一次 exact reserve，当前工具链的可见 capacity 就是请求量。

- 原始来源：`rust-lang/rust` tag `1.90.0`，
  `library/alloc/src/raw_vec/mod.rs`，Git blob `40716755aad34ca8464ddf25d0a48ebe3d7567c7`；
  `library/alloc/src/alloc.rs`，blob `c9b98fa4e5a9b899146b29e63ff51f24a4094b65`。
- 实现需把工具链/目标及 capacity == planned 的回归作为此证明的条件。改变 allocator
  abstraction 或工具链时重新核验；事后看到 capacity 变大再补账，不能证明申请前上限。
- 这里收费的是 Rust 可见 backing capacity / requested Layout；malloc size-class
  rounding 和实际 RSS 不在承诺内。不需要为第一片引入手写 unsafe allocator。

## 3. Base64 与最终 JSON：都先定长，再分配

`wire::result` 先取得上述 plan。拿到 R credit 后分配 wire；再用
base64 0.22.1 的 `encoded_len(R, true)` 得到 B，先取 B credit，分配恰好 B 的
Vec，用原 `STANDARD.encode_slice` 写入。`String::from_utf8` 消费 Vec；显式 move
进 Value::String，延续 PR45 的去副本结果。不能退回 `STANDARD.encode` 或
`encode_string` 的自动增长接口。R 和 B 同时存在时同时收费；wire 真正 drop 后才释放 R。

lookup/cancel 已拿到 durable raw Vec；第一片只为其新增 Base64 分配申请 B。
原 raw Vec 的容量不应被事后包装宣称为全程受控。原始 retained bytes 仍由 core 验证，
不能为了当前本地池小而缩小 durable 64 MiB 格式限额。

最终 JSON 用同一 `serde_json::Serializer` / compact formatter 两遍：第一遍是 checked
`io::Write` count sink；第二遍是预先取得 J credit、一次 exact reserve 的固定 slice
writer。原 Value 仅借用，不能 `to_value` / `json!` 深拷贝。serde_json 1.0.145
`ser.rs:2082–2132` 按借用片段写转义，不构建另一个 expanded String；数字格式使用
固定小 buffer。因此 count 不产生一个 J 大小的影子输出。两遍都使用同一成功/错误
Serialize envelope 和原字段类型，第二遍字节数必须精确等于 J。

推荐在 **原阻塞 worker 上完成最终编码后再发 oneshot**，避免在 Tokio executor
上同步扫描大 Base64/JSON。HTTP 专用 reply 只带 status + 已拥有的 Bytes；公开
Engine::execute / Worker::execute / Scheduler::submit 的旧 Result<Value,Failure>
路径可以继续存在。编码使用原 deadline；不创建新 timeout。HTTP 原 deadline 赢时
仍 UNKNOWN，已发派工作和 credit 继续活到真实完成。finalizer 在最终 JSON 编码后、发送 oneshot 前还必须复查同一个原 deadline。若已
过期，丢弃成功回复/关闭该 sender，让原 HTTP missing-reply 路径返回 UNKNOWN；
不因为本地还知道 receipt 就延长响应机会。CPU 编码正在执行时不是取消 native 工作的证据。

## 4. 源码给出的峰值，不使用最大 R 作 admission 门票

令 B(r)=4*ceil(r/3)，committed JSON J<=B(r)+711，query J<=B(r)+33。
在上述 exact allocation 前提下，service 新大缓冲的阶段是：

| 阶段 | 池内大 backing | 另外仍可能存在的排除项 |
| --- | --- | --- |
| count | 0 | typed graph T |
| wire 完成 | r | T |
| Base64 编码 | r+B(r) | T；lookup 的原 raw Vec 仍属于 core 输入 |
| Value 返回 | B(r) | Engine 返回前 T 才被 drop |
| JSON count | B(r) | 小型投影由基础信用覆盖 |
| JSON 写入 | B(r)+J | 无第二份 Base64 Value |
| body / 最后 Bytes clone | J 的实际 capacity | 工作未结束时仍有基础 hold |

因此新 service 峰值为 `max(r+B(r), B(r)+J)+E`，其统一上界是
`2*B(r)+711+E`。这次 2B 上界成立是因为先消除了旧 Encoder 的几何增长；不能把
它倒套到旧实现。取本片统一 E=65,536 B，R=64 MiB 时为 179,023,223 B，
R=50 MiB 时为 139,876,383 B。它们只作启动合法性/极端容量校验，实际申请仍按 r/B/J。

E 是保守小工作信用，不是在启动时真的 malloc 64 KiB。沿用已推导的最大公开小投影
图上界：metadata `2*19401+1333+4096=44231` B，原 CBU/result 投影小于此。
预先准备的 small/fallback Vec 改为 **2,048 B**（替代旧研究中的1,024 B），增加
1,024 B 后仍远低于 65,536 B；它能容纳现有最大 metadata JSON<=1,536 B 和 CBU<=753 B。
预留还覆盖固定 owner/hold；其结构须有 size/feature guards。BTreeMap 节点、String
及 serde_json features 的原假设继续作为布局前提，不能称为 allocator 实测。

小结果最终 J<=2,048 B 时直接写这份预备 buffer，通常无另一份最终 Vec。普通几十字节
INSERT 的 admission 只占 64 KiB，加随后几百字节实际缓冲，而非 213 MiB。
small buffer 不得在 body 仍持有时给另一个请求复用。

## 5. credit、Rust 所有权与双条件释放

建议一个新 `output.rs` 提供 Pool、Lease/WorkHold、OutputContext、CapacityCharge、
OwnedValue 与 FinalOwner。manager 的单一 Mutex 事务同时检查 global/tenant/分区，
失败即返还，不在 allocator/encoder/S3 I/O 期间持有锁；不排队等待大额度。
tenant ledger 只在活跃 lease 存在时保留，数量仍受原 intake 限制。

1. HTTP 完成原认证/解析/class 校验后、submit 前取得基础 E 与 fallible small buffer。
   pool key 只能来自原 Principal，不能信任 body 里的 tenant。取得失败时 BACKPRESSURE，
   尚未派发；tiny static error Bytes 可继续使用，不能为了报告池满而再等待池。
2. Job 独立持有 WorkHold。另一个 OutputContext 跟本次编码/结果所有权走，初始二者
   共用基础 lease。不得复用 intake 的“字节数”假称输出 charge；两套职责各自保留。
3. 新增显式 `Worker::execute_budgeted(..., &mut OutputContext)` 是现有 dyn Worker
   factory 边界的最小可审查接线。旧 execute 不变；新方法默认 fail closed，生产 Engine
   显式实现。不能默默调用旧 execute 后追账；自定义 HTTP Worker 必须明确实现该能力。
   Engine 私有 budgeted 路径把 context 传入 queried/committed/resolved，禁止 TLS。
4. WorkHold/OutputContext 不能仅因 send 唤醒 HTTP 就退款。worker 返回的 Value 立即
   进入 `OwnedValue { value, context }`，明确保证 Value 先 drop、对应 guard 后释放；
   临时 wire 也用 bytes-before-charge 的 RAII owner。Base64 move 入 Value 后，charge
   作为固定字段随 OwnedValue 持有，不能放进可无限增长的 side ledger。
5. 在 worker 内 finalizer 消费 OwnedValue。成功时先销毁 Value/Base64 和其他已完成
   临时 backing，再把最终 Vec+其 CapacityCharge+基础 lease 移入 FinalOwner。
   若保留 HTTP 侧 finalization，oneshot **必须**直接装 OwnedValue，不能裸 Value；
   receiver cancel/send failure 返回的对象也按同一 drop 顺序处理。
6. FinalOwner 直接交给 `Bytes::from_owner`，AsRef 暴露固定 slice；它保存**原 capacity**，
   不从 remaining len 推导退款。浅 clone/slice 共享一次 charge；最后非空 owner 才
   drop Vec 后释放 charge。独立物理复制必须另申请。原 ReservedBody/ReservedBytes
   仍保留 intake lease，transport 提前 drop Body 而保留 data frame 时两种 lease 都在。
7. 基础 E 在 WorkHold 和 reply/body/final owner **双方都结束**前不退。各大 backing
   的 charge 可以在该 backing 已真实销毁时释放，但这不是宣称 Job 已完成：基础 hold
   继续覆盖后台工作。正常 close、queued cancellation、receiver 丢失、HTTP UNKNOWN
   和 scheduler shutdown 都不能把 still-running Job 的基础信用清零。

更简单而保守的末期规则：成功回复结束后继续把 E 留在最终 owner 直到最后 clone，
即使 Job 已先结束也不急于 shrink E。它避免退款竞态，成本是每个慢小响应额外64KiB，
受原 transport/intake 和该池共同约束；无最大 R 级预占。

## 6. 已提交结果失败必须保留原知识

| 位置/知识 | 输出额度/大 Vec 分配失败后的行为 |
| --- | --- |
| submit 前基础信用不足 | 现有 BACKPRESSURE，零业务派发 |
| query 转换，无提交证明 | 现有 LIMIT；不把 local resource failure 写成 CORRUPT |
| execute 已有可信 receipt（含 retained admission） | 原 COMMITTED_BUT_UNAVAILABLE + 原 receipt |
| lookup/cancel 已返回 Committed | 同一 CBU；不能给出未提交 BACKPRESSURE |
| 原 UNKNOWN / missing reply / outer timeout | 原 UNKNOWN，不虚构 receipt 或重放 |
| deadline 未过、metadata 正常值 | 用已准备2KiB buffer，避免 CAS 后另取大信用 |

原 `wire::result` 把任何 encode_result 错误映射为 CORRUPT；基础切片已单独
把 ResourceExhausted 映射 LIMIT，其它原不变量/格式错误保留原义。
`engine::committed` 继续将其后处理失败转换为 CBU，改用 match 移出可信 typed receipt
可避免现有 receipt.clone。`wire::resolved` 当前是 infallible Json 返回，budgeted
变体必须能返回 Failure，并在任何 B/J 分配失败时使用其已持有的 Receipt。

另一个已由基础切片修正的映射：原 native execute 的 encode_result 错误包成
`scap_object_sqlite::Error::Sql(e)`，service `Failure::from(Error::Engine(...))`
目前把这个嵌套 ResourceExhausted 落到 ENGINE。基础切片在 native 转换点
改成已有 Error::ResourceExhausted；不顺手
改动所有既有 SqlError 的含义。publication 已接受后的 native 失败仍走原 CBU。

final JSON 失败时，只有来自 budgeted Engine 的可信内部 committed Value 才可 move
或借用其原 receipt 子树。先 drop 大 result/半成品 JSON，再把既有 error envelope
写入预留2KiB buffer。字段名、decimal string、HTTP503和SDK形状保持；不从客户端
request 重建 receipt，不回查 S3、不尝试第二次 SQL。如果内部不变量错误使连预备
CBU 都无法编码，只能保留错误/关闭连接，不能制造成功、rollback 或新的提交证明。

## 7. 第一版配置建议：只保护小 control，不承诺大 lookup 槽

| 逻辑配额 | global | tenant |
| --- | ---: | ---: |
| aggregate `/v1` 编码池 | 512 MiB | 256 MiB |
| protected control/recovery 小工作信用 | 8 MiB | 1 MiB |
| shared 动态额度及 data 基础信用 | 504 MiB | 255 MiB |

分区是同一 ledger 的子约束，总额不能重复相加。control/recovery 的 E 从 protected
分区取，任何大 wire/Base64/JSON 增量都从 shared 取；data 的 E 和增量都用 shared。
protected 的128global/16tenant个64KiB信用是容量上限，不是服务成功或公平性保证。
data 不能吃掉这些小信用；其它 control 已占满时仍可 BACKPRESSURE。

明确不保证同时容纳同租户最大 execute 和最大 lookup/cancel：两个约170.7MiB峰值
超过256MiB。大型 lookup 在已查明提交后可能 CBU；小 status/metadata 仍可使用保留区。
若以后要保护一份最大 control，必须单独增加并验证额度，不能把这项承诺写进上述默认。

parsed Config 与直接 ServiceConfig 同一校验：版本/checked arithmetic/isize边界；
tenant<=global；两个分区总和不超过aggregate；启用分区至少一份E；shared 在空池时
能容纳一份最大合法路径的完整峰值（data还含E）；保留区不能为0而声称保护开启。
这保证默认不把某种合法最大结果设成永远不能完成，但并发时允许有界失败。
这里都是建议配置，778 尚无这些字段。

## 8. 文件与验证清单

后续完整 `/v1` 输出池所需生产改动（编码基础已经先行实现）：

| 文件 | 必要改动 |
| --- | --- |
| scap-sql/src/lib.rs + 新 result_encoding.rs（可内联） | 唯一 emitter、count/fixed sink、公开兼容 wrapper、fallible allocation |
| scap-object-sqlite/src/lib.rs | query 仅计数验证；新的 precommit allocation 错误精确映射 |
| scap-service/src/output.rs（新） | 一个 ledger、RAII charges、固定buf/serializer/fallback、FinalOwner |
| scap-service/src/wire.rs | budgeted SCAPRES1/Base64/resolved、ResourceExhausted 语义 |
| scap-service/src/engine.rs | 新显式 context 路径，公开 execute 不变，trusted receipt CBU |
| scap-service/src/scheduler.rs | WorkHold、budgeted worker capability、HTTP reply模式/所有权 |
| scap-service/src/http.rs | 派发前小信用；接收已编码reply；原intake与timeout保持 |
| scap-service/src/config.rs、daemon.rs、lib.rs | 唯一pool创建/启动验证/module与必要错误映射 |

单位/门禁必须覆盖：两个租户原子计费，非阻塞失败/无partial credit泄漏；tiny SQL不
占最大R；精确canonical字节；每个分配失败点和 pre/post commit区别；大结果峰值
不遗漏 wire/B64/JSON overlap；Value先drop；worker在oneshot发出后未退出时基础hold
不释放；timeout/断连/queued cancellation/shutdown仍inflight；最后frame clone保留
capacity；trustedreceipt全字段和SDK协议固定字节；所有新增生产Rust文件的原4D门禁。
实际 seam 再用受控 worker+真实HTTP验证慢客户端/UNKNOWN不会释放仍拥有的额度，
明确区分 mock 所有权证据、real TCP 证据和 RSS。门禁随各候选冻结后分别执行，本文不把计划写成已运行结果。

后续整合缺口应另列：catalogue scheduler 的 small projection/final JSON；discovery
线程的 Value/cursor/最终1MiB backing与原5s/4s时限；core retained/native wire及Frame
临时；typed graph的全局而非仅单工作预算；native allocator/CPU与S3缓存/请求开销。
未完成这些前，不能对用户宣称“所有输出层/所有内存问题已经解决”。

## 9. 静态来源

资源设计的原源码基线为 clean `778a4d2`；本次编码基础原文件另绑定 `5604126`：scap-sql/src/lib.rs、result_memory.rs；
scap-object-sqlite/src/lib.rs/sql.rs；scap-object/src/lib.rs/options.rs；
scap-service/src/{engine,wire,http,scheduler,intake,config,daemon,discovery}.rs。
固定依赖从 Cargo.lock 和本地 registry 核对：base64 0.22.1 engine/mod.rs:115/194，
serde_json1.0.145 ser.rs，bytes1.12.1 bytes.rs:254/1099。

Rust exact-capacity 依据为官方固定源码：
<https://github.com/rust-lang/rust/blob/1.90.0/library/alloc/src/raw_vec/mod.rs>
及 <https://github.com/rust-lang/rust/blob/1.90.0/library/alloc/src/alloc.rs>。
容量算术是基于固定源码的静态推导，不是基准测试或运行结果。
