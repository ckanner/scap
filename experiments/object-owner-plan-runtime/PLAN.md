# HEAD8 accepted owner plan：真实运行合同

状态：**actual01/02 均保留原失败；本轮夹具修订待冻结后执行 actual03**。失败与修复边界见 [ACL 调度诊断](../../docs/evidence/owner-plan-actual01-acl-diagnosis-2026-11-11.json)；第二处同 lane 问题见 [legacy 调度诊断](../../docs/evidence/owner-plan-actual02-legacy-diagnosis-2026-11-11.json)。产品、SDK、正式二进制和本夹具源码各自固定身份后，才能执行新实际合同。71 个轻量单位包括真实公开 SDK 和签名 loopback 传输；这些单位不代表本合同的产品实际通过。

## 权威、目的与固定分母

使用正式 `scapd`、公开 Node SDK、正式 native seed worker、带 SigV4 的本地 SeaweedFS S3。直接数据库通过公开 create/SQL/策略 API 建立；具名数据库通过真实 Catalogue Creation/Name/Control 建立；260 次 native SQL 建立 129/129/2 三个 retained 窗口。禁止重写 HEAD 构造正例，禁止私有 Session/路由/计数器，禁止在 UNKNOWN 后刷新原输入或 If-Match。恢复成功结果只调用原 request 的 lookup；另有一个明确的负边界探针，在 pending owner 时提交旧已成功 request 的 execute，必须在 SQL 执行前返回 FENCED，不计作新的 SQL 成功或恢复。

`spec.py` 独立固定全部 SQL、Scope、owner identity、mode、目标进程身份和四个 nonce。原 `expected_revision/expected_head_serial` 只在该新意图首次保存时取自前驱真实观察，此后 JSON 持久保存，任何重试沿用原字节。分母由固定输入计算并在单位、runner 和独立 oracle 中分别核对。

| 分母 | 数量 |
| --- | ---: |
| 完整 Scope | 17（15 direct、2 同名不同 Creation） |
| 保存的 SQL 原意图 | 297 |
| 原 SQL 成功 ACK | 295，其中 native 260 |
| 全部本地服务缓存丢失后的原成功结果 lookup | 292 |
| 另外的 cold cancellation / 原阻止请求 UNKNOWN / 业务查询 | 1 / 1 / 16 |
| 保存的 owner 输入 / 真正 Descriptor | 50 / 46 |
| admission：Claim / Cancelling | 43 / 2 |
| 终态：Active / Aborted | 36 / 9 |
| 永久 terminal Proof | 28 |
| owner POST：prepare / claim / resume / abort / inspect | 53 / 49 / 47 / 16 / 35 = 200 |
| S3 故障 / S3 delivery / HTTP 故障 | 23 / 26 / 5 |
| 服务 incarnation / SDK controller incarnation | 10 / 10 |
| owned wait4 | 27：10 服务、10 SDK、1 native、2 版本进程、4 后端 |
| 全历史负控 / 原样正控 | 42 / 1，持久保存全部副本及目标 guard |

295 个成功 SQL 中，具名旧 Scope 的 3 份结果随明确删除和终态回收失去普通 lookup 资格；它们的原 ACK 仍完整保留并检查，292 个存活结果逐字节冷 lookup。bulk 的一个取消和一个被 pending 阻止的新 SQL 分别保持 Cancelled 与 Unknown。历史 Result.data_root 是 receipt 元数据，不把它误当作恢复依赖。

## 进程、原期限与观测

初始服务 A/B/C/R/G/Z 分别为 9101/9102/9103/9104/9105/9106；native seed 为 9000。真正的 daemon 重启必须换数值身份：R → 9204 → 9304，B → 9202，冷 C → 9203；SDK controller 重启不改变仍存活 daemon 的身份。所有已调用进程用其 owned Popen/wait4 回收并记录原身份；禁止根据外部 PID 猜所有权。

每个 worker incarnation 使用独立 HTTP 代理监听地址，满足 SDK allowlist 的唯一 endpoint 规则。旧 route 仍转到同一 daemon listen port，因此重启后旧计划真正到达新实例并得到 TARGET_MISMATCH；不会复用 worker 数值伪造跨重启安全。六个 S3 代理只转发所属服务原签名调用；另一个代理独立记录正式 native seed 的完整分母，共 7 个。没有额外 operator 对象修改进程。

固定 SDK control 90s、recovery 300s；服务 HTTP/S3 120s，实际 owner control 仍受 core 自身原 30s 上限；故障调用独立 SDK 1.5s 原期限；每个 proxy hold 180s、整个 raw 1200s。重发是明确独立调用，不能延长旧调用。两个同目标 resume 经同 Scope actor 串行：第一完成一次 Active 发布，第二返回历史 Active；不宣称实际同时发生两个 CAS，算法 CAS 竞态另由 core/model 验证。

每个 HTTP observer 最多 16 个 handler、10,000 请求、128 个 gate，单请求 1 MiB、单响应 64 MiB、header 16 KiB / 64 项；输入/输出各 10s、后端 330s、关闭 join 共用 10s 绝对上界。S3 observer 的每次真实后端连接上限 15s、输入 10s；hold 的 180s 不能续期。启动期 `/healthz` 活性探针不计入 `/v1` / `/v1/catalogue` 产品 POST 分母。

第二 resume 和预算场景的 query 在旧 S3 请求仍持有时，必须已经由实际 HTTP observer 完整 forward；不能仅凭写入 SDK stdin 就放行。query 的 scope、目标进程和 data lane 与原 recovery actor 一致，原 descriptor 投递后才能出现 query payload GET，且必须返回原行。HTTP observer 的两个响应读取线程不保证按 actor 完成顺序运行，因此不把两个 socket 响应日志的先后当作调度器内部时钟。

HTTP 代理保存原请求、真实完整产品响应、向 SDK 的投递/断连及独立关闭时总数；SDK 自己保存原 Fetch 和原 UNKNOWN。S3 保存原 method/path/headers/payload hash、签名验证、forward、真实 backend 响应、可能被注入的 delivery、完整 handler 和关闭时总数。Authorization/secret/token 只存内存和 private 配置，公开证据仅 hash。代理不自动 retry。

## 固定家族

| 家族 | 原调用与必须发生的实际边界 |
| --- | --- |
| bulk | prepare/claim/resume 三个产品 ACK 分别丢失，重启 controller 仅用原完整输入 inspect。prepare 后 ACL 改变使原 P1 Fenced；同 ID 改 base Conflict，原输入仍返回同 Descriptor。P2 Claimed 时 READ query/lookup 和已知 cancel 可读；execute（包括旧已提交 request）、新 cancel、close/lifecycle/compaction/GC/legacy owner 必须 Fenced。恢复遍历全部三窗口和所有 retained result。 |
| late_prepare | Descriptor PUT 已 invoke、SDK UNKNOWN 后杀原 A daemon，proxy 再实际执行原 PUT；新 controller inspect 原输入，继续同计划。 |
| claim_cancel | 原 Claim CAS 延迟；Abort 接受 Cancelling 后 ACK 丢失，杀原 controller daemon R，换身份重启；inspect + 原计划 Abort 到 Aborted；迟到旧 Claim 412。Cancelling 保留旧 A owner，后继独立计划必须 takeover B。另一 ID prepare 返回当前阻塞计划的 Pending，不可当 Prepared 发 claim。 |
| claim_wins | Claim 与原 base Cancel 两个原 CAS 同时持有；先放 Claim，后 Cancel 412。明确 Abort 使已接收目标 tuple 终止；原计划后续 activate-only 新意图恢复。初始 active owner 的 activate-only prepare 失败。 |
| resume_cancel | 完整恢复后的原 Active CAS 延迟，Abort 先终止；原 Active CAS 412，无伪 Active。 |
| resume_wins | 原 Active CAS 延迟后排入第二同目标 resume，再持有 Abort CAS；先放 Active，第二 resume 只观察历史 Active，迟到 Abort 412。后续 SQL 正常且历史 marker 不变。 |
| acl | 恢复 payload GET 延迟期间同权限 ACL 更新导致 Conflict；另一轮撤 ADMIN 导致 Denied。prepare Descriptor GET 在 C 延迟时，由 B 独立 daemon 查询状态并撤 ADMIN，原 C 调用也必须 Denied，不能泄露旧记录。新当前 ADMIN 12 用保存的 creator11 原输入 inspect/resume。 |
| target_death | 原 Claim PUT invoke 后退出 B，原请求随后真实生效；新 B worker9202 收到原 target9102 的 claim/resume 必须 TARGET_MISMATCH。当前 ADMIN abort 后新计划转向 R9204。 |
| resume_death | 恢复最终 Active PUT invoke 后退出 R9204，原请求随后生效；inspect 只能报告历史 Active，不能声称本地 Session。新 R9304 拒绝旧目标；新计划转向 C。 |
| legacy | C9103 原 HEAD6 takeover CAS 与 B9102 HEAD8 Claim 在独立 daemon 竞争，旧 CAS 被 admission fencing。原 legacy activate HTTP 在 Aborted 后才到达，哪怕 expected R 碰巧匹配仍 Fenced；不能绕过已采用的 owner 协议。 |
| proof_claim | 新 Claim 替换旧 Active marker 前，真实 Proof PUT ACK 丢失、Proof GET ACK 丢失各一次；未完成原 exact readback 不得改 HEAD。旧证明缺失仅 Fenced/未知历史；旧 Proof phase 达到当前 admission 的完整故障响应必须 Corrupt。 |
| proof_cancel | 新计划原 base Cancel 入口也必须先持久保存旧 Aborted Proof；Proof 回读丢失后无 Cancelling，原输入再次明确调用完成 Cancelling→Aborted。 |
| named_old | pending named delete 为 Conflict，可遗留原固定 Control，但不能改变 HEAD/Name/payload。Active 后使用新 operation/fresh R 执行真实 named delete；HEAD8 seal + final A GC 后，旧/current owner history 仍元数据可读。复用同名后仍按原 Scope 查看旧记录。 |
| named_successor | 真实新 Creation/Scope，两份 SQL；cold 首次 owner adoption 后原结果不受旧 Scope 回收影响。 |
| missing_descriptor | 当前 Descriptor Missing、旧 Descriptor Missing 但 Proof 存在均 Corrupt 且不得重建。当前 marker 同 creator/operation 换 hash，前后 exact HEAD 稳定时 Corrupt。Descriptor 的首次及重读两次 GET 都交付明确 Missing，夹在两次 Missing 之间和之后的 exact HEAD 必须稳定；历史 Proof 实际读取后还须再观察同一 HEAD。backend 原对象不删。 |
| budget_gets / budget_bytes | 预先配置 gets=0 / bytes=1 的真实目标。hold resume 的 Descriptor GET 时将 READ query 排入同 Scope 同 actor，放行后原 resume LIMIT、无 Active，队列下一 query 验证原行，证明同驻留 Database 未隔离。单凭同 PID 的 control 成功不算。Abort→新目标新计划能恢复。 |

## 独立判定

新 `audit_model.py` 严格独立解码 HEAD6/7/8、Descriptor、Proof，不调用产品 verifier，也不把 owner 字段删掉后交旧 HEAD6 判定器。HEAD8 包括历史 phase/admission 对齐、nonce/目标/epoch、当前 R/S 边界、`R == phase.R => transition.nonce == phase.nonce`；terminal HEAD 保留历史 owner marker，永久元数据不随 payload GC 删除。

oracle 从闭合 raw 分母重建所有 accepted HEAD CAS、原 ETag、Scope、当前 ACL、完整数据/retained closure、每次 SQL 结果及 receipt、owner proof 先于替换的因果、原请求先 invoke/原进程已 wait4 后 S3 effect、原 UNKNOWN 从未回填。prepare 的 hash/digest 按独立 canonical 字段次序计算；GET 的实际 backend 与注入 delivery 必须分开。

Metadata corrupt 故障只能使用计划明确的 delivery；保存 backend 原文和变异原文，不能将通用响应不一致判定整体放宽。同 ID 不同 hash 这一故障组，对同一次 inspect 的首、尾两次 exact HEAD GET 交付同一变异字节和原 ETag，才能独立命中稳定 HEAD2 后的 Corrupt；只改首 GET 会正确得到 Conflict，不算本边界通过。另一坏 Proof 只变一次 GET。静态 HEAD/owner 矛盾（包括 phase nonce 同 R 不一致）由独立 decoder 反例单位完整覆盖；实际本轮专测稳定 HEAD2 诊断，不能声称旧 actual 已覆盖新增静态规则。

Corrupt latch 的后继不能冒充新的物理诊断。`missing_descriptor` 的 current Missing、旧 Descriptor Missing+Proof、同 ID changed hash 分别经 C9103、R9204、G9105 的不同既有服务 lineage；`proof_claim` 的坏旧 Proof 是该家族最后一步，经 Z9106。oracle 必须看到每次对应真实原请求和计划注入被消耗，不能只看相同 CORRUPT 返回值；之后恢复只使用原计划已计入的 cold C9203，不清私有 latch、不复用旧 worker incarnation。

新增 current/historical 第二次 Missing 遗漏反例各一份。全量真实正证据之后执行 42 个持久保存的反例副本和 1 个原样正控；固定清单及目标 guard 在 `controls.py::cases()`。每个负控必须命中其目标 guard，不能以无关格式损坏冒充目标通过。whole exchange 删除必须被独立关闭分母拒绝；移除某项必要 Proof / retained result / HEAD2 读取的反例则同步调整其完整组和关闭总数，以明确命中语义边界。原 ETag、phase/nonce、同 ID hash、永久元数据 DELETE、三种进程退出后 effect、ACL、UNKNOWN、预算和冷结果都有独立反例。修改镜像采用先断开 hardlink 再写入，最后验证原始证据 inventory 未变化。

## 边界与交付条件

本合同不提供后台自动接管 controller，不证明 DNS/K8s 实例身份认证，不给通用 S3 或跨地域吞吐 SLO。只接受本次固定二进制、原限额、真实 SQLite/native/S3 的观察。未知结果保持未知；若失败，完整保留原进程/请求/源码/期限，修复后新 commit、新目录、新 attempt，不回填旧 PASS。

`run.py`、独立 oracle、42 个反例构造、71 个纯夹具单位及固定命令已实现。actual01 的同 Scope control lane 依赖环已定位；本修订将撤权完整路由至独立 daemon，actual02 又确认 legacy takeover 与 Claim 同 lane 导致原 Claim UNKNOWN，因此旧 takeover 改由 C9103，HEAD8 Claim 仍固定 B9102；两处均禁止延长期限掩盖调度错误。当前等待审查并提交冻结本修订；actual03 绑定正式产品 release 的原 receipt，每一项生产/SDK/native 输入都必须与夹具提交逐字节相同。禁止在未冻结的工作树提前跑产品 actual。正式 raw/oracle/controls 的结果应新增到独立验收记录，不能通过修改本计划回填通过。
