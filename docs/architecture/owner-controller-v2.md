# 有限 Scope 的持久 owner 自动控制器：实施提案 V1

状态：实现草稿，单独工作树推进。policy、单 Scope 状态机、fleet、owned HTTP 与 CLI 已通过148个组合开发单位、20个生产模块精确V8检查，以及11个真实loopback/子进程检查；独立有限模型和真实产品网络合同继续验证。本稿不认证已冻结 HEAD8 core 以外的后续产品。

代码依据为已冻结 HEAD8 的 `owner.rs` / `owner_format.rs`、
`owner_wire.rs`、SDK `owner_plan.js` / `owner_plan_wire.js`、`route_registry.js`，
以及 `accepted-owner-plan.md` 和旧 `owner-controller-plan.md` §4。
公开 API 已有完整 Scope、actual worker guard、原 descriptor hash/ETag、accepted phase、
stable proof 和当前 ADMIN；本提案只组合这些正式入口，不实现另一套数据库运行时。

## 1. 目标与不可扩大的边界

一个可选 controller 管理显式配置的有限 Scope 集合。控制器可以在原进程退出、本地目录
全部丢失后发现当前 accepted owner plan，并在同一计划允许的阶段继续 resume 或 abort。
没有 accepted marker 时，也能处理持久 descriptor 已存在但准备响应和本地输入全部丢失。

所有业务 SQL、原请求身份、原结果和 UNKNOWN 查询责任仍属于业务客户端。
controller 不接受 SQL、不调用 execute，不因为 owner 变化重放请求，不产生旧调用 ACK。
网络故障检测只是明确的可疑策略；CAS fencing 决定唯一可接受写入，并不证明被迁移实例死亡。

首片不做动态 Scope LIST、全 fleet 选主、租约、heartbeat 对象、自动 registry 滚动迁移、
动态加入 worker、人工迁移协调或无限历史回收。健康长期空闲 owner 的正常 tick 不写 S3。

## 2. 固定 policy 与多 controller 一致性

每个 Scope 的有效 policy 固定：完整 Scope、可信 authority 标识、专用 controller principal/creator、
受信 metadata 入口集合、worker→endpoint/rank 表、允许的自动模式、探测分类/间隔/阈值、
总期限和硬资源上限。rank 是唯一有序整数，worker 和 endpoint 不重复。配置构造后深度冻结。
token 不进入 policy；同一 principal 的 token 轮换不改变身份。principal 或 registry/rank
改变是另一个 policy，首片不能自动跨越。

### 2.1 用已有四 nonce 保留完整 policy 承诺

建议不新增 S3 journal 或 HEAD 字段，而将完整 SHA-256 承诺放入现有四个 nonce：

1. 对有版本、字段固定、u64 全 decimal、集合排序的 canonical per-Scope policy 编码。
2. 计算 `SHA256(UTF8("SCAPOWNERPOLICY1") || 0x00 || canonical_policy_bytes)`；域分隔字节
   固定为明确 UTF-8 前缀加一个 NUL，不能让日志显示形式改变实际字节。
3. 按 claim/cancel/activate/abort 顺序，分别取 4 个连续 8-byte big-endian unsigned 整数。
4. 显式检查四值均非零、两两不同；不满足就拒绝配置。不得随机补值、加盐重试或丢弃位数。

每个值转换为 u64 decimal，核验时恢复成固定 8 字节再连接，恰好是原 32 字节摘要。
这不是用随机 u64 分配 operation，也没有把摘要截成 64 位。密码学假设与仓库已有 SHA-256
内容身份相同。core 已确认：nonce 只要求同一 descriptor 内互异，没有跨计划唯一性约束。
不同计划共享这些 policy nonce 是合法的；计划区分依靠 Scope、creator/op、descriptor hash、
admission R/S 和原 ETag，而不是仅看某个 nonce。

所有合规 controller 在收养 accepted marker 或恢复自己的 unaccepted descriptor 之前，
都必须读实际 descriptor 并检查完整四 nonce、creator、Scope 与 policy 允许的 mode/target。
只比较 nonce 不能证明 target 存活、当前 ADMIN 或 native Session。

### 2.2 初始没有 marker、不同 policy 竞争、人工 marker

- 相同 creator、同一原 S 的不同 policy 会使用同一 operation key，descriptor first-wins。
  后来的不同 input 冲突，不能换 ID、另开 key 或改 nonce 绕过。
- 不同 creator 在初始 HEAD 上可能各自持久化 descriptor，但原 HEAD CAS 最多接受一条
  Claim/Cancelling。其他旧候选固定原 ETag；后继不会允许它换条件。
- 第一次 accepted marker 保留完整 descriptor 引用。此后每个合规 controller 只有看到
  自己的专用 creator 与同一完整 policy 承诺，才可继续 mutation。未知 creator 或 policy
  永远停在 Blocked；不得“取消陌生计划后接管”。迟到的已 invoked 旧请求仍由 core 围栏关闭。
- 人工计划由不同 principal 或不同 nonce 形成的 marker 视为 foreign policy。controller
  可以只读报告，但不自动收养或覆盖。显式人工迁移/启用新 policy 需要后续独立管理合同。

因此两个遵守规则但 rank 表不同的 controller 不会在一个已绑定 policy 的 Scope 上
互相自动 failback。这个约束由 controller 守卫与原 CAS 实现；core 的 ADMIN 接口仍允许
显式人工管理，不能把它宣传成对任意持有 ADMIN 凭据代码的全局共识或访问控制。
若产品将来要在服务端强制 policy，替代方案是独立 immutable policy anchor 或显式 core
字段/API；本轮不增加这层能力。

## 3. 不依赖随机数或本地计数的 operation 分配

专用 creator 的 operation 固定为 **本计划原 HEAD.head_serial**。该 creator 的整个 owner
operation 域保留给本 controller 协议，不与人工脚本共享。完整 Scope 是 key 的一部分。

合法 HEAD 更新严格增加 S，S 不复用且溢出失败，因此 `(Scope,creator,S)` 不会在较晚的
合法 base 重用。技术 compaction/GC 只增加 S 也分配新 operation；不能改用业务 R。
本地重启不需恢复计数器。另一个 controller 对同一 S 只会命中同一个 first-wins descriptor。

Prepare 前 checked 验证 R、S 至少留下两次后继空间，takeover 还需 epoch+1；pending
终态和元数据空间由 core 强制。operation 本身不用乘法分配 nonce，nonce 不依赖递增计数。
任何不符合专用域规则的已存在 record 都阻断该 Scope；禁止选择随机 operation 逃过冲突。

## 4. 每轮只推进一个明确阶段

每个 Scope 同一进程最多一个 in-flight tick。一个 tick 使用原绝对 deadline，至多一次
会改变控制状态的 owner RPC（prepare 的 immutable PUT 也计入）。其余请求仅为有界
fresh authority、history 或 guarded probe。下一 tick 是新的状态机步骤，不延长旧请求。

| 当前状态 | 允许的本轮动作 |
| --- | --- |
| Ready、active、无 pending，owner guarded probe 正常 | 清除怀疑窗口，报告健康，不准备或迁移 |
| Ready、inactive、无 pending，当前 owner probe 正常 | 按 policy 准备/继续独立 activate-only，target 与当前 owner 一致 |
| 当前 owner 控制路径不可达，其他入口 fresh authority 可得，窗口达标 | 探测较高 rank 的受信目标，准备/继续原 S 的 takeover 候选 |
| 本 policy 的 Claimed | 新鲜核验后，对原 target resume；目标确实不可用且策略达标时 abort 原计划 |
| 本 policy 的 Cancelling | 当前 ADMIN 显式执行下一次 abort，推进 Aborted；不再探测或激活原 claim |
| 本 policy 的 Aborted | 先根据新的当前 HEAD 建立新观察；inactive owner 健康可 activate，故障则只能向更高 rank takeover |
| 历史 Active、当前 inactive | 历史成功不授予 Session；Ready 且存储维护结束后，按新 base 准备 activate-only |
| pending 属于未知 creator/policy，非 Ready，copy/sweep/terminal，未知 owner/route | Blocked，无 mutation |

普通 status 对 Deleted 返回生命周期拒绝，足以停止本 controller；无需靠它发现 Deleted
历史。已知操作的 metadata-only owner history 仍可单独管理。只授 ADMIN 而无 READ 的
controller 无法使用现有 guarded status，首片明确要求 READ+ADMIN，不暗中增权。

## 5. 已 accepted 计划：不需要旧 saved input

1. 通过可信 metadata endpoint fresh status 得到当前 marker reference。
2. 调用 `ownerObserve({creator,operation})` 读真实 descriptor、accepted 与 current status。
3. 要求 current marker 仍与被收养 reference 完整相等；accepted 也匹配。若它已成为历史
   终态而 current marker 不同，则不推进旧计划，重新观察当前状态。
4. 校验完整 Scope、creator、四 nonce policy 承诺、descriptor identity/hash、mode/target、
   已知 route/rank；禁止从服务响应获取 endpoint。SDK 的严格 marker/phase/counter 规则保持。
5. 用经过上述政策核验的 actual input 调用纯 `prepareInput`，再 `inspect(savedInput)`；
   SDK 按完整原输入复核后返回 Prepared brand。纯 `observe` 的对象永远不直接传给 mutation。
6. 再次检查本次 observation 中 marker/phase/当前 owner，按 Claimed/Cancelling 决策一次
   resume 或 abort。claim/resume 必须发送原 target guard；abort 可走可信 bootstrap。

这里没有凭缓存 marker 授权。第二次 inspect 或最终 core guard 遇到并发 ACL/phase/owner
变化时会拒绝或只返回历史观察；控制器不刷新原 descriptor，不修改原 CAS 的 ETag。
新 resume 可按仍 Claimed 的 fresh base 建立自己的合法后继，旧 invoked CAS 不撤销。

## 6. 已有 unaccepted descriptor，但本地原输入丢失

这是 V2 必须闭合的窗口，不能退回 V1 的永久 InspectOnly，也不能凭任意 history mint 权限。

重启后先按当前 S 计算专用 identity，做只读 `ownerObserve(identity)`。Typed Missing
只说明本次观察；另一个旧 prepare PUT 可能仍在途，不能将 Missing 解释成 NotApplied。
再次 prepare 仍使用同一 identity，first-wins 和 immutable readback 处理旧 PUT 与新请求竞态。

若实际 descriptor 已存在，自动收养必须同时满足：

- `creator` 为固定自动化主体，`operation == current head_serial`；Scope 完整相同。
- input.expected_revision/head_serial 与本次 current authority 的 R/S 相同，state 为 Prepared。
  state Prepared 由服务检查完整原 canonical HEAD hash 和同次 ETag，不只是公开 counters。
- 四 nonce 恰好编码本 policy；mode、target 都在固定规则内。takeover 的 target rank 严格
  高于当前 owner；activate-only 只允许当前 inactive owner 本身。
- 任何准备前的故障窗口都不从磁盘继承。重新完成当前 owner 的失败阈值、最短间隔、
  fresh authority 不变检查；activation-only 则需要当前 owner 健康和明确启活策略。
- 准备执行 claim 时，实际 first-winner target 必须重新通过正确 worker 的 guarded probe。

这些条件成立后，应用作出“继续这个固定 first-winner”的新策略决定，构造 actual input
的 SavedInput，再发一次 `prepare(actual input)`。必须返回相同 reference 的 Prepared；
下一轮才能 claim。**不是直接给纯 observe 对象加 brand，也不是用新的首选 target 改写旧 input。**
并发可能在核验后改变 HEAD，最终 claim 仍固定原 descriptor/hash/ETag，失败就重新观察。

若 actual target 与这个 controller 原本首选不同，但符合本 policy 且新探测正常，应继续
first-winner，避免同一 base 不断竞争不同目的地。若它属于本 policy、原 base 仍匹配，但
目标持续不可达，controller 可按明确取消策略重新 prepare 同一 input 取得核验后的值，
下一轮 abort：先 Cancelling，再 Aborted，关闭旧 claim 的未来效果。取消可能使旧 owner
inactive，这是故障策略授权的管理动作，不是“没有效果的清理”。完成后才从新 S 选目标。

若计划仍未 claim、原 target 不可用，但当前原 owner 已恢复为 active 且健康，则保持只读观察，
不为清理 descriptor 执行 abort。该记录可以继续存在；健康 owner 不应因历史失败的候选
而被无故设为 inactive。只有后来新的完整故障窗口成立、原 target 仍不可用，当前 ADMIN
才可依同一 policy 显式取消这个固定计划。取消闭合后从新的 R/S 选择更高 rank 目标，
始终不修改旧 input。

上述只读保护针对 **active 且健康** 的原 owner。若原 base 明确已经 inactive，而当前
原 worker 的 guarded probe 健康，则未接受的 takeover first-winner 会占住当前 S，令
独立 activate-only 永久冲突。此时 policy.cancel 开启后，控制器可 fresh 核验完整原
base 为 Prepared/inactive，原样 reprepare 该 input；后续 tick abort 到 Cancelling/
Aborted，再从新 S 准备 activate-only。不为此更换旧 input、descriptor 或 CAS 的 ETag。
若别人先激活原 owner，旧 base 的取消条件失败。若判断之后别人先 Claim 同一固定计划，
该已授权的 ownerAbort 可关闭它的 Claimed，但不能撤销已 Active 的终态；这不是对
“只在未接受时取消”的保证。若本轮 fresh 已看到 Claimed，仍走目标自身的故障窗口规则。

目标不存在/nonce或policy不符/同 identity 内容自相矛盾/Scope不符不属于这种自动取消；
它们必须 Blocked。若 original base 已被较晚合法 HEAD 取代，旧 descriptor 本来就不能
再 claim；保留 pastUnknown，在新 tick 处理新的当前 authority，不声称旧 prepare 没有发生。

## 7. 单调 rank 与误判、退避

自动 takeover 必须满足 `target.rank > current_owner.rank`。同 rank 仅允许 activate-only，
不自动用同 worker takeover 增 epoch。每次 mutation 前重新核对实际 current owner；
人工反向迁移、foreign policy、未知 worker 或最高 rank 耗尽均停止自动 takeover。
固定 registry、没有外部反向管理的历史中，已接受自动迁移最多 N−1 次。取消尚未接受的
候选不增加 owner rank，故该界限不是所有 prepare/abort 尝试次数或存储成本上界。

已 Claimed 的 target 失联时，先完成针对该 target 的 fresh authority、失败窗口与退避，
再 abort 原计划。Aborted 后的当前 owner 仍是该已接受 target，下一 takeover 的 rank
必须从它计算；不得回到更低 rank 的旧 worker。LIMIT 是恢复预算或配置问题，
RECOVERY_BUSY 是准入压力，两者都不累计死亡，不可借此连续晋升耗尽 registry。

只对 TRANSPORT/客户端 DEADLINE 增加“控制路径不可达”的怀疑，且同轮另一个入口必须
能 fresh 读取同 Scope 的相同 authority。401/403、TARGET_MISMATCH、未知 route、错误
wire/redirect、MISSING/CORRUPT、policy 冲突不累计；429/RECOVERY_BUSY/LIMIT 有界退避。
已核实的 S3/服务端 UNKNOWN、UNAVAILABLE 不能直接当成 owner 死亡。

默认 controller HTTP 将已识别的 TLS 证书错误、错误 HTTP framing 和重定向拒绝归入非死亡
错误；普通 SDK 注入的 Fetch 仍可能把多种底层故障统一为 TRANSPORT。DNS/网络配置错误
与连接失败仍不能全部区分，它们可能导致可疑策略误判。guarded probe 正常只证明控制路径和 fresh READ，
不证明数据 actor 没有卡住。两种局限都需明示，不能声称精确故障检测或无条件 RTO。

FailureObservation 只在内存保留 full Scope、owner tuple、R/S、active/lifecycle、storage
与 marker identity、policy digest、单调首末时间和失败次数。任一权威变化即清零；重启
清零。退避是调度成本控制，不是租约。建议固定初版：3 次失败、相隔至少 1 秒、跨度至少
5 秒；普通 tick 5 秒；忙退避 5→10→20→40→60 秒封顶。具体数值在实现 PLAN 中冻结，
不是生产 SLO。正常探测成功重置怀疑，不因偏好把健康 owner 迁回低 rank。

固定 N 个 worker 是部署与成本边界。每个新进程 incarnation 必须得到从未使用的 worker ID；
已经绑定给退出进程的数值不能分配给重启进程。当前产品没有实现身份分配服务、弹性注册、
无限补充 rank 或跨 policy 滚动一致性。registry 耗尽、worker 重启需要新的身份或配置迁移时，
停止自动推进并交由已有管理合同处理，不能将这些人工前提包装成自动伸缩。

## 8. 绝对期限与资源上界

建议首版最多 128 个配置 Scope、256 个 worker routes、canonical policy 总字节至多64KiB；
每 Scope 一个 in-flight tick，全局最多8个tick、每租户最多4个，全局同时最多1个恢复RPC。
只保留每 Scope 一个固定大小状态与最后报告，队列不按轮次累积，不 LIST 动态扩张。

每轮最多8个HTTP调用、至多1个 mutation phase。owner 请求体 cap16KiB、响应 cap64KiB，
原普通tick总期限30秒；需要resume的tick使用明确的恢复总期限（上限与服务配置协调）。
deadline 从首次验证/authority读取前开始，探测、descriptor核验、SDK路由、Fetch、读取和
解码都传原剩余时间；进入恢复不重置。无剩余额度就不派发。下一轮的新期限只用于新的
状态机步，不重新定义旧 invoked 请求。

一次 tick 的 UNKNOWN 只结束本地等待，不撤销服务的实际工作，也不释放其 actor/recovery
permit。服务端已有归属和资源池继续约束实际工作；新一轮遇忙按策略退避。controller
自身本地限额不是整个 fleet 的全局预算。真实分母必须记录每次原请求和后台已完成清理。

CLI 使用独立的有界 HTTP 归属与关闭流程。现有 global Fetch 的 SDK 调用次数不能直接证明
整个进程 FD/RSS 上限。固定 Node 版本和连接 cap，单独验证慢响应、Abort、shutdown 和
实际资源峰值，不以逻辑字节 cap 冒称 RSS 硬隔离。

## 9. 当前 API 是否足够

上述 Ready/READ+ADMIN/专用creator/固定policy 范围内，现有公开 API 足够，无需新的
mutation endpoint、S3 signing 身份或 fleet journal。需要新增的是 controller 的封闭策略
类型、policy canonical codec、原总预算组合、调度器/CLI和明确报告，不是放宽SDK brand。

当前不支持的扩展：ADMIN-only 无identity当前计划发现、Deleted named库仅凭Scope的
全部历史发现、在线registry/policy迁移、动态worker登记与产品保证的incarnation分配。
它们若以后需要，应新增独立合同；首片不能靠不受信URL、复用名称或旧 worker数值绕过。

## 10. 独立门禁与报告知识

必须先有限模型，再正常生产模块单位精确覆盖、实际多controller/HTTP/S3故障验收。
关键家族：

- 多实例相同policy同S、不同候选target的first-wins；prepare作用已发生但回复丢失、
  本地所有输入丢失后从实际descriptor恢复；Missing读与迟到immutable PUT竞争。
- 不同policy四nonce、同creator与不同creator各一组；首次CAS最多一胜，看到foreign
  marker后永远无后续mutation；未知manual marker只Blocked。
- accepted Claimed/Cancelling重启收养；同base旧CAS在abort前后effect；UNKNOWN后
  新步仍不改原descriptor、原条件和历史调用知识。
- rank不同的两个错误配置不能轮流迁回；同worker明确activate允许，自动takeover同rank拒绝；
  u64临界、technical S变化、policy摘要0/重复字、key冲突都失败关闭。
- ACL撤回、目标替换、proxy误绑、429、完整S3不可用、错误wire、慢恢复：不能当成无条件死亡。
- 原总deadline在validation/route/decoder各处耗尽时不发晚请求；SIGINT停止新tick、全部
  owned资源清理；实际后台工作仍由服务归属，不伪造取消。
- 种子SQL只执行一次，含非确定原结果与UNKNOWN；全程用原lookup/cancel核对结果，
  controller trace里没有execute。含原始HTTP/S3全分母、phase/R/S/nonces、身份、guard，
  独立oracle不读取controller报告来判定成功。

报告分开列 current authority、accepted历史阶段、本轮HTTP观察、已知/未保留的过去调用
结果、future fence状态与下一轮策略原因。历史Active只能报告“观察到已接受阶段”，
不能报“原调用曾收到ACK”或“当前native Session已就绪”。所有未运行项明确NOT_RUN。

## 11. 当前实现与明确资源选择

生产模块位于 `sdk/node/src/controller_policy.js`、`controller.js`、
`controller_fleet.js`、`controller_http.js` 和 `controller_process.js`。策略的 canonical bytes 包含全部固定上限、
故障阈值、路由/rank、Scope、authority 和主体；凭据不进入摘要。四个 nonce 无损保留
整个摘要。每个 Scope 的 operation 使用原 `head_serial`，不会用本地计数器或随机身份。

普通 tick 30 秒、单次 metadata/guarded probe 最多 1 秒；恢复 tick 默认 30 分钟且只能
在创建原 tick deadline 时选择。重启后第一次发现 Claimed 的 tick 先只读核验，下一轮
才选择恢复预算。调用方可以缩短本轮期限，不能延长 policy 上限。每轮最多 8 POST，
最多 1 个 owner mutation；immutable prepare 也计入。任何 SQL API 都不在允许集合。

Fleet 固定最多 128 Scope、256 个唯一 worker incarnation，全部 policy canonical bytes
合计最多 64 KiB；每次轮询只在空闲额度内启动，没有累积 round 队列。同部署+tenant 最多
4 个 tick，全局最多 8 个 tick、1 个恢复 tick。每 Scope 只保留一个最新报告，未消费报告
不会无限排队；它不是完整事件日志。关闭停止新 admission、终止本地等待并等待所有本地
owned 网络资源清理，不宣称撤销已经到达服务的操作。

Node 固定 22.16.0；默认 HTTP 使用内置 http/https，关闭 keep-alive（每个请求独占连接），
无重定向和隐式重试。绝对原 signal、16 KiB 请求/headers、64 KiB 响应和真实 request/socket
关闭后的资源归还由独立单位与 loopback 合同验证。不可取消的系统 DNS 查询在 callback
真正完成前继续占用原 slot；abort 不提前退款。TLS 明确要求 `rejectUnauthorized: true`，
不会因 `NODE_TLS_REJECT_UNAUTHORIZED=0` 接受自签名证书。逻辑资源限额不等同于容器 RSS 硬隔离。

CLI 入口为 `sdk/node/bin/owner-controller.mjs`。启动时读取一个至多 64 KiB 的普通 JSON
文件，固定一次配置；读文件本身有字节上限并检查同一 fd 前后大小与纳秒修改时间。打开时
使用非阻塞标志，FIFO/设备在类型检查时被拒绝。凭据只通过显式 `tokenEnv` 获取；日志不含
凭据、文件路径或原底层异常。所有 Scope/worker 的组合约束仍在 fleet 构造时验证。

进程每 250ms 检查可用 slot；Scope 自己仍遵循 5 秒 tick 和固定退避，没有每 250ms 创建
新轮次的队列。标准输出为每 Scope 最新完成报告的 JSONL；每行最大 128 KiB，使用一次
同步 fd 写入，不建立异步日志队列。部分写、EAGAIN 或其他写错误立即停止新 admission 并
关闭 fleet。阻塞的内核输出目标会阻塞进程，部署方应使用受控日志消费者；这与系统 DNS
不可取消一样，意味着本实现不承诺固定 shutdown RTO。报告不是持久审计日志，也不补造
未消费的旧报告或旧调用 ACK。库使用方可自行调用 `poll()` / `takeReports()` 接入自己的
有界观测出口。

SIGINT/SIGTERM 停止轮询，然后等待所有 Scope tick、请求、socket 与 DNS callback 完成。
重复 SIGINT/SIGTERM 仍走同一关闭流程；SIGKILL/外部强制退出另算，不能记为 graceful join。
关闭期间才完成的最新报告可能没有输出，因此 JSONL 不代表全部调用历史。它只关闭本地
工作，不撤销已在服务 admission 的 owner 操作。重启从实际持久计划重新查证。

参考：[Node 22.16 HTTP](https://nodejs.org/download/release/v22.16.0/docs/api/http.html)。
