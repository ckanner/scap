# PR #59：SQLite on S3 组合验收

> 2026-11-13 接续：执行环境已恢复，旧原件缺失的门禁正在重新采集；当前结果见
> [本轮代码与验证](sqlite-s3-review-2026-11-13.md)。本轮发现并修复检查器允许单文件
> branch 0/0 的缺口，严格逐文件覆盖门禁仍未满足，PR 继续 Draft；见
> [测量说明](branch-coverage-measurement-gap.md)。以下保留 11–12 日的原计划与历史结果，
> 其中“环境不可用”“只余两项”及旧 checker PASS 不代表当前状态。


复核更新：2026-11-12（UTC）。本组合的主线基准是 HEAD7 `fab8ca0`。
[PR #59](https://github.com/ckanner/scap/pull/59) 的组合提交 `fc10287` 同时保留
#56 `1d709db`、#57 `df922b95`、#58 `4216523` 的 ancestry、实现和原证据；
`e485a97` 补回旧 controller 分支遗漏的 owner 夹具和历史证据。
SDK exports、类型和测试同时保留 controller 与 snapshot 两套接口。

## 源码与二进制归属

正式未插桩的 service 和 native/network release 均在干净 `fc10287` 构建，之后只改
夹具及文档。每次实际运行独立冻结源码，逐一验证原 receipt 的277个 service及183个
native build inputs等价，仍记录二进制真实构建来源，没有将新夹具SHA改写成release来源。
controller只需要service receipt；其原生SQLite静态archive也随receipt核对。
新增 listing、deployment discovery、resource 和 GC transport 二进制分别保留自己在
`3b1d50c` 的真实构建 receipt；它们不冒充 `fc10287` 的构建产物。各夹具的源码归属
与实际 Node 输入分别验证，文档提交不会改写已执行历史的 source commit。

| 验证层 | 本次冻结源码 | 新执行结果 |
| --- | --- | --- |
| Rust workspace | `fc10287` | stable/nightly各783项单位；fmt、严格Clippy、67个生产文件逐文件四维精确检查通过 |
| Rust覆盖分母 | `fc10287` | lines 14066/14066、functions 1283/1283、regions 21735/21735、branches 2768/2768；7个文件的真实branch 0/0单列，不冒充独立分支测量 |
| Node/类型 | `e485a97` | 157项SDK单位、21模块精确V8覆盖、19项真实HTTP/TLS/CLI loopback、strict TypeScript通过 |
| owner plan | `e485a97` + 原release | actual/独立oracle/42负控+1正控通过；721 POST、200 owner操作、10047签名S3、295原SQL ACK |
| Missing/HEAD并发 | `e485a97` + 原release | actual/独立oracle/13负控+1正控通过；63 POST、27 owner操作、344签名S3、6原SQL ACK |
| 生产controller CLI | `5f47ce8` + 原release | fresh actual/加强oracle/15负控通过；3个scapd、2个controller、30控制HTTP、3次owner变更、164签名S3 |
| retained snapshot S1 | `c6826df` + 原release | 49项夹具单位、fresh actual、独立oracle和10项负控通过；六原ACK/冷lookup、两保留根、55 HTTP、922 S3、13 wait4 |
| 固定负载与32 MiB恢复 | runtime `fc10287` / fixture `ffff164` | 871 POST、185原execute、288测量调用；actual/独立oracle/14负控+3正控全部通过 |
| native／schema／原结果／生命周期／目录／发现 | `3b1d50c` + 各真实receipt | 新执行15网络合同、30扩展故障、12×6=72个保留结果入口、12生命周期、116目录案例及完整部署发现；独立审计及指定负控通过 |
| 固定1 GiB全冷恢复 | `3b1d50c` + 原release | 16,384个64 KiB BLOB与关闭镜像完整校验；38 execute ACK+1 UNKNOWN原lookup分列，5负控通过；原4 GiB空间门槛未改 |
| 工具／模型 | `3b1d50c`；snapshot精化`6784258` | 74 tooling单位及精确覆盖、各固定完整模型通过；snapshot新38单位、804正例／48负控；只是模型，没有开放S2产品 |
| 多controller固定矩阵 | runtime `fc10287` / fixture `e64eb56` | 23夹具自测、12实际场景、独立oracle、31定向负控通过；57个实际JavaScript输入和原HTTP／S3／进程共同绑定 |

Rust使用全新target及profiles，218份raw和1份merged profile，没有混入集成profile。
完整精确计数和命令哈希见[Rust机器记录](../evidence/sqlite-s3-integration-rust-local-2026-11-11.json)，
SDK/类型见[Node机器记录](../evidence/sqlite-s3-integration-node-local-2026-11-11.json)。
实际合同的原输入、事件、源码、二进制、独立oracle、controls和失败摘要见
[runtime机器记录](../evidence/sqlite-s3-integration-runtime-local-2026-11-11.json)。
每个runner自身仍只输出`OBSERVED_NOT_AUDITED`，后续独立判定不回写原件。
接续的完整门禁分别见[native／容量记录](../evidence/sqlite-s3-integration-native-local-2026-11-12.json)、
[工具与模型记录](../evidence/sqlite-s3-integration-models-local-2026-11-12.json)和
[controller矩阵记录](../evidence/sqlite-s3-integration-controller-matrix-local-2026-11-12.json)。

原冻结 `3b1d50c` 的服务回归已完成HTTP、隔离、分段索引、发现、metadata、
输出池、响应过期、资源和GC transport的实际及指定审计已通过；HEAD6实际和独立oracle
已通过，其完整23负控／1正控与终态退休25负控／1正控尚未完成。执行环境现不可用，
不签发整体PASS，也不合入。

## 本次实际证明的行为

owner专项重新运行固定的丢响应、竞争、取消、撤权、目标替换、恢复预算、晚到请求和
全计算缓存丢失历史；原请求、结果、业务数据和永久计划/证明由独立账本核对。
它们没有运行自动controller，自动推进另用下述生产CLI合同验证。

controller先观察healthy，然后旧owner被SIGKILL且owned wait4完成，删除其整个缓存。
生产CLI自动prepare/claim；claim成功响应丢失后，新CLI进程从同一持久计划继续resume。
两份原客户端ACK、业务UNKNOWN与claim UNKNOWN分别保留；三份原请求只lookup，随机
结果与counter=3逐字节一致。已有snapshot的reference/point不变，旧worker guard拒绝
期间零S3调用。原claim/resume HTTP成功、accepted marker及当前authority独立核验后，
才与CLI报告交叉核对。缓存删除至active报告本次为26.916秒，只是该固定本地历史的观察。

接续的12场景矩阵在 `e64eb56` 完整执行612.476秒，独立oracle6.469秒、31项负控
12.894秒，均退出0。它涵盖同policy竞争、不同policy／creator阻断、人工marker、
Claimed取消、Cancelling重启、原owner仍健康、撤权、worker误绑、429及恢复LIMIT、
S3失败、探测期限、停机与迟到旧CAS。20个真实CLI和108个owned子进程都有生命周期
证据；586 HTTP中363个来自controller，另有1,914个签名S3请求。24份业务ACK、12份
UNKNOWN与36次原lookup分别核验，12个S1保留点均不改变。每个Node子进程在spawn前
绑定完整入口及57个SDK／codec／观察器文件，oracle与源码manifest／tar交叉核对。

最后停机历史保留原Active HEAD PUT的body与If-Match，待新controller已激活后才放行，
旧请求返回412；它不重签旧候选。只读M上的查询和guardedStatus分别证明恢复结果与
路由guard，不单独宣称该M已经成为writer或证明旧native writer fencing。固定fleet、
部署分配不复用worker身份和原有期限仍是前提；正确性运行时间不当作吞吐基准。

snapshot S1的固定历史包含两次capture、两次release、两个保留根、六份原SQL结果、
多根COPY/promote、退休代GC、全暖缓存删除后的恢复，以及Deleted终态seal对保留根的
保护。它不包含从历史根创建新Scope的S2，也不证明任意时间PITR。

本轮负载单库C1/C4写分别为5.149/2.822次每秒，四库C4为7.206次每秒；暖读为
217.396/223.134次每秒。每写约18–20个对象请求，排队和观察到的尾延迟明显。
完整p50/p99、固定分母、预期RECOVERY_BUSY、冷恢复与采样边界见
[负载机器记录](../evidence/sqlite-s3-integration-load-local-2026-11-11.json)和
[吞吐分析](../architecture/sqlite-s3-safety-and-throughput.md#54-本次组合的实际基线热点吞吐仍未解决)。
本轮没有运行同环境历史候选对照，不能据此判断某项代码优化或回退。

## 原失败与审计缺口保留

1. `e485` snapshot actual01因驱动提供错误Node路径启动失败；没有发生数据库验收。
   actual02运行完成，但oracle把GC的`?versioning`/`?object-lock`预检当作LIST，且把
   ordinary Listings误判为GC专用身份。`e56ce0a`严格区分bucket配置/32-key LIST，
   独立GC身份仍是预检、typed exact GET和DELETE的必要条件。原失败和开发诊断分别保存。
2. `e56ce0a` fresh snapshot actual/oracle通过，两个负控提前命中SDK/HTTP一致性检查。
   原因是全局替换共享内容body误改了后来独立送达的inspect。`c6826df`只修改原已丢ACK
   capture交换的私有引用，并加硬链接原件/兄弟请求不变回归。原负控失败不重分类。
3. controller `183396b`实际历史和oracle通过，SQL禁止负控因同类共享body替换命中错误
   guard；`ffff164`修正目标引用并重新执行actual。其九负控通过记录保持原样。
4. 后续独立审查发现`ffff164` oracle过度依赖CLI成功报告：仅把原resume HTTP换成
   FENCED的内存反例仍被接受。真实原响应本来正确，因此这是验收缺口；`5f47ce8`从原
   HTTP与原plan独立证明claim/active，补六项负控，再重新执行actual/oracle/15控。
   旧oracle副本、可复现反例及修复后的只读诊断均保留，不沿用旧通过范围。
5. 接续新增的`73a7140`完整12场景矩阵、旧oracle和28负控均通过，但独立复核将原
   controller argv入口改成另一目录下同名脚本，旧oracle仍接受。原实际入口正确，
   缺口在“实际执行源码”的验收绑定。新夹具在每个Node子进程spawn前核对入口绝对
   路径、SDK/codec/业务观察器全部固定文件hash和运行选项；oracle将这些原事件绑定到
   source manifest/tar及真实argv，新增3控共31。原结果和反例不改写，新冻结组合必须
   重新执行全12例actual/oracle/controls；已在新 `e64eb56` 完成，未给旧事件补字段。
6. `bb4057a` 的新绑定C1诊断在启动业务Node之前拒绝了环境默认`NODE_PATH`（通用
   artifact依赖搜索路径），24.740秒退出且完成清理；没有发生业务或完整矩阵验收。
   该失败保留。后续只从自有Node子进程环境移除这个不属于固定ESM/内建依赖的搜索
   路径，并在inputs记录；非空`NODE_OPTIONS`仍拒绝，全局环境不变，再冻结执行。

这些修正没有改变生产代码、固定业务工作量、时间界限或已规定的安全合同。
原PR的历史失败记录也没有覆盖；每次fresh实际使用新的目录和源码清单。

## 执行环境中断与恢复入口

[服务中断进展记录](../evidence/sqlite-s3-integration-service-progress-2026-11-12.json)只记录13个已完成服务合同、HEAD6已通过部分和中断点，
状态明确为 `PARTIAL_ENVIRONMENT_UNAVAILABLE_NOT_MERGE_READY`；它不替代尚未生成的最终服务验收。

本地服务回归在HEAD6负向验证期间失去原执行会话：工具返回
`Unknown process id 64770`。后续root短命令又返回
`exec-server transport disconnected; failed to resume exec-server session: recovery timed out after 45s`，
随后环境被明确标为 `unavailable`。这是实际观察到的执行阻断；不能据此把产品判为通过
或失败，也不能臆断服务回收的根因。

已有HEAD6 actual退出0（195.039秒）和独立oracle退出0（148.978秒）的原始记录保留。
首轮controls没有最终完整报告，已生成的部分负控目录不构成23负控／1正控全部通过。
其他已完成门禁不重分类；本轮终态合同仍缺完整结果。

恢复执行环境后的顺序：

1. 读取原 `commands.json`、各原件、源码manifest与build receipt，核对冻结 `3b1d50c`
   和实际 `fc10287` release；先检查是否还有存活验证进程，避免重复操作。
2. 原actual和独立oracle证据完整且源码未变时，保留它们。在全新目录运行同一原件上的
   完整HEAD6 23负控／1正控；不改旧目录、不给未完成命令补成功exit，不拼接部分结果。
3. 独立完成原终态退休实际、oracle和25负控／1正控；原预算、权限和故障合同保持不变。
4. 保存最终服务机器记录和失败归属，核对最终代码与已验证输入、文档及远端head/main，
   再按维护者已有本地验证授权合入。

本次中断后的状态文档通过GitHub接口提交。执行环境不可用，因此该文档提交没有运行
本地 `check_repo.py`；此前 `c826723` 的文档检查为665个文本文件、659个本地链接通过。
它没有改变任何生产、SDK、模型或实际夹具源码；不会以文档提交代替未完成的门禁。

## 尚未覆盖的发布条件

本轮是本地SeaweedFS 4.51、逐请求签名及真实SQLite/HTTP/进程合同，不认证AWS。
controller已覆盖固定12场景多实例矩阵，native／1 GiB也有本轮独立新结果；这不扩展
为任意动态fleet、全部部署故障域或完整N1–N4退出。服务HEAD6完整负控及终态退休因环境不可用尚未完成。
实例身份登记/分配、S2 restore/PITR、持续过载、唤醒风暴、公平性、硬RSS/磁盘上界、
长期保留/GC成本、真实AWS和生产数字SLO仍按[路线图](roadmap.md)推进。

远端状态另行保留：`c6826df`返回20个completed/failure check runs；抽查run
`43153429358`的jobs无steps，Rust job `130967748334`日志下载返回404 BlobNotFound，
annotations端点不受当前连接器支持，原因尚未确定。不能据此断定是代码、额度或runner
故障，也不能把本地结果标成远端CI通过；详情见runtime机器记录的`remote_ci_observation`。

按仓库`AGENTS.md`的“未完成所需验证不合并”要求，PR #59保留Draft。
本地专项通过是具体合同的验收，不能扩大为N1–N4完整退出或生产发布。
