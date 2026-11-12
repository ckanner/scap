# PR #59：SQLite on S3 组合验收

复核日期：2026-11-11（America/New_York）。主线仍为 HEAD7 `fab8ca0`。
[PR #59](https://github.com/ckanner/scap/pull/59) 的组合提交 `fc10287` 同时保留
#56 `1d709db`、#57 `df922b95`、#58 `4216523` 的 ancestry、实现和原证据；
`e485a97` 补回旧 controller 分支遗漏的 owner 夹具和历史证据。
SDK exports、类型和测试同时保留 controller 与 snapshot 两套接口。

## 源码与二进制归属

正式未插桩的 service 和 native/network release 均在干净 `fc10287` 构建，之后只改
夹具及文档。每次实际运行独立冻结源码，逐一验证原 receipt 的277个 service及183个
native build inputs等价，仍记录二进制真实构建来源，没有将新夹具SHA改写成release来源。
controller只需要service receipt；其原生SQLite静态archive也随receipt核对。

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

Rust使用全新target及profiles，218份raw和1份merged profile，没有混入集成profile。
完整精确计数和命令哈希见[Rust机器记录](../evidence/sqlite-s3-integration-rust-local-2026-11-11.json)，
SDK/类型见[Node机器记录](../evidence/sqlite-s3-integration-node-local-2026-11-11.json)。
实际合同的原输入、事件、源码、二进制、独立oracle、controls和失败摘要见
[runtime机器记录](../evidence/sqlite-s3-integration-runtime-local-2026-11-11.json)。
每个runner自身仍只输出`OBSERVED_NOT_AUDITED`，后续独立判定不回写原件。

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
   重新执行全12例actual/oracle/controls；不能只给旧事件补字段使其通过新检查。

这些修正没有改变生产代码、固定业务工作量、时间界限或已规定的安全合同。
原PR的历史失败记录也没有覆盖；每次fresh实际使用新的目录和源码清单。

## 尚未覆盖的发布条件

本轮是本地SeaweedFS 4.51、逐请求签名及真实SQLite/HTTP/进程合同，不认证AWS。
controller只覆盖一个固定自动接管历史；多controller竞争、动态fleet及完整故障矩阵
还需验证。此前完整native/1 GiB、资源/GC矩阵的历史结果不能自动充作本轮重新执行。
实例身份登记/分配、S2 restore/PITR、持续过载、唤醒风暴、公平性、硬RSS/磁盘上界、
长期保留/GC成本、真实AWS和生产数字SLO仍按[路线图](roadmap.md)推进。

远端状态另行保留：`c6826df`返回20个completed/failure check runs；抽查run
`43153429358`的jobs无steps，Rust job `130967748334`日志下载返回404 BlobNotFound，
annotations端点不受当前连接器支持，原因尚未确定。不能据此断定是代码、额度或runner
故障，也不能把本地结果标成远端CI通过；详情见runtime机器记录的`remote_ci_observation`。

按仓库`AGENTS.md`的“未完成所需验证不合并”要求，PR #59保留Draft。
本地专项通过是具体合同的验收，不能扩大为N1–N4完整退出或生产发布。
