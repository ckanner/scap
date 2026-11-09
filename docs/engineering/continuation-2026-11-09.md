# 2026-11-09：SQLite on S3 进展与执行中断交接

当前主线为 c5ed0c2ff1b3dfa1fd200edcf3a055d64e711e16（已合入 PR #35）。
受限删除接口的最新已验证实现为 2bd925e4ada39f0a95c383311e3e016def5da4bf，
其验收文档交付为 7dd031ea218f8f4e5fc2db75d5c0cfea2b19cc06（PR #36，草稿）。
这份交接文档不改变生产代码，也不把独立分支或未完成的编译算成主线通过。

## 目标与明确边界

目标是 S3 作为唯一持久权威的多租户 SQLite 服务。SQLite 在可信本地私有目录中执行，
数据、原始结果和索引以不可变对象持久化；每库 HEAD 的原 ETag 条件发布决定接受。
全部依赖持久化、HEAD 接受和 native publication 完成之后才 ACK。
本地计算、镜像和路由缓存可以丢失；UNKNOWN 必须用原请求身份查证或取消，不能自动重放 SQL。

一个数据库仍有串行发布点。多库、多租户可并行，增加 pod 不自动提高一个热点库的写吞吐。
本项目不让多节点共享网络卷上的 .db/WAL/SHM；本地目录和 SQLite 临时文件仍须满足
[执行存储边界](../operations/sqlite-storage-safety.md)。S3 协议不能修复错误本地 I/O、
引擎缺陷或没有预算的进程内存使用。

## 已合入的主线

[PR #35](https://github.com/ckanner/scap/pull/35) 已合入：
有界 S3 传输、全目录发现、无需预知数据库名单的部署恢复、分段请求索引及 SQLite
临时目录防护。该冻结交付的本地 stable/nightly 各 416 个单元、47 个生产文件四维
精确覆盖及指定真实恢复合同已完成；完整范围与原失败见
[发现与恢复验收](discovery-recovery-validation.md)。
主线没有把 N1–N4 全阶段、AWS 或生产 SLO 标记通过。

## 本次新完成的受限删除传输

[PR #36](https://github.com/ckanner/scap/pull/36) 当前仍是草稿：

- scap-object-store 的 stable 与 nightly 各 40/40 单元、0 ignored。
- 全部 6 个该 crate 生产文件，行/函数/region/分支逐文件精确 100%。
- 该 crate strict Clippy、workspace fmt 通过。
- 修正后的真实兼容 S3 合同：42 场景、115 个签名产品请求、136 次独立对象 GET。
- 4 worker 与 4 backend 均由 owned wait4 回收；13 个负控被拒绝，1 个正控通过。
- 源码、工具、实际二进制和原失败记录前后不变。

实际 release SHA256 为
4b2fc4a8df43ba739d651171d5e53487ebffe4add5b260ead746d22fad5ae006；
实际 history SHA256 为
aec4954d1c6d94482bb6a4185734a914b9641bcd64f6b44a37320fe5651604e7。

来源、精确覆盖分母和已保留失败见
[GC 传输验收](gc-store-validation.md)及
[机器摘要](../evidence/gc-store-local-2026-11-09.json)。
该结果不认证 workspace 组合，也不授权自动删除。**产品 GC 为 OFF。**

## 尚未发布合并的本地候选

以下提交是本地工作区检查点，不保证能从 GitHub 按这些本地 SHA 取得。
未提交或回执未知的修改只能在恢复执行环境后核对，不能根据计划推定已落盘。

| 模块 | 已确认的检查点 | 实际验证边界 |
| --- | --- | --- |
| Owner 路由/接管 | 旧分支 cb1/a331/b4cf；基于当前 main 的整合提交 0c8d65018b6da4e699c8d465523b0d857d67874b | 旧 HEAD4 分支457×2单元、51文件四维覆盖、SDK50单元/11 V8模块/8 Fetch/严格TS；R4 real02为113 HTTP、588 S3、29阶段、14故障、18负控、39 owned children，仅绑定a331夹具和经输入等价核验复用的cb1实际二进制，real01 FAILED保留。0c8仅完成源码与轻量门禁，新Rust/native/R4尚未执行，不能继承旧PASS |
| Storage generation/pins | 旧6136606开发运行392/408、16失败；修正提交1a0b6d3；当前main整合已提交12065524e83bec204b766f0faaffe757f588a4fa，其上19文件未提交 | 旧失败保留。新 Runtime/D 接线只完成源码、rustfmt、diff检查，未冻结、未编译、未做四维/真实HEAD6验收 |
| Tenant HTTP intake | bc2ebcf495635d62f4f473b27a5c58b44c97d5f2 | body读取前预留，租约贯穿Job/worker/response/最后Bytes clone。root启动的开发编译会话31939在环境中断后无法查询；最终结果未取得，不得称通过或已回收 |
| N4完整负载夹具 | dc1c810e0e3b749debfe3e45d08d7157c746b035 | 75 Python及5 Node轻量测试通过；364 offered、最多550实际POST、153原始execute输入、144固定lookup、30 owned children的真实计划尚未执行；23负控/1正控的完整真实历史验收NOT_RUN |
| SQLite全局heap/结果内存 | 独立scap-native-heap工作树，以0c8为HEAD，未提交 | 默认256MiB allocator guard及相关错误分类/测试源码有成功写入回执。128MiB typed-result预算的大补丁落盘状态UNKNOWN；全部编译/实际OOM/覆盖NOT_RUN |
| TCP/header | 独立scap-http-connection-limits工作树，以bc2为基线，未提交 | 128连接、64header、16KiB header、32KiB parser buffer、5s显式timer及shutdown接线的生产补丁有成功回执；测试文件写入UNKNOWN，全部编译/真实合同NOT_RUN |
| Response byte pool | 已确认设计缺口 | 尚未实现，不能把请求body或请求数量配额称作响应字节预算 |

Owner 与 N3 旧分支最初落后于当前 main。已改为从 c5 正常按原提交顺序整合，
保留 PR #35 的 native/发现/恢复修改；没有整树覆盖、删除主线新增验收或使用 graft/replace。
Owner 整合已冻结；N3 的 D 接线尚未冻结。

bc2的body预留尚未覆盖新增Owner-control/Owner-recovery入口；需增加独立池，
并把租约贯穿读取、Job、worker、response及最后Bytes clone。已有owner recovery
全局2/tenant1运行额度不是慢body准入保护，正常合并分支不会自动补齐此接线。

## 资源分析：已知事实与待修复事项

冷恢复已经逐个128KiB数据块写入私有文件，并非把10GiB整库存入一个Vec；
保留结果也逐Entry验证释放。不过单个历史结果允许64MiB，解码时可能同时存在原对象
与payload副本，另外还有运输缓冲和Vec容量。D的累计data/GET预算不是驻留内存预算。

响应目前经历SCAPRES1、Base64和JSON表示。64MiB结果的Base64约85.34MiB；
慢客户端会继续占用原class/tenant请求数量额度，但尚无独立响应字节池。
这不能与64KiB请求body额度混为一谈。

native collect_results 的NULL只按一个payload字节计费，却存在Vec<Vec<Value>>中，
大量小值可能造成远大于结果字节数的Rust内存开销。SQLite hard_heap_limit覆盖不到这部分。
待完成的结果内存修复必须在分配前计费、使用checked arithmetic/try_reserve，
计入容器扩容时新旧数组同时存在的峰值；编码后释放旧typed graph。
已提交结果若因当前预算无法物化，应保留原receipt并返回COMMITTED_BUT_UNAVAILABLE，
继续允许读取原始结果字节，不能改成Corrupt或重执行SQL。

SQLite全局heap只能承诺其allocator。安全PRAGMA初始化需要先开一个私有内存probe，
因此正确边界是第一条业务/文件连接之前；读回值不能代替实际OOM验证。
真实原生验收须在独立进程中证明固定native的heap限制确实触发SQLITE_NOMEM。
不同配置及外部漂移必须拒绝；native、Rust、response、TCP与整进程RSS须分别描述。
固定native的实际限制依赖bMemstat/MEMSTATUS，当前构建默认开启；宿主不得修改
MEMSTATUS、allocator或PCACHE配置。PRAGMA读回不证明运行时计费已启用，仍须
以同源实际二进制的独立进程SQLITE_NOMEM实验为证。

[分层资源预算设计](../architecture/resource-budgets.md)规定后续预留、释放、响应与
磁盘边界；这是待实现方案，不把新配置或相应测试算成已有产品能力。

## Storage pins、GC和PITR仍需完成

HEAD6候选将同一个Arc<Runtime>用于目录、数据库、恢复与服务。
远端读取前取得精确generation grant；之后重新读取HEAD和权限，全程持有guard。
D的受限PinObjects只保留一个有界原HEAD/ETag，允许serial+1和追加一个当前代pin；
通用RecoveryMeter仍不开放任意业务PUT。PinAdd按完整请求计费，失败不退款；
canonical PinRelease与Runtime.close的结果须进入真实请求/进程账本。

当前未安全解除的崩溃/暂停pin会阻止GC。TTL不能证明暂停读者已经停止。
强撤销必须另行实现最终token检查和错误分类，并处理旧代码在途请求；
不能仅升级HEAD格式就声称旧读者已被安全隔离。

下一批应按顺序完成：

1. 恢复执行环境，先核对31939原日志、所有partial/UNKNOWN补丁与原实际产物，
   再冻结新的组合源码；不覆盖旧失败，不盲目重放补丁。
2. 合并Owner、HEAD6、intake、TCP、heap、typed-result与response预算，
   完成全部受影响文件的严格单元/Clippy/四维覆盖与真实native/HTTP合同。
3. 将Owner/D/部署恢复的真实fixture和独立oracle严格升级到HEAD6；
   覆盖held读取、Seal、权限变更、UNKNOWN PinAdd、崩溃cleanup和全请求分母。
4. 实现持久退休计划、pin/freeze/drain安全证明、公平重复sweep，
   测试旧PUT/DELETE迟到与全部计算重启；未证明之前不启用产品GC。
5. 加入有界显式快照保留与新数据库身份PITR；源/目标恢复意图可重启，
   不复活旧ACL、owner、请求身份或名称取消屏障。
6. 运行冻结N4真实负载、长期回收成本与实际目标故障域/吞吐/尾延迟SLO。
   AWS配置和资源未提供，真实AWS仍为NOT_RUN，不创建未经配置的付费资源。

完整目标未完成；不会用某一模块的通过结果计算一个笼统完成百分比。

## 外部执行阻断

2026-11-09执行环境报告unavailable，随后执行工具明确返回没有可用执行环境。
当前无法继续编译、核验未提交文件或取得31939最终状态。没有证据表明这些工作已成功，
也不推定所有进程已停止。恢复后应先查原状态，再决定后续动作。

PR #36当前GitHub检查显示failure。已查询的Rust job没有step记录，
日志读取返回404 BlobNotFound；现有连接器拒绝annotations端点。
原因未确认，不能猜测为计费、环境或代码问题，也不能宣称CI通过。
不修改分支保护或通过禁用门禁处理这类未知。

## Turso对照与官方依据

应区分旧libSQL/bottomless、新Rust引擎与Turso Cloud：
bottomless公开实现持续S3备份；Cloud公开资料描述WAL先写S3 Express One Zone再确认、
之后整理进S3；新引擎的MVCC/group commit不自动适用于当前SCAP的SQLite提交路径。
可以借鉴分段缓存、对象持久化后ACK、批量提交和系统化故障测试，
不能继承其性能数字或把One Zone当多AZ容灾保证。

- [SQLite网络文件系统说明](https://www.sqlite.org/useovernet.html)
- [SQLite WAL与同机共享内存约束](https://www.sqlite.org/wal.html)
- [AWS条件写](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)
- [Turso持久化架构](https://turso.tech/blog/how-does-the-turso-cloud-keep-your-data-durable-and-safe)
- [2026-11-04 Turso Cloud仍采用S3 Express WAL](https://turso.tech/blog/turso-cloud-now-runs-in-singapore-and-frankfurt)
- [Turso 0.8并发写与group commit](https://turso.tech/blog/turso-0.8.0)
- [旧bottomless实现](https://github.com/tursodatabase/libsql/blob/main/bottomless/README.md)

这份交接通过GitHub API保存，执行环境中断后未运行本地文档检查；生产代码未改变。
