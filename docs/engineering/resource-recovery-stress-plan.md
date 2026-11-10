# 资源、冷恢复与吞吐的组合门禁

状态：完整组合仍为设计；小规模首批 [object-load](../../experiments/object-load/PLAN.md)
已按冻结 HEAD6 完成实际运行、独立审计和14负/3正向核对，见[验收记录](head6-runtime-validation.md)。
这里的完整目标不是已完成的性能承诺。大库、持续过载和硬资源隔离
仍须分别通过下面的门禁，不能由一次本机延迟数字代替。

## 已有保证与待测问题

[执行隔离设计](../architecture/execution-isolation-and-throughput.md) 已限制 actor 数、
排队数和 control 预留。[准入](../../crates/scap-service/docs/intake-reservations.md)、
普通 `/v1` 输出池和 HTTP 发送期限约束各自实际拥有的资源。它们没有共同构成进程 RSS、
磁盘或网络带宽硬上限。`pages_per_actor` 在操作完成后决定是否保留 Session，不能据此拒绝
正在下载的数据库，也不能预留恢复期间的磁盘空间。

冷恢复仍下载完整 SQLite 数据树并校验保留请求历史。COPY 则流式读取整个当前闭包，
条件创建并回读目标；一个 recovery deadline 内未完成时下次重新遍历。GC 每候选在
prepare/resume 中各做一次完整 exact GET，删除仍用持久原 ETag；专用 transport 在每次
inspect/delete 前重新检查后台配置。这些正确性成本都应进入请求和字节分母。

## 分层判据

| 门禁 | 固定工作与证据 | 失败条件 |
| --- | --- | --- |
| R1 准入与生命周期 | 慢上传、慢响应、客户端消失、worker 尚在运行；同租户换主体及跨租户探针 | 后台未结束或最后 Bytes 未释放时提前归还额度；control 预留被 recovery 消耗 |
| R2 并发恢复 | recovery permits 为 1/2；同时提出 2/3 个不同库恢复；暂停真实 chunk GET | 超额恢复开始读对象；热库/短 control 被同库之外的恢复线程占住 |
| R3 冷恢复容量 | 32 MiB 基线、独立 1 GiB 和默认 10 GiB 档；全部 compute cache 丢失；全部值与原结果核对 | 漏失调用、调大预算后沿用原 PASS、抽样数据替代完整核对、缺少原始 UNKNOWN |
| R4 热点与公平性 | 同库 1/4 并发、多库 4 并发；随后固定 offered-rate 过载、租户轮转和 actor 唤醒风暴 | 只报成功请求延迟；丢失拒绝/超时；旧 actor 未退出就复用同 HEAD 槽位；已接收工作无限饥饿 |
| R5 资源峰值 | owned daemon 的 RSS/HWM、FD、线程；缓存及后台文件逻辑/分配字节；共享 cgroup 单列 | PID 归属未证明；缺测填 0；采样最大值宣称为硬峰值；把后端或代理开销算成 daemon RSS |
| R6 维护竞争 | 写入期间的 GC；COPY/冷恢复竞争同一 recovery permit；已有原结果继续查询 | 原 SQL 重放、旧 CAS 换 ETag、活跃/target 对象被删除；忽略技术 CAS 对业务 Conflict 的影响 |
| R7 外部容量隔离 | 独立临时卷的空间耗尽、受控文件限制、可配置容器内存限制 | 修改共享宿主限制；本地文件失败被当提交失败并重做 SQL；进程死亡后不核对原 receipt |

R1 已有独立真实夹具，但受影响产品代码变化后仍须复跑。R2/R4/R5 的小规模子集由首批
object-load 完成；R3 的 GiB 档沿用 object-capacity 的独立默认参数合同。R6 使用
object-reclamation-runtime，不能把其功能故障验证冒充持续 GC 服务能力测量。

## 测量与分母

请求在进入 SDK 前记录原始输入和完整身份，在 HTTP 结束与 SDK 解码结束分别记时。
主延迟从 SDK 调用开始到结果/错误返回，包含网络、服务排队、SQLite、S3 和 SDK 解码；
客户端限并发之前的计划等待另列。采用固定 nearest-rank 分位数，同时给样本数、最大值、
全部状态分布、实际发出数、成功吞吐和 offered 吞吐。排队、失败和拒绝不能从分母删除。
小样本 p99 通常就是最大样本，不能报告统计置信度或生产 SLO。

每个阶段同时统计全部 S3 请求数、完整 request/response body 字节、HEAD/immutable 分类、
实际响应码和条件头。应用用户字节、SQLite 文件大小、S3 活对象逻辑字节、后台分配字节
分开；不把压缩、稀疏文件或重复对象误当成真实容量。

资源采样目标为 100 ms，记录实际间隔与缺口。父进程不能直接用未经证明的
`/proc/Popen.pid`，本环境存在不同 PID 视图。首选 owned pre-exec launcher 打开自身
`/proc/self` directory fd，经私有 socket 传给父进程，再 exec 原样正式 scapd；采样使用
这个实际目录 fd，并核对原 start ticks、boot id 和 exec 后二进制身份。若环境不能提供
可信映射，RSS/FD/线程必须标记 unavailable；不能改用父进程或全容器值冒充。
结束时用 owned `wait4` 的 kernel usage 另列生命周期 maxrss。代理、Node、后端和共享
cgroup 都有独立边界。缓存磁盘采样只遍历本实验创建的路径，不跟随 symlink。

## 负控制与退出条件

每批原始历史须由不导入产品或 runner 的 oracle 审核。至少拒绝：删掉一个慢请求、
伪造一次成功、改请求身份/随机原结果、改业务行、漏一个 S3 发布/回读、热查询偷做恢复、
超额恢复触碰 S3、控制响应晚于 gate release、错误二进制、错误 PID/start ticks、缺失
采样、用 VmHWM 回落推导新低峰值、未回收进程和修改冻结参数。修改 controller summary
的正控制应保持相同事实结论。

任何超时、OOM、磁盘保护、采样器或代理失败都保留原目录。修正后新建证据，不缩小输入
或加宽 deadline 后重写旧结果。正式运行与开发诊断、单位四维覆盖分开。只有所有所需
层次均完成，才讨论相应容量范围的生产参数；AWS Standard、跨 AZ、设备冷启动和无限
持续负载仍需要真实环境与单独预先冻结的门禁。
