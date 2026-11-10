# 有界本机吞吐与冷恢复隔离基线

本计划在执行前冻结。全部数据库工作使用未插桩的正式 `scapd`、正式 Node SDK、native
SQLite 和需要签名的 SeaweedFS 4.51。夹具只生成输入、限制并发、暂停一条真实 S3 GET、
采样资源并记录原始字节。它不实现另一套数据库运行时，不自动重放 SQL。

## 固定工作负载

八库、两租户、一个 worker。seq/same/m0/m1/cold 属于租户 7，m2/m3/hot 属于租户 8。
每库独立 create/activate/DDL；hot 写一行 4 KiB 随机 BLOB；cold 用 16 次事务写入
512 行各 64 KiB 独立随机 BLOB，共 32 MiB 用户数据。所有输入在发送前保存并 fsync。
种子共 41 POST、25 次原始 execute。数据库真实页数须至少覆盖用户字节，不用稀疏或零
内容代表容量。

| 测量阶段 | 原 execute/query 数 | 同时在途上限 | 数据库 |
| --- | ---: | ---: | --- |
| write_seq | 32 | 1 | 空 seq 库 |
| write_same | 64 | 4 | 空 same 库 |
| write_multi | 64 | 4 | 四个空 m 库，每库一个客户端 lane、16 次 |
| read_same | 64 | 4 | 已完成的 same 库 |
| read_multi | 64 | 4 | 四个 m 库 |

每个测量 write 写入一行独立 4 KiB 随机 BLOB，RETURNING 完整 id/payload 和 SQLite
`random()`；每个 query 读取 count/sum。基线共 288 次测量调用。采用 closed-loop 的固定
并发，记录 SDK 调用到返回的端到端延迟，包含服务排队；计划等待另列。单次固定小样本
不估计开放环过载吞吐或生产 p99。结果必须同时报告成功、明确拒绝、UNKNOWN/不可用和
传输错误；任何错误不移出分母，不隐藏在“成功请求延迟”里。

结束五个阶段后优雅停止并 wait4 原 daemon，删除其全部 owned compute cache，启动同一
二进制的新进程。先 Open hot，然后 Open cold，并在第一条 cold Chunk GET 转发前暂停。
保持期间完成 8 个 hot query、2 个 cold status，以及 1 个 seq Open（必须
429 RECOVERY_BUSY，且不得触碰 seq S3 对象）。这些 11 个探针必须在 4 秒以内结束，
并且全部早于显式 gate release。GET 最长保持 12 秒，S3 期限 15 秒；不得依靠超时释放
来通过。释放后 cold Open 完成，再发一条 HEAD-only 的 warm cold query。此阶段含 hot
Open 共 14 POST。cold Open 报告总耗时与 gate 保持时长，不能把人为保持当吞吐退化。

验证阶段固定 528 POST：25 份种子 request 各 lookup 一次；160 份测量 write 原身份各
执行 lookup/cancel/lookup 三次，保留原 committed bytes 或建立原 cancellation 屏障；
从不第二次 execute。另有 16 个分块 cold payload query 与 7 个其余数据库完整 payload
query。独立 oracle 逐字节/逐 hash 核对全部输入与实际 committed 集合、每份原 receipt
和随机结果。原 UNKNOWN 以后查到 committed 也不改写原响应。全实验固定 **871 POST**。

## 固定边界

actor 8、每租户 5、control worker 2、global queue 64、tenant queue 32、database queue 8、
control reserve 4；data/control/recovery intake 为 16/8/4；recovery permit 1；
pages_per_actor 16384（64 MiB，操作后缓存阈值）。正文 4 MiB；普通/恢复 HTTP 各 60 秒；
SDK 普通/恢复 65/70 秒。TCP connection 64、发送/停机各 30 秒。执行结果图 128 MiB；
输出池 global/tenant 为 256/192 MiB，其中 control 预留 8/1 MiB；S3 15 秒。每个 Node
phase 至多 180 秒，整个运行至多 20 分钟；原 deadline 不续期。

执行前勘误：原计划 SHA-256 为
`ca70851fdb79d7b70d69f0f5bb4b2cd50ffca7ed4f35261d3074ef2d1f53a453`，其 spec 的 tenant
输出池误设为 128 MiB，扣除 control 后小于正式服务 `maximum_peak(MAX_RESULT_BYTES)`
要求的 179023223 字节，必在启动时被 CONFIG 拒绝。实际运行尚未开始；现修为合法的
192 MiB，并保留原计划/无效配置的诊断副本。这是构造合同修正，不是根据吞吐结果扩容；
871 次请求、并发、数据量及全部期限均不变。

正式配置来自 spec.py，运行前保存完整配置和凭据摘要。backend/缓存使用新 owned 目录，
不得落到容量较小的默认 tmpfs；启动前至少 2 GiB 可用空间，低于 1 GiB 即失败停止新调用。
原始 body 按 SHA 保存，最多 2 GiB；最多 30000 个 S3 请求、32 个并发 proxy handler。
代理原始日志和采样有固定上限；截断即失败，不能继续产出 PASS。

## 资源及证据

owned pre-exec launcher 通过私有 Unix socket 传出自己打开的 `/proc/self` directory fd，
然后 exec 正式二进制。父进程经该 fd 读取 status/stat/fd/task，核对 start ticks 和
exec 后二进制；不按未经证明的数字 Popen.pid 读别的进程。目标 100 ms 采样 RSS/HWM、
FD、线程；记录实际间隔、原始 status/stat 和 FD/task 名单。缓存/后端文件逻辑及分配
字节、文件系统可用空间同时取样。wait4 kernel maxrss 单列；采样最大值不是瞬时硬峰值。
任何指标不可用都显式失败该观测项，不能填零。Node、代理、S3 后台和共享页缓存不属于
scapd RSS。启动后瞬时峰值或两次采样之间的峰值不在采样保证内。

保留：完整输入、每次调用/HTTP 原请求与响应、SDK 原结果及错误、S3 条件和完整 body、
phase 起止及 gate 事件、资源 raw samples、所有 owned 子进程 wait4、原 build receipt
和源码/二进制摘要。oracle 独立重算分位数（nearest-rank）、各类吞吐、全部 S3 数量/字节、
冷恢复与资源统计；不依赖 runner 汇总。采集器文件 I/O/SDK 解码等开销包含在测量中。

负控制至少覆盖缺失调用、丢弃慢样本、改原请求/结果/行、漏 S3 发布、暖查询下载对象、
恢复 permit 绕过、gate 提前释放、错 PID/start ticks、缺失资源样本、错 binary 和未回收
进程。每个修改在原证据的独立副本执行；原样副本和改 summary 的正控制仍须通过。
单位测试仅检验 fixture/oracle 边界，不替代真实 daemon 执行或产品单位覆盖。

`aws_standard=NOT_RUN`、`production_slo_passed=false` 固定保留。GC/compaction、GiB 级
恢复、控制器、硬 RSS/磁盘隔离及持续负载公平性由其他门禁承担。此基线只报告本次实际
原生与签名兼容 S3 环境中的结果及瓶颈，不制造 AWS TPS 或已经完成全部产品目标的结论。
