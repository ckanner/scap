# 实际服务热路径诊断与有限连接池修复

日期：2026-11-17。结论：保留 `synchronous=FULL` 和每次提交后检查完成的
`wal_checkpoint(TRUNCATE)`；把共享 S3 HTTP 客户端每主机最多保留的空闲连接从 2
调至固定 8。这解决了已测到的四数据库工作负载中的连接反复创建问题。
**原 PR60 两次约 24% 的四库 TPS 回退仍未归因，也不宣布已经修复。**

产品修改是本地提交 `95d71160d5df32f83ec2aa56ba532432f99257a6`，仅涉及
`scap-object-store/src/lib.rs`、`listing_guard.rs` 和已有 `tests.rs`。
运行记录、全部时延/计数样本、来源及排除理由见
[机器可读记录](../evidence/service-hot-path-profile-local-2026-11-17.json)。

依据 AGENTS 不提交运行日志的要求，原始 SDK 合成数据、运行日志与 receipt 档案保留在
仓库外的审查工作区 `scap-work/service-hot-path-profile-raw-2026-11-17.tar.gz`。
其 SHA256 为 `b039381b34bd5d743f8efc651daffcd2acc12c92bf4773491f0c85ff2e45eaf4`，
完整位置及来源摘要记在 JSON 中；仓库仅保存结构化观测、分析和诊断源码。

## 测了什么

此次没有用指纹函数的纳秒级微基准代替实际服务分析。诊断构建运行真实 `scapd`
入口、原有有界 HTTP transport、调度器、Engine、对象协议、签名 S3 客户端和固定
版本的 native SQLite。仅在冻结的临时源副本中加入 Rust 计数器及只用于本机诊断的
`/__profile` 路由。产品没有依赖这个诊断 crate，也没有更换 allocator。

共同产品基础为 `936ff92` 加 PR60 `9b5e9ae` 的对象实现，本地固定为 `bb15999`。
每个源副本拥有独立 Cargo target；每个运行记录源文件、二进制、工具链和 native
archive 的 SHA256。FULL 与 NORMAL 比较的两个完整输入清单只差 `config.rs`；
连接池比较只差两个生产文件及新增回归测试所在的已有测试文件。

诊断直接访问带 SigV4 验证的本地 SeaweedFS 4.51，使用 Rust 1.90.0、Node 22.16.0
及官方 Node SDK。保留原 object-load 的服务资源参数，单独固定较小的诊断工作负载：

| 阶段 | 原始调用数 | 并发 | 工作 |
|---|---:|---:|---|
| 顺序写 | 16 | 1 | 单库、每次 4 KiB BLOB、RETURNING 原结果 |
| 四库写 | 64 | 4 | 四个库各一条闭环 lane |
| 同库写 | 32 | 4 | 四条 lane 争用同一个数据库 actor |
| 四库读 | 32 | 4 | 每次刷新授权后的热缓存 count 查询 |

每轮还有 18 个初始化 POST、112 个原始请求 lookup 和 6 个最终完整行审计，合计
280 个 SDK POST。固定生成的 BLOB 字节、SQL、Scope、业务身份在比较之间相同；
`random()` 的结果按每轮原始返回值核对，不要求跨轮相同。计时期间不重试 SQL，
保留所有失败。所有完成的轮次均通过 144 个测量调用、112 个原结果核对及 6 库完整行审计。

这是**独立诊断**。原 object-load 的 871 POST、288 个测量调用、冷恢复、故障注入、
原始 body 证据和 oracle 分母完全没有修改。原证据代理会为请求/响应持久化原始
body、串行维护证据预算，并主动关闭 HTTP 连接；Node 记录器也会同步持久化证据。
这些成本属于那份原始实验环境。不能用去掉代理后的 TPS 声称产品变快，也不能把
历史回退未经证明地归因给代理。

## 实际瓶颈与单写者边界

最终连接池对照中，原 cap2 四库写每次平均 Engine 时间为 33.837 ms，其中 S3
GET/PUT span 合计 28.668 ms，约占 84.7%；native publication 为 2.763 ms，
检查完成的 checkpoint 为 1.660 ms，排队为 0.118 ms。该轮整个 daemon 的 CPU
累计为每次 3.831 ms，等待明显大于 CPU 执行时间。

单次 4 KiB 用户写在该四库阶段平均调用 11 次 GET、6 次 PUT，下载约 103.6 KB、
上传约 55.8 KB 的对象 body。这包括当前 HEAD、数据树/请求索引、原结果以及不可变
对象完整回读；不是用户 payload 大小，也不含 HTTP/TLS header。不能只用 PUT 次数
衡量写放大，亦不能通过跳过 hash、readback、权限或原始身份校验减少这些数值。

同一轮四 lane 写单库时，平均 Engine 为 23.425 ms，而排队为 63.149 ms。
换成 cap8 后仍分别为 22.317 ms 与 60.169 ms。单库事务由一个 actor/SQLite writer
串行执行，这个限制依然存在；把持久权威放到 S3 不会自动获得同库并行写。
多个数据库可以并行推进，不能据此宣传成单库多写者。

进程 Rust allocation/reallocation 计数在原 cap2 四库阶段平均为每次 2,819 次、
累计请求容量 1,354,445 字节。cap8 对应 2,770 次、1,199,517 字节。这些是本次诊断的
分配请求量，包含重分配和计数器开销，**不是 peak memory、live heap、RSS，也不包括
SQLite 的 native malloc 统计**。S3 span 的 CPU/分配只覆盖调用线程；整个 daemon
另有进程级 CPU 计数。所有 span 都是 inclusive，不能把 Engine、COMMIT 和其内部
S3/native span 再相加。

## 为什么没有改同步或 checkpoint

本地 image 的确是一次创建、私有、可丢弃的缓存：`PreparedImage` 只能由新建
builder 生成，writer 不提供原路径重开；失败会永久停止该连接，新的 Session 从
授权的 S3 根重建。S3 依赖及 HEAD 接受先于 native publication，普通 ACK 还要求
native publication 和 checkpoint 成功。

但 `synchronous=OFF` 同时取消 xSync 错误观察，不只是取消断电持久性。运行中的
本地延迟写回失败与“进程重启后丢弃缓存”不是同一情形；此次不采用 OFF。
依据 [SQLite 的同步说明](https://www.sqlite.org/pragma.html#pragma_synchronous)
及固定 libSQL `d8bc862d20bedc72945a1da27c8b7045414c0261` 的 `pager.c`、`wal.h`、
`wal.c`，NORMAL 保留 checkpoint 同步，但移除普通 commit 的额外 WAL 同步。
因此只把 FULL/NORMAL 作为较窄的诊断候选，并保持 TRUNCATE 不变。

最终可用的安静 NORMAL→FULL 单对结果如下。样本不足以估计稳定吞吐提升：

| 阶段 | NORMAL 诊断 TPS | FULL 诊断 TPS | NORMAL 相对 FULL |
|---|---:|---:|---:|
| 顺序写 | 41.61 | 34.36 | +21.1% |
| 四库写 | 110.10 | 111.64 | -1.38% |
| 同库写 | 40.81 | 42.53 | -4.04% |
| 四库读 | 1449.79 | 1731.03 | -16.25% |

四库 native publication 从 FULL 的 1.368 ms 变为 NORMAL 的 1.229 ms，但 checkpoint
从 0.738 ms 变为 1.266 ms；整个阶段没有一致收益。没有依据将 NORMAL 当作产品优化
提交，更没有理由为了这个结果改 WAL reset、checkpoint 的故障边界或 ACK 顺序。

## 已实现：保留有界的共享连接

S3 clones 已共享一个客户端和 runtime，但客户端原来最多保留两个空闲连接。
四数据库 lane 在对象请求与本地计算之间交错时，连接会被不断丢弃、重新建立。
固定 Hyper-util 0.1.21 的 counter-only subscriber 直接记录 TCP connect 完成事件和
空闲连接 checkout，不记录 headers、凭据或 body。

在所有参与者明确确认安静后，cap2 与 cap8 按顺序各跑一次。每轮均等待 daemon 与
所有四个 backend 子进程终止，再启动下一轮。两轮 SDK 请求 body hash 的有序多重集
摘要均为 `4792ddca128b3e0709b7bcd9cdd8636fbf6b66fbbcc8010911b88b09e9580b82`。

| 指标 | cap2 | cap8 |
|---|---:|---:|
| 四库写成功 TCP connect 事件 | 83 | 4 |
| 四库写 GET / PUT 调用 | 704 / 384 | 704 / 384 |
| 四库写下载 body 字节 | 6,632,904 | 6,632,904 |
| 四库写上传 body 字节 | 3,568,556 | 3,568,556 |
| 四库写所有测量调用成功 | 64 / 64 | 64 / 64 |
| 四库读新建 TCP 连接 | 3 | 0 |

连接重建减少 95.2%，对象调用、对象 body 和原结果核对分母保持相同。一次诊断中的
四库 TPS 为 107.52→112.20（+4.35%），同库写为 42.53→44.65，顺序写为 39.57→43.73；
四库读却为 1446.07→1334.83（-7.69%）。这些样本全数保留，**不宣称一般 TPS 提升、
AWS 吞吐结果或生产 SLO 达标**。接受本修复的依据是具体的连接保留行为和确定性的
回归测试，不是从单次 TPS 中挑选正数。

产品使用同一个私有常量给 SDK options 和显式 reqwest connector 设置固定 cap8。
它只限制每主机保留的空闲连接，不新增 SQL 并发、重试、超时预算或后台写入，也不是
活跃请求/连接的总量上限。相比此前最多多保留六个空闲 socket；部署仍需给活跃 actor、
HTTP intake、线程、FD 和内存配置独立预算。

## 验证和不通过的尝试

- 新回归测试用实际 S3/SigV4 客户端完成两波各四个并发 GET。每波响应都等待四条
  连接同时到达，防止快速串行响应掩盖问题。旧 cap2 的独立 control target 得到六条
  TCP 连接，精确失败于“应保留四条”；cap8 通过。服务对象返回值和 ETag 同时检查。
- cap8 `scap-object-store` 全部 45 个 unit 测试通过，0 ignored；原条件失败、UNKNOWN、
  deadline、禁止 redirect/retry、对象大小和 GC 行为测试仍在原分母内。
- 同一隔离 product target 的 strict Clippy `--all-targets -- -D warnings` 通过。
  这不是全 workspace、新 AWS 或完整 native fault suite 的替代凭证。
- 尝试 syscall trace 时，容器拒绝 `PTRACE_TRACEME`；daemon 和 workload 尚未开始。
  不请求绕过权限，不把空 trace 当作通过，保留原错误。
- 最初两轮 FULL/NORMAL 因调度错误同时启动 backend；均保留为不适合时延比较的样本。
- 随后的严格串行 ABBA 中，第一轮 FULL 与另一 agent 的 18.89 秒 unit run 有重叠；
  保守排除第一对的比较，只使用后面的安静 NORMAL→FULL 单对。
- 最终连接池对照等全部 agent 明确确认安静才开始，顺序和进程退出时间均记录。

## 下一步的设计门槛

本轮不引入更大的存储格式或调度改动。后续评估应按已经测到的成本排序：

1. **真实 S3 RTT、请求数及写放大。** 当前一次小写仍需串行依赖上传/回读和 HEAD CAS。
   对 AWS standard storage class 的延迟、费用、错误语义、region 和 TLS handshake
   需另立固定实验，不能从本机 Seaweed 外推。
2. **显式 SQL transaction batching。** 当前一个业务请求内已有多语句事务能力；先测
   有界批量输入、原结果、deadline 和每库公平性。独立业务身份的 group commit 则需
   新设计：同一次 HEAD CAS 原子绑定多个原结果/请求索引，逐请求冲突与取消、未接受/
   UNKNOWN/accepted 的分类、队列最大等待、批次字节预算及饥饿防护都必须保留。
   不能把多个 ACK 提前到后台上传之前。
3. **Lazy page/VFS 与冷热分层。** 若完整 image 恢复的 I/O/磁盘/RSS 成为主因，再考虑
   按验证过的 snapshot root 拉页、缓存校验、同一 reader 的 snapshot pin、GC/release
   与故障后的 cache invalidation。不能直接把 `.db`/WAL 放在网络文件系统上。
4. **新引擎 MVCC。** S3 权威、独立库并行和单库多写者是不同问题。采用 Turso 类方案的
   并发控制需要单独的事务/冲突协议、隔离级别及 native gate 证明，不能把本次 HTTP
   pool 修复或本地缓存的可丢弃性当成已经实现 MVCC 的证据。

原约 24% 回退需要历史候选在相同完整证据环境下的 CPU/等待/传输观测才能归因。
本次识别并修复了一个具体连接保留问题，给后续实验提供了可复用的 Rust 诊断挂点；
没有改写原失败记录或缩减其验证分母。
