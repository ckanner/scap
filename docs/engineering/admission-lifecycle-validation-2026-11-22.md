# 生命周期诊断与相同 seed 对照：验证台账

状态：**生产诊断与本地八轮 equal-seed 完整验收已通过；旧过载生成器修复尚待真实验收，
PR 保持 Draft**。四个预登记性能配对仅一个满足全部改善条件，不建议默认开启组提交。
本文件保留精确来源、原始失败与派生结论，不将历史结果改记为新候选已运行。

[PR #71](https://github.com/ckanner/scap/pull/71) 已先以 `183e925d3e9bcf0a62819bf456e42fd55be05a53`
提交[冻结设计](../architecture/admission-lifecycle-diagnostics.md)，随后开始实现。
基线是已合并 PR #70 的 `20a72da51ff7de96a93a31da669a771ab5ebc12d`。

## 已完成的实现

- 固定五个 intake lane、八个可重叠的驻留 interval、19个含上界微秒桶；固定大小
  trace 附着原 Lease，不增加原工作或字节的 owner。
- HTTP ready 与 worker/encoding 返回分开；group 的可信 consumed 前缀使用共同
  invocation 范围，未消费后缀保留原 enqueue；group attempt 单独聚合。
- 原 quota 退款与 queue pending 移出均先释放业务锁，再做诊断收尾，不改变 native
  先于最后 lease 清理的所有权。原 SQL、身份、deadline、ACK/HEAD/native 屏障不变。
- 默认关闭的独立诊断凭证与 GET 接口；一个65536字节导出额度由 body/frame/clone/
  非空slice保留到最后真实字节 owner 释放。无数据库标识标签，不覆盖 discovery。

实际内存结构为 Registry 9296字节、Trace 152字节、GroupAttempt 40字节、Snapshot
9280字节；所有计数取u64最大值的JSON为29368字节。结构及最坏序列化由独立单元
断言检查，不能把这些固定开销描述为整个进程RSS上限或默认关闭零成本。

## 验证状态

生产代码预检的 Rust stable 全workspace 1019项、fmt与Clippy `-D warnings` 已通过。
首轮远端 `72d6bcf4` 的 exact coverage 检出了 daemon/export 的未覆盖路径；已保留
失败并补充故障端口测试，不排除生产代码。冻结候选
`b7b1f71fe5435658dc818965959f90e5582e920c`（tree
`e10ef46a6fe214073b2d439d77b7ce468731e893`）现已完成 fresh unit-only 全workspace
1020项；85个生产文件逐文件四维精确100%。合计 lines18228/18228、functions1605/1605、
regions27692/27692、branches3652/3652。远端该候选的 Rust exact job 也已成功。

正式 release 的328个构建输入均记录摘要；scapd SHA-256 为
`872305efeecd6b30458b162657346ffa7969026843b365a4718a48e83bda3164`，实际 native archive
SHA-256 为 `ab0981f53ac70eeafa604624f6ee4fdff0754f8b9195c713be35e138a85ba3f5`。
完整源码清单938文件，真实回归执行前后保持干净。生产覆盖、SDK、资源与组提交结果
归属 b7；后续 equal-seed 的实际来源另列为 bd8。受影响的夹具修订须重新取得实际证据。

| 门槛 | 当前状态 |
| --- | --- |
| 冻结生产候选源码/工具/release身份 | PASSED：b7b1f71；Rust1.90.0、Node22.16.0、SeaweedFS4.51 |
| fresh unit-only四维精确100% | PASSED：1020 tests，85个生产文件 |
| Node SDK/V8、HTTP、controller与类型 | PASSED：192 unit、7 HTTP、14 controller；严格类型 |
| 生命周期真实TCP/native/S3三场景 | PASSED：25 HTTP、3 BP、22完整cohort、8 snapshots、50 S3；20负控及正对照 |
| 原组提交真实故障与恢复 | PASSED：28原提交、20接受HEAD、1拒绝组CAS、28份冷恢复lookup；40负控 |
| equal-seed-v1八cell实际/独立oracle/负控 | PASSED：bd8ccce，5632 measured INSERT、2048 seed INSERT，1正控/22负控；前两次失败保留 |
| equal-seed预登记性能改善 | NOT_MET：四对仅12-off-1/on-1满足全部条件 |
| 旧object-overload到达时钟修复 | 原bd8远端失败保留；新时钟Node8/Python29自测PASSED，新实际/18负控NOT_RUN |
| AWS Standard/跨AZ/生产SLO/长期工作集 | NOT_RUN |

## 保留的实际失败

`b7b1f71` 的首次本地 equal-seed attempt 在首轮 `rate-12-off-1` 的 seed_rows 阶段
停止：资源观察器返回 `FileNotFoundError`，尚未进入load。最后完整sample为544，
中止前148个完成调用全部成功；已启动的7个owned子进程均取得reap记录，服务正常退出。
未完成的Node阶段按失败清理被终止，private与原始证据保留，不能计成seed或测量通过。

远端同一候选也出现相同观察器失败，见
[CI原始job](https://github.com/ckanner/scap/actions/runs/45103408597/job/137459153891)与
[失败artifact](https://github.com/ckanner/scap/actions/runs/45103408597/artifacts/14786367784)；
artifact zip SHA-256 为 `5af261e05771f1801044bac05f3c93621386390fbbe089208ec839bf5a4e6895`。

代码检查可确定性复现：观察器先枚举子目录，原SQLite临时目录随后被清理，pending
目录的scandir在异常处理范围外，导致正常文件生命周期被误当作监控失败。旧原件
只记录异常repr而没有栈，因此不能声称已确定此次消失的具体pathname。夹具现已
记录这类子目录消失竞态，同时继续拒绝根目录缺失/替换、其他I/O错误和活进程缺失，
并补充有界来源栈。26个夹具自测通过，同一确定性竞态在b7原函数上失败、修订后通过。
修订不改变生产代码、配额、工作量、期限或判定阈值；
必须在新冻结来源和独立新目录重跑完整矩阵，原失败不覆盖。

第二次实际来源为 `8198ab606c7efedb708775156c2561b7ba6e6ac9`。前五个cell完整结束；
第六个 `rate-32-on-1` 的load、完整诊断终点与原身份核验也已完成，但服务关闭期间
观察器的第2067次采样返回 `required owned-process metric unavailable`，立即停止矩阵。
完整错误栈指向原proc status解析，全部9个owned子进程随后取得reap记录；服务正常
退出，错误记录至service wait4约2.995毫秒。失败原件没有该次status原文，因此不能
确定具体缺项/零值，也不把稍后的wait4当作缺失瞬间的证明。

上游Linux在[proc status实现](https://github.com/torvalds/linux/blob/master/fs/proc/array.c)
中仅在task仍有mm时输出内存字段，[退出实现](https://github.com/torvalds/linux/blob/master/kernel/exit.c)
则先清理mm、后发布zombie状态；这支持短暂退出过渡的机制解释，不替代本次未记录的
原字节。新的观察器仅对相应缺项/零值或proc子路径ENOENT，使用同一个owned proc fd、
相同PID/start_ticks，在每次process sample开始后的10毫秒内最多8次重读，间隔至少
1毫秒；必须实际读到Z才记录退出样本，不填零、不用任意更晚的退出代替证明。
初始stat、失败status、操作、全部探针原stat和起止时间均保留，独立oracle复核边界。
仍活、身份变化、超时、额外读取、权限及格式错误继续失败，原预算和工作量不变。

第二次矩阵失败后，在独立8198源码中按原90秒/cell预算开发预检了12-off-1、12-on-1、
32-off-1；原版完整cell审计分别用21.342、13.479、50.764秒通过。三轮seed均为256行、
257个身份、21页、87844个原结果字节，生命周期cohort与原HTTP分母一致。原完整矩阵
来源检查仍因失败运行缺少fixture-after记录而失败，未构造该记录；上述预检不能算
全矩阵验收或改善通过。其后统一候选 bd8 在全新目录执行全部八轮，独立 oracle、
22 个定向负控及运行后完整源码清单检查均通过。

### 旧过载生成器的远端失败与独立修复

[object-overload job 137473883600](https://github.com/ckanner/scap/actions/runs/45108086437/job/137473883600)
的 PR head 为 bd8，实际 CI checkout 为 merge `16beab5bca50e85108097b1f04db5422fc357c25`。
二者 tree 都是 `5f9b8688ae69a3822b1085cd00c39034930619b8`；不能将 merge 的运行身份改记
成本地 bd8。原1140个到达只有1133个POST，7个generator_rejected/posts=0达到原64个
客户端并发上限。服务exit0、proxy.errors=[]；完整verify/recovered、oracle与18负控
未执行。失败[artifact 14788621463](https://github.com/ckanner/scap/actions/runs/45108086437/artifacts/14788621463)
SHA-256为 `1a1291fbe10b63fbebb9b020d40b1c601e1eb67752684005f8fe5c56b8e9f7f6`。

7次拒绝集中在约3.223毫秒。当时15个连续过期offer先将active从56增至64，随后拒绝7个；
全部64个都尚未记录完整HTTP响应。最后拒绝后0.965毫秒记录首个HTTP429，随后50毫秒内
有21个HTTP/SDK终态。此前还存在1561.831毫秒的完整HTTP记录空档；原件没有header或
OS-ready时刻，不能唯一归因于事件循环，也不能把7个未发HTTP算成服务BACKPRESSURE。

同代码旧8198的该合同成功仍只属于原记录；两次远端scapd摘要相同不使本次失败消失。
检查发现旧until在所有target过期时只产生微任务续体，可能连续推迟就绪I/O。新时钟
只在原绝对等待后无条件让一次setImmediate turn，不读取active、不等待响应、不改
64上限/速率/lag/窗口/分母/SQL/身份/同步原字节采集和oracle规则；共享schedule.mjs不变。
一次turn只固定调度动作次数，不固定耗时、不保证清空I/O，也不保证实验永不触顶。

Node22.16.0上的确定性回归证明：旧时钟在6个过期到达、cap2、就绪回调完成的合成情形中
发2拒4；新时钟发6拒0，全部原scheduled值保持。另一反例让71个到达中的前64个调用
直到arrivalsFinished才释放，新时钟仍发64拒7，证明没有改为等待响应的闭环。两个测试
有5秒超时；原观察失败仍传播。全部8个Node与29个Python合同自测通过。该机制证明不能
回填历史七次失败；修订仍需新冻结、新目录完整实际、原oracle/18负控和原件复核。

## 第三次完整矩阵：来源与结果

第三次实际来源为 `bd8ccce8224520283454e28d8f479d659471b3ed`，tree为
`5f9b8688ae69a3822b1085cd00c39034930619b8`。源码清单938文件在运行前后相同，
本地release与全部328个构建输入仍与b7逐字节一致；完整生产覆盖没有被冒称为bd8重跑。
八轮各用独立后端、服务、库和私有cache。原256条seed全部ACK后drain，再执行32秒load。
逻辑seed统一为256行、257个保留身份、21页、数据树level0、请求树level1、epoch1、
87844个原结果字节，无overflow/freelist。随机witness、对象摘要与seed过程中的组尺寸
可以不同，均按本轮原件核验，不声称seed的完整物理对象历史逐字节相同。

完整actual、原HTTP/S3对象闭包、SQLite integrity_check、原身份查证、8轮进程清理、
五lane生命周期差分、1个正控和22个精确规则负控全部通过。5632条测量INSERT全部有一次
原POST；另有2048条seed INSERT、8次DDL与每轮8个load status。原load结果为2383 ACK、
3249 BACKPRESSURE、0 UNKNOWN、0提交后结果不可用、0其他。全部BP首先命中
`intake_data_requests_tenant;used=40;limit=40;requested=1`，全部generator_rejected为0。
后续查证建立原身份的最终committed/cancelled，不重发SQL、不回填原ACK。

派生机器摘要见[admission-lifecycle-local-2026-11-22.json](../evidence/admission-lifecycle-local-2026-11-22.json)。
原完整audit+controls JSON SHA-256为
`e2d7d0a865d0d0caba603f8b63d86462e6e85b102f2092288daa4e6c39aa5eea`。

### 原始业务结果

| Cell | Offered | 原 ACK | 原 SDK BP | UNKNOWN | 提交后结果不可用合并项 | 其他 | ACK % | 最终 committed | 最终 cancelled |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| rate-12-off-1 | 384 | 312 | 72 | 0 | 0 | 0 | 81.250 | 312 | 72 |
| rate-12-on-1 | 384 | 355 | 29 | 0 | 0 | 0 | 92.448 | 355 | 29 |
| rate-12-on-2 | 384 | 288 | 96 | 0 | 0 | 0 | 75.000 | 288 | 96 |
| rate-12-off-2 | 384 | 301 | 83 | 0 | 0 | 0 | 78.385 | 301 | 83 |
| rate-32-off-1 | 1024 | 288 | 736 | 0 | 0 | 0 | 28.125 | 288 | 736 |
| rate-32-on-1 | 1024 | 294 | 730 | 0 | 0 | 0 | 28.711 | 294 | 730 |
| rate-32-on-2 | 1024 | 279 | 745 | 0 | 0 | 0 | 27.246 | 279 | 745 |
| rate-32-off-2 | 1024 | 266 | 758 | 0 | 0 | 0 | 25.977 | 266 | 758 |

BP 与 UNKNOWN 已按原 SDK 结果分开；迟到的 HTTP BP 不把 UNKNOWN 改写为 BP。“提交后结果不可用”包含 wire CBU 和已提交后的 SDK deadline，不能当成精确 wire CBU 数。最终 settlement 结果不回填原 ACK。actual_http_posts（实际 POST）只数 execute 的原始 POST，不含 load 的 8 个 status control 或 seed_rows 的 4 个 status control，也不代表该 phase 全部 HTTP POST。其他分类的完整分解保留在 JSON。

### 到达窗口、延迟与业务 drain

| Cell | 32 秒内 SDK ACK | 业务 drain 秒 | ACK/drain 秒 | 成功 p99 ms | Control p99 ms | Offer lag p99 ms | Offer lag max ms | 生成器拒绝 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| rate-12-off-1 | 273 | 36.401 | 8.571 | 4974.185 | 49.869 | 11.834 | 60.171 | 0 |
| rate-12-on-1 | 315 | 34.998 | 10.144 | 3984.390 | 46.263 | 37.898 | 78.581 | 0 |
| rate-12-on-2 | 256 | 35.322 | 8.154 | 5338.847 | 909.308 | 650.665 | 799.344 | 0 |
| rate-12-off-2 | 261 | 37.078 | 8.118 | 5240.011 | 51.305 | 16.038 | 36.419 | 0 |
| rate-32-off-1 | 248 | 36.443 | 7.903 | 5421.330 | 69.225 | 10.409 | 94.872 | 0 |
| rate-32-on-1 | 254 | 35.797 | 8.213 | 5968.473 | 53.595 | 64.985 | 158.029 | 0 |
| rate-32-on-2 | 246 | 35.369 | 7.888 | 6418.089 | 223.018 | 34.348 | 106.507 | 0 |
| rate-32-off-2 | 226 | 36.333 | 7.321 | 6304.526 | 64.682 | 13.191 | 58.001 | 0 |

业务 drain = max(arrivals_finished, 最后 execute call_finished) − phase origin。它不包含更晚的 control 或诊断 quiescence 完成时间。成功/control 延迟来自 scheduled→观测 call_finished；32 秒内 ACK 使用原 SDK terminal。每 cell 只有 8 个 load control，nearest-rank p99 即该组最大值。

### Load + drain 的全部 S3 成本

| Cell | S3 attempts | S3/原 ACK | 请求 B/ACK | 响应 B/ACK | 双向 B/ACK | S3/offered | 双向 B/offered |
| --- | --- | --- | --- | --- | --- | --- | --- |
| rate-12-off-1 | 6600 | 21.154 | 101510.106 | 202237.462 | 303747.567 | 17.188 | 246794.898 |
| rate-12-on-1 | 6602 | 18.597 | 99209.837 | 198132.794 | 297342.631 | 17.193 | 274887.068 |
| rate-12-on-2 | 5346 | 18.562 | 101382.378 | 202407.858 | 303790.236 | 13.922 | 227842.677 |
| rate-12-off-2 | 6366 | 21.150 | 101953.007 | 203116.123 | 305069.130 | 16.578 | 239129.708 |
| rate-32-off-1 | 6090 | 21.146 | 102913.840 | 205025.347 | 307939.188 | 5.947 | 86607.896 |
| rate-32-on-1 | 5451 | 18.541 | 101076.017 | 201798.582 | 302874.599 | 5.323 | 86958.137 |
| rate-32-on-2 | 5175 | 18.548 | 103477.097 | 206581.441 | 310058.538 | 5.054 | 84478.840 |
| rate-32-off-2 | 5625 | 21.147 | 105888.981 | 210942.556 | 316831.538 | 5.493 | 82301.942 |

分子包含该阶段全部 S3 尝试、控制请求和双向 body；不是 HEAD PUT 数，也不等于 TLS 流量或 AWS 账单。N/A 不按 0 处理。

### 四个预登记配对

| Pair | 达标 | ACK off→on | 窗口 ACK off→on | 成功 p99 比 | Control p99 比 | S3/ACK 比 | Body/ACK 比 | 未通过规则 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| rate-12-off-1 → rate-12-on-1 | 是 | 312 → 355 | 273 → 315 | 0.801 | 0.928 | 0.879 | 0.979 | 无 |
| rate-12-off-2 → rate-12-on-2 | 否 | 301 → 288 | 261 → 256 | 1.019 | 17.723 | 0.878 | 0.996 | control_p99_within_5_percent, offer_window_ack_not_reduced, original_ack_not_reduced |
| rate-32-off-1 → rate-32-on-1 | 否 | 288 → 294 | 248 → 254 | 1.101 | 0.774 | 0.877 | 0.984 | success_p99_within_5_percent |
| rate-32-off-2 → rate-32-on-2 | 否 | 266 → 279 | 226 → 246 | 1.018 | 3.448 | 0.877 | 0.979 | control_p99_within_5_percent |

比值均为 on/off。ACK 与窗口 ACK 不下降；四项延迟/成本不增加超过 5%；原 ACK 或 S3/ACK 至少改善 5%。这里直接保留 oracle 的 checks，未重新挑选阈值或用均值替代四组配对。

### 名额驻留的主要范围

下表是data lane已完成interval的均值；本轮成功acquire均为原ACK，八种interval均完整，
没有censored/not_reached。未取得lease的BP不进入该cohort。完整五lane计数、八interval、
19桶、group attempts与独立S3发布组大小都保留在机器摘要中。

| Cell | Queue ms | Invocation ms | Encoding ms | Post-work ms | Post-HTTP ms | Total hold ms |
| --- | --- | --- | --- | --- | --- | --- |
| rate-12-off-1 | 3502.896 | 116.525 | 0.012 | 0.174 | 0.063 | 3619.671 |
| rate-12-on-1 | 1984.226 | 751.008 | 0.005 | 0.190 | 0.027 | 2735.585 |
| rate-12-on-2 | 3085.509 | 945.052 | 0.005 | 0.259 | 0.038 | 4030.951 |
| rate-12-off-2 | 3729.148 | 123.053 | 0.010 | 0.181 | 0.061 | 3852.459 |
| rate-32-off-1 | 4508.320 | 126.380 | 0.009 | 0.159 | 0.050 | 4634.931 |
| rate-32-on-1 | 3476.263 | 963.089 | 0.006 | 0.284 | 0.031 | 4439.760 |
| rate-32-on-2 | 3619.457 | 999.050 | 0.006 | 0.187 | 0.025 | 4618.834 |
| rate-32-off-2 | 4872.738 | 136.413 | 0.012 | 0.146 | 0.058 | 5009.367 |

queue是等待，invocation是完整worker调用范围；group成员共同记录一次可信调用范围，
不能除以成员数后称为每条SQL的实测服务时间，也不能将所有重叠interval相加当作wall time。
本负载的post_work_hold均值仅0.146–0.284ms，而queue为秒级，因此当前没有依据优先拆分
work/response额度或提前释放原lease。它也不证明大结果、慢客户端下的尾部持有没有问题。

12-on-2的8个control全部total_hold之和69.829ms，而端到端p99为909.308ms；32-on-2相应
总和74.118ms、p99为223.018ms。聚合计数不能逐请求配对，但这些界限足以排除将整个尖峰
直接解释为已测lease内部排队。原到达lag、生成器/观察器停顿、入站及完整响应捕获等仍可能
参与。两项尾延迟失败按预登记规则保留，不删除慢样本，也不把它们都归因于组提交阻塞。

### 完整阶段成本与存储增长

| Cell | Phase | S3 attempts | 请求 B | 响应 B | HEAD 尝试 | HEAD 接受 | Method:status | 发布组大小:次数 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| rate-12-off-1 | startup | 2 | 32 | 32 | 0 | 0 | {"GET:200": 1, "PUT:200": 1} | {} |
| rate-12-off-1 | seed | 27 | 12417 | 13774 | 3 | 3 | {"GET:200": 17, "PUT:200": 10} | {"1": 1} |
| rate-12-off-1 | seed_rows | 5004 | 18175623 | 38077993 | 256 | 256 | {"GET:200": 3336, "PUT:200": 1667, "PUT:412": 1} | {"1": 256} |
| rate-12-off-1 | load | 6600 | 31671153 | 63098088 | 312 | 312 | {"GET:200": 4401, "PUT:200": 2199} | {"1": 312} |
| rate-12-off-1 | verify | 3501 | 1655974 | 19868291 | 72 | 72 | {"GET:200": 3284, "PUT:200": 217} | {} |
| rate-12-on-1 | startup | 2 | 32 | 32 | 0 | 0 | {"GET:200": 1, "PUT:200": 1} | {} |
| rate-12-on-1 | seed | 27 | 12417 | 13774 | 3 | 3 | {"GET:200": 17, "PUT:200": 10} | {"1": 1} |
| rate-12-on-1 | seed_rows | 5004 | 18175623 | 38077993 | 256 | 256 | {"GET:200": 3336, "PUT:200": 1667, "PUT:412": 1} | {"1": 256} |
| rate-12-on-1 | load | 6602 | 35219492 | 70337142 | 51 | 51 | {"GET:200": 4402, "PUT:200": 2200} | {"1": 3, "2": 2, "3": 2, "4": 1, "5": 1, "6": 1, "7": 1, "8": 40} |
| rate-12-on-1 | verify | 2940 | 740913 | 16760647 | 29 | 29 | {"GET:200": 2853, "PUT:200": 87} | {} |
| rate-12-on-2 | startup | 2 | 32 | 32 | 0 | 0 | {"GET:200": 1, "PUT:200": 1} | {} |
| rate-12-on-2 | seed | 27 | 12417 | 13774 | 3 | 3 | {"GET:200": 17, "PUT:200": 10} | {"1": 1} |
| rate-12-on-2 | seed_rows | 4947 | 18160928 | 38056606 | 237 | 237 | {"GET:200": 3298, "PUT:200": 1648, "PUT:412": 1} | {"1": 221, "2": 13, "3": 3} |
| rate-12-on-2 | load | 5346 | 29198125 | 58293463 | 39 | 39 | {"GET:200": 3565, "PUT:200": 1781} | {"1": 2, "2": 1, "4": 1, "8": 35} |
| rate-12-on-2 | verify | 3799 | 2310595 | 23202574 | 96 | 96 | {"GET:200": 3510, "PUT:200": 289} | {} |
| rate-12-off-2 | startup | 2 | 32 | 32 | 0 | 0 | {"GET:200": 1, "PUT:200": 1} | {} |
| rate-12-off-2 | seed | 27 | 12417 | 13774 | 3 | 3 | {"GET:200": 17, "PUT:200": 10} | {"1": 1} |
| rate-12-off-2 | seed_rows | 5004 | 18175623 | 38077993 | 256 | 256 | {"GET:200": 3336, "PUT:200": 1667, "PUT:412": 1} | {"1": 256} |
| rate-12-off-2 | load | 6366 | 30687855 | 61137953 | 301 | 301 | {"GET:200": 4245, "PUT:200": 2121} | {"1": 301} |
| rate-12-off-2 | verify | 3646 | 2033598 | 21794642 | 83 | 83 | {"GET:200": 3396, "PUT:200": 250} | {} |
| rate-32-off-1 | startup | 2 | 32 | 32 | 0 | 0 | {"GET:200": 1, "PUT:200": 1} | {} |
| rate-32-off-1 | seed | 27 | 12417 | 13774 | 3 | 3 | {"GET:200": 17, "PUT:200": 10} | {"1": 1} |
| rate-32-off-1 | seed_rows | 5004 | 18175623 | 38077993 | 256 | 256 | {"GET:200": 3336, "PUT:200": 1667, "PUT:412": 1} | {"1": 256} |
| rate-32-off-1 | load | 6090 | 29639186 | 59047300 | 288 | 288 | {"GET:200": 4061, "PUT:200": 2029} | {"1": 288} |
| rate-32-off-1 | verify | 14701 | 19138505 | 106077357 | 736 | 736 | {"GET:200": 12482, "PUT:200": 2219} | {} |
| rate-32-on-1 | startup | 2 | 32 | 32 | 0 | 0 | {"GET:200": 1, "PUT:200": 1} | {} |
| rate-32-on-1 | seed | 27 | 12417 | 13774 | 3 | 3 | {"GET:200": 17, "PUT:200": 10} | {"1": 1} |
| rate-32-on-1 | seed_rows | 4992 | 18221681 | 38171969 | 252 | 252 | {"GET:200": 3328, "PUT:200": 1663, "PUT:412": 1} | {"1": 249, "2": 2, "3": 1} |
| rate-32-on-1 | load | 5451 | 29716349 | 59328783 | 38 | 38 | {"GET:200": 3635, "PUT:200": 1816} | {"1": 1, "5": 1, "8": 36} |
| rate-32-on-1 | verify | 14621 | 18814035 | 104727261 | 730 | 730 | {"GET:200": 12423, "PUT:200": 2198} | {} |
| rate-32-on-2 | startup | 2 | 32 | 32 | 0 | 0 | {"GET:200": 1, "PUT:200": 1} | {} |
| rate-32-on-2 | seed | 27 | 12417 | 13774 | 3 | 3 | {"GET:200": 17, "PUT:200": 10} | {"1": 1} |
| rate-32-on-2 | seed_rows | 5001 | 18174848 | 38076973 | 255 | 255 | {"GET:200": 3334, "PUT:200": 1666, "PUT:412": 1} | {"1": 254, "2": 1} |
| rate-32-on-2 | load | 5175 | 28870110 | 57636222 | 37 | 37 | {"GET:200": 3451, "PUT:200": 1724} | {"1": 2, "5": 1, "8": 34} |
| rate-32-on-2 | verify | 14826 | 19307895 | 106844832 | 745 | 745 | {"GET:200": 12582, "PUT:200": 2244} | {} |
| rate-32-off-2 | startup | 2 | 32 | 32 | 0 | 0 | {"GET:200": 1, "PUT:200": 1} | {} |
| rate-32-off-2 | seed | 27 | 12417 | 13774 | 3 | 3 | {"GET:200": 17, "PUT:200": 10} | {"1": 1} |
| rate-32-off-2 | seed_rows | 5004 | 18175623 | 38077993 | 256 | 256 | {"GET:200": 3336, "PUT:200": 1667, "PUT:412": 1} | {"1": 256} |
| rate-32-off-2 | load | 5625 | 28166469 | 56110720 | 266 | 266 | {"GET:200": 3751, "PUT:200": 1874} | {"1": 266} |
| rate-32-off-2 | verify | 14987 | 19587156 | 107718966 | 758 | 758 | {"GET:200": 12703, "PUT:200": 2284} | {} |

startup 为服务启动；seed 为 create/activate/DDL；seed_rows 为固定 256 行预填充；load 含原业务与控制的 drain；verify 为 settlement 和最终查询。

| Cell | Seed pages | Seed retained | Final pages | Final retained | 最终行数 | 累计不可变对象 | 累计不可变 B | 最终 live B | Orphan B |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| rate-12-off-1 | 21 | 257 | 43 | 641 | 568 | 3450 | 51000696 | 779020 | 50221676 |
| rate-12-on-1 | 21 | 257 | 46 | 641 | 611 | 3625 | 53869854 | 825967 | 53043887 |
| rate-12-on-2 | 21 | 257 | 42 | 641 | 544 | 3353 | 49375485 | 755580 | 48619905 |
| rate-12-off-2 | 21 | 257 | 42 | 641 | 557 | 3405 | 50395022 | 766058 | 49628964 |
| rate-32-off-1 | 21 | 257 | 41 | 1281 | 544 | 4642 | 65953204 | 896506 | 65056698 |
| rate-32-on-1 | 21 | 257 | 42 | 1281 | 550 | 4664 | 65953731 | 904448 | 65049283 |
| rate-32-on-2 | 21 | 257 | 41 | 1281 | 535 | 4604 | 65541329 | 888583 | 64652746 |
| rate-32-off-2 | 21 | 257 | 40 | 1281 | 522 | 4552 | 64929138 | 874349 | 64054789 |

Final retained = 经审计 originals_verified + 1 个 DDL 身份。GC 关闭；不可变对象统计不含 worker identity 和可变 HEAD 版本。JSON 另保留 phase start/end 的 retained、committed 和 page 状态。

独立oracle是在已捕获原字节上离线重建，不新增产品S3请求。业务load成本包括该阶段的
8个status及drain；verify另含全部lookup/cancel和最终查询。32/s的verify开销明显大于
load，拒绝后的查证与取消不能从全流程成本中省略。GC保持关闭，约49–65MB的每轮orphan
均按原件保留；最终live closure约0.76–0.90MB，不是整个后端的物理磁盘大小。

### 资源、采样与观察器成本

固定目标间隔100ms是采样计划；下列为原样本实际值。每轮由owned proc fd与原身份核验
全部9个子进程，记录wait4终态。采样峰值是接受观察，不构成内核hard cap，也不能证明
采样间没有更高瞬时值。本次完整证据实际allocated为1729073152字节、80976个inode，
低于原24GiB/200000上限；所有上限、期限与速率未因失败而提高。

| Cell | Samples | Service RSS MiB | Observer RSS MiB | Service CPU s | Observer CPU s | Observer span s | Interval p99 ms | Interval max ms | Scan p99 ms | Scan max ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| rate-12-off-1 | 1400 | 13.281 | 26.516 | 9.190 | 53.670 | 140.223 | 101.153 | 146.901 | 64.984 | 139.891 |
| rate-12-on-1 | 1350 | 13.203 | 31.531 | 8.169 | 50.390 | 135.255 | 101.931 | 126.939 | 59.526 | 68.966 |
| rate-12-on-2 | 1411 | 13.148 | 32.633 | 10.657 | 63.350 | 144.586 | 166.095 | 224.752 | 120.615 | 220.071 |
| rate-12-off-2 | 1434 | 13.285 | 35.641 | 9.513 | 54.920 | 143.790 | 102.176 | 194.162 | 71.725 | 193.707 |
| rate-32-off-1 | 2050 | 13.496 | 39.309 | 15.749 | 114.670 | 206.309 | 113.557 | 207.576 | 108.322 | 207.071 |
| rate-32-on-1 | 2099 | 13.328 | 37.855 | 16.571 | 127.050 | 212.926 | 143.415 | 529.377 | 129.068 | 517.004 |
| rate-32-on-2 | 2174 | 13.223 | 39.648 | 16.845 | 125.350 | 219.501 | 126.925 | 298.046 | 110.004 | 297.566 |
| rate-32-off-2 | 2188 | 13.621 | 40.523 | 16.974 | 132.610 | 221.783 | 129.213 | 470.444 | 123.625 | 468.964 |

| Role | 最大已采RSS MiB | 最大已采FD | 最大已采tasks |
| --- | --- | --- | --- |
| service | 13.621 | 66 | 8 |
| node | 131.121 | 67 | 11 |
| backend | 936.758 | 124 | 58 |
| observer | 40.523 | 18 | 5 |

Service CPU来自单个daemon的完整wait4生命周期；Node/后端的各子进程CPU另列在机器摘要。
Observer CPU依据运行前SC_CLK_TCK及同身份原stat的首末utime/stime差计算，包含runner、
代理与采样的整轮已观察跨度，排除未观测的前后缀；不是纯load CPU或诊断净开销。
Scan跨度包含锁等待和进程/文件系统观察，不含completed_ns之后的JSON编码与追加。
本次最大采样间隔529.377ms、最大scan跨度517.004ms，必须保留观察器扰动的限制。
两边均启用诊断与同版观察器，当前实验没有隔离“诊断开/关”的净成本。
本次成功矩阵没有走到需要多次stat确认的exit_probe，退出竞态修复另有确定性反例与边界单测；
不能将没有复现历史竞争写成对其发生频率的证明。

### 远端来源单独记账

远端[bd8 equal-seed job](https://github.com/ckanner/scap/actions/runs/45108086437/job/137473883590)
已完成actual、独立审计及反控。PR head为bd8，实际checkout为merge16beab5，其tracked tree
与bd8相同；远端执行身份独立，不能当成本地bd8矩阵的原结果。
[artifact14788989001](https://github.com/ckanner/scap/actions/runs/45108086437/artifacts/14788989001)
为184787013字节，SHA-256
`d39038aeb3a2f2313864af03473d882f092e33611e87ce474abe6dc6b142d093`。
旧8198远端同合同也成功，而其本地第六轮退出竞争失败，两份结果都保留。
当前CI的旧overload失败仍须按上节单独处理，不能写“当前CI全绿”。

## 后续判定

保持data intake租户40；本轮目标是确认名额驻留阶段和相同seed起点的有限增长表现。
不通过缩短drain分母、丢弃拒绝或选择有利pair宣称容量提升。完整业务分母、成本、
观察器开销和失败原件将在本文件与派生机器摘要中保留。新的吞吐优化必须另立单一机制候选。
优先区分worker内部对象I/O、HEAD/native完成与到达/采集路径的干扰；当前粗粒度invocation
不足以选择某一I/O并行实现，control尖峰也不足以推出服务端调度饥饿。保持group默认关闭、
intake40与原lease/ACK边界；不优先做响应额度拆分。后续较长窗口、更大工作集、真实AWS
Standard/跨AZ、持续GC和生产SLO均另需冻结合同与完整证据。

若进入下一项最小优化对照，优先提出同为group开启时的 `max_members: 8 → 4` 单变量
候选：减少共同调用范围可能降低整组等待，代价是增加HEAD发布频率和S3成本。该假说
直接对应本轮组大小、队列与调用范围证据，比直接引入新的I/O并发所有权更小；它尚未
冻结或运行，不能声称一定提速或会修复lease之外的control尖峰。新合同须保持全部原
intake/queue/transport、SQL/身份、deadline、字节预算、不等待凑组及原ACK屏障，按原ACK、
窗内ACK、尾延迟、全部S3/body成本和资源非退化共同判定，不修改本次equal-seed-v1原件。
