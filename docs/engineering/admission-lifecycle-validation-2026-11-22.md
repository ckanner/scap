# 生命周期诊断与相同 seed 对照：验证台账

状态：**实施中，PR 保持 Draft，尚未通过完整验收**。本文件后续只补充当前 PR 的
精确来源、原始失败与派生结论；不将历史结果当作新候选已运行的证明。

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
完整源码清单938文件，真实回归执行前后保持干净。下列结果明确归属此冻结候选，
后续夹具修订必须重新取得受影响的实际证据。

| 门槛 | 当前状态 |
| --- | --- |
| 冻结生产候选源码/工具/release身份 | PASSED：b7b1f71；Rust1.90.0、Node22.16.0、SeaweedFS4.51 |
| fresh unit-only四维精确100% | PASSED：1020 tests，85个生产文件 |
| Node SDK/V8、HTTP、controller与类型 | PASSED：192 unit、7 HTTP、14 controller；严格类型 |
| 生命周期真实TCP/native/S3三场景 | PASSED：25 HTTP、3 BP、22完整cohort、8 snapshots、50 S3；20负控及正对照 |
| 原组提交真实故障与恢复 | PASSED：28原提交、20接受HEAD、1拒绝组CAS、28份冷恢复lookup；40负控 |
| equal-seed-v1八cell实际/独立oracle/负控 | FAILED：两次观察器竞态失败均保留；完整矩阵oracle/22负控NOT_RUN |
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
全矩阵验收或改善通过。修订后的统一候选仍须在新目录完整执行全部八轮。

## 后续判定

保持data intake租户40；本轮目标是确认名额驻留阶段和相同seed起点的有限增长表现。
不通过缩短drain分母、丢弃拒绝或选择有利pair宣称容量提升。完整业务分母、成本、
观察器开销和失败原件将在本文件与派生机器摘要中保留。新的吞吐优化必须在归因后
另立单一机制候选，当前仍不预定某项优化一定有效。
