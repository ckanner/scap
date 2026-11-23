# 同库组提交上限 8 与 4 的相同 seed 对照

状态：设计先行，actual 尚未运行；本合同在首次 actual 前冻结。基线为 PR #71
合并提交 `b8e24d0f252e01efa91726a0ea3909d148c25587`。后续实测结果另写验收报告，
不通过修改本文门槛解释已取得的结果。

## 目标与动机

[生命周期与相同 seed 验收](../engineering/admission-lifecycle-validation-2026-11-22.md)
显示，开启最多 8 个独立事务的组提交后，四个配对的 S3 requests/original ACK
均下降约 12%，但只有一个配对同时通过吞吐、成功延迟、control 延迟与成本门槛。
负载期间组的平均 invocation 持有时间约为 751–999 ms；提交后的租约持有时间
很短，不能据此优先修改租约释放边界。

本轮只检验一个假设：将 `group_commit.max_members` 从 8 降为 4，能否减小
单组公共提交耗时及等待，同时在相同接纳容量下保持 ACK 吞吐与成本。
这只是候选方向；较小组也可能增加 HEAD 发布次数和 S3 成本，实际组宽取决于
已到达队列，不能预设它一定更快。

生产 [scheduler](../../crates/scap-service/src/scheduler/group.rs) 已按配置取兼容的
队列前缀，没有等待凑组；[profile](../../crates/scap-service/src/group.rs) 已支持 4。
本轮新增实验、独立审计与结果，不需要新增生产分支。生产默认继续关闭组提交。
即使局部性能判定通过，也不自动改变默认配置或宣称生产 SLO 达标。

## 固定处理变量与工作负载

实验名 `group-width-v1`，实现目录 `experiments/group-width-load/`。两个 arm
都显式开启组提交，唯一处理变量是 `max_members: 8` 与 `max_members: 4`。
现有 `equal-seed-load` 和 `group-commit-load` 文件保持不变。

| 项目 | 冻结合同 |
| --- | --- |
| 顺序 | rate 12/s：8、4、4、8；随后 rate 32/s：8、4、4、8 |
| cell 名称 | `rate-{rate}-cap{8或4}-{1或2}` |
| 独立性 | 8 个全新 backend、service、数据库、cache 和私有目录，顺序运行 |
| seed | 原 DDL；256 行，4/s，64 s；全部原始 ACK 后 drain |
| load | 每 cell 32 s，按绝对时间开环到达；8 个固定 4 s 窗口 |
| 原始 SQL | 原 INSERT、payload、`random()` witness、RETURNING、身份与查询全部不变 |
| 分母 | 5632 个 measured inserts；另报 2048 个 seed inserts、8 个 DDL |
| control | 每 cell seed 4 次、load 8 次，保留原计划时间与身份 |
| client | inflight 192；允许 offer lag 最大 1000 ms；generator rejection 必须为 0 |
| group 其他预算 | input 1 MiB、changed pages 1024、result 1 MiB |
| admission | 原 `data_intake=80`，tenant intake=40；body/queue/worker/control 配置不变 |
| 诊断 | 原 lifecycle v1，seed drain 后 baseline；load drain 后、settlement 前 end |
| retry | UNKNOWN 只查询、取消、再查询；不重放 SQL；不自动重跑 cell |

不添加 sleep、人工 queue gate、等待凑组或按容量等待的 arrival generator。
cap 从服务启动起生效，包含 seed；seed 成本与组分布单独报告，不混入 load。

相同 seed 指相同 schema、payload、页数、257 个保留请求、结果字节数、数据树和
请求树层级。`random()` witness 保留，因此不要求对象 hash 或数据库字节相同；
每个 cell 的结果均从自身 original HTTP、S3 对象闭包和 native SQLite 校验。
不能复制另一 cell 的缓存，也不能借更换 SQL 来制造字节相等。

## 资源和时间边界

沿用 `equal-seed-v1` 的固定上限，不因 cap 4 较慢、请求增加或实测失败而扩容。
这些是本合同验收上限，不是对全部输入的数学资源证明。

| 边界 | 固定值 |
| --- | --- |
| 每 cell 原始内容 | 2 GiB；每 body 64 MiB；S3 requests 60000 |
| 每 cell trace | 240000 行、384 MiB；proxy handlers 32 |
| SDK / intents | 22000 行、32 MiB / 最多 1281 行、2 MiB；HTTP POST 最多 5139 |
| diagnostic | 两个边界各最多 8 次 GET；每响应 64 KiB；总内容 1 MiB、ledger 64 KiB |
| resources | 最多 15000 tick、100 ms 目标间隔，两个资源 ledger 合计 64 MiB |
| events / child log | 4096 行、2 MiB / 每个 1 MiB |
| backend / matrix | 2 GiB / 24 GiB、200000 inode |
| 启动和保留空间 | 启动空闲 26 GiB、220000 inode；运行保留空闲 2 GiB |
| 采样 RSS / FD / tasks | service 2 GiB/2048/256；Node 1 GiB/1024/64；4 个 backend 合计 2 GiB/2048/512；observer 1 GiB/1024/128 |
| service / seed / load | 60 s / 100 s / 90 s |
| settlement / shutdown | 600 s / 30 s |
| client / recovery / S3 | 65000 ms / 70000 ms / 15000 ms |
| cell / matrix | 900 s / 7200 s |
| 独立 audit | 每 cell 90 s；matrix 额外校验与 controls 共 120 s |
| 闭包局部上限 | image 128 pages、data chunks 32、data tree level 0、request tree level 1；保留项与节点数按原合同计算 |

采样不是硬资源限制：保存实际采样跨度、全部 owned process、kernel wait4 usage，
不把缺失角色算成零。GC 关闭，必须报告可达闭包、orphan、总对象/bytes 和本地
分配增长。32 s 负载只证明有限增长；AWS Standard、跨 AZ、稳态与生产 SLO
均为 `NOT_RUN`。

## 配置、原始发布和诊断的完整审计链

新 `Contract(rate, max_members)` 明确区分相同 rate 下的两个 cap；matrix plan、
真实 service config、启动配置 hash、cell 结果与最终报告均可核对该 cap。
不能将原来的 enabled 布尔值用作区分两个 arm 的身份。

复用已有 runner/observer/reader 时，在初始化阶段为 8、4 分别建立固定的 spec
绑定。原 equal-seed runner 的 `CONTRACTS[rate]` 和原 group reader 的
`PROFILE.max_members` 各绑定到对应 cap；执行期间不修改模块全局值或 profile。
oracle 不导入 runner，也不导入生产 serializer、状态机或 SDK 解析器。

保留原有完整分母、单 original POST、原始结果、HEAD 原 ETag CAS、闭包、完整性、
资源、源码与二进制验证，增加以下检查：

1. 每个 cell 都开启 group，真实配置和 workload plan 精确等于对应合同。
2. 原始 HEAD 发布中事务 sequence 增量不得超过该 cell cap，包含 seed 和 load。
   旧 reader 的常量 8 不能继续审计 cap 4。
3. **每个成功原始 diagnostic 响应**的 `selected_sizes` 和 `consumed_sizes`
   中，大于 cap 的桶必须为零；不只检查 end-minus-baseline。
4. baseline/end 的原始计数、完整/截断/未到达 interval 和 cohort 守恒全部继续验证。
   保存 seed 的组分布、load 的分布和真实 publication 宽度，允许 singleton。
5. 固定 ABBA 顺序、独立进程区间、八 cell 原始结果、fixture 归档与源码 SHA
   全部匹配。结束后的报表不改写已封存 cell 内容。

audit 的 `PASSED` 只表示证据合格；性能不改善也应完整发布。
每项负控必须命中预定规则，任意异常不等于负控通过。至少保留原有 22 项负控
和 unchanged positive control，并新增 cap 配置错配、group 关闭、5 成员发布、
守恒但超 cap 的 selected/consumed 桶、baseline 超 cap 而 delta 为零、配对标签
与顺序错配。不能重新运行 SQL 生成更好看的 controls。

## 在 actual 前登记的性能判定

预定四对分别为两个 rate 下的 cap8-1 对 cap4-1、cap8-2 对 cap4-2。
第二对按真实执行顺序是 candidate 先、baseline 后，报告仍以 8 为分母。
每一对必须同时满足：

- drain 后 original ACK 总数不减少；32 s offer window 内 original ACK 不减少。
- 成功请求 scheduled-to-terminal p99、control scheduled-to-terminal p99、
  S3 requests/original ACK、双向 body bytes/original ACK，各不超过 baseline 的 1.05 倍。
- 至少一个有 5% 改善：original ACK 增加到至少 1.05 倍，或 S3 requests/ACK
  降至不超过 0.95 倍，或成功 scheduled-to-terminal p99 降至不超过 0.95 倍。

全部四对满足，才称“本地有限增长样本一致支持 cap 4”。任一对不满足就报告
未通过，不能挑选最好的一对、删除有效慢轮或改变阈值。5% 是预定工程门槛，
不是统计显著性；四对样本不能估计总体收益。

逐 cell 还要报告所有 terminal 类型、BACKPRESSURE 首层、settled 与 original ACK、
窗口 ACK、drain、offer lag、每项 S3 绝对请求与双向 bytes、每 offered/ACK 成本、
CPU/RSS/FD/task、磁盘、orphan、lifecycle 均值与桶分布。资源采样在固定上限内
仍可能增加，应完整展示，不能仅用 S3 requests/ACK 宣称总体成本下降。

成功样本组成变化会影响 p99；每 cell 只有 8 次 control，该 p99 接近样本极值，
不代表总体尾延迟。lifecycle 粗桶不能导出精确 p99，group invocation 也不能
除以成员数后当作实际单 SQL 时延。两 arm 若大多 singleton，应明确处理差异有限。

## 实施和退出条件

先将本文提交到 PR，再实现 `spec/shared/run/oracle/controls` 的薄适配与有意义的
单元测试。固定工具为 Rust 1.90.0、Node 22.16.0、SeaweedFS 4.51，所有下载和
可执行文件记录 hash；保留正式 build receipt、fixture manifest、源码归档。

冻结实现 commit 后执行八 cell actual，再做一次完整独立 audit 与原始证据投影
负控。新增 CI job 运行相同合同并保存失败证据。若实现缺陷导致失败，保存原始
失败及原因，在新的明确源码身份下修复重测；不得将旧失败覆盖成同一轮成功。

本轮生产文件不变，已通过的生产覆盖率事实按精确源码身份引用；新实验单元、
repo 检查、正式 release build、真实 HTTP/S3 八 cell 和独立审计是本轮必须完成
的验证。若改变生产代码，重新执行受影响的完整单元覆盖与 native/HTTP/S3 gates。
缺失门槛保持 Draft 和 `NOT_RUN`。

最终验收报告写明配置、源码、工具、所有实际尝试、四个配对和未覆盖范围。
本轮不合格时保留原默认值，并根据原始证据选择下一项有界优化；不能靠提高
intake、queue、deadline 或资源预算把本轮变成通过。
