# 固定开环过载与显式 SQL batch 合同

本计划在实际运行之前冻结。使用未插桩的正式 `scapd`、正式 Node SDK、固定 native
SQLite 和需要签名的 SeaweedFS 4.51。S3 代理保留全部原始条件、body、ETag 和交换，
owned 子进程通过原 `/proc/self` fd 交接采集资源。本夹具没有替代数据库实现。

## 工作量与语义

四库、两租户、一个 worker `6101`，每库 create / activate / DDL 各一次。
`single`、`batch`、`hot` 属于租户 7，`quiet` 属于租户 8。

1. `single`：64 个独立事务，每事务一条 INSERT。
2. `batch`：8 个独立事务，每事务 8 条 INSERT；与 single 的 64 行输入逐字相同。
   每条 INSERT 都有 `RETURNING id,payload,random()`。批内语句共享一次事务提交，
   不称为 64 个独立事务，也不称为已经实现服务器 group commit。
3. `overload`：原始 30 秒窗口。hot 每秒 32 个原 execute；quiet 每秒 4 个强 query；
   hot 的 control 每秒 2 个 status。共 960 / 120 / 60，合计 1,140 次计划到达。
   所有时间点在阶段开始前固定，不等待上一个响应后再生成下一次到达。
4. `verify`：每个预先保存的原 execute 身份都执行 lookup / cancel / lookup，
   即使未实际发送也沿原身份建立最终 committed / cancelled 状态。全部行逐字核对。
5. `recovered`：排空与原身份查证后，四库分别强读，验证两租户仍可取得执行资源。

客户端最多同时 64 个 SDK 调用。到达时槽位已满，立即记录 `generator_rejected`，
不排队、不发送 SQL、不换身份。完整原计划分母保留；若出现该状态，本次无法认证
规定服务 offered-rate，实验不通过。到达处理最多滞后 1 秒；迟到也不平移后续计划。
服务的明确拒绝、UNKNOWN、超时及传输错误全部保留，不能丢弃慢样本或自动 execute。
每阶段完整 deadline 600 秒、整个运行 1,200 秒，均从原起点计算，不续期。

## 预先声明的判据

- 30 秒内必须观察到至少一次 hot 的明确 BACKPRESSURE，否则报告“未形成过载”，
  本合同不通过；不能事后提高 offered-rate 并沿用同一结果。
- 将原始到达时间分成六个 5 秒窗口：每窗 hot 至少一项原 execute 成功，quiet 至少
  一项强 query 成功，control 至少一项 status 成功。这些调用必须在本窗到达并在
  本窗结束前完成，不能用排空阶段的迟到成功填补停滞窗口。这是固定负载的进展判据，
  不承诺所有租户比例公平，也不是生产延迟 SLO。
- 每个调用保留计划时间、实际开始、HTTP 发送及终态、SDK 终态。SDK 成功必须与
  原始 HTTP 一致；所有成功 commit 与 S3 原 Result、完整回读、原 HEAD 发布绑定。
- 每个原 execute 只发一次。最终查证覆盖全部原身份，原 ACK 的 receipt、随机结果
  保持逐字相同，实际行集合等于最终 committed 集合。cancel 不撤销已提交事务。
- single / batch 必须完成相同逻辑工作量；单独报告独立事务数、语句/行数、成功
  事务每秒、成功逻辑操作每秒、端到端时延、对象请求及字节，不预设提速比例。
- 所有采样、正式构建 receipt、源码、工具、身份、启动声明及 owned 退出证据齐全。
  最后强读和正常停止验证本批工作释放与可继续服务；它不证明任意负载下绝无泄漏。

服务配置逐字段冻结在 spec.py：4 actors、每租户 3、2 control workers；queue 为
global / tenant / DB = 32 / 16 / 8，control reserve 4；intake 16 / 8 / 4。
`admission.read_pool = null` 明确关闭本批另行开发的并行读池，保留原 actor 路径。
global output pool 512 MiB、tenant 192 MiB，保留原 8 / 1 MiB control 预留；
单 execute result-memory 128 MiB。选择两个租户各可拥有一个完整结果预算，避免
global output 小于两个 tenant 原预算造成测试先天不可并发；此配置在执行前固定。
native FULL、受检 TRUNCATE、原 Manifest GET、条件写和 ACK 顺序不变。

## 证据与边界

复用原 object-load byte collector / owned sampler，原 helper 源码连同本目录一起
归档并逐文件校验；原 object-load 的 871 POST 合同和所有原门槛保持不变。
新实验不进入正式构建输入范围；正式产品源码与本次夹具源码分别绑定，只有精确
构建输入全相同才可复用正式二进制。运行前后都再次核验。

原始证据有 2 GiB、30,000 S3 请求、200,000 trace 行、32 个代理 handler 上限；
触发即失败，禁止截断后 PASS。owned daemon RSS / FD / thread / cache / backend
每 100 ms 尝试采样，实际间隔与 kernel wait4 maxrss 单列。采样峰值不是硬上限。

完整原始历史由不导入 runner 或产品的 oracle 独立审核；负控在不可变源的独立
hardlink 副本中以替换文件方式修改。修改 summary 的正控应不影响事实结论。
原始失败保留，修复后的输入需要新提交、新目录和新实际；不延长预算或选取好样本。

本结果只认证这份固定负载的正确计账与进展。代理有同步证据开销；这些 TPS 不能
等同无代理的 S3 后端性能。`aws_standard=NOT_RUN`、`production_slo_passed=false`、
`sampled_resource_peak_is_hard_bound=false` 固定保留。动态 fleet、lazy VFS、服务器
group commit、硬资源隔离、冷启动风暴和持续 GC 的独立合同不由本实验推导。
