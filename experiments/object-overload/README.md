# 开环过载、租户进展与显式 SQL batch

本实验执行 [PLAN.md](PLAN.md) 的固定工作负载。四库、两租户、一个正式 worker；
32/s 热点写入、4/s 另一租户强读、2/s control，持续 30 秒。每个计划到达都在
发出前保存；原 SQL 不重试。客户端过载、迟到到达、服务拒绝、UNKNOWN 和传输错误
分别计入完整分母。当前基础配置不启用并行读池。

另有 64 个单语句独立事务与 8 个八语句事务的等量数据对照。两个阶段都写入同样
64 行，并保存每条语句的随机原结果；报告明确区分事务/s 和逻辑操作/s。这使用
已有 `prepare([...statements], identity)` / `execute`，不宣称服务器 group commit。

到达时钟保留原始绝对时间，每次期限检查返回前固定让出一次事件循环 turn。
该动作不读取 active、不等待空位或 SDK 完成，也不平移后续计划；它让已经过期的
连续到达之间仍有处理就绪 I/O 的机会。一次 turn 不代表固定耗时，也不保证清空
全部 I/O。真实 64 个调用未完成时仍立即记录 generator_rejected，原 1 秒 lag、
30 秒窗口、1140 分母和全部失败判据不变。确定性回归同时保留旧微任务追赶反例和
71 个到达、64 个真实阻塞调用仍拒绝 7 个的证明。历史失败与修订来源见
[生命周期验证台账](../../docs/engineering/admission-lifecycle-validation-2026-11-22.md)。

## 执行

需要正式 release `scapd` 及完整构建 receipt、Node 22.16.0、SeaweedFS 4.51。
运行前提交并冻结夹具及正式产品来源；与其他测试、编译和后端负载协调安静窗口。

```sh
python -m unittest discover -s experiments/object-overload -p test_contract.py
node --test experiments/object-overload/test_schedule.mjs
node --check experiments/object-overload/probe.mjs

python experiments/object-overload/run.py \
  --source-root /absolute/frozen-product-checkout \
  --server /absolute/release/scapd \
  --build-record /absolute/service-build/build.json \
  --weed /absolute/weed \
  --evidence /absolute/evidence/object-overload-attempt-1

python experiments/object-overload/oracle.py /absolute/evidence/object-overload-attempt-1
python experiments/object-overload/controls.py /absolute/evidence/object-overload-attempt-1 \
  --output /absolute/evidence/object-overload-attempt-1-controls
```

`--source-root` 固定正式产品，夹具使用自身 checkout。归档分别绑定正式构建输入、
本目录、原 byte collector / proc sampler / launcher / independent wire reader。
审计在原夹具 checkout 执行。新目录不在现行 `object-service/build.py` 的构建输入
集合；原 Rust/SDK 等正式输入发生变化时必须新构建，不能复用旧 receipt。

runner 只产生 `OBSERVED_NOT_AUDITED`。独立 oracle、18 个负控、修改 summary 的
正控以及最后的原件复核全部完成，才能将此固定合同标为通过。所有失败目录保留，
不调大 deadline、不少发请求、不删除慢样本、不修改原始 receipt。

## 读数

- `open_loop`：完整 1,140 次计划到达、实际生成延迟、六个 5 秒窗口的各 lane 进展。
  本窗到达的成功须在本窗结束前完成；排空后的成功不能填补停滞窗口。
- `measured.single/batch`：同逻辑数据的独立事务数、逻辑操作数、原始延迟和 S3 工作量。
  固定先 single 后 batch 的一次对照不提供稳定提速比例或统计置信区间。
- `measured.overload`：全部原状态、包括排空的实际总时间、服务调用延迟及从计划
  到达算起的延迟。服务拒绝保留在总分母；原 UNKNOWN 不因后来查到 committed 改写。
- `results`：全部原身份最终 committed / cancelled，原 receipt / 随机结果和全部行。
- `publication_closures`：完整 HEAD 条件版本链、不可变依赖完整回读早于发布、原结果
  与每次 committed 回复之间的关系。
- `resources`：owned daemon 的原始 proc 采样、实际采样间隔、wait4 生命周期峰值、
  缓存/后端分开计量，以及正常停止与私有目录回收的原始身份。

完整 S3 观察器的文件同步和连接关闭开销仍存在。本机结果不能外推成真实 AWS TPS、
无代理 SLO 或任意负载下的公平性；RSS 采样也不是硬上限。动态 fleet、冷启动风暴、
持续 GC、lazy VFS 和并行读池由各自的新合同验证。
