# group-width-v1：同库组提交上限 8 与 4

本实验实现[先行冻结的设计](../../docs/architecture/group-width-comparison.md)。
两 arm 均显式开启 group commit，唯一服务配置差异是 `max_members`。生产现有
配置已支持两个值；本实验不改变生产默认、ACK、HEAD、native publication 或身份协议。

## 固定八 cell

每个 rate 顺序为 `cap8-1 → cap4-1 → cap4-2 → cap8-2`，先 12/s 再 32/s。
每 cell 全新 backend/service/database/cache，DDL 后以 4/s 写入 256 行 seed，
每个 original 必须 ACK，drain 后运行 32 秒开环负载。总计 5632 个 measured
inserts、2048 个 seed inserts，另有 8 个 DDL。SQL、payload、随机 witness、
原始身份、client inflight 192、offer lag 1000 ms、tenant intake 40、队列和
所有预算/deadline 均沿用 [equal-seed-v1](../equal-seed-load/README.md)。

不等候凑组，不增设人工队列闸门，不放大接纳容量，不自动重跑。按实际已排队
前缀形成组；允许 singleton，并报告真实宽度。相同 seed 是 schema、行数、页数、
保留身份、结果字节和树高相同，随机 witness 的字节和 hash 不要求相同。

## 复用与独立审计

- `spec.py` 用 `Contract(rate, max_members)` 固定四种合同与全部矩阵顺序。
- `shared.py` 在初始化阶段为 4、8 各建立一个固定 spec/reader/auditor；runner
  仅由 `run.py` 初始化，oracle 不导入它。运行中不修改任何 cap 绑定。
- `run.py` 复用原 equal-seed `Cell` 的 setup/observe/close、原 recorder、owned
  process 监控和 backend。`probe.mjs` 直接导入原 probe，SQL 不重放。
- `oracle.py` 的逐 cell 原始 HEAD 闭包审计使用对应 cap；每个成功的原始诊断
  快照都检查 selected/consumed 桶上限，包含 baseline 和未选中的中间 poll。
  baseline/end cohort、完整 original 分母、native SQLite、资源与 provenance
  继续按原 reader 审计。
- `controls.py` 先做一次完整八 cell audit，再对已验证 originals 做定向内存投影，
  只能命中指定拒绝规则；不再执行 SQL，也不改写 raw evidence。

负控也必须适用于合法的全 singleton 或零 load ACK 结果：诊断没有实际组时，
仅在内存中向已验证的快照加入守恒的合成组，并在控制报告标记
`synthetic-group-added`；这不是实际观测。HEAD 负控按 load、seed_rows、seed
的固定优先级选取真实成功发布，记录来源阶段，再只投影错误的 sequence 增量。
缺失 hook 负控优先使用成功 load 请求；load 没有成功请求时，使用保证全 ACK
的 seed baseline 并记录来源。这些选择不改变 load 分母、实际组分布或性能判定。

旧 equal-seed/group-commit-load 目录不变。新 fixture inventory 包含完整的新旧
实验源码、诊断和构建的真实依赖及先行设计。fixture manifest/source archive
与正式 release build receipt 是两项独立来源核对，不能互相替代。

## 运行

要求 Linux、本地可丢弃目录、固定 Rust 1.90.0、Node 22.16.0、SeaweedFS 4.51
及 libclang。先提交并冻结候选，保持源码干净。以下输出目录必须不存在；
将工具路径替换为已校验的实际路径。实际执行失败会保留结果，不自动重跑。

```bash
export CARGO_BUILD_JOBS=2 CXXFLAGS=-g0 PYTHONDONTWRITEBYTECODE=1
python3 -B -m unittest discover -s experiments/group-width-load -p 'test_*.py' -v
python3 -B experiments/object-service/build.py \
  --target-dir /tmp/scap-group-width-release \
  --evidence /tmp/scap-group-width-evidence/build
python3 -B experiments/group-width-load/run.py \
  --binary /tmp/scap-group-width-release/release/scapd \
  --build-record /tmp/scap-group-width-evidence/build/build.json \
  --weed /path/to/weed --node /path/to/node \
  --evidence /tmp/scap-group-width-evidence/run
python3 -B experiments/group-width-load/controls.py \
  /tmp/scap-group-width-evidence/run \
  > /tmp/scap-group-width-evidence/audit-and-controls.json
```

`oracle.py <evidence>` 可单独重审证据；CI 使用聚合 `controls.py`，避免做两次
相同完整审计。单 cell audit 上限 90 s；matrix 额外审计与 controls 共 120 s。
每 cell 900 s、全矩阵 7200 s；全部资源上限见先行设计与 `spec.matrix_plan()`。

## 性能门槛与解释

证据 `PASSED` 和性能获益分别报告。四对固定为每个 rate 的 cap8-1 对 cap4-1、
cap8-2 对 cap4-2，以 cap8 为分母，每对必须同时满足：

1. original ACK 与 32 s 窗口内 original ACK 均不减少。
2. 成功 scheduled-to-terminal p99、control p99、S3 requests/ACK、双向 body
   bytes/ACK 各最多增加 5%。
3. 至少一项改善 5%：original ACK 增加，S3 requests/ACK 减少，或成功 p99 降低。

仅当四对全部满足，才称本地有限增长样本一致支持 cap 4。缺失或非正分母不算
获益。5% 是工程筛选，不是统计显著性；每 cell 8 次 control 的 p99 接近样本极值。
成功样本组成也会影响 p99。粗桶 lifecycle 只报告总量、均值、桶和完成状态，
不能推算精确 p99 或将 group invocation 除以人数当作单 SQL 时延。

完整报告所有 terminal、BACKPRESSURE 来源、窗口/总 ACK、drain、S3 绝对量、
每 offered/ACK 成本、实际组宽、CPU/RSS/FD/tasks、磁盘和 orphan。GC 关闭，
资源采样能漏过短时峰值。本实验不证明稳态、AWS Standard、跨 AZ 或生产 SLO，
不据此自动开启组提交。
