# 并发读、动态 fleet 与资源边界：组合交付

日期：2026-11-18（纽约）。基线为已合入 #65 的 `02476c8`。本批生产、单元、真实
HTTP/S3 与内核合同各自保存来源；本页不将代码完成等同于真实合同已通过。

## 产品变化

| 能力 | 行为 | 明确边界 |
| --- | --- | --- |
| 同库强读池 | `admission.read_pool` 建立固定独立 reader，按 tenant/database 活跃限额轮转；每个 worker 独占完整 native 镜像；新强读重新授权 | 缺省保持原 actor 路径；SQL 前仅一次 stale 重建；没有并行 writer、共享 WAL 或 lazy pager |
| 动态 fleet | version=2 配置与单调进程内 revision，有限完整历史、追加 worker、不可逆 retirement、原计划 abort/续进；reload join 原 tick/socket/DNS 后切换 | 受信部署器提供配置；没有跨 controller 全局 epoch、自动成员发现或自动扩缩容 |
| 内核资源准入 | `resource_envelope` 验证实际 cgroup、CPU 调度及全部临时 tmpfs；`--check-config` 在不 claim 身份、不建 S3 客户端、不监听时验证配置 | 部署器保持内核与目录命名空间稳定；组内存控制不是瞬时单进程 RSS/每租户隔离；不认证普通 ext4/XFS 项目配额 |
| 持续开环与 batch 验收 | 固定 30 秒 1,140 次到达，六个窗口各类请求取得进展；全部原写身份最终查证；同 64 条逻辑写比较单事务与显式 SQL batch | 本地兼容端点与证据代理；事务数、逻辑操作数分别报告；没有生产 TPS 或独立事务 group commit 结论 |

全部变化保留原 exact HEAD body/ETag、当前权限、不可变对象条件创建与回读、原 CAS、
native publication 和 ACK 顺序；没有借助网络共享活动 SQLite 文件或重放 UNKNOWN SQL。

设计入口：[读池](../../crates/scap-service/docs/read-pool.md)、
[动态 fleet](../architecture/dynamic-owner-fleet.md)、
[内核资源](../architecture/kernel-resource-envelope.md)、
[开环负载](../../experiments/object-overload/PLAN.md)。

## 审查中发现并修复的问题

- 读池最初的并发测试未固定“弹出一项后仍有同库排队”的时序。组合 strict profile
  检出 scheduler 的 1 行、3 region、1 branch 未命中；补两项排队与显式线程屏障，
  保证实际产品 dequeue 路径被执行。旧失败保留，不以另一轮偶然覆盖替代确定性。
- fleet reload 不能只等 Promise 拒绝；原 DNS callback 和 socket 可能仍然存在。
  `ControllerHttp.quiesce()` 暂停 admission 并等待这些真实资源结束，之后才复用。
- `cpu.max` 不能约束实时调度，也可能被 BPF 全量调度接管。新准入要求普通策略、
  无额外 burst、未启用 sched_ext，并明确所有后续任务的部署不变量。
- OOM group 不杀 `oom_score_adj=-1000` 的任务。准入拒绝自身免疫，部署器同时不得
  加入免疫邻居或在之后改变策略。缺失临时目录也须在整个生命周期保持解析不变。
- 旧 GC 超时单位把 40 ms 同时用于两次 preflight 和 DELETE，可能在实际发送前已
  合法超时，而 TCP 夹具仍等待第三个请求。异步 timer 效果改为受控 transport 与
  暂停 Tokio 时钟；原 `std::Instant` 保留，另以真实墙钟测完成后的总期限屏障。
  原实际 HTTP/S3 deadline 合同继续独立执行，生产期限和错误分类未改变。
- 原 Manifest GET 优化的历史约 24% 回退仍未归因；按[独立决策](manifest-get-elision-decision-2026-11-18.md)
  正式退出本次发布。请求数下降没有被当作吞吐通过。

## 验证状态

组合验证进行中；最终单位、实际、负控、CI 与合入身份在完成后更新。本段保持
`NOT_RUN`/待验状态直到取得各自原始结果，不借用 #65 或局部 agent 的绿色替代组合门禁。

| 门禁 | 当前状态 |
| --- | --- |
| Rust stable/nightly 单位与逐文件四维覆盖 | 组合源码重新执行中 |
| Node 单位／精确 V8／真实 HTTP／CLI／类型 | 组合来源重新核对中 |
| read-pool 完整 HTTP/S3 与独立原字节审计、负控 | NOT_RUN |
| dynamic fleet 完整 HTTP/S3 与旧计划、退出、负控 | NOT_RUN |
| overload 固定完整实际与所有原身份查证、负控 | NOT_RUN |
| kernel-envelope 真实 systemd/cgroup/tmpfs | 本地无相应内核能力；由固定 CI 执行，当前 NOT_RUN |
| 真实 AWS Standard、跨故障域、长期成本、生产 SLO | NOT_RUN，未创建云资源 |

正式 release 使用现有 `object-service/build.py` 的完整构建输入清单。新实验独立
绑定自己的固定源码、helper、原始构建 stdout/stderr、native archives 和二进制，
不修改旧实验的输入集合或检查门槛。观察器自测、实际运行、原始审计和负控分别判定。

## 后续独立能力

当前提交没有实现独立事务 group commit、lazy VFS、新 MVCC 执行引擎、任意墙钟时间
PITR、全局 fleet 配置共识、无限成员历史压缩，或多轮 GC/冷启动风暴的长期认证。
这些能力分别需要提交／读页／历史／迁移协议，见[交付计划](sqlite-s3-delivery-plan.md)
和 [Turso 接续设计](../architecture/turso-adoption-next.md)。本批可直接使用的四项
能力按上表有限合同交付，不以单次本地通过宣布整个生产路线退出。
