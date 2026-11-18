# 并发读、动态 fleet 与资源边界：组合交付

日期：2026-11-18（纽约）。基线为已合入 #65 的 `02476c8`。本批生产、单元、真实
HTTP/S3 与内核合同各自保存来源；本页不将代码完成等同于真实合同已通过。

**本地最终组合 stable/nightly 各 911 项单位通过，77 个 Rust 生产文件逐文件四维
精确 100%；四项实际均已通过各自冻结来源的完整 CI 合同。** 下面区分本地原件复核、
首轮 CI 和修复后的组合验证。最终远端 head、各项检查与合入身份由
[PR #66 checks](https://github.com/ckanner/scap/pull/66/checks)记录，不能从旧候选结果推导。
精确计数、原日志 hash 和失败历史见[组合机器记录](../evidence/sqlite-s3-scale-local-2026-11-18.json)。

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
- 第三、第四轮各 911 单位通过，但 `gc.rs` 仍只有 460/461 regions。LLVM 逐函数
  报告显示 `execute` 的四个泛型实例最多 11/12；另一个实例命中相同源码坐标，
  不会补足这个文件的 summary。第一次补及时完成仍缺同一 future 的进入前过期
  分支。最终在同一个 future 类型验证原 deadline 已到时完全不得 poll、及时完成
  为 Ok、越过原 deadline 完成为 UNKNOWN；第五轮全仓 fresh profile 才通过。
- 首轮 CI 的独立 `resource-limits` 工程在 `--locked` 下拒绝构建，因为其 lockfile
  未列出服务新增的 `rustix 0.38.44`。只补依赖表的一行，没有升级其他包；该独立
  工程的 `--locked --offline` Clippy 和当前组合 Clippy 均通过。
- 首轮过载 CI 全部通过，但 ZIP 把硬链接控制副本的字节重复存储，得到 1,044,566,776
  字节，超过连接器 512 MiB 的下载上限。原 artifact 保留；新 workflow 将整个目录
  以保留硬链接的 `tar.gz` 加 SHA-256 交付，不删原件、不省控制。包装的本地往返
  已核对 42 个文件及 20 个硬链接；这只是包装验证，新 CI 交付另行核对。
- 原 Manifest GET 优化的历史约 24% 回退仍未归因；按[独立决策](manifest-get-elision-decision-2026-11-18.md)
  正式退出本次发布。请求数下降没有被当作吞吐通过。

## 验证状态

最终本地单位来源为本地提交 `74e592ae172b6660603ff96e2917f79de45e047e`，309 个正式
输入的 canonical SHA-256 为 `0abb8dc83414b327f698b572cef529177db9aeb5b781f8fa631a7330b27eed29`。
其后的报告编辑不改变这些输入；远端 Git Data 发布的提交身份由 PR 记录，实际输入
逐字核对。旧 actual 继续绑定 `a2cc536`；新增 GC 单测不能继承旧 actual 的完整来源标记。

| 门禁 | 已取得结果与准确来源 |
| --- | --- |
| Rust stable / nightly 单位 | 各 911/911；`--workspace --lib --bins --all-features --locked`，没有集成 profile 混入 |
| Rust 精确覆盖 | 第五轮 fresh unit-only LLVM；77 文件逐文件 lines/functions/regions/branches 全部 count=covered 且分母为正；`gc.rs` 461/461 regions；checker 与门槛未放宽 |
| 代码质量 | stable 1.90.0 完整 workspace/all-targets 严格 Clippy、fmt；独立 resource-limits 的 locked/offline Clippy 通过 |
| Node / codec | SDK 182 单位、22 生产 JS 文件全部 V8 原计数精确覆盖；HTTP 7、controller HTTP/CLI 14、codec 13、严格 TypeScript 通过；SDK 字节与所列实际候选一致 |
| read-pool | `a2cc536` 的本地完整实际与原字节审计通过；21 SDK 命令、27 POST、183 S3；19 负控（8 raw、11 interval projection）与 1 正控通过；首轮 CI 同时通过 |
| dynamic fleet | 同候选完整实际 66.517 秒；4 worker/1 controller、4 reload、2 配置拒绝、3 原结果；13 负控+1 正控，170 原文件前后 hash 不变；首轮 CI 通过 |
| overload | 首轮 CI build/完整实际/oracle/18 负控+1 正控门禁及上传成功；1,140 固定开环到达、全部原身份最终查证按冻结合同执行。原大 ZIP 尚未独立取回，性能读数保持未取得，不填造 TPS |
| kernel-envelope | 首轮 CI 的真实 systemd/cgroup/tmpfs：14 场景（1 合法、9 拒绝、4 压力）、24 负控+2 正控通过；已取回 ZIP 并重算 hash、309 构建/13 夹具输入及 238 个案例文件；本地无相应内核能力 |
| 首轮其他 CI | owner/absence/controller/固定矩阵/S1/S2/显式与自动身份九项 control-plane job 全部通过；旧质量 lane 的失败按上节保存，最终完整 head 必须单独通过 |
| 真实 AWS Standard、跨故障域、长期成本、生产 SLO | NOT_RUN，未创建云资源 |

专门报告：[读池原件](read-pool-validation-2026-11-18.md)、
[动态 fleet 原件](dynamic-owner-fleet-validation-2026-11-18.md)、
[真实内核原件](kernel-resource-validation-2026-11-18.md)、
[开环首轮 CI 与取回边界](open-loop-overload-validation-2026-11-18.md)。

首轮新 runtime workflow 为 [44258165625](https://github.com/ckanner/scap/actions/runs/44258165625)，
PR head 为 `a2cc536770d7fc2e1b155d439616e29d25ad724a`，实际 checkout 为
`b1fd8ff64b8f159f8dea7aed883f6831c725df61`。本地与 CI 二进制分别绑定各自构建，
不能因源文件相同而宣称跨环境 binary hash 相同。最终 PR 校验使用自己的新构建。

正式 release 使用现有 `object-service/build.py` 的完整构建输入清单。新实验独立
绑定自己的固定源码、helper、原始构建 stdout/stderr、native archives 和二进制，
不修改旧实验的输入集合或检查门槛。观察器自测、实际运行、原始审计和负控分别判定。

## 独立源码复审

再次沿正式调用链检查队列 mutex、租户/库 active 额度、ReadWorker native/cache 先
释放再还额度、启动失败及 shutdown join；强读刷新只匹配 fresh HEAD/authorize 后、
native SQL 前的 StaleSnapshot，沿原 deadline 最多一次。资源准入在 claim/listen
之前，cgroup 成员复读、实际有限上限、tmpfs 去重/溢出与 CPU/OOM 旁路均失败关闭。
这次只读复审未发现新的阻断生产问题，不把 review 当成实际或云端验证。

读池的缓存数是操作后的保留预算，不是峰值 RSS/磁盘硬限；读池 actual 未额外执行
并发 GC/owner handoff。内核合同验证启动条件及四类限制行为，没有运行被 OOM 杀死的
daemon 的 SQL/S3 恢复。部署者须保持 namespace/cgroup/调度/OOM 不变量，这些限制
均保留在专门设计和报告中。

## 后续独立能力

当前提交没有实现独立事务 group commit、lazy VFS、新 MVCC 执行引擎、任意墙钟时间
PITR、全局 fleet 配置共识、无限成员历史压缩，或多轮 GC/冷启动风暴的长期认证。
这些能力分别需要提交／读页／历史／迁移协议，见[交付计划](sqlite-s3-delivery-plan.md)
和 [Turso 接续设计](../architecture/turso-adoption-next.md)。本批可直接使用的四项
能力按上表有限合同交付，不以单次本地通过宣布整个生产路线退出。
