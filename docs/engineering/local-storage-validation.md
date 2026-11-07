# 本地 SQLite 执行目录防护的完整本地验收

2026-11-07，[PR #28](https://github.com/ckanner/scap/pull/28) 的冻结候选完成本轮所需本地门禁：新增文件系统准入、全部 Rust 单元与精确覆盖、真实原生 SQLite/S3、HTTP/Node 和 1 GiB 恢复均已执行。精确身份、实际退出码、失败及独立审计范围见[机器记录](../evidence/local-storage-guard-2026-11-07.json)。这不是完整 N1/N2、AWS 或生产发布验收。

## 候选与防护范围

实测 commit 为 `a11e61ece526c9251b494a781247683284fea56f`，tree 为 `b5eb36a7f29951ad2643db4100942ea37c21653e`。执行前后核对同一份 169 文件源码清单，其规范摘要为 `5017792612249fed465ef013a3cd1b7932d3c43ad1045b8c7a27f021be5a9e45`。本报告及机器摘要在验证后添加；交付时另行证明生产代码、测试、依赖、工作流和构建输入与实测候选逐字节相同，不改写原 source manifest。

Linux 通过实际目录描述符执行 `fstatfs`，只接受列明的 ext 系列、XFS、Btrfs、tmpfs 和受信任 overlay。NFS/EFS、SMB/CIFS、FUSE、Ceph、9p、procfs 及未知类型拒绝。检查覆盖配置准备、直接 `Engine` 构造，以及 `ImageBuilder` 的父目录和新私有目录；符号链接检查实际目标。非 Linux Unix 明确拒绝。

单元覆盖类型分类、open/fstatfs 错误、准入后的创建失败、实际目录和 procfs/symlink 拒绝。真实 NFS/EFS/FUSE 挂载故障本轮没有执行；分类测试不能证明任意 overlay 底层、共享块设备或临时目录安全。部署边界见[存储安全说明](../operations/sqlite-storage-safety.md)。

## 单元与工程门禁

| 门禁 | 本轮结果 |
| --- | --- |
| stable 与 nightly Rust 单元 | 各 204 passed，0 failed，0 ignored；六个 test target |
| Rust 精确覆盖 | 24 个生产文件；行 4036/4036、函数 392/392、region 6124/6124、分支 792/792 |
| 新增 `storage.rs` | 行 30/30、函数 5/5、region 38/38、分支 2/2 |
| 工具脚本 | 74 tests；401/401 statements、184/184 branches，无排除 |
| 开发环境控制器 | 32 tests；280/280 statements、36/36 branches，无排除 |
| Node codec / SDK | 13 / 24 unit tests；逐生产模块覆盖及原始 V8 range 检查通过 |
| 真实 Node HTTP 合同 | 另进程 4 tests；不填入 SDK 单元覆盖 |
| 有界 N0 模型 | 89 tests；664 条正向历史、30 条正确拒绝的负对照 |
| 网络 / 服务夹具 | 41 / 27 tests；不计入 Rust 生产覆盖 |
| 工程检查 | workspace 与 worker 的固定 fmt、严格 Clippy、文档/JSON/链接、Actionlint 1.7.12、shell 语法通过 |

两个没有分支结构的服务入口文件 `lib.rs`、`main.rs` 明确记录 branch 0/0，不把零分母称为测得的 100%。其余要求的计数逐文件核对，没有用聚合数字掩盖缺失文件。

nightly 独占 fresh target 的一次 `--lib --bins` 调用产生 210 份 `.profraw` 和一个合并 `.profdata`。实际路径、大小和摘要已保留，其中包含该次编译执行的依赖 build script profile。第一方生产覆盖来自单元执行，没有 integration/doctest 调用或外部 profile 混入。

## 真实构建、故障与恢复

| release 产物 | SHA-256 |
| --- | --- |
| 网络/容量 worker | `6cf3ebb5f710bbf8620d9df2be9b842adee1637625ef5d624827dde230be9f28` |
| 正式 `scapd` | `6ea71e20fb70b497015db3ef5b74968efb33fa1d85d7861fe3f7d8274507f7a3` |

两份成功收据都记录实际 Cargo 最终成功事件、独立 target 的 executable、实际 `libsql-ffi` native archive 和完整输入摘要。运行未带 LLVM 单元插桩；构建及运行前后重新核对输入和二进制。

基础网络、30 个扩展故障场景及 schema 回归通过。独立审计核对 4 个基础 ACK、61 个扩展 ACK、12 个 schema 原始 ACK 与 12 次成功重放，共 89 次实际成功 execute 响应。14 个依赖上传切点、1 个 HEAD 前切点、10 个冷恢复缺失/损坏拒绝，以及真实同 ETag 竞争分别保留。三个没有 execute ACK 的已提交结果单列。冷激活在物化期间观察到 HEAD 改变时，合同是 fresh GET 变化后返回 Conflict 且没有 HEAD PUT，不要求后端 412。

保留结果验收有 12 种语义损坏、每种 5 个正式入口，共 60 次拒绝；独立重建损坏 Result frame 并验证解码拒绝。30 条原始 ACK 的完整 receipt、SCAPRES1 与冷恢复结果无差异。

1 GiB 档位恢复核对 16,384 个 65,536 字节 BLOB，共 1,073,741,824 字节，逐条长度和 SHA-256 与发送前输入一致。39 份已确认原始结果拆为 **38 次 execute 成功与 1 次 UNKNOWN 后 committed lookup**，完整 receipt 和原始结果均一致。该组在所有计算进程退出、缓存删除之后终止四个后端进程，再从原持久目录启动后端和新 worker。基础网络组的后端重启发生在恢复 worker 仍存活时，不能将两组证据混为同一个切点。

正式 HTTP/SDK probe 完成鉴权、跨租户、无损类型、重复结果、取消、撤权、两个 daemon 条件创建、已接受 HEAD 的响应丢失、S3 黑洞和两库恢复。保存了 10 个唯一 ACK、8 次完全相同的重复 ACK，并把 UNKNOWN 与后续查证分开。

### 独立审计范围

四组最终只读审计绑定同一个冻结脚本，SHA-256 为 `bb23ec40c84b698455ec5abad854d1d2ba7848d3d8dc25d92755fa93b27598c2`。它没有导入 runner 或生产转换算法，也没有以 summary 的 passed 标签作判据；重新核对输入、请求指纹、完整结果、对象 hash、真实请求/响应和可观察的进程顺序。

现有服务 fixture 未保存每次恢复 lookup/query 的完整 HTTP 响应体。最终独立审计确认全部原始/重复 ACK、11 个恢复阶段 Result GET 的 hash 和实际并发创建 200/412；**18 份恢复 HTTP 响应与恢复业务行的比较由实际执行的固定 Node probe 断言支持，不能称为离线独立重算。** 服务进程损失也只有 summary 中的 wait4/缓存测量，缺少完整 start/stop/restart 时间链。后续服务验收需要补全这些账本。

部分私有随机输入已由原 fixture 删除，离线审计使用发送前保存的长度与 SHA-256，不能重新读取已删除的输入文件。缓存删除是控制器的实际 I/O 观察，可与进程退出记录交叉核对，不能重造过去的文件系统状态。

## 失败记录与交付边界

先前环境失联与最初 NOT_RUN 状态仍保留。方案先行提交 `d7219a6` 的首次正式 Rust 门禁因 rustfmt 差异停止，随后在新候选修正并重新验证。

`a11e61e` 的首次两个 release 构建均退出 101：归档过程中出现零长度 `.o`，分别涉及 reqwest 和 object_store。失败 Cargo 日志、收据及观察记录保留；具体成因未确定。之后使用同一冻结源码、同一 toolchain 和默认 release 配置，在新的独立 target 串行重建并通过，才运行真实合同。没有降低优化、修改依赖或把失败收据改成成功。

早期独立审计的失败输出也保留：一次将拒绝后的可信修复 PUT 误纳入调用窗口，另一次错误要求冷激活必须出现 412。最终脚本按实际调用区间和正式合同修正，重新审计四组既有原证据，没有重跑数据库。早期脚本曾被覆盖，旧 SHA 对应的精确代码版本未单独保留，因此早期报告不能按其原代码版本重放；最终冻结脚本与四份报告均完整保留。

机器记录中的本地路径标识原始证据，不是仓库附件；日志、profile、账本和数据库不提交到仓库。交付提交仅追加报告与文档时再次核对 diff。合并绑定实际远端 PR head/base，依据维护者的完整本地验收授权，不将远端 CI 失败写成通过，也不修改分支保护。

真实 NFS/EFS/FUSE 挂载、AWS Standard、跨 AZ、设备断电、生产 SLO、长期运行和 10 GiB 边界本轮均未执行。目录、自动路由、完整生命周期矩阵、GC/PITR 等继续按[路线图](roadmap.md)推进，本地目录防护通过不表示整个目标完成。
