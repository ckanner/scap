# 认证 HTTP 与 Node SDK 的完整本地验收

2026-11-07，冻结候选的正式 Rust 服务、Node SDK、真实本地 S3 故障恢复及 1 GiB 回归通过独立审计。结论只覆盖下列已执行的本地门禁；名称目录、AWS Standard、生产 SLO 和 N1/N2 整体退出仍有独立工作。精确计数、摘要、原始证据路径和实际命令见[机器记录](../evidence/http-service-local-2026-11-07.json)。

## 源码与构建身份

实际测试本地 commit 为 `aa01150145f6b1017dafc024b9c12c8ad4251556`，tree 为 `a086fb30fc2ae058f9ba5bca1e310a82f7d4e725`。三个独立证据组在执行前后核对同一份 162 文件 source manifest；独立审计又逐个读取 Git blob、重算文件摘要并比较工作区原字节。源码清单 SHA-256 为 `51ea5e38c2c70f28adcd53224e36937fdda441a05faa18e56696f4fa725e4ea5`。

| release 产物 | SHA-256 | 构建输入 |
| --- | --- | --- |
| 正式 `scapd` | `0aedd7548747a26f8f3f402e85594a15f0a2095418484465fd97966e1bd92cee` | 85 个 Rust、SDK、夹具、manifest 与锁文件 |
| 网络与容量 worker | `ecce081d32c9bab7e3bc33702eb2dfe6913c88ce8c6677f68edcc7707dfdab41` | 68 个 Rust、网络／容量夹具、manifest 与锁文件 |

两份收据都含实际目标 executable、构建时 `libsql-ffi` native archive 和最后一条成功 `build-finished`。独立审计重新枚举输入和 native archive，核对原始 Cargo JSONL、stderr、实际二进制与摘要。网络、保留结果和容量使用同一份成功 worker 收据；真实 HTTP/S3 验收不带单元覆盖插桩。

这份文档及机器摘要在验收结束后添加。它们不改写原实测提交或 source manifest；最终交付提交须另外记录文档差异，并证明生产代码、测试、依赖、工作流和构建输入与冻结候选逐字节相同。

## 单元、覆盖与工具门禁

| 门禁 | 实际结果 |
| --- | --- |
| stable Rust 单元 | 199 passed；无 failed、ignored 或 filtered |
| nightly 覆盖单元 | 同样 199 passed，六个 test target 的完整结果与 stable 一致 |
| Rust 原始 LLVM 计数 | 23 个生产文件；行 3984/3984、函数 382/382、region 6055/6055、分支 790/790，逐文件核对 |
| 覆盖 profile 来源 | 初始 coverage target 不存在；209 份新 `.profraw` 的实际集合、记录集合和 merge list 完全相同，逐份核对大小与摘要 |
| 仓库工具 | 74 tests；401/401 statements、184/184 branches，无排除 |
| 开发环境控制器 | 32 tests；280/280 statements、36/36 branches，无排除 |
| 网络／服务夹具 | 分别 41 和 27 tests，独立于 Rust 生产覆盖 |
| Node codec／SDK | 分别 13 和 24 unit tests；每个生产模块的 Node 行、函数、分支表均为 100%，另逐条核对 V8 原始计数 |
| 真实 Fetch 合同 | 另一个进程执行 4 tests；这些 profile 不填入 SDK 单元覆盖 |
| 有界模型 | 89 tests；664 份正向历史、30 个正确拒绝的负对照，694 份原始产物逐份核对摘要 |
| 工程检查 | workspace／网络实验的 fmt、Clippy、仓库链接与 JSON、Actionlint、开发脚本语法全部通过 |

`crates/scap-service/src/lib.rs` 与 `main.rs` 在当前结构下没有 branch region，明确记录为 0/0；其行、函数、region 均有非零分母。没有把 0/0 描述为测得的 100% 分支覆盖，也没有以聚合总数掩盖缺文件。

| Node 生产模块 | 全部命中的函数 | 全部正计数的 V8 ranges |
| --- | --- | --- |
| codec.js | 17 | 89 |
| client.js | 31 | 40 |
| wire.js | 38 | 113 |
| transport.js | 14 | 75 |
| errors.js | 5 | 5 |

## 真实服务与恢复

[正式服务实验](../../experiments/object-service/README.md)启动真实 `scapd`、正式 Node SDK、故障代理和 SeaweedFS 4.51，验证 bearer／租户边界、严格无损值编码、重复请求、取消屏障、暖读撤权、两 daemon 条件创建、HEAD 已接受后的响应丢失、热缓存时 S3 黑洞，以及显式 takeover 后的旧 owner fence。

客户端记录 10 个唯一成功请求及 8 次成功重复 execute，共 18 个成功响应。独立审计从发送前输入重新计算全部 10 个请求指纹，独立解码 `SCAPRES1` 原始字节，比较 scope、request、transition 和完整 receipt，另对 8 个 64 KiB 业务 BLOB 逐个重算摘要。随机 `RETURNING` 原结果、i64 最大值和 Unicode/BOM/NUL 都参与原字节比较；Result 对象摘要与裸结果摘要分别处理。

另一个 execute 在后端 HEAD PUT 已返回 200 后被代理丢弃响应，实际 SDK Fetch 调用次数为 1，返回 UNKNOWN。后续 committed 查证保存在独立账本，保留原随机结果，不把查证追记成原 execute ACK。黑洞时已有缓存也不能产生成功强读。

实验 SIGKILL 两个计算进程、删除全部计算缓存，再 SIGKILL 四个对象后端进程；全部等待状态为 `-9`。由全新 owner 从原对象后端恢复两个有数据的租户库，核对 9+1 条业务数据、18 次成功响应的完整 receipt／原结果及取消屏障，零不一致。通过后服务 private fixture 已删除；独立审计复核保存的输入、ACK、完整阶段结果和冻结 SDK probe 的恢复断言，没有声称另行重读已删除的服务数据库。

## 既有 native、网络与 1 GiB 回归

同一冻结候选还完成基础 10 类真实网络合同、30 个扩展故障场景和 schema 回归。独立比较基础 4 条 ACK、扩展 61 条 ACK，以及 schema 的 12 条原 ACK 在三种观察中的 36 次完整 receipt／encoded-result 比较，均为零不一致。

保留结果覆盖当前和关闭世代的 12 类格式损坏。每类分别调用 lookup、cancel、activate、activate_session 和 session_open，共 60 次 `Corrupt` 拒绝；记录实际 Result GET、HEAD 不变和恢复目录不存在。该组另外恢复比较 30 条已确认请求的完整原回执与结果。

1 GiB 档位使用默认 `Options` 与独立发送前输入，确认 39 条请求，恢复核对 16,384 个 BLOB、1,073,741,824 字节。独立审计再以输入账本和实际 ACK 集合推导期望值，使用 immutable/read-only SQLite 连接重读保留的恢复文件：`integrity_check` 为 `ok`，全部 BLOB 的大小与 SHA-256 同期望值及恢复记录一致，零不一致。这是对同一个恢复文件的额外审计，没有把它算作第二次 S3 恢复。默认 10 GiB 物理边界没有在本批重跑，历史容量证据保持原身份。

## 原始失败与证据完整性

先前 commit `3f3b4c1fc9f402b0bdb83917ef1fbd54ddb85e6c` 的 checkpoint 保持 `BLOCKED`：两份工具日志与保存摘要不符，nightly 日志缺完整测试结果，服务构建缺目标产物记录。原文件和退出记录保留，单独重跑没有把原记录重新标为通过。

本批第一次网络 release 构建仍被正确拒绝：Cargo 退出 0，但 stdout 只有 32,429 字节，stderr 只有 1,118 字节，没有最后的 `build-finished` 和完整目标产物证据。两个摘要与失败收据相符，因此观测只能证明写入收据前日志已不完整；具体原因未确定，不能宣称 fsync 解决了所有捕获问题。

随后在**同一冻结源码和同一隔离 target** 上真实重跑原构建命令，使用新的 `network-rerun-001/build` 目录保存实际 incremental Cargo 输出。这次 trace 完整，构建 guard、二进制及 native archive 校验通过，才启动真实网络和容量门禁。首次失败收据仍在机器记录中列为 `REJECTED`。

外层验收 runner 使用 PIPE 捕获，再由 Python 写入、flush/fsync，并比对捕获字节数与落盘 SHA。独立审计复核全部 54 份退出记录和日志；其中保留首次构建的非零门禁退出，最终成功结论绑定单独的成功重跑。

## 原始记录与复现入口

本次本地证据根保存在机器记录的 `evidence_layout.root`，下列相对路径均以此为基准：

| 路径 | 内容 |
| --- | --- |
| `runtime-final-002` | source manifest、Rust／Python／Node 原始单元、LLVM/V8、工具结果及首次被拒绝的 worker 构建 |
| `service-final-002` | 正式服务 build receipt、HTTP/S3 输入与 ACK、网络历史、恢复阶段及源码前后校验 |
| `runtime-final-002/network-rerun-001` | 成功 worker 构建、network、retained、gib1 与源码前后校验 |
| `audit/acceptance-v2-audit-001.json` | 不导入产品夹具的独立审计；SHA-256 `2cd191ab19e1ecb0440e285153ccb320952b0ef65fe0b84ceb1ecf1c76b9df1f` |
| `audit/acceptance_audit_v2.py`、`audit/checkpoint_audit.py` | 独立核对源码、日志、覆盖、构建、ACK、输入与 BLOB 的审计源文件，摘要记录在审计结果中 |
| `audit/pr27-remote-premerge.json` | 合入前实际远端观察；SHA-256 `1bf4a825ec14775d5dfef1a726fc46e96829ab92f78677f91db055f1aba86b7b` |

这些路径标识本地原始记录，不是仓库中的可下载附件。原始日志、profile 和账本须单独保留；摘要不能代替文件。随机凭据、private fixture 和数据库不复制进仓库。

机器记录保存实际执行 argv。重新验证时使用独立的新 target／evidence 目录，依次执行[单元覆盖命令](testability-and-coverage.md)、[服务 build/run](../../experiments/object-service/README.md)、[网络与保留结果](../../experiments/object-network/README.md)、[容量 gib1](../../experiments/object-capacity/README.md)，并在全部门禁前后执行 `scripts/source_manifest.py capture/verify`。不要向已有证据目录写入新尝试；完整目标产物与最后的成功 Cargo 事件仍是必需判据。

## 远端状态与未完成范围

2026-11-07 09:20:27 UTC 的实际远端观察：PR #27 head 为 `adf0ccf0b61240846ada0c8bb19aaf58776fdcea`，main/base 为 `6052644a25755df38ab3042ba5867cd2989ea75a`，PR 为 draft、mergeable、状态 `unstable`。5 个 workflow run 全部 completed/failure；返回的 8 个 job 均无 steps 和日志 URL，另外直接读取的 Rust 与 SDK job 的 steps 为空。没有将远端 CI 记为通过，也没有推断额度或具体失败原因。合入依据维护者已有的完整独立本地验证授权，不修改分支保护；最终远端提交与 tree 的交付核对另行记录。

AWS Standard、跨 AZ、真实断电、生产 SLO、长期存储成本与硬 RSS 界限没有在本批验证。名称目录仍在单独工作中；自动 owner 路由、完整冷热点隔离、分段请求索引、物理对象 GC、pin/PITR 也未完成。当前 HTTP 服务验收通过不等于上述功能或 N1/N2 整体退出。
