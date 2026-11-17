# 计算实例自动身份分配：本地验证记录

任务日期：2026-11-17。绑定 [PR #62](https://github.com/ckanner/scap/pull/62) 的代码提交
[`b58e625`](https://github.com/ckanner/scap/commit/b58e62567731e4b4e888f65088201d6a245956b8)。
完整协议见[自动分配设计](../architecture/worker-instance-allocation.md)，逐项计数、源码及
原始证据摘要见[机器记录](../evidence/worker-instance-allocation-local-2026-11-17.json)。

**结果：stable 与 fresh nightly 各 808 项单元通过；真实进程/S3 自动分配 18 个场景、
显式 ID 兼容 10 个场景通过。三个变动生产文件的行、函数、region、branch 均精确 100%。
全仓覆盖门禁仍失败：原有 7 个生产文件的 branch 分母为零。**
本页不是 AWS 资格、远端 CI 或合并批准；后续组合提交须另行验证。

## 1. 精确候选与构建

| 标识 | 值 |
| --- | --- |
| 远端代码提交 | `b58e62567731e4b4e888f65088201d6a245956b8` |
| 实际测试的本地提交 | `cd18e3b948ac16404d8f8f86ab1a7238aa728c07` |
| 两者相同的 Git tree | `d9126eb38f2a06d57a1d59ac2d47d4b01d62422e` |
| 746 个跟踪文件的源码清单指纹 | `0d48dd888a14c2044c1022dba5903dd099ed2df50baaceae193d61e37b47e781` |
| 实际 `scapd` SHA-256 | `45150afcb6c6dca2676f835db1980739b04f0b97d250dfe281a48ef9bd4f97c3` |

构建前冻结，全部检查后复核源码未变；发布者确认远端与本地完整 tree 一致。本页和机器记录
是验证后的文档附加，不属于上表冻结 tree。stable 与 coverage 使用各自独立 target，未与
其他 worktree 共用构建产物；真实 HTTP/S3 实验没有向单位覆盖写入 profile。

工具为 Rust 1.90.0、nightly-2025-09-18、cargo-llvm-cov 0.6.21、Python 3.12.14。
实际后端为固定 SeaweedFS 4.51，commit `153ab668c99731a6d29492bf6c61d0b4fa701101`，
SHA-256 `eb9adf3a75b53c32f5ad9ba856e1fb652dae03dc6f6222673c3f88c0cbd25d0e`。
二进制采用 dev/unoptimized 配置；这里没有生产性能结论。运行时间及 native 依赖的源码绑定
保存在机器记录中。

## 2. 单元、覆盖与静态检查

| 检查 | 结果 |
| --- | --- |
| `cargo test --locked --workspace --lib --bins --all-features` | 808 passed、0 failed、0 ignored |
| fresh nightly `llvm-cov`，同一 workspace/unit 目标，启用 branch、单线程 | 808 passed、0 failed、0 ignored |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | 通过 |
| `cargo fmt --all -- --check` | 通过 |
| 冻结候选的文档/链接检查 | 694 个文本文件、711 个本地链接通过 |

两个 Rust 单元运行的分项均为 object 427、object-sqlite 81、object-store 44、service 219、
SQL 37。新增测试涵盖初始化缺失/重复、规范配置、同次 GET ETag、并发 CAS、显式 marker
冲突、UNKNOWN 后停止、原期限、16 次竞争预算、counter 倒退/损坏/耗尽、晚到或空 ACK、
discovery 绑定和最终身份传入实际 worker。源代码独立审查没有发现未解决的协议阻断项；
该审查不是运行结果或 IAM 证明。

| 变动生产文件 | 行 | 函数 | Region | Branch |
| --- | ---: | ---: | ---: | ---: |
| `crates/scap-service/src/instance.rs` | 118/118 | 10/10 | 171/171 | 24/24 |
| `crates/scap-service/src/config.rs` | 241/241 | 24/24 | 318/318 | 66/66 |
| `crates/scap-service/src/daemon.rs` | 322/322 | 34/34 | 482/482 | 44/44 |

全仓门禁退出码仍为 1，仅报告以下原有零 branch 分母，没有其他未覆盖的生产计数：

- `crates/scap-object/src/catalogue/types.rs`
- `crates/scap-object/src/object_frame.rs`
- `crates/scap-service/src/catalogue.rs`
- `crates/scap-service/src/lib.rs`
- `crates/scap-service/src/main.rs`
- `crates/scap-service/src/owner_wire.rs`
- `crates/scap-service/src/snapshot_wire.rs`

本次扩展没有更改覆盖阈值、排除项或测试源码分类，也没有用真实进程结果填补单位分母。

## 3. 实际进程、S3 与 native SQLite

[实验 runner](../../experiments/worker-instance/README.md) 只启动正式 `scapd`、固定后端和签名
代理，按实际退出、listener、配置字节、cache 和对象请求账本判断结果。18 个自动分配场景为：

| 场景 | 关键观察 |
| --- | --- |
| 缺 counter、明确初始化、再次初始化 | 普通启动拒绝；管理命令一次创建；再次初始化不覆盖或收养 |
| 首次 auto 启动及 native SQL | 分配 101；实际创建/激活数据库，`SELECT 42` 精确返回 42；错误 worker guard 被拒绝 |
| 正常退出、SIGKILL 与全部 compute cache 丢失 | 原配置字节、路径和端口不变，分别分配 102、103 |
| 旧路由和原数据库 owner | 重启后旧 guard 101 返回 `TARGET_MISMATCH`；新 guard 103 可查询；数据库 owner 仍为 101 |
| 两个 auto 进程同时 CAS | 分配 104、105；一次明确冲突后选择新的候选，共 3 GET / 3 CAS |
| 显式进程抢占 auto 已预留 ID | 显式进程取得 106；auto 明确遇到 marker 冲突后分配 107 |
| counter CAS ACK 丢失及下一次启动 | 108 被预留，原进程 UNKNOWN 且没有 marker PUT；下一次分配 109 |
| marker PUT ACK 丢失及下一次启动 | 110 被占用，原进程 UNKNOWN 且没有 marker GET；下一次分配 111 |
| listener 绑定失败及原配置再启动 | 112 只有 claimed、没有 ready；下一次分配 113 |
| 独立 bucket 最后一个 u64 及耗尽 | 分配 `18446744073709551615`；下一次明确 EXHAUSTED，无写入、无回绕 |
| 独立 bucket 的坏 counter | 明确 CORRUPT，无 marker 或 worker 启动 |

失败均检查退出码 1、精确错误码、没有开放 listener、cache 前后内容不变。产品 counter
创建/CAS 与 marker PUT/GET 次数分别检查；产品写入只使用规定条件头。故障夹具的管理员写入
仅用于破坏测试 counter，不是产品覆盖/重置路径。

三个测试 bucket 使用 24 个有界 volume 槽位，每个 64 MiB、不预分配。依据是固定后端
`weed scaffold -config=master` 的 `copy_1 = 7`，每个未复制 bucket collection 默认增长七个
volume。额外 bucket 先通过夹具 readiness，再进入产品场景；没有把后端 provision 失败
改成产品重试或降低 oracle 要求。

独立的显式 ID 兼容实验又通过 10 项：新 ID、存活/正常退出/崩溃后的重复 ID、改用新 ID、
同 ID 并发、接受 PUT 后丢 ACK、不确定 ID 继续被占用、坏回读和不可达后端。原十进制 JSON
配置继续有效；直接 Rust 配置的 `WorkerInstance` 枚举是已记录的 API 变更。

## 4. 保留失败与修正范围

五次早期进程实验均保留为 FAILED，不能计入最终通过：分别在 4、0、9、15、17 个已验证
场景后停止。原因依次是缺少 API 准入 header、oracle 读取了关闭的内存 capture、错误要求
SIGKILL 后旧 cache 为空、两个 volume 槽位不足、12 个槽位仍不足三个 collection。
修正均针对夹具，最终源码冻结后完整运行 18 项；原日志、结果及观察账本的 hash 保留。

首轮并行 stable 还暴露既有 discovery 测试竞争：响应 body 释放时，plain worker 可能仍
持有 reservation。测试现在先 join 实际 worker，在保留 body 时确认仍拒绝准入，再释放
body 并确认可重新准入；后续 DENIED worker 也在下一请求前 join。没有添加 sleep、改变
生产 admission 或削弱断言。保留失败日志后，原完整 workspace 命令重新通过 808 项。

## 5. 部署边界与未验收项

持久 counter 使用严格的版本化二进制格式；普通启动绝不自动初始化、重置或从 UNKNOWN
收养身份。初始化要求可证明的历史上界，0 只适用于全新 authority。counter 和所有永久
marker 必须跨 IAM、生命周期、GC、备份与恢复保留；未知结果和后续构造失败产生的空洞不回收。
停止并禁止未登记旧二进制重启，是历史环境迁移的前提。

自动 ID 不更新静态 `OwnerController`/route registry，也不改变数据库 owner。部署控制器
必须消费新的实例登记；数据库交接继续使用当前 HEAD 和持久 owner 计划。底层受信 Rust
嵌入仍由调用者负责顶层 authority、身份及生命周期。

以下均为 **NOT_RUN**：AWS S3 Standard、目标 IAM enforcement、历史身份迁移、跨 bucket 或
灾难恢复、生产吞吐/容量/成本，以及本候选其余既有 native/network/transport 合同。
动态 fleet 登记、路由刷新和数据库自动接管不在此实现范围内。真实本地 SeaweedFS 通过不能
替代 AWS；原始日志、凭据、数据库和运行配置没有纳入提交。
