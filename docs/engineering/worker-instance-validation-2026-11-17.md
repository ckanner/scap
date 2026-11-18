# 计算实例身份占用：本地验证记录

日期：2026-11-17。本页绑定 PR #61 的代码提交
[`841da9c`](https://github.com/ckanner/scap/commit/841da9c76913232d98e409ab7a3b12a8633af25e)。
设计及部署约束见[永久启动占用](../architecture/worker-instance-claim.md)，
逐项计数、源码及证据 hash 见[机器记录](../evidence/worker-instance-local-2026-11-17.json)。

**结果：stable 与 nightly 单元各 797 项通过；实际进程/S3 启动 10 个场景和 TCP 8 个场景通过。
完整逐文件四维覆盖门禁仍失败，原因是原有 7 个生产文件的 branch 分母为零。**
本页不是 AWS 资格验证、远端 CI 结论或合并批准，不把后续组合提交自动视为已验收。

## 1. 精确候选与隔离构建

| 标识 | 值 |
| --- | --- |
| 远端代码提交 | `841da9c76913232d98e409ab7a3b12a8633af25e` |
| 实际测试的本地提交 | `2c0d18f0c68fecdf337451ea134cc15f23f6c03e` |
| 两者相同的 Git tree | `0047a419d3f09b76d9da8ab82425ffb2a6cf5981` |
| 742 个跟踪文件的源码清单指纹 | `ed5c730685a00d03aac85f42059f62a777b43c9b1a1bc5454eee7c9774de7d8b` |
| 实际 `scapd` SHA-256 | `7bf0ddb83f9599207e4ad5a59b7a8bd0f1ae5c47f787f9f282c9ffb7f8ddff17` |

源码在构建前冻结，验证后复核未变；远端提交与本地测试提交的完整 tree 一致。
本页及机器记录是验证后的文档附加，不属于上表冻结代码 tree；不因此声称重新运行了测试。
stable 与 coverage 各有独立 target，均未与其他 worktree 共用构建产物。

使用 Rust 1.90.0、nightly-2025-09-18、cargo-llvm-cov 0.6.21、Python 3.12.14。
真实本地后端为固定 SeaweedFS 4.51，commit `153ab668c99731a6d29492bf6c61d0b4fa701101`，
二进制 SHA-256 为 `eb9adf3a75b53c32f5ad9ba856e1fb652dae03dc6f6222673c3f88c0cbd25d0e`。
native 依赖与 `Cargo.lock` 随冻结源码绑定。

## 2. 单元与覆盖率

| 检查 | 结果 |
| --- | --- |
| `cargo test --locked --workspace --lib --bins --all-features` | 797 passed、0 failed、0 ignored |
| fresh nightly `llvm-cov`，同一 workspace/unit 目标，启用 branch，单线程运行 | 797 passed、0 failed、0 ignored |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | 通过 |
| `cargo fmt --all -- --check` | 通过 |
| 冻结候选的仓库文档/链接检查 | 690 个文本文件、702 个本地链接通过 |
| bounded-transport oracle 单元 | 5 项通过，包括行为反例、缺失/重复观察、错误 profile、释放顺序及退出清理反例 |

两个 Rust 单元运行的分项均为：object 427、object-sqlite 81、object-store 44、service 208、SQL 37。
真实 HTTP/S3 与进程实验独立运行，没有向 unit coverage 写入 profile。

| 本次变动的生产文件 | 行 | 函数 | Region | Branch |
| --- | ---: | ---: | ---: | ---: |
| `crates/scap-service/src/instance.rs` | 40/40 | 4/4 | 64/64 | 10/10 |
| `crates/scap-service/src/daemon.rs` | 257/257 | 28/28 | 373/373 | 38/38 |
| `crates/scap-service/src/auth.rs` | 79/79 | 13/13 | 111/111 | 30/30 |
| `crates/scap-service/src/lib.rs` | 44/44 | 2/2 | 42/42 | **0/0，门禁失败** |

完整覆盖检查退出码为 1，仅报告以下 7 个零 branch 分母；没有其他未覆盖行、函数、region 或分支：

- `crates/scap-object/src/catalogue/types.rs`
- `crates/scap-object/src/object_frame.rs`
- `crates/scap-service/src/catalogue.rs`
- `crates/scap-service/src/lib.rs`
- `crates/scap-service/src/main.rs`
- `crates/scap-service/src/owner_wire.rs`
- `crates/scap-service/src/snapshot_wire.rs`

没有降低覆盖率阈值、排除生产文件或用集成结果填补 unit 分母。只把新增测试源码及实验目录
加入原分类。首轮覆盖曾暴露 daemon 的 3 行、4 个 region；补充 claim 后实际 cache 丢失和
catalogue 构造失败的回归，并在最终候选重新采集。旧报告及先前启动实验的 hash 均保留。

## 3. 实际进程与本地 S3

[启动实验](../../experiments/worker-instance/README.md) 运行实际 `scapd`、固定 SeaweedFS 和
签名请求代理；按外部进程退出、HTTP listener、cache 内容及对象请求账本判断结果。

| 场景 | 观察结果 | 产品 PUT / GET 次数 |
| --- | --- | ---: |
| 全新 ID | 启动并响应 healthz | 1 / 1 |
| 同 ID、原进程仍运行 | `INSTANCE_REUSED` | 1 / 0 |
| 同 ID、原进程正常退出 | `INSTANCE_REUSED` | 1 / 0 |
| 改用新 ID | 可以启动 | 1 / 1 |
| 同 ID、原进程被 SIGKILL | `INSTANCE_REUSED` | 1 / 0 |
| 两个进程并发争用同 ID | 恰好一个启动，另一个 `INSTANCE_REUSED` | 2 / 1 |
| 后端接受 PUT 后丢弃 ACK | `INSTANCE_UNKNOWN`，不查询或重试 | 1 / 0 |
| 上一不确定启动的 ID 再用 | `INSTANCE_REUSED`，占用仍存在 | 1 / 0 |
| PUT 后故障夹具破坏回读记录 | `INSTANCE_CORRUPT` | 1 / 1 |
| S3 endpoint 不可达 | `INSTANCE_UNKNOWN` | 代理 0 / 0 |

最后一项使用单独的不可达 endpoint，因此零计数仅指代理账本，不表示没有尝试连接。
失败启动均检查退出码、精确错误代码、没有 listener、没有服务 worker cache。
所有观察到的产品 PUT 都带 `If-None-Match: *`，没有 If-Match 或无条件写。

[bounded TCP 实验](../../experiments/bounded-transport/README.md) 也改用真实本地 S3 完成启动占用，
然后通过 8 项：连接额度、首个 header deadline、keepalive header deadline、header bytes 边界内/外、
header count 边界内/外及 HTTP/2 拒绝。正常 SIGINT 退出并回收子进程。
不再保留“S3 不可达仍启动 healthz”的旧夹具假设，也没有测试 bypass。

## 4. 实现边界与未验收项

该协议永久占用显式配置 ID，不是自动编号分配器或数据库 owner 授权。每次启动必须使用新 ID；
claim 后的资源失败也消耗 ID。完整 daemon/assembly 入口受保护，底层受信 Rust 嵌入原语仍由
调用者负责顶层身份和生命周期。HEAD CAS、owner epoch、ACK 顺序和 discovery nonce 规则保持原协议。

目标环境必须允许 worker registry 的精确条件创建/读取，同时禁止覆盖、删除、生命周期过期，
备份/恢复也必须保留 registry。首次采用须停止并禁止旧二进制重新启动，保留历史发号证据；
无法证明历史唯一性时不能声称迁移已完成。

以下均为 **NOT_RUN**：AWS S3 Standard 条件写资格、真实 IAM enforcement、历史身份迁移、
本候选全部既有 native/network/performance 合同及生产容量/成本验收。自动身份分配器尚未实现。
本地 SeaweedFS 通过不能代替 AWS，实际启动通过也不证明自动故障切换、服务吞吐或全仓门禁通过。
原始日志、数据库、凭据和运行配置未纳入提交；机器记录仅保留结构化结论、源码与证据 hash。
