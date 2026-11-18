# S2 恢复核心审查与单元验证（2026-11-17，纽约）

执行器记录日期为 2026-11-18 UTC；本文面向用户的日期采用 America/New_York。

本轮关闭恢复核心原先的四个生产文件覆盖缺口。最终七个变更生产文件的行、函数、region、分支均为非零分母的精确 100%。完整计数、源码 SHA-256、命令结果、原始报告摘要和执行文件摘要见 [机器可读证据](../evidence/restore-core-review-2026-11-18.json)。本轮未修改覆盖率门槛、checker 或排除列表。

## 源码与分层结果

- 原审查基线：`82317ae24c95baf33b8e603b3ab8a8f5674234de`，tree `aa3402b8f2b0792c0f1def797c5aad8fc9c8988c`，与远端 `12f35c0` 的 tree 相同。
- 生产重构及真实故障回归：`f8020a61e4261c608901cbd17e137933d54caef0`，tree `b94576e4d8f1fe425e86a8d195ffcb05d6e83499`。stable/nightly 全 workspace 各 884 passed、0 failed、0 ignored；strict workspace Clippy 通过。
- 最终测试尾部：`34cac99bd33080326afd14d4253a39d671a83bba`，tree `d36247579a8407549e11b11d032c1e298d3d42bd`，仅补既有测试里的 Empty recipe abort 拒绝断言，生产代码不变。stable 定向测试 1/1、fresh nightly core 486/486、strict core Clippy 通过。
- 独立整合结果：root 冻结 `1cbe6b39fdfff72610956a18bb6fe1d523bab8eb` / tree `de2317e25fb840fb1338090088c1b1b434bf0277` 后，stable/nightly 全 workspace 各 887/887；原严格 checker 对 76 个生产文件全部四项通过。本报告读取了该组合的原始摘要和 gate，不把分支定向 profile 宣称为完整 workspace 通过。

所有单元 profile 来自独立 target；使用 Rust 1.90.0、nightly-2025-09-18、cargo-llvm-cov 0.6.21，启用 `--branch --no-cfg-coverage --no-cfg-coverage-nightly`，清理旧 profile 后采集。没有以进程/S3 实验覆盖率补单位分母。

| 生产文件 | 行 | 函数 | region | 分支 |
|---|---:|---:|---:|---:|
| `create.rs` | 126/126 | 4/4 | 244/244 | 14/14 |
| `inspect.rs` | 268/268 | 15/15 | 428/428 | 28/28 |
| `records.rs` | 243/243 | 24/24 | 371/371 | 62/62 |
| `restore.rs` | 403/403 | 21/21 | 612/612 | 52/52 |
| `restore_copy.rs` | 268/268 | 25/25 | 424/424 | 18/18 |
| `restore_records.rs` | 104/104 | 10/10 | 143/143 | 30/30 |
| `restore_types.rs` | 54/54 | 6/6 | 70/70 | 12/12 |

## 审查发现与改动

原缺口包含两类：已经由上游不可变记录/严格 HEAD 验证建立的不变量被重复判断，以及尚未实测的真实失败传播。本轮没有发现新的可复现数据损坏漏洞；保留了原有 fail-closed 语义，并让结构明确承载这些不变量。

`Canonical<Descriptor>` 的内部 shape 保留已验证的最大页数。该 shape 不序列化，不改变 descriptor 字节、哈希、HEAD 格式或公共 Rust/JSON API；既有固定格式测试继续通过。`Restoring` 同时借用不可变 canonical descriptor 和它自己的 recipe，Empty recipe 在每个公共 restore 入口拒绝，后续步骤不再重新解包可选 recipe。规划器把经过验证的 Provisioning HEAD、绑定和 copying 状态一起返回，普通 create 的入口仍拒绝 restore recipe。

`RestoreSource` 把第一次 fresh READ 权限屏障后的 exact ObjectContext 和同一个 metered Database 绑定。最后一次权限屏障仍使用原数据库、后端与原 deadline。原 HEAD body/ETag、不可变完成记录回读、目标闭包验证、native SQLite 验证以及原 ETag CAS 均保留。

`install_copied` 的序号候选采用饱和递增，唯一接受边界仍是 `PreparedHead::restore`：先验证原 HEAD、Scope 和非空 ETag，再对原 serial 做 `checked_add(1)` 并要求候选严格等于结果，检查剩余 cleanup debt 后才编码和发布。因此 `MAX → MAX` 不能变成有效更新。真实合法 Copying HEAD9 的 `MAX-2` 基线保留 delete+seal 两个序号；复制若占用其中一个，必须返回 `Limit`，不能发布。新增测试同时拒绝 `MAX-2/MAX-1/MAX` 候选，检查零 I/O；公共恢复测试验证合法 `MAX-2` 的精确 `Limit` 和未变的 HEAD。

## 新的真实失败与防误用回归

- 通过真实 `ImageBuilder` 和 `SqliteWriter` 打开、验证并关闭 native image；同一个 interrupt provider 在目录真实销毁后返回中断，最后检查必须返回 `Unknown`。测试没有睡眠、假 writer 或跳过 native 成功路径。
- fresh copy 和已有 completion 两条路径在真实文件 FD 存活时删除自有 image 目录；下一次真实目录 fsync 得到 I/O 失败。两条路径均返回 `Unknown`，未发布 Copied HEAD，也不伪造新的 completion；后续明确 resume 可以重新完成。
- 已有 completion 无权覆盖调用者已经占用的 staging 目录。真实创建失败保留 sentinel，原 HEAD/completion 不变，新目录上的明确 resume 成功。
- completion 存在但永久目标 HEAD 缺失时，最后一次 HEAD 回查的 `Unknown` 继续失败关闭，inspect/resume 均不得重建 HEAD。
- 单独合法但与 immutable recipe 不符的 Provisioning quota 不能通过规划器；合法序号余量不足不能通过发布器。
- hash-valid 的多层树错误子节点、相互绑定但 page_count 与真实 manifest 不符的 retained metadata，均在完成前拒绝，不能把部分目标对象当作完整恢复。
- 对 Empty recipe 构造语法合法的 RestoreRef 和完全匹配的取消 creation，`abort_restore` 仍返回 `Conflict`；不因取消入口而跳过 recipe 类型检查。

这些单位测试的对象权威使用带条件写与原始 quoted ETag 的内存 fixture，native SQLite 和本地文件 I/O 是真实执行。它们不等于 HTTP/S3 后端的实际进程验收。

## 原始失败与后续验收边界

最初未冻结草稿的编译失败保留：局部重构语法错误，以及旧测试把 shape 固定为 `()` 的断言。修正后才冻结生产候选。`f8020a6` 的第一份完整覆盖率 gate 也保留为失败：八个原分母为零的文件，以及 `abort_restore` 新边界的一个未覆盖 region（611/612）。后者由 `34cac99` 的真实 API 回归关闭，八个文件由独立分支修复并在 root 组合 profile 中一起验证；没有重写第一次失败结果。

本报告未运行新组合的真实 HTTP/S3/进程矩阵；该项在此标为 `NOT_RUN`，需配套新的未插桩 release build receipt 和七项 S2 / 126 项反例、显式身份 10 项、自动身份 18 项运行。AWS Standard/IAM、长期容量与生产 SLO 也不由本报告证明。

复现主要命令：

```bash
cargo test --workspace --lib --bins --all-features --locked -- --test-threads=1
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo +nightly-2025-09-18 llvm-cov clean --workspace
cargo +nightly-2025-09-18 llvm-cov --workspace --lib --bins --all-features --locked --branch --no-cfg-coverage --no-cfg-coverage-nightly --json --output-path /absolute/new/unit.json -- --test-threads=1
python3 scripts/check_unit_coverage.py /absolute/new/unit.json
```

分支最终精确覆盖率使用同一收集参数，将 workspace 选择替换为 `-p scap-object --lib`；它仅证明上表文件，完整产品 gate 以整合后的独立全 workspace profile 为准。原始日志、profile、编译档案与 source manifest 只保留在外置 evidence 目录；仓库只提交无秘密的摘要和哈希。
