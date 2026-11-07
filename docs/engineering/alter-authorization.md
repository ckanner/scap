# N1 增量：单语句 ALTER 授权边界

状态：**完整本地门禁通过，可按已有授权合入本批原生修改**。最终受测身份与结果见[完整验收记录](native-integrity-validation.md)。初始草稿基于主分支 `819050679a306a2d799c8c14a76c7a157f3e522d`（PR #21），已在 main `49408e0` 上与保留结果修复合并并重新冻结验证。仍按 PR #16 的 S3 唯一持久权威路线推进；没有引入 Raft、改变对象格式、降低容量或放宽提交条件。

## 发现的问题

固定主分支的 `scap-object-sqlite/src/sql.rs` 声明允许 `AuthAction::AlterTable`，但普通函数白名单没有 SQLite 的内部 schema 重写函数，并且一律拒绝 `temp` schema。因此，允许顶层 ALTER 不代表重命名表、重命名列和删除列能完成编译。

还存在一个参数解释问题。固定引擎 `sqlite3AlterDropColumn` 调用 `sqlite3AuthCheck(..., SQLITE_ALTER_TABLE, zDb, pTab->zName, zCol)`，被 rusqlite 暴露为 `AuthContext::database_name` 的位置，在该操作中承载被删除的列名。真正的目标库位于 `AuthAction::AlterTable.database_name`，不能从通用上下文字段或 SQL 文本猜测。

固定上游来源：

- [libSQL alter.c：内部语句、临时 schema 检查、DROP COLUMN 回调及 INTERNAL_FUNCTION 注册](https://github.com/tursodatabase/libsql/blob/d8bc862d20bedc72945a1da27c8b7045414c0261/libsql-sqlite3/src/alter.c)。
- [固定 rusqlite AuthAction/AuthContext 及 authorizer 生命周期](https://github.com/tursodatabase/libsql/blob/d8bc862d20bedc72945a1da27c8b7045414c0261/vendored/rusqlite/src/hooks.rs)。
- [SQLite authorizer 文档：prepare 与 schema 改变导致的 re-prepare](https://www.sqlite.org/c3ref/set_authorizer.html)。

## 修改范围

1. 普通授权对 ALTER 使用 action 中的真实 schema；其余动作保持原来的 schema 和函数规则。
2. 写路径为每一个 `Statement` 安装全新的有状态回调。只有该语句先出现已允许的、顶层 `main` ALTER，才启用必要的内部例外。
3. 例外仅包含固定引擎的六个内部函数，以及 `temp.sqlite_temp_master` 的读取/更新。没有允许 `sqlite_*` 前缀，没有允许任意 temp 数据，没有开放 temp DDL、扩展、PRAGMA、ATTACH 或事务控制。
4. 状态在同一语句的 stepping/re-prepare 期间保留；下一个 Statement、下个请求重新建立。一次输入含多条 SQL 仍由原有 Batch 检查整体拒绝。
5. 独立只读入口仍使用原来的只读 authorizer，不安装写语句例外，仍拒绝所有 ALTER。
6. 原有结果缓冲、提交 gate、UNKNOWN、Rejected、CommittedButUnavailable、失败后停止 writer 和物理恢复规则不变。

这个边界依赖固定引擎的内部函数注册与回调次序。升级引擎必须重新验证，不允许以“函数名字类似”扩展白名单。普通 SQL 在固定引擎未开启内部测试功能时不能直接调用 INTERNAL_FUNCTION；语句作用域和 accessor 检查是额外约束，不用来代替这个引擎事实。

## 新增 Rust 回归合同

`crates/scap-object-sqlite/src/alter_tests.rs` 添加 12 个测试函数，涵盖：

- DROP COLUMN 的真实库参数、列名与库名相同、非 main 目标及 view/trigger 来源。
- 六个 helper 的精确匹配、大小写、scope、accessor、未知前缀和只读拒绝。
- 临时 schema 的最小例外及其他操作仍拒绝。
- 表/列重命名、删除/新增列，view、trigger、index 和 foreign-key schema 的更新。
- Rejected/Unknown 后原 schema 可见、writer 停止。
- 后续 Statement 和后续请求不能借用 ALTER 权限；失败导致整个事务回滚，不到达提交 gate。
- 同一字符串多语句拒绝、只读 DDL 拒绝。
- 从已接受物理页恢复 schema 及原随机结果。
- 已接受 ALTER 后 TRUNCATE checkpoint 被旧 reader 阻塞，返回 CommittedButUnavailable，原物理提交仍能恢复。

覆盖率配置仅登记新测试文件；`sql.rs` 仍完整进入生产分母，100% 四维要求及现有门禁未更改。

## 初始草稿诊断与当时的环境边界

以下保留初始评审的 NOT_RUN 事实，不代表当前状态。后续固定工具链、159 项 Rust 单元、14 个生产文件四维精确 100%、真实 S3 schema／结果合同与 1 GiB 恢复均已完成，详见上方完整验收记录。

本轮执行容器未安装 Rust/Cargo，也不能解析依赖站点的外部域名。通过 GitHub connector 核对了最新主分支和固定上游源码；对待改的两个原文件计算 Git blob SHA，与主分支 tree 一致。本地工作目录只是被修改文件的精确快照，不是已经构建过的完整 checkout。

实际运行的是宿主 Python SQLite **3.46.1** 与独立授权策略镜像：12 项诊断通过，复现原规则拒绝三类 ALTER，并验证收紧例外后的编译行为、权限撤销、回滚和 view/trigger/index/FK 保持。这不是固定 libSQL **3.47.0**，也没有调用 Rust 产品代码、WAL gate 或 S3。

因此，以下全部为 **NOT_RUN**：Rust 编译、rustfmt、Clippy、新/旧 Rust 单元、精确四维覆盖率、真实 S3 故障、容量回归。12 个新增 Rust 测试的数量不表示执行通过。宿主诊断不能用来完成合入门禁，也不能复用 PR #21 的旧覆盖率计数为本批背书。

机器记录见 [本批诊断与待验状态](../evidence/alter-authorization-diagnostic-2026-11-06.json)。原始诊断脚本与 callback 轨迹随交付补丁保留，不作为正式 runtime 或第二套产品实现。

## 合并前门禁与复验方法

下列门禁现已在冻结合并候选执行通过；保留复验命令及其原始范围。

在具备固定工具链的环境，先格式化并处理编译/测试失败，再冻结新的源码身份。至少执行：

```bash
cargo +1.90.0 fmt --all -- --check
cargo +1.90.0 clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo +1.90.0 test -p scap-object-sqlite --lib sql::alter_tests:: --locked -- --test-threads=1
cargo +1.90.0 test --workspace --lib --all-features --locked -- --test-threads=1
mkdir -p target/coverage
cargo +nightly-2025-09-18 llvm-cov clean --workspace
cargo +nightly-2025-09-18 llvm-cov --workspace --lib --bins --all-features --locked --branch --no-cfg-coverage --no-cfg-coverage-nightly --json --output-path target/coverage/unit.json -- --test-threads=1
python3 scripts/check_unit_coverage.py target/coverage/unit.json
python3 scripts/check_repo.py
```

继续使用当前 quality workflow 的固定 release build、`object-network` 提交/冷恢复合同，以及 `object-capacity --profile gib1`。现已在真实 S3 上加入并验证“schema 迁移成功、原请求查证、HEAD 后计算丢失、新目录恢复”的明确场景；不能拿纯 policy 或 native 模拟 gate 测试代替它。10 GiB 历史结果仍是旧候选证据，不能声称本批已经重跑。

这些所需门禁已通过，因此本批已从 Draft 转为本地验收 ready；可按授权合并。现有本地验证代替 CI 的授权不等于允许跳过本地验证。整体 N1、AWS Standard、N2 多库与 SDK、N3 GC/PITR 和 N4 生产验收仍按主路线逐项推进。
