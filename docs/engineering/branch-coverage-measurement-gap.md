# 分支覆盖测量缺口：0/0 不能作为完整门禁

核查日期：2026-11-13（UTC）。本页纠正当前检查器与历史验收文字的口径，
不改写原始测试、profile、LLVM JSON 或旧命令退出码。适用的冻结 Rust 输入为
PR #59 的 `b15bc455349ea36162b8004c2c73fc7d812d4c10` 和
PR #60 的 `fd508cc052c21dba0e3c54b8e8e82d11c167777a`。

## 结论与合入影响

两份源码分别完成 stable/nightly 各 783 和 791 项单元测试，67 个生产文件均出现在
新采集的 unit-only LLVM map 中，已发出的计数全部命中。但两份报告都有 7 个生产
文件的 branch 计数为 `0/0`。这只能说明采集器没有发出该维度的计数，不能称为
这 7 个文件各自完成了独立的分支覆盖测量。

`AGENTS.md` 和[验证计划](validation.md)要求零分母不能当作通过。旧
`scripts/check_unit_coverage.py` 对单文件 branch 允许零分母，仅在全项目 branch
总分母为零时拒绝。因此其他文件的正分母可以掩盖某个文件没有 branch 测量的事实。
旧检查器的 exit 0、归档中的 `PASS_UNIT_GATES_ONLY` 和文件名中的 `passed` 是原命令
观察，不能扩大为已经满足逐文件四维门禁。

本次修复使检查器对任一生产文件的零分母明确失败，并增加跨文件掩盖反例。
没有修改阈值、生产文件分类、AGENTS、编译器固定版本或生产 Rust。
对原两份 LLVM JSON 只读重验均退出 1，并拒绝这 7 个文件；这表示测量门禁没有闭合，
不表示原先已通过的数据库测试突然出现了新的业务失败。PR 继续保持 Draft。

## 实际缺失的文件

下表是 `b15bc45` 的原始计数；这些文件在 `fd508cc` 中未改变，计数相同。
分子和分母保留原值，不能将 `0/0` 改写为百分比。

| 生产文件 | 行 | 函数 | region | branch | 源码中实际存在的结构 |
| --- | --- | --- | --- | --- | --- |
| `crates/scap-object/src/catalogue/types.rs` | 8/8 | 1/1 | 8/8 | 0/0 | 配额选择的 `match` |
| `crates/scap-object/src/object_frame.rs` | 60/60 | 5/5 | 101/101 | 0/0 | payload `match` 与错误传播 |
| `crates/scap-service/src/catalogue.rs` | 55/55 | 3/3 | 103/103 | 0/0 | action 分派与错误映射 |
| `crates/scap-service/src/lib.rs` | 44/44 | 2/2 | 42/42 | 0/0 | 错误分类及嵌套 `match` |
| `crates/scap-service/src/main.rs` | 3/3 | 1/1 | 6/6 | 0/0 | 委托到服务实现的薄入口 |
| `crates/scap-service/src/owner_wire.rs` | 81/81 | 12/12 | 144/144 | 0/0 | preparation/state 分派 |
| `crates/scap-service/src/snapshot_wire.rs` | 78/78 | 16/16 | 146/146 | 0/0 | state 分派与 Option 映射 |

因此历史记录中的“自然零分母”只可理解为**采集器实际输出了零**。
“这 7 个文件结构上没有分支”的解释不成立。薄入口本身没有需要凭空制造的源码分支；
也不能为了得到正分母，新增无业务意义的条件或把文件移出生产分母。

这 7 个文件是当前可以直接机器拒绝的显性缺口。其他 60 个文件即使包含已被计数的
`if`，也可能同时有采集器未计数的 `match`／`?`；语义测量盲区不只限于零分母文件。

## 编译器能力与独立复现

固定 nightly 为 `nightly-2025-09-18`，实际 `rustc 1.92.0-nightly`、LLVM 21.1.1。
本机选项核验及[官方 Unstable Book](https://doc.rust-lang.org/unstable-book/compiler-flags/coverage-options.html)
均列出 `block`、`branch`、`condition` 三个级别；切换显示选项不能产生原本缺失的映射。

[Rust 上游 #124118](https://github.com/rust-lang/rust/issues/124118)在本次核查时仍开放，
明确列出 individual match arms、or-patterns 和 `?` 的插桩限制。
`?` 会展开为 `match`；已有 region 计数与分支计数不是可以互相替代的度量。
[match 分支原型 #124154](https://github.com/rust-lang/rust/pull/124154)仍为 Draft，
不能据此声称更换一个现成 nightly 就能完整解决当前门禁。

独立小样例使用原固定编译器直接编译，不修改产品，也不把样例 profile 混入 workspace：

| 观察 | `branch` | `condition` | 含义 |
| --- | --- | --- | --- |
| `if` 正对照，两个结果均执行 | branch 2/2 | branch 2/2 | 采集与读取流程确实启用了分支计数 |
| 完整执行 `match`／`?` 样例 | branch 0/0 | branch 0/0 | 更换到 condition 未补出所缺计数 |
| 遗漏一个完整 match arm 或 `?` 的 Err 路径 | region 从 6/6 降到 5/6 | 同左 | region 能识别这一类未执行代码 |
| 遗漏 or-pattern 中一种输入 | region 仍为 6/6，branch 0/0 | 同左 | region 全命中不能独立证明所有选择路径 |

小样例的源码、准确命令、工具版本、ELF、原始 profiles 与 export 均另行保存。
它证明测量能力的限制，不是数据库协议的反例；完整计数、原件摘要和新检查器
验证归属见[机器记录](../evidence/branch-measurement-review-2026-11-13.json)及
[本轮验收](sqlite-s3-review-2026-11-13.md)。

## 后续完成条件

继续保留严格失败结果，不使用聚合百分比、region 替代、假分支、生产排除或旧 profile
把门禁变绿。真实补测需要具有明确定义的源码／控制流边映射、固定计数器来源、
遗漏 match/or-pattern/错误路径能被拒绝的反例，以及相同实际 unit 集合的完整采集。
低层 CFG/edge 覆盖不能未经论证就改名为 Rust 源码 branch 覆盖。

无源码分支的薄入口与测量器尚不支持的决策结构是两类情况。若今后选择明确的
“无适用分支”规范，须作为可审查的验收规范变更处理，不能在这次产品合入时
暗中当作现有严格门禁的例外。本轮没有作出这一规范变更。
