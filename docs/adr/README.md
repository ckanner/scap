# 架构决策记录

ADR 记录背景、选择、代价和重新评审条件。当前记录为设计基线；其中需要 PoC 的组件不能因为 ADR 已写下就视为已实现。

| 编号 | 决策 | 状态 |
| --- | --- | --- |
| [0001](0001-sqlite-scope-and-client.md) | SQLite 优先，SDK 服务化入口 | 设计基线 |
| [0002](0002-shared-quorum-cells.md) | 共享同步复制 cell 与 CP 行为 | 设计基线；持久化适配待验证 |
| [0003](0003-object-storage-and-cold-lifecycle.md) | 异步归档、明确发布、可验证回收 | 设计基线；恢复链待验证 |
| [0004](0004-engine-and-implementation-boundary.md) | libSQL / Rust 技术方向及自研边界 | 候选；G0 通过后锁定 |

新增 ADR 使用下一个编号，保留被替代记录并注明替代关系。用户或维护者改变范围时记录原因，不通过删除旧决策隐藏取舍。
