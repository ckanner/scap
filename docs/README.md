# SCAP 文档

| 主题 | 入口 |
| --- | --- |
| 已接受的目标方案 | [对象存储原生方案](architecture/object-storage-native-proposal.md)、[ADR-0020](adr/0020-object-storage-native-authority.md) |
| 当前实际实现 | [对象运行时](engineering/object-runtime.md)、[ADR-0021](adr/0021-object-native-runtime.md) |
| 逻辑协议模型 | [N0 验证](engineering/object-authority-n0.md) |
| 阶段与剩余工作 | [路线图](engineering/roadmap.md) |
| 本批原生修复验收 | [ALTER 与保留结果完整本地验收](engineering/native-integrity-validation.md)、[机器证据](evidence/native-integrity-local-2026-11-06.json) |
| 正确性与验证 | [验证规范](engineering/validation.md)、[覆盖率](engineering/testability-and-coverage.md)、[本地源码身份](engineering/local-validation.md) |
| 运行与故障 | [运行说明](operations/runbooks.md)、[故障矩阵](operations/failure-matrix.md) |

旧三节点原型的事实、代码和证据保留在 [重写前的提交](https://github.com/ckanner/scap/tree/4cd99eb3ce404dfa26a8df2536d881f078c9c809)。它们不约束当前格式或 API，也不计作新实现通过的证据。
