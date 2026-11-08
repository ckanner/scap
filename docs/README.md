# SCAP 文档

| 主题 | 入口 |
| --- | --- |
| 已接受的目标方案 | [对象存储原生方案](architecture/object-storage-native-proposal.md)、[ADR-0020](adr/0020-object-storage-native-authority.md) |
| 当前实际实现 | [对象运行时](engineering/object-runtime.md)、[ADR-0021](adr/0021-object-native-runtime.md) |
| HTTP 与 Node 接入 | [ADR-0023](adr/0023-authenticated-http-and-node-sdk.md)、[服务配置](../crates/scap-service/README.md)、[Node SDK](../sdk/node/README.md)、[恢复手册](operations/http-service.md) |
| 名称目录正式候选 | [ADR-0024](adr/0024-named-catalogue-and-permanent-identities.md)、[协议](architecture/name-catalogue-plan.md)、[服务接口](../crates/scap-service/catalogue.md)、[真实切点矩阵](../experiments/object-network/catalogue-matrix.md) |
| HTTP／Node 完整本地验收 | [冻结候选、独立审计与限制](engineering/http-service-validation.md)、[机器证据](evidence/http-service-local-2026-11-07.json) |
| 逻辑协议模型 | [N0 验证](engineering/object-authority-n0.md) |
| 阶段与剩余工作 | [路线图](engineering/roadmap.md)、[2026-11-07 主线审查与实施状态](engineering/status-2026-11-07.md) |
| 本地执行目录防护验收 | [冻结候选、真实回归与审计范围](engineering/local-storage-validation.md)、[机器证据](evidence/local-storage-guard-2026-11-07.json) |
| SQLite／NFS 边界 | [本地执行文件防护与验证范围](operations/sqlite-storage-safety.md) |
| 后续实施计划 | [名称目录](architecture/name-catalogue-plan.md)、[N1 生命周期与退休合同](engineering/n1-lifecycle-validation-plan.md) |
| 本批原生修复验收 | [ALTER 与保留结果完整本地验收](engineering/native-integrity-validation.md)、[机器证据](evidence/native-integrity-local-2026-11-06.json) |
| 正确性与验证 | [验证规范](engineering/validation.md)、[覆盖率](engineering/testability-and-coverage.md)、[本地源码身份](engineering/local-validation.md) |
| 运行与故障 | [运行说明](operations/runbooks.md)、[故障矩阵](operations/failure-matrix.md) |

旧三节点原型的事实、代码和证据保留在 [重写前的提交](https://github.com/ckanner/scap/tree/4cd99eb3ce404dfa26a8df2536d881f078c9c809)。它们不约束当前格式或 API，也不计作新实现通过的证据。

- [N1 生命周期真实合同验收](engineering/n1-lifecycle-validation.md)：十二场景、完整原结果／进程账本与失败记录。

- [名称目录有界模型验收](engineering/named-catalogue-model.md)：固定意图、永久身份屏障、发布竞争、910 份原始历史摘要及证明范围。
