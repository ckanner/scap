# SCAP

面向多租户 SaaS 与 Agent 的 SQLite 数据库平台：以轻量计算单元服务大量独立数据库，以共享同步日志提供故障保障，以对象存储承载冷数据与历史。

> **当前阶段：架构设计与仓库初始化。** 本仓库尚未实现可运行的数据库服务。文档中的接口、组件部署、恢复流程与可靠性指标均为设计或验收目标；不代表已经实现、经过压测或可以直接用于生产。

## 核心决策

- **SQLite 优先**，PostgreSQL 暂不进入实施范围。
- SQL 执行优先复用 **libSQL 的 SQLite C 内核及 WAL 扩展接口**；它与 Turso 的 Rust 重写引擎是不同项目。
- Node.js 优先接入现有 **`@libsql/client`**；存量 `better-sqlite3` 应用评估 **`libsql` 兼容驱动**。兼容范围必须通过真实应用验证。
- 每个数据库只有一个获准写入的 owner。多个数据库共享执行节点和存储 cell，**不为每个小库固定部署一套三节点集群**。
- 每个 storage cell 初始为跨三个可用区的 **三副本 Raft 组**。事务变更和写者版本由同一个有序状态机裁决；多数派持久化并接受事务后才能返回成功。
- **S3 异步归档不会降低提交保障**：未完成归档的数据必须仍由可靠日志或可恢复的状态机快照保留。
- 网络分区时采用 **CP 策略**：无权威多数派的一侧不接受新的强一致读写，禁止自动降级为本地写成功。
- Bottomless / Litestream 用作备份机制参考及实验对照，**不承担本设计的同步提交与自动选主职责**。

## 设计导航

| 文档 | 回答的问题 |
| --- | --- |
| [需求与故障合同](docs/architecture/requirements.md) | 什么是成功、可用、零丢失，以及承诺的故障范围？ |
| [总体架构](docs/architecture/overview.md) | 请求流向、组件职责、部署和扩展方式是什么？ |
| [一致性协议](docs/architecture/consistency.md) | 分区、提交、读屏障、旧写者和未知提交怎样处理？ |
| [存储与生命周期](docs/architecture/storage-lifecycle.md) | S3、日志回收、休眠、唤醒、删除和恢复怎样协作？ |
| [客户端与 API 契约](docs/architecture/api-contracts.md) | Node.js 如何接入，哪些兼容性和重试行为有边界？ |
| [租户隔离与安全](docs/architecture/tenancy-security.md) | 权限、配额、进程隔离和密钥怎样管理？ |
| [技术栈](docs/architecture/technology-stack.md) | 用什么语言、组件，哪些需要自行实现？ |
| [组件故障矩阵](docs/operations/failure-matrix.md) | 每个组件失效、分区或重启后，系统具体做什么？ |
| [运维恢复手册](docs/operations/runbooks.md) | 如何升级、恢复、换节点和处理异常？ |
| [验证计划](docs/engineering/validation.md) | 怎样证明提交不丢失、无双写、可正确恢复？ |
| [实施路线](docs/engineering/roadmap.md) | 开发顺序、验收门禁和停止条件是什么？ |
| [成本与容量](docs/engineering/capacity-cost.md) | 规模和成本怎么测，长尾收益来自哪里？ |
| [开源组件调查](docs/research/components.md) | 上游实际提供什么能力，证据与许可是什么？ |
| [ADR 索引](docs/adr/README.md) | 为什么这样选择，替代路线是什么？ |

## 可靠性目标与边界

在单区域三个独立故障域、正确持久化、无拜占庭故障、仍有有效多数派或其可恢复数据的前提下，目标是：**单进程、单计算节点、单存储副本或单可用区故障不丢已确认事务**。

永久丢失多数副本、区域灾难、凭证泄露或应用误删不被包装成相同的 HA 承诺。区域恢复使用已核验的归档恢复点，可能存在未归档尾部损失；误删需要历史恢复。RTO、冷启动延迟和吞吐尚未测量。

## 初始技术方向

| 层 | 方向 |
| --- | --- |
| 平台服务 | Rust，Tokio，Axum，Tonic / Protobuf |
| SQL 引擎 | libSQL / SQLite C 内核，Rust FFI 适配 |
| 日志复制 | OpenRaft + 自行实现并验证的持久存储适配 |
| 本地日志与索引 | RocksDB 候选，显式同步持久化和恢复契约 |
| 对象存储 | 具备已验证一致性、持久性和校验能力的 S3 兼容服务 |
| 控制目录 | etcd；只保存目录、意图和控制元数据 |
| Node.js 接入 | TypeScript，`@libsql/client`，可选 `libsql` 兼容入口 |
| 观测 | OpenTelemetry，Prometheus，结构化日志 |
| 部署 | Linux / OCI 容器；生产可用 Kubernetes，编排器不承担数据库选主 |

完整的同步 WAL 适配、cell 状态机、恢复协议和生产控制面**是本项目需要开发的部分**。采用现有 SDK 不意味着这些能力已经存在。依赖版本须在第一阶段验证后锁定，不能长期追随上游 `main` 或浮动 `latest`。

## 仓库使用

当前只需要 Python 3.11+ 来运行文档和契约检查，不需要安装数据库集群：

```bash
python3 scripts/check_repo.py
```

这项检查验证文档链接和设计清单等仓库约束，**不是数据库正确性测试**。

开发规则见 [CONTRIBUTING.md](CONTRIBUTING.md)，AI / 自动化协作规则见 [AGENTS.md](AGENTS.md)，安全报告见 [SECURITY.md](SECURITY.md)。主文档使用中文；代码标识符、协议字段、提交类型使用英文。

## 许可

本仓库自身的分发许可尚待维护者决定，当前不添加未经选择的开源授权。第三方组件的许可证、上游修改义务和供应链记录见组件调查；引入源码前完成核验。

设计基线日期：**2026-10-27**。
