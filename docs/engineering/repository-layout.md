# 仓库结构与语言约定

## 1. 当前结构

| 路径 | 用途 |
| --- | --- |
| `README.md` | 项目定位、状态、设计导航 |
| `AGENTS.md` | 自动化与 AI 协作规则 |
| `CONTRIBUTING.md` | 分支、评审、验证和文档规则 |
| `SECURITY.md` | 漏洞报告与敏感信息处理 |
| `docs/architecture/` | 需求、架构、协议、存储、API、隔离、技术栈 |
| `docs/adr/` | 设计决策记录 |
| `docs/operations/` | 故障行为与运行手册 |
| `docs/engineering/` | 实施、验证、容量和仓库结构 |
| `docs/research/` | 开源证据、许可和复用边界 |
| `contracts/design-contract.json` | 当前方案的机器可读清单，不是服务配置 |
| `scripts/check_repo.py` | 无第三方依赖的文档检查 |
| `.github/` | 文档 CI、PR 与 issue 模板 |

## 2. 实现阶段的规划结构

以下模块在实施阶段创建，本次不创建假实现：

| 规划路径 | 语言 / 内容 |
| --- | --- |
| `crates/scap-types` | Rust；身份、错误、版本化存储类型 |
| `crates/scap-engine` | Rust + libSQL C FFI；SQL/WAL 适配与恢复 |
| `crates/scap-cell` | Rust；Raft 状态机和写者/提交规则 |
| `crates/scap-store` | Rust；RocksDB 持久存储与快照适配 |
| `crates/scap-archive` | Rust；S3、manifest、恢复和 GC |
| `crates/scap-gateway` | Rust；协议、认证、路由和会话 |
| `crates/scap-controller` | Rust；生命周期与目录 reconciliation |
| `crates/scap-observability` | Rust；受控指标、链路和审计 |
| `bin/` | Rust 服务入口及受控运维 CLI |
| `proto/` | 版本化 Protobuf；先定义契约，再生成代码 |
| `sdk/typescript/` | 薄 SDK、管理 API、错误和请求身份封装 |
| `examples/node/` | 原生 SDK / ORM 接入样例 |
| `tests/` | 契约、状态机、故障注入、兼容与恢复测试 |
| `deploy/` | 开发和生产部署清单，明确区分故障域 |

## 3. 语言策略

服务端采用 Rust，复用 SQLite / libSQL 的 C 内核；不为统一语言而重写 SQL 引擎。Node.js 接入与 SDK 使用 TypeScript。当前 Python 仅用于仓库辅助检查，不是数据库运行时依赖。

中文用于主设计文档和面向当前团队的说明。代码标识符、协议字段、错误码、目录名、提交类型使用英文。文档中的术语第一次出现时给出中文解释，避免无定义缩写。

## 4. 工具链与版本

第一批 Rust 代码合入时提交固定的 toolchain 和 `Cargo.lock`；第一批 TypeScript 代码合入时提交包管理器版本与锁文件。依赖升级必须同时考虑 RPC、日志、磁盘、对象格式和 SDK 兼容性。

不在文档初始化阶段指定未经验证的 MSRV、虚构可编译的依赖版本或发布镜像标签。编译选项、引擎 page size 与 extension 清单进入可复现构建记录。

## 5. 变更边界

核心存储格式和内部协议使用版本化结构，未知版本明确拒绝。破坏提交语义、故障合同、身份或恢复格式的改动必须先更新 ADR 和验证计划。

部署文档只能出现真实实现且经过验证的命令；计划接口以“计划”标注，不通过占位命令制造已完成印象。
