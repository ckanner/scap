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
| [contracts/technology-decisions.json](../../contracts/technology-decisions.json) | 技术方向、候选和证据登记；不是运行配置或依赖锁文件 |
| `contracts/coverage-policy.json` | 第一方生产源码与精确单元覆盖率门禁 |
| `contracts/performance-targets.json` | 性能与恢复目标及测量前提 |
| `scripts/check_repo.py` | 无第三方依赖的文档检查 |
| `scripts/check_unit_coverage.py` | 精确计数、生产源码与 coverage map 对账 |
| `crates/scap-core/` | Rust；已实现的窄提交完成策略与单元测试 |
| `crates/scap-raft-store/` | Rust；有界持久状态策略、codec/校验与 raft::Storage；最终 I/O 通过 AtomicBackend 注入 |
| `crates/scap-raft-driver/` | Rust；正式单 cell 串行 RawNode driver、读票据、预算与应用次序 |
| `crates/scap-raft-rocks/` | Rust；正式独占 RocksDB 后端，目录准入与 WAL + sync 原子镜像 |
| `experiments/wal-gate/` | 独立真实引擎探针，不能作为运行时依赖 |
| [experiments/raft-rpc/](../../experiments/raft-rpc/README.md) | 独立真实 loopback 编码/传输实验；只有测试与构建目标，不能作为运行时依赖 |
| [experiments/raft-store/](../../experiments/raft-store/README.md) | 独立真实 RawNode/RocksDB 契约与进程恢复实验；使用正式存储策略，后端和 driver 装配仍为测试夹具 |
| [experiments/raft-cluster/](../../experiments/raft-cluster/README.md) | 独立三进程真实磁盘与受控消息故障；直接使用正式 driver/backend，合成应用与 IPC 路由为测试夹具 |
| `tests/tooling/` | 仓库脚本自身的单元测试 |
| `.github/` | 文档 CI、PR 与 issue 模板 |

本轮技术栈的事实依据放在 [TiKV 审计](../research/tikv-rust-stack.md)，取舍放在 [ADR-0007](../adr/0007-tikv-stack-and-rpc-boundaries.md)，实现必须遵守 [运行与 RPC 契约](runtime-and-rpc.md)。机器可读清单登记选择与证据；实验 README 记录实际版本、运行结果和未验证边界，各自不能替代产品实现。

## 2. 实现阶段的规划结构

除上面的已实现小范围核心与探针外，下列模块在后续实施阶段创建：

| 规划路径 | 语言 / 内容 |
| --- | --- |
| `crates/scap-types` | Rust；身份、错误、版本化存储类型 |
| `crates/scap-engine` | Rust + libSQL C FFI；SQL/WAL 适配与恢复 |
| `crates/scap-cell` | Rust；连接已有 driver 的完整业务状态机、写者/提交规则和运行调度 |
| 增量存储 / I/O 执行模块 | Rust；在已有有界 Store 与 native 后端上实现可扩展布局、大快照和多 cell 有序执行 |
| `crates/scap-archive` | Rust；S3、manifest、恢复和 GC |
| `crates/scap-gateway` | Rust；协议、认证、路由和会话 |
| `crates/scap-controller` | Rust；生命周期与目录 reconciliation |
| `crates/scap-observability` | Rust；受控指标、链路和审计 |
| `bin/` | Rust 服务入口及受控运维 CLI |
| `proto/` | 自有版本化 Protobuf 与 Raft 外层 envelope；先定义契约，再生成代码 |
| `sdk/typescript/` | 薄 SDK、管理 API、错误和请求身份封装 |
| `examples/node/` | 原生 SDK / ORM 接入样例 |
| `tests/` | 契约、状态机、故障注入、兼容与恢复测试 |
| `deploy/` | 开发和生产部署清单，明确区分故障域 |

## 3. 语言策略

服务端采用 Rust，复用 SQLite / libSQL 的 C 内核；不为统一语言而重写 SQL 引擎。Node.js 接入与 SDK 使用 TypeScript。当前 Python 仅用于仓库辅助检查，不是数据库运行时依赖。

中文用于主设计文档和面向当前团队的说明。代码标识符、协议字段、错误码、目录名、提交类型使用英文。文档中的术语第一次出现时给出中文解释，避免无定义缩写。

## 4. 工具链与版本

当前 Rust 核心已有固定 toolchain 和 `Cargo.lock`；引擎和 RPC 探针各自独立锁定上游 commit 与依赖，所测版本不自动成为产品依赖。第一批 TypeScript 代码合入时提交包管理器版本与锁文件。依赖升级必须同时考虑 RPC、日志、磁盘、对象格式和 SDK 兼容性。

引入库时同时记录完整源码版本、features、代码生成器/protoc、native 库及 submodule、目标平台、许可证和 patch。TiKV 的 fork、nightly 工具链与 allocator 是审计参考，不能因为同名组件存在就认为 SCAP 已采用或验证。

固定 sqld 的旧依赖树与现代平台候选栈须明确 fork、模块提取或独立构建/进程边界；单独放进另一个 workspace 不会自动解决同进程的类型、运行时或 native 链接冲突。实际边界选择及 Hrana/SDK 回归属于 G0 门禁。

不在文档初始化阶段指定未经验证的 MSRV、虚构可编译的依赖版本或发布镜像标签。编译选项、引擎 page size 与 extension 清单进入可复现构建记录。

## 5. 变更边界

核心存储格式和内部协议使用版本化结构，未知版本明确拒绝。破坏提交语义、故障合同、身份或恢复格式的改动必须先更新 ADR 和验证计划。

部署文档只能出现真实实现且经过验证的命令；计划接口以“计划”标注，不通过占位命令制造已完成印象。

RPC 实验的 8 项通过结果只涵盖其编码/传输契约，没有 RawNode、持久化、quorum 或 HA。若复用实验逻辑，须迁入正式模块并纳入 100% 第一方生产单元覆盖率与真实依赖/故障验证，不能把实验目录变成运行时依赖或覆盖率例外。
