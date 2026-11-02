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
| `crates/scap-raft-wire/` | Rust；固定 envelope、有限 protobuf 预检、实际 leaf pin/日期与 cell/node 授权 |
| `crates/scap-raft-transport/` | Rust；正式 Tonic mTLS peer server/client，全局连接/RPC 预算与绝对 deadline |
| `crates/scap-raft-runtime/` | Rust；单 cell 串行 owner、自动 tick、有限请求/inbox、读和反馈；ordinary/snapshot 异步发送；含正式 `RaftDriver` 委托 |
| `crates/scap-cell-client/` | Rust；固定 scope、请求上下文、Safe ReadIndex 与精确 tracked 业务裁决的正式 CommitGate |
| `crates/scap-sql-worker/` | Rust；线程内 ClaimOwner、物理恢复、新目录 native 创建、ActivateOwner 和每次执行生命周期 |
| `crates/scap-cell/` | Rust；有界确定性业务状态机，身份、owner/auth、事务接受、去重、取消和版本化 codec |
| `crates/scap-sql/` | Rust；有界请求类型、精确请求 fingerprint 与完整结果 codec |
| `crates/scap-engine/` | Rust；版本化物理页事务、完整逻辑镜像与权威历史恢复 |
| `crates/scap-sqlite/` | Rust + 固定 libSQL C；私有连接、SQL 准入、提交 gate、原生完成与新目录物化 |
| `experiments/wal-gate/` | 独立真实引擎探针，不能作为运行时依赖 |
| [experiments/raft-rpc/](../../experiments/raft-rpc/README.md) | 独立真实 loopback 编码/传输实验；只有测试与构建目标，不能作为运行时依赖 |
| [experiments/raft-store/](../../experiments/raft-store/README.md) | 独立真实 RawNode/RocksDB 契约与进程恢复实验；使用正式存储策略，后端和 driver 装配仍为测试夹具 |
| [experiments/raft-cluster/](../../experiments/raft-cluster/README.md) | 独立三进程真实磁盘与受控消息故障；直接使用正式 driver/backend，合成应用与 IPC 路由为测试夹具 |
| [experiments/sqlite-cell/](../../experiments/sqlite-cell/README.md) | 固定 libSQL 与正式 cell/driver/backend 的真实提交与恢复合同；受限引擎及 IPC 装配为测试夹具 |
| [experiments/sqlite-engine/](../../experiments/sqlite-engine/README.md) | 正式 SQLite adapter 与真实 cell 的独立故障合同，含 SQL 子进程被杀 |
| [experiments/raft-network/](../../experiments/raft-network/README.md) | 三个独立进程使用正式 wire/transport/runtime 与 RocksDB；端到端 mTLS、透明 TCP 故障代理、重启和 snapshot；合成 payload 不执行 SQLite SQL |
| [experiments/sqlite-network/](../../experiments/sqlite-network/README.md) | 三个独立进程的真实 SQLite 与正式 mTLS 共识组合；fence、UNKNOWN、发布前 SIGKILL、owner 恢复及 snapshot |
| `tests/tooling/` | 仓库脚本自身的单元测试 |
| `.github/` | 文档、独立单元覆盖和真实依赖/故障 CI；PR 与 issue 模板 |

本轮技术栈的事实依据放在 [TiKV 审计](../research/tikv-rust-stack.md)，取舍放在 [ADR-0007](../adr/0007-tikv-stack-and-rpc-boundaries.md)，实现必须遵守 [运行与 RPC 契约](runtime-and-rpc.md)。机器可读清单登记选择与证据；实验 README 记录实际版本、运行结果和未验证边界，各自不能替代产品实现。

正式单 cell peer 网络的当前边界见 [ADR-0012](../adr/0012-bounded-raft-network-runtime.md)和[模块合同](raft-network-runtime.md)。运行代码只位于正式 crates；实验中的控制协议、证书夹具、透明代理和子进程编排不作为产品依赖。生产服务入口、外部 SQL/SDK 和自动 writer 接管仍待实现。

## 2. 实现阶段的规划结构

除上面的已实现小范围核心与探针外，下列模块在后续实施阶段创建：

| 规划路径 | 语言 / 内容 |
| --- | --- |
| `crates/scap-types` | Rust；身份、错误、版本化存储类型 |
| `crates/scap-cell` 后续扩展 | Rust；补全现有接受子集之外的生命周期、迁移、删除和归档规则；调度另设明确边界 |
| 增量存储 / I/O 执行模块 | Rust；在已有有界 Store 与 native 后端上实现可扩展布局、大快照和多 cell 有序执行 |
| `crates/scap-archive` | Rust；S3、manifest、恢复和 GC |
| `crates/scap-gateway` | Rust；协议、认证、路由和会话 |
| `crates/scap-controller` | Rust；生命周期与目录 reconciliation |
| `crates/scap-observability` | Rust；受控指标、链路和审计 |
| `bin/` | Rust 服务入口及受控运维 CLI |
| 后续业务 `proto/` | SQL/控制面自有版本化协议；当前 peer schema 已放在 `crates/scap-raft-transport/proto/peer.proto`，最小服务直接由正式源码实现 |
| `sdk/typescript/` | 薄 SDK、管理 API、错误和请求身份封装 |
| `examples/node/` | 原生 SDK / ORM 接入样例 |
| `tests/` | 契约、状态机、故障注入、兼容与恢复测试 |
| `deploy/` | 开发和生产部署清单，明确区分故障域 |

## 3. 语言策略

服务端采用 Rust，复用 SQLite / libSQL 的 C 内核；不为统一语言而重写 SQL 引擎。Node.js 接入与 SDK 使用 TypeScript。当前 Python 仅用于仓库辅助检查，不是数据库运行时依赖。

中文用于主设计文档和面向当前团队的说明。代码标识符、协议字段、错误码、目录名、提交类型使用英文。文档中的术语第一次出现时给出中文解释，避免无定义缩写。

## 4. 工具链与版本

当前 Rust 核心已有固定 toolchain 和 `Cargo.lock`；各独立探针另行锁定上游 commit 与依赖，所测版本不自动成为产品依赖。正式 sys/WAL adapter 在根 workspace 固定同一 libSQL revision，边界见 [ADR-0011](../adr/0011-bounded-native-sqlite-adapter.md)；正式 peer 栈固定 Tokio 1.50.0、Tonic 0.14.6、Prost 0.14.3 与相应 TLS features，完整解析依赖仍由根锁文件管理。第一批 TypeScript 代码合入时提交包管理器版本与锁文件。依赖升级必须同时考虑 RPC、日志、磁盘、对象格式和 SDK 兼容性。

引入库时同时记录完整源码版本、features、代码生成器/protoc、native 库及 submodule、目标平台、许可证和 patch。TiKV 的 fork、nightly 工具链与 allocator 是审计参考，不能因为同名组件存在就认为 SCAP 已采用或验证。

固定 sqld 的旧依赖树与现代平台候选栈须明确 fork、模块提取或独立构建/进程边界；单独放进另一个 workspace 不会自动解决同进程的类型、运行时或 native 链接冲突。实际边界选择及 Hrana/SDK 回归属于 G0 门禁。

不在文档初始化阶段指定未经验证的 MSRV、虚构可编译的依赖版本或发布镜像标签。编译选项、引擎 page size 与 extension 清单进入可复现构建记录。

## 5. 变更边界

核心存储格式和内部协议使用版本化结构，未知版本明确拒绝。破坏提交语义、故障合同、身份或恢复格式的改动必须先更新 ADR 和验证计划。

部署文档只能出现真实实现且经过验证的命令；计划接口以“计划”标注，不通过占位命令制造已完成印象。

早期 `raft-rpc` 的 8 项结果只涵盖其编码/传输契约，没有 RawNode、持久化、quorum 或 HA。新增 `raft-network` 则组合正式运行模块、三个真实持久进程与 mTLS，保留独立 integration profile。二者都不补生产单元覆盖率。测试文件和研究目录按 [coverage policy](../../contracts/coverage-policy.json)精确登记；包括 `runtime/src/driver.rs` 在内的正式源码保留在生产分母，不因委托很薄而排除。

正式 SQLite 网络组合与 owner 恢复入口见 [ADR-0013](../adr/0013-tracked-sqlite-network-commit.md)。`EngineFactory`、`CellPort` 和 Runtime adapter 都计入第一方单元分母；实验只装配正式实现与故障控制，不保存另一套生产算法。
