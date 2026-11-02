# 可测试架构与 100% 单元测试覆盖率

> 状态：工程合同与实施规范。本文要求第一方生产代码达到 **100% 单元测试行覆盖率和 100% 单元测试函数覆盖率**；Rust 生产代码的 **100% 实测分支覆盖率同样是硬门禁**。工具无法准确测量时阻断相应门禁，不自动降低门槛。工具配置、实际计数和运行证据必须由仓库 CI 给出；本文不以规范文本宣称实现已经达标。

100% 是交付要求。代码难以单元测试时，应重新划分职责、显式传入依赖和重构控制流，不能通过排除入口、适配器、异常分支或未实现功能来改变分母。单元覆盖率必须独立计算，集成测试、真实故障测试和人工操作产生的执行记录不能补入单元覆盖率。

本规范与[一致性协议](../architecture/consistency.md)、[存储生命周期](../architecture/storage-lifecycle.md)、[验证与发布门禁](validation.md)共同生效。覆盖率通过不会替代其中的正确性与持久性门禁。

## 1. 100% 的精确定义

### 1.1 分子、分母与报告范围

对每个受支持的生产构建配置 `configuration`，定义：

```text
ProductionScope(configuration)
  = first_party_production_code(configuration)
    - explicitly_registered_non_first_party_or_generated_artifacts

unit_line_coverage
  = lines_executed_by_unit_tests / instrumented_executable_lines_in_scope

unit_function_coverage
  = functions_executed_by_unit_tests / instrumented_functions_in_scope

gate_pass
  = inventory_complete
    AND unit_tests_passed
    AND covered_lines == total_lines
    AND covered_functions == total_functions

rust_gate_pass
  = gate_pass
    AND branch_measurement_is_valid
    AND covered_branches == total_branches
```

这里的分母不是物理文本行数。空行、注释和编译器没有映射为可执行代码的声明，不会自然形成行计数器。LLVM 的报告区分行、函数、region、分支和实例等统计维度。[S1] [S2]

**`instrumented` 不是允许漏算代码的理由。** 必须先证明第一方生产源码、target、feature 和平台清单已被覆盖映射包含，才能使用该分母。文件没有出现在报告中、函数被测试构建替换、依赖未链接或 feature 未开启，都是需要调查的缺口，不能解释为已经覆盖。

100% 按整数判断：未覆盖行数和未覆盖函数数都必须为零。不能依赖显示为 `100.00%` 的四舍五入，也不能只对变更行设 100% 而允许其余生产代码持续未覆盖。

### 1.2 不同指标不能互相代替

| 指标 | 计量内容 | 达到 100% 仍不能证明什么 | SCAP 要求 |
| --- | --- | --- | --- |
| 行覆盖 `line` | 被工具映射的可执行行是否执行过 | 同一行中的全部判断、短路项和错误结果都执行过 | 100%，硬门禁 |
| 函数覆盖 `function` | 被映射函数是否至少执行过 | 函数所有分支、所有泛型实例都执行过 | 100%，硬门禁 |
| 区域覆盖 `region` | 编译器标记的代码区域是否执行过 | 区域内完整决策组合、所有状态历史都覆盖 | 单独报告；不能充当分支覆盖 |
| 分支覆盖 `branch` | 工具可表示的分支或判断结果是否执行过 | 所有条件独立作用、所有多分支组合都覆盖 | 100%；Rust 使用准确报告执行硬门禁 |
| 条件覆盖 `condition` | 布尔表达式中的原子条件是否实际取过所要求的值 | 每个条件独立影响最终决策 | 独立说明测量能力，关键条件使用决策表验证 |
| 修正条件/判定覆盖 `MC/DC` | 每个条件能否独立影响复合判定的结果 | 所有执行路径、并发顺序或故障都正确 | 关键安全判断采用相应测试设计；自动度量需单独验证 |
| 实例覆盖 `instantiation` | 泛型或其他多实例函数的实例是否执行过 | 所有合法输入和状态都正确 | 生产支持的不同实现/类型要有测试，不能只测一个 fake 实例 |

工具对“分支”的映射粒度不同，不能只看字段名称推断覆盖了多少原子条件。Rust 当前的覆盖插桩选项区分 `block`、`branch`、`condition`；LLVM 的 region、branch 和 MC/DC 也分别报告。[S2] [S3] [S4]

例如提交条件涉及 `owner_matches && auth_matches && base_matches`，只有一组全真和一组全假的测试，可能已经走过“接受”和“拒绝”两个顶层结果，但没有证明每个拒绝原因都有效。测试至少应独立改变每一项、保持其他项有效，并检查被拒绝时没有修改状态、没有发布页面、没有泄露旧结果。由于短路求值，“给了一个 false 参数”也不等于该条件实际被求值。

覆盖率不是“所有路径覆盖率”。循环次数、无限状态空间和并发调度不能用一个有限的行或分支计数完整表示，必须继续使用属性、模型、契约和故障验证。

### 1.3 无数据、不可测和不适用

- 仓库还没有某种语言的生产代码时，报告 `NO_PRODUCTION_CODE` 或 `NOT_APPLICABLE`，不生成“100% 已达成”的徽章。
- 有生产代码但分母为零、没有 coverage map、profile 丢失或报告解析失败时，门禁失败。
- 分支插桩不可用、不完整或无法确认分母时，报告 `NOT_MEASURED` / `TOOLING_BLOCKED`，不能用 `0/0`、region 或行覆盖率填成 100%。Rust 生产门禁保持阻断。
- 行和函数已经实测 100% 时，可以准确报告这两个事实；在分支未测量时，不能扩大为“全部覆盖维度均为 100%”或宣称完整分支目标已经完成。
- 工具缺陷需要修复工具链、提供可复核的覆盖映射，或重构受影响代码。不能把难测生产代码记成“不适用”来绕过要求。

## 2. 生产代码范围与排除规则

### 2.1 必须计入的第一方代码

| 范围 | 必须覆盖的行为举例 |
| --- | --- |
| 状态机与领域逻辑 | owner/auth fence、revision、幂等、生命周期、错误和拒绝路径 |
| gateway 与协议适配 | 解析、权限准入、路由、响应映射、未知结果、不合法输入 |
| worker 与引擎适配 | staged/publish/abort、快照绑定、取消、FFI 参数和错误处理 |
| 持久化适配 | 编码、写入顺序、回调处理、错误传播、重启元数据与 snapshot 引用 |
| 归档、恢复、GC | 引用闭包、pin、连续性、checksum、重试、删除许可和容量保护 |
| 控制面与后台任务 | reconciliation、重复事件、调度竞争、暂停/唤醒、任务恢复 |
| 服务入口与运维 CLI | 参数和配置校验、组件装配、初始化失败、退出与资源清理 |
| TypeScript SDK | 请求身份、错误分类、查询状态、重试规则、取消和过期处理 |
| 第一方补丁及手写 FFI | libSQL 集成补丁、手写 C/Rust bridge、边界转换和资源释放 |

日志降级、指标缓冲满、连接初始化失败、checksum 不符、磁盘满、超时和无法达到 quorum 的分支，都是生产行为。不能因“正常情况下不发生”而排除。

辅助脚本、覆盖率判定器、构建工具和代码生成器也要有独立的单元测试与适用的覆盖率合同；它们的计数不能并入数据库生产代码，抬高产品的覆盖比例。

### 2.2 允许清楚列明的分母外内容

允许的范围只有：未经第一方修改的第三方代码、可重现的纯生成产物、测试/fixture 本身以及文档等非生产执行内容。排除清单必须机器可读、进入版本控制，并逐项记录：

- 精确路径或有边界的匹配规则，以及该范围实际展开的文件列表。
- 分类、来源、生成器/依赖版本或来源标识、责任人和审查理由。
- 是否存在第一方修改；生成产物如何重现、是否禁止手工修改。
- 对应契约或兼容性验证入口，以及清单变更对分母的影响。

下面这些不能成为排除理由：`hard to test`、`entrypoint`、`adapter`、`error path`、`unsafe`、`async`、`FFI`、`platform-specific` 或“只是几行”。

未经修改的 SQLite/libSQL、`raft-rs`、RocksDB 和 SDK 依赖本体可归入第三方；**SCAP 对它们的配置、封装、错误转换、持久化次序和自维护补丁必须计入**。代码放进 `vendor/` 不会自动变成第三方。Rust 覆盖率也不能替代手写 C 和 TypeScript 的覆盖率；各语言需要自己的准确报告，分别满足 100% 要求。

生成代码的模板、生成器和手写扩展不能随生成产物一起排除。包含手写逻辑的混合文件应拆分，或提供可审计的精确映射，不能整文件忽略。

### 2.3 测试夹具与 G0 研究探针

测试 fixture、fake、独立模型和仅用于研究的探针必须显式登记为测试/研究资产，并给出相应执行层级。它们不是生产代码分母的一部分，也不能凭它们自己的执行行数提高生产覆盖率。

`experiments/wal-gate` 的角色是 G0 引擎行为探针与测试 harness：验证真实 libSQL 的 WAL 提交边界，不是可供服务运行的 engine adapter。其运行归入独立集成层，不并入 `scap-core` 的单元 profile。这个分类必须由实际依赖关系和用途支持，而不是因为目录名叫 `experiments`。

`crates/scap-raft-store` 的格式、校验、状态转换和 `raft::Storage` 已属于正式源码，由可控 AtomicBackend 支撑独立单元覆盖。`experiments/raft-store` 使用同一正式实现，另行装配真实 RocksDB、RawNode 和子进程恢复测试；夹具的执行结果只提供真实依赖契约证据。后续产品采用其后端或运行循环时，必须先将对应第一方实现纳入正式源码与单元门禁。

后续正式 `scap-raft-driver` / `scap-raft-rocks` 遵守相同分类：单 driver 的次序、输入和预算测试控制 I/O、应用、逻辑 tick 与输出，使用未修改的 Raft 内核，不再编写另一套 fake 共识算法。native adapter 的薄委托使用 RocksDB memory Env 测试参数和返回，其策略错误通过实际 I/O 边界注入；默认入口仍实际覆盖。单独目录准入测试只检查隔离临时命名空间的元数据操作。任何真实 payload 磁盘重开、跨节点协议历史、进程崩溃或全系统模拟都继续进入独立契约层，不能靠放进单元 test module 改变分类。具体边界见 [ADR-0009](../adr/0009-serial-driver-and-native-backend.md)。

研究探针必须满足以下边界：

- 生产 crate、发布 binary 和运行时配置不得依赖它，不能把其中的逻辑作为隐蔽的生产模块调用。
- 探针的源码范围、目的、fixture 数据、依赖与报告独立列明，不把测试结果扩展为生产 adapter 的可靠性承诺。
- 需要将其算法、桥接代码或模块用于产品时，先登记并迁入生产范围，拆出可注入依赖的行为，补齐 100% 单元行/函数/分支门禁，再保留原真实引擎测试作为契约或集成证据。
- 即使暂时没有移动文件，只要被运行时使用，就已经是生产代码；不能等待目录重命名后才计入分母。

不得为提高覆盖率把原有产品逻辑搬入研究探针、fixture 或测试工具目录。范围校验必须检测这种依赖和归属变化。

### 2.4 禁止用构建或源码技巧改变分母

禁止通过以下方式把未覆盖代码藏起来：

- 在生产函数上添加 `coverage(off)`、忽略文件规则、`cfg(coverage)` 替代实现或仅测试可见的捷径。
- 把难测逻辑移到排除目录、宏展开、生成模板或未列入 workspace 的 package。
- 只测 `--lib`，却把服务 binary 和 CLI 入口称为已覆盖。
- 只编译默认 feature，忽略实际发布使用的其他实现。
- 把测试用 fake 编译成“生产实现”，使真实适配器完全没有出现在报告里。
- 用大批测试 helper 的执行行数稀释生产分母。

测试代码自身可以从产品分母中排除，但边界必须可核查。对同文件的测试模块，不能使用一个会同时匹配生产代码的宽泛规则。

若某个分支确实不应存在，应通过类型、不变量和控制流重构消除它，并保留对应外部输入或损坏检测的测试；不能简单删除必要的防御逻辑来取得 100%。

## 3. 用可测试性约束模块边界

### 3.1 纯决策与副作用执行分开

SCAP 的核心应尽量把“根据已提交状态决定什么”与“如何访问外部系统”分开：

```text
deterministic_state + command
    -> decision + next_state_or_delta + required_effects

effect_executor + ports
    -> explicit_completion_or_failure

completion_event
    -> next deterministic transition
```

这是架构形态，不是允许提前发布状态。`Accepted`、持久化完成、本地 SQL 可见和客户端 ACK 的顺序仍严格遵守一致性协议。状态机算出了 next state，不等于它已经可以对外可见。

同一个输入状态、同一个命令和相同格式版本，必须得到同样的判定。Raft `apply` 中不能临时读取墙钟、生成随机数、查询 etcd、访问 S3 或依赖当前机器环境。时间和随机生成的业务事实如确需参与协议，必须在准入阶段形成可验证输入，或通过有序命令进入状态。

### 3.2 在真实变化边界设置 ports

以下为接口职责示例，最终名称和签名按实际实现冻结；不要求为每个函数创建 trait。

| port / 边界 | 核心需要的合同 | 单元测试替身可控制什么 |
| --- | --- | --- |
| `CommitAuthority` | 返回已接受、明确拒绝或未知；携带权威提交位置 | 延迟、拒绝、响应丢失、已提交但未响应 |
| `ReadAuthority` | 同一权威视图中的 owner/auth epoch 与目标 revision | quorum 失败、版本竞争、尚未应用 |
| `EngineTransaction` | 暂存、封存、发布、丢弃和固定读快照 | 每阶段错误、重复回调、发布失败 |
| `DurableLogIo` | 区分可读取、刷盘完成与写入失败 | 短写、迟到 flush、失败及回调顺序 |
| `StateStore` | 原子持久化业务变化与 applied 元数据 | 写前失败、结果不明、恢复视图 |
| `ObjectReader` / `ObjectPublisher` | 不可变对象、内容验证、明确读写结果 | 对象缺失、内容错误、PUT 成功但响应丢失 |
| `PinRegistry` / `GcAuthority` | 引用与删除许可具有有序版本 | pin 与删除竞争、旧计划、过期引用 |
| `AdmissionClock` / `IdSource` | 准入时间和身份生成可控 | 到期边界、回拨、种子和 ID 冲突 |
| `TaskScheduler` | 可观察排队、执行、取消与完成事件 | 指定事件顺序、背压、重复任务 |
| `ProcessEnvironment` / `Shutdown` | 显式参数、配置、启动和退出结果 | 无真实服务的初始化失败和清理 |

端口返回领域错误，不把 AWS SDK、HTTP、RocksDB 或 FFI 的所有类型直接暴露到核心。`Timeout` 不能被一个通用 `bool` 压成“未提交”；持久化的 `Pending` 也不能和 `Durable` 共用一个模糊成功值。

依赖在 composition root 装配，通过构造函数或参数传入。尽量不用全局单例、可变环境变量和隐藏服务定位器，避免测试必须改变进程全局状态才能触发一种行为。

### 3.3 入口与适配器仍然必须可测

入口应把参数解析、配置验证、组件构造、运行和退出结果映射分成可直接调用的行为。应用层返回 `Result` 或退出描述，避免在深层函数直接调用进程退出。组件启动和释放接受明确的生命周期依赖，测试可以验证启动中途失败后关闭了哪些资源。

“main 很薄”不构成排除理由。Rust 的 `--test` 会生成测试 harness 入口，替换原 `main` 作为执行入口，原函数仍会编译；不能因测试 binary 运行过就认为生产 `main` 已执行。[S5]

G0 必须验证生产入口本身是否存在于覆盖映射、是否由受控单元 harness 真实调用。仅覆盖其委托函数不能自动覆盖剩余装配代码。若目前的入口结构或采集方式做不到，应重构入口和依赖装配、修复采集；不能删掉报告中的 `main`，也不能将一次真实部署启动混进单元 profile 来补数字。

适配器同样需要单元测试：解析/编码、参数传递、错误转换、资源生命周期、回调注册和顺序控制都由第一方代码负责。替身应放在真正的系统调用或依赖边界，不能把整个适配器 mock 掉后声称适配器已测。

## 4. SOLID 与模块质量的具体检查

| 原则 | SCAP 中的应用 | 审查时发现的问题 |
| --- | --- | --- |
| 单一职责 `SRP` | 提交规则、SQL 执行、存储 I/O、协议转换各自聚合自己的不变量 | 为测试一次 epoch 拒绝，必须先启动 S3、HTTP 和 SQLite |
| 开闭原则 `OCP` | 增加经过同一契约验证的对象存储或调度实现，不改核心接受/拒绝规则 | 每增加一个后端，就在状态机中加入后端名判断 |
| 里氏替换 `LSP` | 任何 `DurableLogIo` 实现都满足相同的完成、错误和顺序合同 | 内存 fake 把 append 当 durable，真实后端却需要 flush |
| 接口隔离 `ISP` | 只读恢复者不必实现删除权限；GC 不必持有 SQL 执行接口 | 一个大接口要求所有测试实现几十个无关方法 |
| 依赖倒置 `DIP` | 领域定义所需能力，外部实现依赖领域合同；核心不依赖具体 SDK | 核心直接创建 S3 client、读取环境或打开真实磁盘 |

高内聚要求同一个安全不变量有一个清晰归属，例如提交权限最终归属 cell 状态机，不能分别在 gateway、worker 和 controller 实现略有不同的“权威”判断。低耦合要求测试一个规则只构造相关输入和依赖，不必准备整个部署。

OCP 不表示永远不能修改核心协议。新增 `AuthFence`、改变提交格式或 GC 安全条件，本来就需要修改穷尽式枚举、ADR 和验证矩阵。不能为了让源码“不变”而引入一个能任意改变共识行为的插件框架。

避免为了覆盖率套用设计模式：只有存在明确外部依赖、替换需求或需要独立验证的责任，才引入相应边界。没有独立变化理由的小型纯函数不需要额外的 service、factory 和 trait。不要仅为了测试把私有状态变成公共 API；模块内单元测试和可观察结果优先。

## 5. 确定性 fixture 与测试替身

### 5.1 替身必须表达合同

优先使用小而明确的 fake 或 scripted port：输入请求，返回事先安排的 completion event，并保留可验证的效果记录。它必须覆盖成功、拒绝、延迟、取消和不确定结果，而不是默认所有调用都成功。

例如日志替身应该区分 `append_received`、`readable`、`flush_completed` 和 `flush_failed`。测试可以证明 SCAP 在 `flush_completed` 之前没有发出 durable acknowledgement，但这个测试不能证明真实磁盘的 `fsync` 有效。

同一端口的 fake 和真实适配器运行共享的行为契约；真实版本在独立的契约/集成测试中执行。共享的是期望合同，不是从被测实现复制的一份判定代码。

### 5.2 控制所有不确定性

- 时钟由测试显式推进；测试 60 秒缓存边界、token 到期与时间回拨不需要真实等待。Raft `apply` 的接口本身不提供准入时钟。
- RNG 和 ID 生成使用固定 seed 或显式序列；失败报告保存 seed、输入与事件顺序。
- 调度用事件队列控制 `proposal`、flush、response、fence、pin 和取消的先后；避免 `sleep` 后猜测后台线程已经运行。
- fixture 只使用合成数据，显式说明初始 `incarnation`、epoch、revision、manifest、pin 和请求状态。
- 持久化 fake 区分易失和已持久状态；模拟 restart 只保留规定层级，不能默认把所有内存都恢复。
- 网络 fake 表达发送、接收、重复、丢弃和响应丢失，不把“超时”固定解释为未执行。
- 发生失败后保留最小输入和事件序列；属性测试可以缩减样例，并将修复对应的反例变成固定回归测试。

### 5.3 断言行为，不只执行代码

每个测试必须断言有意义的结果：新状态、明确错误、允许的效果、禁止发生的效果或恢复后的不变量。对拒绝分支，不能只断言返回一个错误，还应检查没有推进 revision、没有发布页面或删除对象。

只调用函数不检查结果、使用永远为真的断言，或从被测函数计算预期值，不构成合格测试。可以对核心判断进行有针对性的变异检查，例如移除 epoch 比较、将 `<` 改为 `<=`、把 `UNKNOWN` 改为可重试，确认已有测试会失败。

私有 helper 调用次数通常不是稳定合同；而“持久化完成后才回调”“先持久 pin 再允许 GC”是协议规定的效果顺序，可以且应当断言。

## 6. SCAP 安全条件的最低单元测试矩阵

下表是最低行为集合，不代表达到覆盖率后就不再扩展测试。每个新增分支还必须加入对应输入、断言和故障证据。

### 6.1 提交、读与权限

| 编号 | 条件和输入变化 | 单元测试必须断言 | 必须保留的后续验证 |
| --- | --- | --- | --- |
| `U-C01` | 正确/错误 `database_id`、incarnation、placement 和 worker identity | 错误身份不改变状态，也不能命中其他库的原结果 | 跨租户协议测试 |
| `U-C02` | 旧/当前/未来 owner epoch；commit 在 `ClaimOwner` 前后 | 之前合法提交保留；之后旧 writer 拒绝 | Raft 与旧 worker 分区测试 |
| `U-C03` | base revision 相等、落后、超前；前序哈希错误 | 只接受连续提交，不跳号、不覆盖新状态 | 真实日志重放/恢复 |
| `U-C04` | `AuthFence` 在提交前后；旧权限查询已存在的去重结果 | 先检查当前权限；撤销后不提交、不泄露原结果 | cell 权限撤销集成测试 |
| `U-C05` | 60 秒缓存边界、token 到期、时钟回拨；不同 apply 时钟 | 准入遵守时限；确定性 apply 结果不依赖本地墙钟 | 多副本时钟偏移验证 |
| `U-C06` | staged、单副本接收、quorum durable、状态机拒绝/接受 | 接受前不 publish、不 ACK；拒绝条目仍正确推进 Raft 应用位置 | libSQL 可见性、真实 quorum 故障 |
| `U-C07` | 已接受但本地 publish 失败；写 `RETURNING` 尚未提交 | 不声称回滚；不提前输出成功结果；恢复流程保留已提交事务 | 多连接 WAL、worker 崩溃恢复 |
| `U-C08` | 提案前失败、提案后超时、已提交但响应丢失 | 只有可证明情况为未提交；其余 `UNKNOWN`，不自动重放无 ID 写 | gateway/SDK 断连测试 |
| `U-C09` | 同 ID 同摘要、同 ID 不同摘要、不同 incarnation、过期结果 | 窗口内返回原结果或冲突；窗口外不伪称 exactly once | 重启后幂等状态恢复 |
| `U-C10` | Lookup 未找到；迟到 proposal；`ResolveOrCancel` 的不同排序 | 未找到不等于未提交；取消后原 proposal 被 fence | Raft 队列与响应丢失测试 |
| `U-C11` | 取消记录保留、退休边界、配额耗尽 | 必要 fence 不被 TTL/配额清除；拒绝新请求不破坏历史 | snapshot 与跨版本恢复 |
| `U-C12` | ReadIndex 失败、状态机落后、owner/auth 不匹配 | 拒绝新强读；不借本地文件或缓存 TTL 绕过 | 分区与旧 leader 测试 |
| `U-C13` | 屏障后 owner 改变、worker 未到目标 revision、只执行延迟 BEGIN | 固定精确 SQL snapshot；未固定时不返回伪最新数据 | 实际 SQLite snapshot 与锁顺序 |
| `U-C14` | 既有读遇分区/撤销；随后新 RPC 到达 | 既有获准操作按合同结束；新操作重新验证权限/屏障 | 流式响应与会话测试 |

### 6.2 持久化、pin、归档与恢复

| 编号 | 条件和输入变化 | 单元测试必须断言 | 必须保留的后续验证 |
| --- | --- | --- | --- |
| `U-S01` | 短写、刷盘失败、迟到/重复/乱序持久化完成事件 | 不提前发送 `persisted_messages` 或虚报持久推进；失败不会被转成成功 | 真实存储与 `raft-rs` driver / adapter 契约 |
| `U-S02` | 业务状态与 applied 元数据写入失败；未提交日志后缀存在 | 不发布半状态；不把日志末尾等同 committed head | 原子持久化、断电与重启 |
| `U-S03` | 不完整事务、截断数据库、checksum 或格式错误 | 不接受不完整物理事务；正确处理最终数据库大小 | WAL/page 导入与 C FFI 契约 |
| `U-S04` | PUT 超时但对象可能已存在；manifest 未发布/已发布 | 不原地覆盖；未发布对象不替代恢复基线 | 实际 S3 接口与读回校验 |
| `U-S05` | segment 缺口、重复、错序、错误世代和超过 head | 拒绝非连续恢复链，不静默跳段或回退 | 干净环境完整恢复 |
| `U-S06` | pin 在 GC 计划前、计划后、删除授权前建立；旧计划重试 | pin 与删除许可有安全有序关系；旧计划重新校验，不能删仍被保护对象 | 并发 GC 与恢复读取 |
| `U-S07` | 冷库最后一笔写很旧、活跃库持续归档 | 共享日志 GC 覆盖所有库，不能仅取活跃库水位 | 大量冷库 purge 后恢复 |
| `U-S08` | cell snapshot 含未归档 payload，或引用已发布 manifest | 两条合法恢复路径分别成立；缺失 payload/ref 时不 purge | snapshot 安装与日志裁剪崩溃 |
| `U-S09` | DR checkpoint 生成中、完成、取消、保留到期；缺对象/密钥 | 持久 pin 保护完整闭包；半成品和零散新对象不提高恢复点 | S3-only 灾难恢复 |
| `U-S10` | S3 故障下 Suspend 与 fullyCold | cell tail 完整时可 Suspend；归档证明不足时不得卸载持久 tail | worker 重启和 S3 故障演练 |
| `U-S11` | 同库并发唤醒、ready 前新请求、旧启动任务恢复 | 只有一个有效 owner；未恢复到权威状态不 ready | 冷唤醒风暴与真实调度 |
| `U-S12` | 删除重建、旧上传回调、旧 GC 任务、源 seal 后目标失败 | 不复活旧 incarnation；不解除不可逆 seal；不双端激活 | 生命周期与跨 cell 离线迁移 |
| `U-S13` | worker 缓存损坏、存储节点数据损坏、无合法恢复源 | 隔离损坏状态；无证据时失败，不用旧数据冒充当前值 | 校验、修复与区域恢复演练 |
| `U-S14` | 磁盘高水位、绝对预留、compaction 临时空间、日志服务失败 | 用户写背压；fence/撤销/恢复空间不被普通写耗尽 | 真实容量和 I/O 故障测试 |

`U-S06` 不能只验证“删除前查了一次引用”。需要枚举查询与删除之间新增 pin 的竞争，并验证协议实际拥有有序授权、条件检查或等价保护。`U-S09` 也不能只验证 checkpoint JSON 可解析；单元测试验证引用规则，独立恢复验证引用字节真的齐全。

`raft-rs` 接入新增的第一方运行循环、配置校验、传输封装、存储 completion 处理、读请求上下文及恢复装配均纳入上述分母。单元边界注入逻辑 tick、网络、持久化完成和调度事件，验证错误次序被拒绝、`LightReady` 不被遗漏、应用水位不超前；与真实 `RawNode` 的契约测试单独报告。具体场景见 [raft-rs 集成门禁](raft-rs-integration.md)，不能用重新实现一份共识算法或只测试 fake 来替代真实接合验证。

## 7. 单元覆盖率与其他证据分开

| 测试类型 | 主要证明内容 | 是否计入单元覆盖率 |
| --- | --- | --- |
| 单一模块行为测试 | 生产函数在可控输入和端口下的规则、分支与效果 | 是 |
| 同模块属性/决策表测试 | 大量输入仍保持不变量，最小反例可重放 | 是，前提是执行生产实现且依赖满足单元隔离 |
| 仅运行独立参考模型 | 模型自身满足其性质 | 否，不能把模型执行计成生产代码覆盖 |
| 实际依赖的契约测试 | `raft-rs`、libSQL、存储、SDK 与封装的真实约定 | 单独报告 |
| 多模块/多进程集成 | RPC、事务、存储与生命周期协作 | 单独报告 |
| 全系统确定性模拟 | 多 worker/cell 的事件顺序与不变量 | 单独报告，不能因不出进程就改称单元测试 |
| 故障、崩溃、断电与三 AZ 测试 | 持久性、故障切换和恢复范围 | 单独报告 |
| 性能、兼容、升级与灰度 | 运行代价和支持矩阵 | 单独报告 |

测试属于哪一层取决于它的依赖和验证对象，不取决于文件名叫 `unit`，或测试是否刚好放在 `#[cfg(test)]` 中。

mock 可以证明“SCAP 对 flush 成功/失败作出了哪些动作”，不能证明真实文件系统兑现 fsync；fake network 可以枚举重排，不能证明实际 RPC、连接管理和三 AZ 拓扑正确；fake WAL 不能证明 SQLite 没有提前更新公共 WAL 索引。这些需要保留 [validation.md](validation.md) 中的契约、故障和恢复证据。

## 8. Rust 覆盖率工具和 CI 合同

### 8.1 选型事实与版本冻结

Rust 使用 `-C instrument-coverage` 生成 LLVM 覆盖映射与 profile。`cargo-llvm-cov` 封装了相应流程，提供 JSON/HTML 等报告、行/函数阈值和未覆盖数量检查。当前官方文档仍把 branch、MC/DC 等相关支持标注为不稳定能力，具体是否可用需要与选定 Rust/LLVM 工具链一起验证。[S1] [S4] [S6]

本文不指定未经本仓库验证的 Rust、LLVM 或 `cargo-llvm-cov` 版本。实施时必须锁定兼容组合，记录完整版本、target、features、profile、插桩开关和报告 schema。工具升级后重跑采集自测，不能只接受一个比例看起来相同的新报告。

使用与编译器生成的数据兼容的 LLVM 工具；不要把不同编译器、不同源码版本和不同覆盖映射的 profile 随意合并。[S1]

### 8.2 单元采集必须独立

单元覆盖率任务的行为合同：

1. 根据生产源码和 target 清单确定范围，包括 library、binary、CLI、feature 和第一方跨语言代码。
2. 使用干净或明确隔离的单元 profile 目录；记录本次 build identity。
3. 只运行明确登记的单元测试 target。Cargo 默认 `test` 会运行多类测试，不能把默认命令的混合结果直接标成单元覆盖率。[S7]
4. 对 Rust library/binary 单元 target 分别验证。`--lib --bins` 可以表达相应 target 选择，但仍必须核对实际构建和生产入口；不是完整分母证明。
5. 收集所有相关的 instrumented object 和 profile，并验证它们属于本次单元任务。禁止合入集成、故障、手工运行或上次构建的 profile。
6. 导出机器可读完整报告、缺失位置及便于审阅的明细，执行整数门禁和范围对账。
7. 测试失败、profile 合并失败、报告缺字段、缺 target 或 coverage map 不完整时返回失败。不能用“报告成功生成”掩盖测试失败。

`cargo-llvm-cov` 的行/函数阈值及未覆盖计数开关可以作为第一层门禁；仓库校验器还必须检查范围完整性、零分母、精确计数和 profile 来源。不得启用会把测试失败转成成功退出的容错模式。[S6]

集成任务可以保留自己的覆盖率报告帮助发现测试盲点，名称和输出路径必须明显区分。它不参与单元阈值计算，即使它覆盖了单元报告里缺失的最后一行。

### 8.3 分支能力必须经过已知答案校验

在启用分支门禁之前，覆盖率工具测试应包含小型、结果已知的 fixture：

- 一个未执行分支必须产生非零未覆盖计数。
- 一个同一行包含多个判断的表达式，不能仅因该行执行过就被误报为全部分支覆盖。
- 短路表达式、`match`、错误传播和泛型/宏等实际使用结构必须检查映射范围。
- 仅达到行/函数 100% 的 fixture 不能通过“分支 100%”检查。
- 未开启分支插桩或工具未输出分支数据时，报告必须为未测量/失败，而不是零分母通过。

如果冻结的工具链无法准确报告某些生产分支，必须登记具体缺口并修复工具或结构；Rust 分支门禁保持失败或阻断。行/函数任务可以继续产出有效报告用于定位问题，但不能代替整体通过，更不能将分支阈值自动降低。真实报告未达到 100% 时，同样阻断。

条件覆盖与 MC/DC 需要另外的能力检查，不能因为存在 `branches` 字段就自动声称这些指标也为 100%。

### 8.4 采集器和门禁自身也要被测试

覆盖率校验器至少测试：缺失文件、意外文件、负数/不合法计数、`covered > total`、四舍五入陷阱、零分母、缺少函数数据、排除规则意外匹配、旧 profile 混入、测试失败和版本不兼容。

对每种受支持配置保存 source/target/features 清单及原始整数。每个配置分别满足合同，再提供汇总；不能用某个 feature 的执行记录掩盖另一个正式发布配置的缺口。合并多个**单元**运行的覆盖率时，也必须保留各自来源和兼容性证据。

### 8.5 PR 报告的最低字段

```text
commit_sha
scope_manifest_digest
production_target_and_feature_matrix
toolchain_and_coverage_tool_versions
test_kind = unit
unit_test_result
line_total / line_covered / line_uncovered
function_total / function_covered / function_uncovered
branch_measurement_status
branch_total / branch_covered / branch_uncovered, when supported
condition_and_mcdc_measurement_status
missing_source_or_target_list
exclusion_manifest_diff
raw_report_and_profile_provenance
```

汇总中的“通过”必须可以追溯到原始计数和受测源码。没有 production code、没有运行、工具不支持与测试失败是不同状态，不能统一显示成绿色 100%。

## 9. 可实施的研发工作流

### 9.1 开始一个功能

1. 写清输入、结果、必须保持的不变量、拒绝原因和外部副作用；关联对应协议条款及 `U-*` 测试项。
2. 判断哪些规则可以做成纯转换，哪些动作需要已有 port；只有确有新边界时增加接口。
3. 先写一个能暴露缺失行为的失败单元测试，以及关键拒绝/错误用例。
4. 实现最小生产路径，使用与生产相同的函数和适配逻辑；替换依赖，不替换被测行为。
5. 补齐决策表、边界输入、错误、资源释放和禁止效果的断言。
6. 运行本模块测试，检查覆盖率缺口；缺口暴露耦合时先重构，再补测试。
7. 运行全量单元覆盖率与范围对账，要求行/函数精确 100%；Rust 的真实分支报告也必须为 100%，缺少可靠测量时阻断。
8. 对改变的外部边界运行对应契约/集成测试；对提交、持久化、pin/GC、恢复和权限语义运行相应故障与模型验证。
9. 重构后再次运行相同门禁，提交范围、计数、行为证据和剩余工具缺口。

新增实现从第一笔代码起遵守 100% 门禁，不建立“先合入未覆盖代码以后补齐”的惯例。纯文档变更仍运行仓库文档检查；不会借一个未执行的数据库测试报告声称实现通过。

### 9.2 处理生产缺陷

先把问题缩减为可复现的输入、状态和事件顺序，加入会失败的单元回归测试；如果问题只在实际 I/O、WAL 或并发环境暴露，同时保存相应集成/故障回归。修复后覆盖率保持 100%，原始故障也必须重现为通过。

不能只通过改变 mock 的默认返回值消除失败，除非问题确实是替身违反了端口合同，并有真实实现的证据说明。也不能为了 CI 稳定把失败用例标记 ignored，却继续把该行为报告为已验证。

### 9.3 改变架构或支持范围

改变模块边界、支持的平台/feature、生产语言、引擎补丁或源码归属时，同时更新覆盖范围清单和测试矩阵。取消一个真实产品能力是产品/架构决策，需要 ADR 和相关合同变更，不能作为提高比例的测试技巧。

覆盖率要求本身不能由一次 PR 中的排除注释降低。遇到不可测路径，给出耦合来源、重构方案和采集修复；未解决前不能宣布目标完成。

## 10. 代码审查规范

审查者应逐项确认：

- 第一方生产文件、入口、适配器、错误路径和 feature 是否全部计入，排除清单有没有扩张。
- 单元 profile 是否只来自单元测试，所有计数是否有正确分母，是否存在遗漏 target 或被替换的生产实现。
- 新模块是否有单一责任；为了一个局部测试是否被迫构造大量不相关依赖。
- trait/port 是否对应真实变化边界，fake 与真实实现是否接受同一合同，是否出现万能接口或无价值的接口层。
- 测试是否断言外部可观察行为和禁止效果，是否只是调用代码以提高数字。
- 安全条件是否逐项独立翻转过；超时、旧 epoch、权限撤销、精确快照、取消和 pin/GC 边界是否有反例。
- 新错误是否有明确处理，尤其不能把 unknown、持久化失败或缺少恢复源包装成普通成功。
- 入口及异步任务能否在受控依赖下结束、取消和清理，测试是否使用真实等待掩盖竞态。
- 对外部语义的变更是否保留契约、真实持久化/网络/WAL、属性和模型验证。
- PR 是否分别陈述已执行结果、尚未测量的维度和工具限制，而没有把文档目标写成完成事实。

通过标准是：代码的责任与依赖边界清楚，第一方生产代码拥有真实且独立的 100% 单元行/函数覆盖证据，Rust 真实分支计数同样达到 100%，条件/MC/DC 等其他指标按实际能力准确披露，并完成本次变更所需的其他正确性门禁。工具失败、分支缺失或任何要求的计数未达标均不能变成绿色通过。

## 11. 官方来源

下列来源说明工具和语言的现有行为；SCAP 的阈值、范围、模块规范和审查要求是本仓库的工程合同。检索日期：2026-10-28。实施时以冻结版本的实际行为和已知答案测试复核，不直接以本文选择工具版本。

- [S1] Rust 官方：插桩覆盖率、coverage map、profile 和 LLVM 工具兼容性。[Instrumentation-based Code Coverage](https://doc.rust-lang.org/rustc/instrument-coverage.html)
- [S2] LLVM/Clang 官方：行、函数、region、分支、实例和 MC/DC 指标的区别。[Interpreting reports](https://clang.llvm.org/docs/SourceBasedCodeCoverage.html#interpreting-reports)
- [S3] Rust 官方：`coverage-options` 的 `block`、`branch` 与 `condition` 层级。[coverage-options](https://doc.rust-lang.org/unstable-book/compiler-flags/coverage-options.html)
- [S4] LLVM 官方：覆盖数据的展示与 JSON 导出。[llvm-cov](https://llvm.org/docs/CommandGuide/llvm-cov.html)
- [S5] Rust 官方：`--test`、libtest 和生成的测试入口。[Tests](https://doc.rust-lang.org/rustc/tests/index.html)
- [S6] cargo-llvm-cov 官方项目：功能、target 选择、阈值、未覆盖计数及已知限制。[cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov)
- [S7] Cargo 官方：unit、integration、documentation tests 及 target 选择。[cargo test](https://doc.rust-lang.org/cargo/commands/cargo-test.html)

[S1]: https://doc.rust-lang.org/rustc/instrument-coverage.html
[S2]: https://clang.llvm.org/docs/SourceBasedCodeCoverage.html#interpreting-reports
[S3]: https://doc.rust-lang.org/unstable-book/compiler-flags/coverage-options.html
[S4]: https://llvm.org/docs/CommandGuide/llvm-cov.html
[S5]: https://doc.rust-lang.org/rustc/tests/index.html
[S6]: https://github.com/taiki-e/cargo-llvm-cov
[S7]: https://doc.rust-lang.org/cargo/commands/cargo-test.html

## 12. 正式服务与 TypeScript SDK 的当前门禁（2026-11-02）

Rust fresh unit-only 采集覆盖全部 workspace 的 lib 与 bin，固定 `--test-threads=1` 隔离进程级 POSIX 信号 fixture；生产 Raft/HTTP 并发由独立真实合同验证。全部 45 个生产文件由 `contracts/coverage-policy.json` 与实际目录核对，不因为入口、异步回调、native 代理、CLI 或无条件分支文件而遗漏分母。

SDK 先执行 `npm --prefix sdk/node test`，固定 c8 的 `--all` 与四维 100% 门禁，再执行 `python3 scripts/check_sdk_coverage.py sdk/node/coverage/coverage-final.json`。后者枚举 `sdk/node/src` 的全部生产源、逐个原始 statement/function/branch hit 和 map identity；新文件未进入报告、空分母、未执行分支或忽略标记均失败。SDK 与服务端到端测试另有入口，不给 unit coverage 填缺。

Clock、System/Assembly、Inbox、对象存储和 CellPort 分别是实际可替换边界；单元注入失败，正式委托仍有原生调用覆盖。泛型实例的覆盖表现不能靠目录排除修饰；同一个语义函数必须被完整验证，必要时收敛成单一窄接口。行、函数、region、branch 的 100% 不代表 MC/DC 或所有线程交错已被证明；原始 SQL/网络/S3 故障及长期容量测量仍须独立验收。
