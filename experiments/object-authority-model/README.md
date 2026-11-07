# 对象权威 N0：协议模型与独立历史判定

这里是 [N0 协议规格](../../docs/engineering/object-authority-n0.md)的可执行研究模型。它建模可信候选构造、按 ETag 的单 HEAD 发布及故障观察，不连接 AWS，不执行 SQLite，不构成可部署后端。正式产品不能依赖本目录；将来复用任何产品逻辑必须进入生产源码和原精确覆盖率门禁。

## 模型边界

- 单个不可复用 authority scope、有限参与者、合成整数业务值和有界结果 token；业务变化是抽象状态，不是 SQL/WAL。
- principal 和 fingerprint 是可信准入交给模型的身份/业务符号。模型检查绑定、冲突和当前授权，不实现真实凭据验证或 SQL/参数规范化；这些入口不能由不可信客户端自报，在 N1/N2 另行实现和测试。
- HEAD GET 与条件写是显式假设。存储只比较 ETag；业务权限、owner、请求世代及前序数据检查属于可信协议。
- stage、逐个依赖上传、闭包验证、CAS 发出/执行/响应、本地发布与业务响应分开，可以观察响应丢失及全部本地状态丢失。
- 默认探索窗口为 2，保留最近 2 个完整 closed 窗口和 current；对象总数 96、计数器 255、未决尝试 8 的上限用于有限实验，不是线上容量。
- Close 仅对满窗口由可信协调器提出；旧 epoch 永久不再接受。结果查不到时严格区分 unknown、closed、retired 和 cancelled。
- 没有物理 GC，旧对象和未发布残留仍占预算。计数器/对象/请求预算不足就背压，不用静默淘汰或隐式成功解除限额。

## 运行

使用 Python 3.11 或更新版本，仅依赖标准库：

```sh
python3 -m unittest discover -s experiments/object-authority-model -p 'test_*.py' -v

python3 experiments/object-authority-model/explore.py \
  --output /absolute/new-object-model-evidence
```

每次使用新目录，不能覆盖原尝试。原始历史和 summary 应在进程退出后再复制或打包；失败历史保留。具体成功场景、状态/转换数、负对照数及源码 SHA 以该次输出为准，不把模板中的目标算作已执行。

2026-11-05 的本地执行通过 89 项单元、664 条合法历史（640 预定竞态与 24 定向场景）和 30 条预期拒绝的人工反例，见[执行证据](../../docs/evidence/object-n0-local-2026-11-05.json)及[枚举范围说明](../../docs/engineering/object-authority-n0.md)。这些结果不关闭整个 N0，也不验证真实 S3/SQLite。

## 独立判定

`model.py` 是被测离散协议，`oracle.py` 只读取原始事件，不导入被测模型或调用候选构造函数。`explore.py` 枚举有限交错并把轨迹交给独立判定器。`test_oracle.py` 构造明确错误的轨迹，验证判定器确实拒绝提前成功、旧写者覆盖、结果分离、缺依赖、错误取消、旧差分换 ETag、提前退休等错误。

必须报告实际枚举的范围与完整分母。多个预定场景和有限排列通过，不等于遍历了所有状态或证明了任意执行。模型中的 object durability、令牌比较和可信调用者都是显式假设，不能用模型通过代替真实 S3、SQL gate、多进程和生产故障实验。

机器可读语义与 profile 见 [object-authority-model.json](../../contracts/object-authority-model.json)。正式字节格式、真实预算、调度活性、目录、多库、pin/GC/PITR 和成本仍按 N0–N4 继续验证；本目录不继承旧 Raft 单元或故障结果作为新协议证据。

## 名称目录：独立的有界研究模型

`named_catalogue_model.py` 与 `named_catalogue_oracle.py` 研究[名称目录协议](../../docs/architecture/name-catalogue-plan.md)的多 key 顺序；不把目录产品代码移入实验目录。正式 Rust 目录尚需实现，并通过单独的逐文件精确单元覆盖、原生和真实 S3 门禁。

这个模型包含不可变 CreateDescriptor/ControlDescriptor、Reserved/Bound/Aborting/Tombstone、Provisioning/Ready/Deleted HEAD、永久 AbortProof，以及正常删除和名称重用。物理 HEAD key 只使用 deployment/tenant/database，故可强制测试不同 incarnation/generation 或不同来源占用同一 key。Scope 是有限的符号输入，不实现生产身份派生函数；JSON 和 key 字符串也不是生产 wire/对象格式。

控制意图先以 caller/kind/operation 永久准入，随后才竞争名称或 HEAD。目标 CAS 412 或 UNKNOWN 后，同 operation 不能换 expected revisions、nonce 或目标。取消仍只由 Reserved → Aborting 接受；ControlDescriptor 或 AbortProof 已持久都不等于名字已经释放。模型另有最小 HEAD admin 授权变更，验证非 creator 的当前 ADMIN 可以正常删除，而不能借 ADMIN 取消别人的创建；这不验证完整身份认证、ACL 或撤权竞态。

### 执行与原始证据

仅使用 Python 3.11+ 标准库：

```sh
python3 -m unittest discover -s experiments/object-authority-model -p 'test_named_catalogue*.py' -v

python3 experiments/object-authority-model/named_catalogue_model.py \
  --output /absolute/new-catalogue-model-evidence

python3 experiments/object-authority-model/named_catalogue_oracle.py \
  /absolute/new-catalogue-model-evidence/positive-race_double_create_00_00.json
```

输出目录必须是新的绝对路径，已存在时拒绝，不能覆盖失败尝试。CLI 保存每份合法/反例历史、独立判定结果、失败位置、源码 SHA-256、准确枚举范围、实际状态/边/命令/事件计数及 `summary.json`。反例历史交给 oracle 单独执行时应退出非零。总结果仅在所有正向历史被接受且每个反例以指定不变量被拒绝时通过。

### 精确探索范围

每类竞态先构造两个候选，再枚举两条 `invoke → effect → receive` 链的全部 20 个合法交错，每个交错分别执行两端正常/丢响应的四种组合，共 **10 × 20 × 4 = 800 条竞态历史**：

| 竞态 | 判定内容 |
| --- | --- |
| 同 create operation 的两次 descriptor 条件创建 | 至多一个固定意图持久，另一进程只按同意图恢复 |
| 不同创建意图竞争同名 | 一个 reservation 获胜，失败者不自动换 Scope |
| 同意图两个 Provisioning 条件创建 | 唯一物理 HEAD，恢复不重新初始化 |
| Reserved 上 bind 与 abort | 同一个 ETag 排序，Bound 与 Aborting 互斥 |
| 迟到 provision 与 absent-HEAD 取消 tombstone | 两种 If-None-Match 胜出顺序都阻止复活 |
| 两个同意图取消接受 | 唯一名称转换，重复调用只能恢复原取消 |
| 两个同意图 Ready 完成 | 不重复完成或重设创建字段 |
| 两个不同正常删除意图 | 唯一 HEAD 删除证明，失败者不能冒认 |
| 两个相同控制 descriptor 准入 | 同控制意图可查证恢复 |
| 同 control operation 以不同 nonce 竞争准入 | 一个完整控制意图胜出，失败者不能改条件继续 |

另有定向历史覆盖各 CreateDescriptor/ControlDescriptor/名称/HEAD/AbortProof 发布边界的发送前退出、效果前后退出、丢响应、全部计算状态丢失、ForeignOccupied 后重用名称、旧请求迟到、同 operation 在首个目标 CAS 冲突后的变参、不同 caller 的 ADMIN 权限、资源耗尽和未完成前缀。实际定向历史数量以该次 summary 为准，不把目标清单当作执行证据。

默认硬预算为 32 个持久记录、revision/fence 最大 31、64 个尝试、8 个在途请求、每份历史 1024 个事件。本批最多两个候选并发、一个名称槽、三个候选身份（包括旧身份、新身份和外来占用者）；实际峰值另外记录在 summary。`observed_scheduler_states` 按场景和完整调度快照区分，`observed_storage_states` 仅计算实际看到的持久存储快照；它们不是任意状态空间的分母。

**这不是所有有界程序执行的穷尽搜索。**每次 prepare 中的多次 GET 在这批调度器里连续执行，发布后的在途请求可以任意按上述交错迟到；没有枚举 prepare 内每两个 GET 间的全部穿插。强读/权限的生产时序、完整 SQL 恢复闭包、真实 S3 合同、无限活性、LIST/全目录 inventory、GC/PITR 都不由本结果认证。

### 判定器的独立性与负对照

oracle 不导入模型、调度器或共享转换函数。它从原始 exact GET、sealed candidate、invoke/effect/receive 重建存储，检查原 ETag 条件、不可变身份、每次名称/HEAD 转换的前提和字段变化，再独立核对实际观察到的业务结果。收到 UNKNOWN 不清除已持久事实；已发出的请求不会因进程退出自动消失。每次 GET 绑定实际计算 generation；新进程不能重新认领旧进程尚未使用的 GET 来构造候选或报告 Ready。独立审查曾构造出这两类跨 crash 旧读取反例，修复后的反例门禁保留它们；旧运行记录不被改写为修后证据。

负对照至少包括：固定 Scope 被替换、错误来源、跳过 Provisioning、旧候选换 ETag、未 invoke 就产生效果、丢响应被误判失败、缺永久 HEAD 屏障、删除 AbortProof、证明已写但名字未释放却报告 Aborted、旧取消冒认、修改外来 HEAD、同 operation 在 412 后换条件、缺 ControlDescriptor、无当前 ADMIN 删除、名称重用后偷换控制目标，以及未使用的旧 GET 跨计算丢失被新进程冒用。对若干变体，历史中的 GET/ETag 仍保持自洽，从而要求 oracle 通过协议不变量而不是偶然缺字段拒绝。

合法前缀也能通过安全审计；通过并不表示所有操作终结或达到活性目标。例如 Aborting + 已持久 AbortProof + 名称尚未释放是合法前缀，审计器必须同时确认此时没有观察到 Aborted ACK。单元自测也检查每个前缀、oracle 的导入独立性和模型硬预算。

另外两个边界必须保留：receive 发生在对象服务 effect 之后；本批没有直接枚举客户端先收到 timeout/UNKNOWN、原请求随后才 effect 的全部时序，也没有拆分已生成的业务回复跨 crash 在网络中排队的场景。判定器完整检查本模型的发布前提、就绪和肯定终态回执，但 rejected 的每个错误理由及所有非终态 progress 只做部分约束；不能据此声称逐个拒绝代码、完整可用性分类或活性已经独立证明。
