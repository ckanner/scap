# Controller 有限策略模型计划：controller-policy-1

## 1. 范围和先决条件

本计划新增一个独立、有界的 controller 策略投影。它组合
`../object-owner-plan-model/model.py` 的原始 HEAD8 权威事件；独立 checker
只加载 `../object-owner-plan-model/oracle.py`，不导入本模型、cases、生产 JS
或其报告。所有用于决策的 HEAD body/ETag、descriptor 和 caller outcome
都要绑定原 ledger 中同一个实际调用/GET。报告中的 summary 不参与判断。

这不是生产 controller 执行，也不是 native SQLite、HTTP/S3、AWS、吞吐或故障
SLO 验收。模式假设的 transport/deadline 是明确的环境输入，不声称模拟了真实 TLS、
DNS、429、代理或网关行为。真实 TLS 分类及精确 JS 覆盖另见
`../../docs/evidence/controller-tls-node22-local-2026-11-11.json`。

旧推进记录中的 **354 正向 / 48 负控 / 3 正控** 没有对应的可复核、冻结模型源码和
枚举分解。本计划不补写那些历史结果，不以本矩阵计数替代旧门禁。若合并需要原门禁，
其状态继续为未完成，必须明确批准新合同或恢复原冻结输入再运行。

## 2. 固定正向矩阵

每次完整运行必须恰好 **402 条**，每条是独立初始 World，必须保存完整双 ledger；
不能用多次 audit、改变摘要、反复跑同一历史、提前失败或没有达到场景的空历史凑数。

| 家族 | 分解 | 条数 |
| --- | --- | ---: |
| Prepare 交错 | 相同 policy、同 creator 异 policy、异 creator 三组；每组 60 种两条 `admit→invoke→effect→respond` 且两次 admission 均早于任何 effect 的完整线性扩展；每种无丢失/首个实际成功 PUT 回复丢失 | 360 |
| 基本及组合 | healthy、同 owner activate、取消后 activate、重启后 Missing 与迟到 prepare PUT、失败间隔/跨度、rank 耗尽、原 SQL UNKNOWN | 7 |
| Pending 重启 | Claimed、Cancelling | 2 |
| 旧 Claim | 作用先于取消、取消后旧条件作用 | 2 |
| Foreign | 同 creator 手工 nonces、异 creator；各 pending/terminal | 4 |
| 非死亡失败 | INVALID、DENIED、BUSY、LIMIT、TARGET、LIFECYCLE、CORRUPT | 7 |
| 窗口重置 | technical S、健康、非法回应、丢本地状态重启 | 4 |
| 原预算 | 第九调用、原截止时间、第二 mutation 被拒 | 3 |
| 生命周期 | copy、sweep、deleted、terminal | 4 |
| 计数边界 | revision、serial 保留两步；epoch 用尽 | 3 |
| 明确开关 | takeover、activate、cancel 关闭 | 3 |
| 权威变化 | status 后 inspect 读到新 HEAD、真实 ACL 撤回 ADMIN、原 target 被新 incarnation 替代 | 3 |
| 总计 | 360 + 42 | **402** |

两条四步链共有 70 种线性扩展，但其中 10 种会让一方在另一方写入之后才 admission，
直接读到 existing descriptor；其 invoke/effect/respond 宏步退化为 no-op，可能重复
同一原始历史。开发诊断曾跑 462 个调度。本冻结候选排除这 10 种，要求每条 race 真正
有两次 immutable PUT，原始双 ledger（忽略 name/summary）必须逐条不同，另有具名
迟到 PUT/Missing 案例。不能把开发诊断计数当作正式冻结运行结果。

Prepare 每条还必须具备这些见证：两个 controller 先读同一 S、选择不同候选；丢回复
分支确有原 caller UNKNOWN；两进程都重启且没有保存原输入；从实际 descriptor 恢复；
所有同 policy 合法候选都指向 first-wins 的实际 target；同 creator 异 policy 一方停止；
异 creator 两个可写 descriptor 的原 HEAD CAS 竞争最多一胜；第二次重启后按原普通
预算先观察 Claimed，再于下一 tick 按恢复预算完成；所有旧 UNKNOWN 保持原知识。
覆盖的是本表的宏观切点，不宣称枚举了原子内存操作、任意 worker 数或无限历史。

## 3. 独立 checker 和故障控制

Core checker先独立验证全部 GET/PUT、原 ETag、不可变对象、native closure、caller
知识和历史状态。Controller checker再从每个观察的 core cut 重建策略状态，复算完整
policy 摘要、原 scope/身份、失败窗口、first-wins、rank、恢复预算和请求/变更分母。
不能用 producer 的“健康”“成功”“已完成”等摘要取代原权威事件或推导。

固定 **40 项负控** 的名称与唯一预期规则在 `controls.py`，分别检查完整 policy/Scope、
固定上限、原期限/恢复预算、实际第九 RPC/第二 mutation、调用分母、业务 SQL、
principal、exact ETag、错误 worker、非死亡错误、独立新确认、失败窗口、nonce、
target、计数保留、原 revision、实际 first-winner、成熟窗口、健康 owner、rank、
目标健康、最后一次独立 inspect、已验证 prepare、foreign marker、原 UNKNOWN、
假 ACK、假 native session、实际错误 target guard、遗漏真实调用、变化后的 HEAD、
假 response/descriptor、旧 tick HEAD、早于失败的确认、同一次 inspect 重复计数、
用伪造 report reason 掩盖实际错误并保留旧失败窗口。
任何异常、语法错误或早于预期的规则拒绝都不算目标规则通过。三项正控分别为原历史、
伪造 summary 仍得到同一结果、负控后原字节及结果未变。不用它们凑旧 48。

## 4. 显式有限边界

1 Scope、2 controller 身份及有限重启 incarnation、3 固定且不复用的配置 worker/rank；
一个替换场景另建未配置的 worker 4，必须被原 target guard 拒绝。
R/S/E 使用最大值 40 的有界计数投影，u64 原始边界另由 HEAD8/生产单位证明。
普通 tick 30000、恢复 tick 1800000 个单调模型时间单位；每 tick 最多 8 个调用、
1 次 mutation；失败 3 次、间隔至少 1000、跨度至少 5000。
Scope、worker/rank、全部模式和预算均进入完整固定 policy 摘要。模型摘要域明确为
`SCAPOWNERPOLICYMODEL1`，它不认证生产 SDK 的 canonical byte 编码。

正常外部 operator 的 setup/SQL/terminal proof preservation 会在原 core ledger
中单独具名；不会算成 controller 的 RPC。Core 投影把 proof preservation 暴露为
独立动作，因此“取消后 activate”需显式保存旧终态 proof；这不证明生产 controller
是否自行完成该对象写入。不能将此抽象扩大成自动化运行时验收。

生产 fleet 公平性、全局并发数、SIGINT/owned handle 清理、真实后台工作终止、临时文件、
wire 编解码与真实共享故障不在本有限模型中。未发生 SQL 重放只能证明模型这条边界，
不能替代原业务端的实际结果查询/取消验收。

## 5. 执行和证据

顺序：有意义的模型/独立 checker 单位 → 固定 explore → 保存全部原始 trace 后重新从
磁盘独立 audit → 具名负控/三正控。每次用全新目录，保留原失败，不覆盖为通过。
三个顺序执行的单 Python 进程共享固定 180 秒总期限、512 MiB 原始证据；
不延长失败运行的期限。
正式运行需要所有声明源码已提交，源清单前后完全一致，记录 Python 路径/版本/二进制
SHA256、仓库 HEAD、每个输入文件 SHA256、全部 trace 数和分母。
开发诊断允许 dirty，但必须标注 diagnostic，不将它称为冻结候选正式通过。
