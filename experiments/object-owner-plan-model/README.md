# Accepted owner plan 的独立有限模型

这是 [V2 方案](../../docs/architecture/accepted-owner-plan.md)的可复跑研究门禁。
它回答 owner 计划的持久接受、恢复、取消、历史覆盖和旧入口 fencing 是否遵守声明的
有限状态合同；**不提供生产 owner API，也不启动 controller、SQLite、HTTP 或 S3**。

固定范围、分母与资源界限见 [PLAN.md](PLAN.md)。当前注册 985 条正向原始轨迹、
45 个明确拒绝边界的语义反例，以及 3 个判定器正控。是否实际通过以对应冻结源码和
证据 `report.json`、`controls.json` 为准；此 README 中的数量不是运行结果。

## 文件职责

| 文件 | 职责 |
| --- | --- |
| `model.py` | 单 Scope、有限计数的候选协议；原条件请求与后端在途队列独立 |
| `cases.py` | 固定工作负载及两条宏步骤链的完整线性扩展；断言每个目标场景确实发生 |
| `oracle.py` | 只消费原始事件，独立重建对象服务、同次 GET body/ETag、调用与进程知识；不导入以上文件 |
| `counterexamples.py` | 45 个定向错误历史；期望规则名称固定，错误位置变化即失败 |
| `explore.py` | 有界落盘、源码/工具身份、全部审计、正负控与源后复核 |
| `test_model.py` | 协议边界、负控、枚举分母、独立可执行 oracle 和证据保存自测 |

HEAD8 marker 与 descriptor/proof 使用独立的有限 JSON 投影。模型为方便检查把 phase
owner 写成 `{instance,epoch}`，把 reference 拆成 identity/hash；生产 API 的
`owner_instance/owner_epoch`、`target_worker`、decimal string 与实际 Rust wire codec
必须另行严格实现和验证。这里的 canonical JSON/hash 和模型 ETag 不认证生产编码。
真实 payload 类型解析及 SQLite 的 native publication 合同沿用已单独验证的产品假设；
模型只用完整的有限 data/result 依赖对象表示该前提。

## 已接受与未接受的取消

descriptor 的存在不授予 owner 权限。Claim 与未接受 Abort 的第一步都竞争 descriptor
捕获的原 HEAD body/hash/ETag。Abort 先写 Cancelling，再以新步骤写 Aborted；不能直接
把独立取消对象当成在途 claim 的撤销。退出或 UNKNOWN 不删除已经 invoke 的请求。

每个具体恢复 candidate 固定自己的 Snapshot、ETag、body 和 deadline；ACL/quota
竞争使旧 candidate 失效。新调用可以从仍 Claimed 的最新 HEAD 再验证并恢复。该能力
来自 HEAD 上的 accepted phase，旧 `OwnerClient.restoreIntent` 的派发能力不改变。

第一次采用 owner plan 后，legacy owner 操作永久关禁。模型明确保留“在 pending 时
才准备、终态之后才到达、revision 恰好相同”的旧 activation，证明单靠 R+2 并不足够。

## 原 prepare 回复丢失

保存的输入包含完整身份、原 expected R/S、target/mode 和四 nonce，不需要预知服务器
计算的 descriptor hash。prepare 先查固定 key：已有时在 current ADMIN 检查后返回
输入一致的原 record；Missing 才可构造。inspect-by-operation 能找回实际 descriptor，
恢复端逐字段比较原保存输入后才得到 hash-required ref。当前 HEAD 改变不会重建原 base。

模型分别覆盖原计划已 Claimed 后继续恢复、metadata 已推进导致原 admission 被 fence，
以及 Deleted 后仅查询历史。它保留原调用 UNKNOWN，不补造过去收到过 ACK 的事实。

## 历史 proof 与资源

proof 只包含 marker 的原稳定字段。后来的 SQL、ACL、quota 和 named delete 可以改变
当前 HEAD、owner epoch，却不改变旧 proof 的字节。新 Claim 与 Cancelling 两个覆盖入口
都必须 exact 回读旧 proof。双 HEAD 的历史查询遇 ACL/marker 变化返回观察不稳定。
历史 Active 不意味着当前 active，也不意味着新进程已有可执行 native Session。

每次元数据调用最多 8 次 GET/条件 PUT，并持有原总期限。descriptor 16KiB、proof 8KiB、
marker 4KiB、HEAD 256KiB；它们只是待实现合同在模型中的边界。控制历史永久累积，
payload GC 不回收它们。模型没有声称无限历史、自动故障检测或生产吞吐/RTO。

## 运行与解释

```sh
python -m unittest discover -s experiments/object-owner-plan-model -p 'test_*.py' -v
python experiments/object-owner-plan-model/explore.py --output /new/evidence/path
python experiments/object-owner-plan-model/oracle.py /new/evidence/path/positive/proof-0-claim.json
```

开发时可以显式 `--diagnostic`，但这不能代替提交后的源身份复验。输出目录必须不存在；
任何失败都保留已写原轨迹、具体错误和控制副本。控制器 summary 不参与 authority 判断。
正向矩阵中的调度编号还会独立与原事件的 admit/recover/invoke/effect/response 顺序比对，
从而不能把一条合法轨迹改名后冒充另一种 interleaving。

通过只能证明已列的有限投影。在途 GET 的所有网络子步骤、无界客户端/主机数、真实
工作负载性能、AWS Standard 和生产 controller 均不在此证据内。产品需要另行冻结
HEAD8 core/service/SDK、全部构造入口、精确单位覆盖以及实际网络/进程故障验收。
