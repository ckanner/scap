# Accepted owner plan V2：固定有限模型计划

本计划绑定 [accepted-owner-plan.md](../../docs/architecture/accepted-owner-plan.md)，
包含原 prepare ACK 丢失后的固定输入找回合同。模型不是生产 core、SDK 或 controller；
其运行不能替代 HEAD8 的真实 SQLite、HTTP、S3、崩溃和覆盖门禁。

## 固定分母与界限

| 家族 | 原始输入/调度 | 正向轨迹 |
| --- | --- | ---: |
| Claim / unaccepted Cancel | 两条 admit→invoke→effect→response 链的全部 70 个线性扩展，各交叉两种响应模式 | 140 |
| 两个 Resume | 两条 admit→recover→invoke→effect→response 链的全部 252 个线性扩展，各两种响应模式 | 504 |
| Resume / Abort | 长度 5 与 4 的链的全部 126 个线性扩展，各两种响应模式 | 252 |
| 独立固定家族 | first-wins、4 类 crash、Cancelling 重启、恢复中 ACL/quota、R/S/epoch、target 更替、legacy、proof、storage/入口、期限/I/O、SQL UNKNOWN | 76 |
| prepare ACK 丢失找回 | effect 在 crash 前/后 × HEAD 未变/已 Claimed/metadata 推进/Deleted | 8 |
| 损坏控制元数据 | current/past descriptor 缺失、superseded proof counter 矛盾及跨读变化 | 5 |
| **合计** | 全部名称在运行前写入 inventory.json | **985** |

响应模式固定为两条竞争请求的回复均正常、或它们实际发生的写回复均丢失。未发生的
候选不会被伪造为 invoke/effect；oracle 从原始 admission/recovery/PUT 历史独立核对
每个调度编号对应的宏步骤顺序。它不会通过读取模型的状态或构造器得出答案。

45 个命名语义负控全部在 `counterexamples.py` 注册，必须在预先指定的 rule 拒绝；
换成 generic malformed/EOF 等其他失败不能计为通过。每个失败原始前缀独立留存。
3 个正控依次为指定原 proof 历史、伪造 controller summary 后同一历史、全部负控后
再次审计且核对未改变的原历史。它们不是三轮生产数据库测量。

一次完整探索最多 120 秒、256 MiB 证据、一个 Python 进程。计数上限为 5、15、20
的有限投影；Scope 固定一个、每个竞争矩阵同时两个请求，最多三个顺序 owner 计划。
进程 incarnation 的 worker ID 不复用是明示环境假设；这不是进程身份认证模型。
失败原始文件保留，已有输出目录与已有文件都不覆盖。没有自动扩大期限或重跑策略。

## authority 与知识边界

每个 HTTP dispatch、server admission、exact GET 的 invoke/effect/response、条件 PUT 的
invoke/effect/response、caller observation 和进程退出分别留事件。GET 三个事件采用
一个调度宏步骤；条件写三个切点可分别调度。恢复有单独切点；历史读取可在 proof
前后暂停。模型不声称遍历 GET 内每一条网络指令，也不包含无限进程/任意 SQL。

已经 invoke 的 PUT 永远保留在后端队列。client timeout、服务退出、丢回复、原请求
期限过去都不撤销它；其 effect 可以后来发生。每个具体 candidate 的 body、原 ETag、
deadline 固定。新 resume 是同一 accepted Claimed 的新步骤，重新读 current ACL、
完整数据/结果闭包和最后相同 HEAD barrier，不能为旧 candidate 换 ETag。

新 prepare 保存 creator/op、原 expected R/S、mode/target、4 个不同 nonce。先 exact
读取固定 descriptor，再 fresh HEAD/current ADMIN。已有且原输入一致时返回原 bytes；
仅 Missing 才可以从匹配原 R/S 的 fresh HEAD 构造新 descriptor。hash-required ref
必须来自原 ACK 或 inspect-by-operation 返回的实际 record，并逐字段匹配保存输入。

首次 Claim/Cancelling 原子升级 HEAD8。Cancelling 保持原 owner、inactive，再到 Aborted；
Claimed 只允许 Active/Aborted。Prepare/Claim 为终态保留两个 R/S；pending ACL/quota
更新仍留下一个终态位置。owner epoch 与 auth epoch 都不 wrapping/saturating。
activate-only 必须原 owner==target 且 inactive；显式同 worker takeover 仍可以增加 epoch。

terminal marker 的 phase R/S/nonce/owner 是历史固定字段。普通 SQL、ACL、quota 和
named delete 不重写它。新 Claim 或 Cancelling 覆盖之前都需要旧 proof 持久及 exact
回读。proof 不使用创建它时的当前 R/S/ACL/ETag。历史 inspect 读 descriptor→HEAD→
proof→HEAD；双 HEAD/ETag 变化仅报不稳定，权限以当前 HEAD 为准，缺 proof 不报 NotApplied。

## 组合入口

pending 下逐项拒绝：execute、commit、cancel Unknown、close_full、epoch、lifecycle、
named delete、catalogue recovery publication、compact begin/copy/promote/abort、GC
prepare/resume、永久 storage seal。允许的 status/query/lookup/open-readonly/cancel-known
只返回读取能力。legacy takeover/activate 在 HEAD8 终态后仍永久拒绝，包括 pending
期间新准备、恰好带终态 revision 的旧 HTTP。旧已经 invoke 的 CAS 由其原 ETag fencing。

模型只测试上述入口的 guard 决策，**没有重实现这些生产操作**。copy/sweep/Deleted/
storage terminal 仅用有限标志组合验证 owner admission 排斥和 marker 保留。
native recovery 闭包以完整 hash 对象和保留结果的小集合投影；原始结果 bytes 不因
owner 操作变化。普通显式 SQL 用一个不透明固定输入与原结果表示，UNKNOWN 后不重放。

## 冻结与证据

`explore.py` 先保存源码清单、Python 二进制 hash/版本、固定 inventory；每条正向原始
历史先落盘，再由不导入 model 的 oracle 判定。全部负控也先保存，失败不会删除副本。
最后重新核对声明的源码输入。`--diagnostic` 明示未提交源码，仅供开发；正式运行要求
本目录、两篇协议文档和 AGENTS 的声明输入已提交且未变化。根工作树内不相干的并行
产品编辑不纳入此有限模型的源码身份，模型不能认证它们。

正式命令：

```sh
python -m unittest discover -s experiments/object-owner-plan-model -p 'test_*.py' -v
python experiments/object-owner-plan-model/explore.py --output /new/evidence/path
```

源码变更后必须用新输出目录重新运行。生产实现、所有消费者、逐文件精确覆盖、真实
故障夹具和 controller 的每轮并发/资源/总期限仍是独立待完成门禁。
