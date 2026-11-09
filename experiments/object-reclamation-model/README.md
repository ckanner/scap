# N3.2 物理世代、pin 与回收的有限独立模型

本目录实现一个可执行的**有界协议模型**，没有导入 SCAP 生产代码，没有操作真实
bucket，也没有启用产品 HEAD 5、pin 或 DELETE。生产边界和后续落点见
[设计说明](../../docs/architecture/reclamation-model.md)。

`inputs.json` 固定一个完整逻辑 Scope、8 个原始内容对象、26 个有限程序集合和
629 条 actor 指令。其原始字节 SHA-256 为
`06a5eec502e2ca9f367715d107b4c10407f3b22200065b0ae2d0e6e3e8518a76`，独立 oracle
直接校验这个输入身份。变更程序、初始状态、对象图或任何 bound 都必须重新冻结并
重新运行；不能把较小输入的结果用于较大输入。

## 运行完整门禁

只需要 Python 标准库。下面三个输出目录均须不存在；输入、源码、原始图、失败与
独立反例输出保留在源码目录外。CI 的 `object-reclamation-model` job 和完整本地
`dev/environment/validate.sh` 已接入同样四个阶段。

```sh
python3 -m unittest discover -s experiments/object-reclamation-model -p 'test_*.py' -v
python3 experiments/object-reclamation-model/run.py --output /tmp/scap-reclamation-graph
python3 experiments/object-reclamation-model/oracle.py \
  --evidence /tmp/scap-reclamation-graph --output /tmp/scap-reclamation-oracle
python3 experiments/object-reclamation-model/controls.py \
  --evidence /tmp/scap-reclamation-graph --output /tmp/scap-reclamation-controls
```

Unit 的 22 项 harness/边界检查与完整图分开。`run.py` 只报告 `ENUMERATED`，它不是
安全结论；只有独立 oracle 对完整原始图通过，且 41 项负控与 1 项正控都满足对应
边界，才完成本模型门禁。39 项协议 mutation 从已经独立验证的原始执行前缀出发，
只改最后一个效应；另外两项检查遗漏 enabled successor 和截断报告。负控若因
无关的 hash/fixture 错误被拒绝，整个负控运行失败。

`--profile` 是 producer 的开发选项。正式 oracle 不接受只运行部分 profile；
内部的显式 partial-development 模式也会标记 `EXPLICIT_PARTIAL_DEVELOPMENT_ONLY`。
状态、边或时间 cap 命中时保留 `INCOMPLETE` 原始文件并非零退出，不会剪掉剩余
队列后报告通过。CI/本地脚本不捕获或忽略这些失败。

## 固定边界与初始状态

| 边界 | 模型值 | 含义 |
| --- | ---: | --- |
| 完整逻辑 Scope | 1 | 不覆盖跨 Scope/PITR；所有物理 key 隐含同一个固定 Scope |
| 每 profile 的 actor | 1–4 | 每个 actor 的原始程序与初始状态全部在输入中固定 |
| 内容图 | 8 objects | 当前闭包为 4 个；写后闭包为 5 个，保留原 Result |
| `head_serial` | 1–16 | 技术/业务 CAS 都严格增加；到上界明确拒绝 |
| business `revision` | 1–8 | 技术变化保持业务 revision/transition |
| storage generation | 1–4 | `M+1` 分配；已放弃的世代永不复用 |
| durable pins | 2 | 包含完整 Scope、worker/process/broker/acquisition 身份 |
| 每 broker live guards | 2 | 关闭 gate 与新 guard 准入原子排序 |
| 每 profile 请求 token | 64 | 原请求字节、key、ETag、backend 效应、client 知识分开保留 |
| durable checkpoint | 2 | 有界描述符的原子、原版本比较更新；不是产品 wire 格式 |
| 每 checkpoint cursor | 0–8 | 身份、Scope、generation 与批次不能换绑 |
| 执行资源 cap | 200,000 states / 1,200,000 edges / 120 seconds per profile | cap 不是协议性质，也不授予 incomplete 图通过资格 |

这些数值只限定有限证明，**不修改生产 u64、SQL、ACL、结果、保留窗口或容量上界**。
部分 profile 从 Ready 初态开始，另一些从明确合法的已 pin、空 pin Copying 或已有
retired 世代状态开始。后者是各自声明的前提，不是“所有前史均已穷举”的结论。
Copying 与 live pin 不共存；Delete+live pin 和 Delete+Copying 使用不同合法轨迹。

## 状态转换和网络边界

一个 actor step 是一个完整局部动作；exact HEAD GET 的 body/ETag 取自同一次观察。
HEAD ETag 是完整 HEAD 字节的内容摘要，因此同字节复现可得到相同 ETag，没有额外的
隐藏唯一 store version 替协议提供 fence。每个技术 CAS 增加 serial 才能避免 ABA。

网络请求一经发出就保留原 key、generation、完整候选和原条件。backend apply 只
执行这些条件，不重新运行今天的 ACL、lifecycle、freeze 或本地 gate 检查。对象
物理寻址使用原 hash key，诊断名称 `object` 不参与寻址。CreateOnly PUT 可以
迟到，DELETE 可以先应用后丢响应；同 raw bytes 重建也允许重复 ETag。

PinAdd 是 metadata-only CAS，随后必须有新的 exact HEAD GET 才能封存业务
AttemptContext。UNKNOWN Add 在原 serial 上“找不到”仍是 pending；只有更大
serial 上匹配完整 token 的观察或实际完成的 metadata fence 才能结束不确定性。
同进程的两个 broker 使用不同 acquisition 身份，不能因 grant serial 相同就
冒认对方 token。PinRelease 只删除自己的完整 token，保留最新业务/权限/生命周期
字段；Deleted/quarantine 仍允许关闭 gate、排空实际 guards 后做这种窄清理。

首版 Freeze 要求 **zero live durable pins**，冻结期间拒绝新 PinAdd 和新远端
恢复/lookup 准入。纯 status、已经完整物化的本地暖读是另外的入口。本模型不沿用
早期设计里允许新短 lookup 的较宽可用性描述。冻结期间 quota/takeover/root 变化
必须先 Abort；ACL 可以排序更新，Promote 必须保留当时有效的 ACL。逻辑 Delete
原子放弃 T，保留 M/A/pins；迟到复制成为 orphan，旧 Promote 无法复活数据库。

复制遵循当前数据和保留请求索引/Result 的显式引用边。Result 中的
`receipt_data_root` 是身份字段，不自动扩张为历史数据保留根。复制必须保留非规范
JSON 的原 frame bytes/hash。验证记录绑定完整计划；重新 capture 清空旧缓存，
旧计划的迟到 GET/verify 响应不能补入新目标的已验证集合。

## API 出口与明确不覆盖的行为

Reader 从实际已观察的原 GET 字节完整 materialize，绑定原授权 Snapshot；此时
实际 guard 必须仍存活。之后即使结束 guard、Release、迁移并删光旧世代，return
也只能消费已物化字节。已结束 worker 不能接纳迟到 GET 来补物化结果。caller
已离开则不产生成功出口。入口之后发生的 ACL 更新不额外引入“出口再取最新 ACL”
的强语义。

Writer 的原 HEAD CAS 已知 accepted 后，模型显式枚举 native publication 的
commit/fail。commit 后才能 SQL ACK；fail 保留原提交 reference，记录
`COMMITTED_BUT_UNAVAILABLE`，不撤回权威、不重放 SQL。native 仅是抽象结果分支，
没有执行真实 SQLite 或验证 SQL 查询语义。

`caller_timeout` 表示 caller 已停止等待，**不是 native operation 的绝对 deadline**。
后台继续执行的安全范围是有意保留的；`ticks` 不赋予 pin 到期语义。absolute-deadline
时间行为为 `NOT_MODELED`，不能据此声称已证明 timeout 禁止新的 dispatch。真实
SDK deadline、SQLite、HTTP/S3/进程恢复已有各自独立门禁。

Deleted 的最后一个 active generation 回收、跨 Scope/PITR、真实 LIST 分页、
checkpoint transport UNKNOWN、IAM、versioned bucket 和 Object Lock 都不在此
模型范围。产品 HEAD5、pin broker、GC/delete、AWS 和生产 SLO 均未由本目录交付。

## 完整图与独立复核

`model.py` 是 producer reducer；`oracle.py` 不导入它、runner 或生产算法。oracle
独立检查每个原动作允许的完整 state delta、内容闭包、原发布身份、client UNKNOWN
与 backend 实际效应，并独立计算每个状态的 enabled actions。

完整性需要同时满足：所有报告状态从固定初态可达；同一原动作没有重复后继；每个
状态的原始边集合恰好覆盖全部 enabled actions；BFS 队列已耗尽；每个指定危险交错
都有可重放的完整原始前缀。汇总计数、`passed` 字段或 convenience summary 都不能
代替这些检查。

终态严格指没有任何 enabled action：所有 actor 已完成、被拒绝或暂停，且所有
已发请求都已应用或被丢弃。仍有可应用的网络 token 时不算终态。某些终态合法地
保留 `GC_BLOCKED`、paused pin、COPYING 或需要显式重试的元数据冲突；穷举完成不
代表每条调度都完成迁移。

安全、阻塞与成本活性分别报告。第 18 组保留“本轮为空后迟到 PUT 又产生 orphan”
的原始轨迹。第 19 组只在成功迁移、旧请求真实结束、有限已知 key 被完整公平清扫
的终态子集中检查旧世代为空；它不是无限暂停、无限迟到或整个 bucket 成本收敛证明。

每轮证据包括固定输入、source tar/manifest、Python 身份、压缩原状态/边、每个
profile 的 complete/INCOMPLETE 收据、独立 witness traces 及其原始 SHA-256。
所有负控保存原前缀和改坏的前缀及 hash。开发失败、较早模型输入和后续正式冻结的
结果必须分开保留，不能把旧输入的通过替换成新输入的验收。

## 固定程序集合

下表中的编号对应 `inputs.json` 的完整名字。每个程序中的所有 enabled 交错和
不确定网络选择都会枚举；不会用手写的一条成功路径替代其它调度。

| 编号 | 重点 |
| --- | --- |
| 01 | 同进程两个 broker 的 UNKNOWN Add 与完整身份 |
| 02 | 原 serial 上 absence pending；更大 serial/fence 后才能 settle |
| 03 | 已保护 GET 与 Freeze 竞争 |
| 04 | caller 离开、worker 暂停、时钟前进仍保留 guard/pin |
| 05 | gate close 与两个实际 guards 的竞争 |
| 06 | 迟到原 HEAD CAS、Release/Freeze、native commit/fail 与 ACK |
| 07 | PinAdd/Release 技术 churn 使原业务候选失效 |
| 08 | 原字节复制并继承最新 ACL |
| 09 | Copying 中 Delete、迟到 copy/Seal/Promote |
| 10 | Delete 保留 pin；quarantine 下窄 Release |
| 11 | Abort 后 M+1，迟到 PUT 留在永久放弃的 T2 |
| 12 | 旧条件 DELETE、UNKNOWN 与新的 active generation |
| 13 | 旧 checkpoint/cursor 不得转向另一世代 |
| 14 | Provisioning 排除技术准入，原业务 revision 1→2 |
| 15–17 | serial、generation、pin table 耗尽明确拒绝 |
| 18 | empty scan 后仍可出现迟到旧 PUT |
| 19 | 额外 drain/公平清扫前提下的有限成本结论 |
| 20 | 缺少完整复制闭包时 Seal 拒绝 |
| 21 | Freeze 阻止 quota/takeover，显式 Abort 后才能继续 |
| 22 | 已验证 T2 不能替 T3 提供验证证据 |
| 23 | 新 capture 后的迟到旧 verify 回复拒绝 |
| 24 | guard/Release/旧世代清扫后只返回已经物化的原字节 |
| 25 | 未物化与 caller 已离开的 API 出口拒绝/抑制 |
| 26 | 实际 worker 结束后不能消费迟到 GET |
