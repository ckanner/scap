# 可中止普通操作与世代回收：独立有界模型

本目录是 **候选协议的有界模型**。它不接入生产 HEAD、不调用 S3、不启用 DELETE，
也不替换已经发布的 `experiments/object-reclamation-model`。旧模型的 source、26 个
profile 和 41 个负控制保持独立。本模型的 **41 个 profile** 是另一组输入，不能把
两个模型的通过分母相加。

本轮选定的下一步默认方向是：**普通操作没有 durable PinAdd/Release**；旧 PR41
的非撤销 operation-pin 协议保留为保守替代方案，不再是开启下一片生产工作的
必经默认路线。retained snapshot roots 的显式 hold 和 active copy plan 仍须持久
保护；取消普通 operation pin 并不取消这些保护。这是候选协议选择，不代表当前
生产已具备 retirement、SnapshotExpired 或 GC。

当前协议清单在 [SCENARIOS.md](SCENARIOS.md)，保留了 v1/v2/v3 原文。输入生成器把
显式程序、初始对象、Scope、barrier、错误注入、原始字节和 mandatory witness
展开到 `inputs.json`；展开后的程序先冻结，之后才探索。当前 v4 有 41 个 profile、
1,690 个展开步骤、92 个 mandatory witnesses。单个 actor 最多 98 步；声明上限为
128。所有程序和暂停条件都是有限 fixture 假设，不能描述为任意无限业务程序。

## 1. 要回答的设计问题

普通操作从新鲜授权的 exact HEAD 捕获原 Snapshot、完整 Scope、物理世代和根；
它们不登记 durable operation pin，也不为普通读/写增加 PinAdd/Release HEAD CAS。
显式管理员 Freeze 使用原 ETag CAS 增加 serial、固定根、分配单调且不复用的 target。
旧 writer 只能提交原候选、原 key 和原 ETag，不换条件、不重放 SQL。

完整验证后的旧读结果仍可在线性化到原授权 observation 后返回。其最后 GET、
materialize、return 可以发生在 Freeze、ACL 修改、logical Delete 或物理 sweep
之后。没有为了制造“立即撤销”而增加结束时 HEAD GET。未完成的旧读不会成功：
它需要另一次 exact HEAD 为原失败证明永久退休，才能把该物理世代的 Missing/Corrupt
报告为 scoped SnapshotExpired。authority 不可用时仍是未证实；当前 active/target/
held 世代损坏仍是 Corrupt，不能自动恢复健康。

显式保留快照的 hold 与当前复制计划单独保护根。永久退休是：

`1 <= g <= M && g != A && g != current_target && no_retained_hold(g)`。

不能简化为 `g < A`。Aborted G2 可在 A1/T3 下退休，而源 G1 仍受保护。退休是单调
事实；旧世代不能重新 active、重新加 hold 或重新分配为 target。未来 PITR 必须
复制到新的世代，不能复活已允许迟到 DELETE 的旧 namespace。

## 2. 原始请求、后端效果与调用方知识

每个 HEAD GET、HEAD CAS、immutable GET/Absent PUT、conditional DELETE 都分为：

1. client dispatch 创建不可变请求 token；
2. 后端独立选择 apply/discard；
3. client 观察 known 或 UNKNOWN。

原 token 保留完整 key/body/condition/protection，client 退出后仍存在。所有 pending
token 都继续有 apply/discard 边；backend 不在交付时重新读取“当前 ACL”来替换原
授权，也不把旧 key 转到新 active generation。HEAD ETag 是 body 派生，serial 防止
body ABA；object ETag 是 opaque，同字节删除后重建可以得到不同版本条件。

`detach` 只表示调用方不再等待，不代表 worker、HTTP、SQLite 或 S3 已结束。
`local_stop` 关闭新 dispatch 和新的公开 success；它无法撤回已经发出的原请求。
已知 durable publication 后，native 仍可做 commit/fail 收尾，但关闭出口不会再给
新的 ACK。withheld 不等于持久状态回滚。原 UNKNOWN 不会被迟到的 backend success
倒填成原调用方的 ACK。

公开 outcome 是历史观察：出口检查发生在 return/ACK edge 上。一个成功返回以后
再 detach/stop，不会追溯否定早先成功。读、业务 ACK、Provisioning Complete ACK
和 already-Ready metadata 出口都有独立场景和反例。

## 3. 有界持久检查点

本模型用同一 HEAD 上的 bounded checkpoint 保存最多两个精确候选：plan/batch/
sequence、捕获的 generation、每个完整 physical key、原 ETag、disposition 和证据。
当前 copy plan 与当前 sweep checkpoint 互斥；清除当前记录不删除已发请求 token。

检查点的安装、disposition 更新、clear 均使用真实的模型 HEAD GET/CAS/UNKNOWN
交错，不再假设“原子持久化 checkpoint”。DELETE 必须有 fresh exact own batch
观察；PUT 回执和本地 candidate 不能制造 Snapshot。

- 同 serial HEAD 缺少 batch 时，原 UNKNOWN CAS 仍可能 pending，不能判定未提交。
- 更高 serial 可以 fence 原条件，但不能发明原 Applied。
- 原 DELETE UNKNOWN 保持 UNKNOWN。后来的 typed exact-key NoSuchKey 可以建立
  `observed_absent` disposition；NoSuchBucket、不可用和无类型的 Missing 不行。
- disposition 先以新原条件 CAS 持久化并 exact 观察；安全完成的 batch 再 clear。
- clear 后，原 DELETE 仍可能在新 batch/新 copy plan 存在时交付。单调退休、原
  physical key 和原 ETag 使它不能误删新 active/target 的同 hash 对象。
- 同字节重建导致 ETag 变化时，必须由另一次使用旧条件的真实尝试记录其自己的
  Conflict 等结果，再安装一个不同的 exact candidate；不能在 RAM 里替换旧 ETag，
  也不能把新重试的结果改记到原 UNKNOWN 上。

未来生产接入必须证明 S3 adapter 的 typed NoSuchKey 与 NoSuchBucket 区分。模型中的
类型不是对现有泛化 `Missing` 错误的兼容承诺，也不证明任意兼容对象存储的条件
DELETE 行为。

## 4. 权限与错误作用域

`inputs.json.required_current_rights` 逐动词列出权限。新的 Freeze/Seal/Promote、
candidate/checkpoint 和 hold 管理验证它们新 exact HEAD 的 admin 权限；这些动词
不要求 worker 等于普通写 owner。普通写另外要求 read+write、Ready、active owner
以及无复制计划。Complete/Abort 则绑定精确创建身份。

owner 变化可以 fence 原 CAS，但不能自动撤销一项仍然保留的 admin 权限。撤销
admin 后，fresh checkpoint/维护操作拒绝；已发 DELETE 仍按原条件交付。失败调查
只判断原 Scope/generation 的永久退休，不能从中制造新的 READ grant。

模型中的 incident map 只是世代级作用域的抽象。生产的 Database/ObjectContext
quarantine、缓存连接、跨进程状态和“authority 不可用以后如何恢复调查”仍需要
具体实现与验证，不能由本模型提前宣称完成。当前生产错误处理没有被放宽。

## 5. Producer 与独立 oracle

| 文件 | 职责 |
| --- | --- |
| `build_inputs.py` / `inputs.json` | 显式生成并冻结每个有限程序和初始 cut；生成器不运行探索。 |
| `model.py` | Producer reducer；原请求和 caller knowledge 分开，所有 pending delivery 保留。 |
| `run.py` | BFS，保存所有 state/edge、源码、Python identity、分母和 cap 状态；最多报告 ENUMERATED。 |
| `oracle_protocol.py` | 从 raw frame/key/original token 检查协议、错误分类、权限、原条件、typed evidence 与 allowed-delta。 |
| `oracle.py` | 独立重建 enabled choices，检查图完整性、每个实际边和可达性。 |
| `oracle_witnesses.py` | 从实际图构造连通 witness 路径；时间先后需要同一路径，不能合并不同分支的事实。 |
| `controls.py` | 先验证原始可达 prefix，只改变最后效果做语义反例；另有遗漏/重复 enabled 边、截断状态和正控制。 |
| `test_model.py` | 小规模边界测试，独立于完整图和正式 controls。 |

oracle 不导入 producer 的 reducer、enabled-choice 函数或闭包。它直接解析冻结 raw
frame 的引用边；Result 的 receipt data-root 是身份字段，不成为历史数据树边。
非规范 JSON 的原始字节必须逐字节复制，不能 decode→encode 后冒充原对象。

allowed-delta 约束每项知识/效果的唯一写入口：非 fixture 指令不能改变 backend
fault，token/body/ETag 和原 UNKNOWN 不可重写，context 不能重捕获，view 必须来自
本次已观察 HEAD token，labels 只能绑定实际新请求，proof map 只能加入当前已观察
对象的证据，新 plan capture 会清空旧证据。它还检查 gate、detach、已知 durable
事实的单调性。该表不是另一个 producer reducer，也不会生成枚举的期望状态。

## 6. 运行与证据

只依赖 Python 标准库。输出目录必须全新；不覆盖原失败、cap 或通过证据。

```bash
python3 -B -m unittest discover -s experiments/object-reclamation-abortable-model -p 'test_*.py' -v
python3 -B experiments/object-reclamation-abortable-model/run.py --out /tmp/scap-abortable-run-NEW
python3 -B experiments/object-reclamation-abortable-model/oracle.py --graph /tmp/scap-abortable-run-NEW --out /tmp/scap-abortable-audit-NEW
python3 -B experiments/object-reclamation-abortable-model/controls.py --graph /tmp/scap-abortable-run-NEW --out /tmp/scap-abortable-controls-NEW
```

正式运行前还要冻结本目录所有文件。最终 receipt 必须绑定 inputs、producer/oracle/
controls 源码、Python 可执行文件、全部 graph/trace、unit 原日志和旧模型未修改清单。
每个 profile 的 state/edge 分母、所有 required witness 路径都保留。缺 witness、
state/edge/time cap、missing map、source 变化或异常都不能报告验收通过。

探索上限是每 profile 50,000 states、150,000 edges、120 秒，最多 96 network
tokens；原始 state 用压缩缓存，输出为 gzip JSONL。该 time cap 是探索资源预算，
不是产品的 absolute deadline 验证。停止超过最后一次扩展的 time cap 也会保留为
INCOMPLETE，不因为已经生成大部分图而宣布穷举。

开发证据与最终验收分开。原 dev03 没有公开出口 stop 场景；独立审查指出缺口后才
添加 v4。原 controls01 因 rebase 负控实际上没有改变输入而失败；原 unit03 因新的
allowed-delta 更早正确拒绝了反例，测试原预期错误边界不再匹配而失败。它们均保留，
不改写成通过。当前文件不把尚未完成的 final source freeze/正式控制标为通过。

## 7. 不能由此推出的结论

本模型使用 `MODELFRAME1` 和抽象 HEAD/native outcome，**不是 SCAPOBJ2、HEAD5 codec、
SQLite B-Tree 或 SCAPRES1 完整语义的证明**。它不验证真实 LIST 分页、Name/Descriptor/
Proof 全部跨 key 协议、S3 签名与云端一致性、wire 最大长度、RSS、实时 deadline、
任意数量的 actor、无限计划的公平性或吞吐。它不证明 native fail 后连接如何隔离，
不证明已有业务表损坏能恢复，更不把 orphan 的 eventual cleanup 说成有时间上界。

Deleted 的最后 active generation 和现有 retained hold 仍受保护；本模型没有终端
销毁/PITR 生产协议。没有 ordinary durable pin 只隔离了“每次普通进程死亡永久留
pin”的问题；反复暂停的旧 uploader 仍可能产生退休世代 orphan，反复重启的 copy
仍可能饥饿，必须另行限额、计量和调度。

生产下一步还需要完整 raw-byte closure/cursor、HEAD 中的 generation/plan/retirement
编码与严格大小证明、scoped error/health 实现、checkpoint UNKNOWN 传输、精确条件
DELETE capability 和 source-bound 实际服务验收。本模型通过也不授权直接打开 GC。
