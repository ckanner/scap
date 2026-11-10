# Handle 知识域的独立有界模型

本包检查一个明确的后续设计：普通 read/write 不为每次操作持久写入 PinAdd/Release；
失败知识属于 `(可信 authority domain, full Scope, handle lineage)`。它不修改生产
generation、错误码或 quarantine，也不修改已接受的 PR41/PR43 模型。只有绑定本包
源码和输入的独立完整图 receipt 才能证明本轮验收完成；`ENUMERATED` 只是 producer
已走完有限输入，不能称为生产正确性或独立验证通过。

## 所选合同

Database clones、同一 Session/ObjectContext 共用 lineage。另一次 Database 构造、
Catalogue/Recovery 构造的新 handle，即使位于同一 worker，也有独立 lineage。可信
authority domain 是实际 bucket/prefix/backend 配置的抽象，不是用户提供的字符串或
Arc 地址。本模型有两个独立后端 map；full Scope 包括 incarnation，永久 HEAD slot
相同不意味着身份相同。

quarantine/latch 阻止后续相关 publication。它不等于“所有读取都拒绝”：失败的原
attempt 不能恢复前缀或公开成功；同 lineage 全新 fresh 授权、全自有 GET/验证的
只读操作可以成功，但不得清除旧知识。独立 H2 必须有完整成功的可达正例，防止把旧
全局 latch 偷留在模型里，再以全部拒绝冒充安全。

最后一次 healthy 检查、dispatch、backend delivery、观察结果、native 收尾和公开
ACK 是不同步骤。晚到的同 lineage latch 不能撤回已经通过最后检查的原 permit，
也不能取消原 token。相反，明确 local stop 仍阻止新的 dispatch/public success。
已发 token 在 caller/handle 关闭后仍可 apply/discard；原 UNKNOWN 是历史观察，后端
后来 Applied 不把它改成 ACK。已有公开成功也不会被后来 stop/latch 追溯改写。

`native_publish` 的 commit/fail 只是**抽象的已知 durable 后收尾分支**。模型不证明
当前 SQLite 在每个停止时点都能 commit，也不证明真实引擎、线程或时钟的取消行为。
Known durable + native fail 与未提交、UNKNOWN、公开 ACK withheld 分开记录。

## 物理失败与语义失败

原始 Missing/hash 故障保存实际 GET 的 domain/Scope/generation/key/token。最多一个
专用 exact HEAD probe 可用于调查，不能产出可 rebase Snapshot，不能借另一 handle
或后端的 HEAD。永久退休要求：

`1 <= g <= allocated_through`，同时 g 不是 active、current target 或 retained hold。

任何合法后继都不能重新 active、重新分配或新 hold 已退休 g。这样，abandoned G2 在
A1/T3 下也可退休；不能把退休缩成 `g < active`。原 domain/slot 的 probe 若读到
foreign Scope、malformed 或 unavailable HEAD，必须失败关闭，不能靠看似推进的
serial/generation 降格为 SnapshotExpired。

Hash-valid Scope/type/typed-edge/content 语义错误单独 latch，不能借物理退休变成
expiry。K15a 的坏 typed edge 保持 active，不假装它通过了合法 raw-copy Seal。
K15b 则明确声明：raw 图合法，但后续抽象 content/native 判据失败；相同原字节可以
被 raw-copy Promote，失败不能因此变成成功。本模型的格式是 MODELKNOWLEDGE1，
**不是** SCAPOBJ2、真实 data tree、B+ tree、SCAPRES1 或 SQLite 的验证证明。

K16 独立演示新 H2 从自己的 fresh READ HEAD、index 和 Result GET 取得旧 durable
receipt。Result.data_root 是身份字段，不是自动指向历史 data graph 的遍历边。
这个新查询不会改写 H1 的 UNKNOWN，也不会重新执行 SQL/native。

## 冻结范围和有限假设

`inputs.json` 固定 **46 profiles、1,899 actor steps、119 mandatory witnesses**。原
38 个 program 对象保持不变，新增八个 profile 补上原 domain 的坏 probe 和 stop
在 permit/dispatch 两侧的边界；`program-history.json` 保存逐 profile 的原指纹。
`PLAN.md` 描述 K01–K17，`build_inputs.py` 只展开程序，不执行状态转移。

每个 mark/await 都是明确的 fixture/program 调度假设。有限程序的全部交错不等于
任意客户端程序或无限 worker 的全部调度。每一个已发 pending token 的 apply 和
discard 仍独立 enabled；fixture barrier 不能删掉它。可选 UNKNOWN 可以先于
delivery 观察，也可以在实际效果之后观察；结果观察只能写一次。

| 维度 | 每 profile 的上界 |
| --- | ---: |
| actors / lineages / workers | 4 / 3 / 2 |
| authority domains / full Scopes | 2 / 2 |
| physical generations / hold / current plan | 3 / 1 / 1 |
| 固定 raw frames / network tokens | 8 / 48 |
| 每 actor 显式步骤 | 96（当前最大 52） |
| states / edges / exploration time | 50,000 / 150,000 / 120 s |

超限原样标记 INCOMPLETE，并保留原图、日志、源码和停止位置；producer 在第一个失败/
超限 profile 停下，不继续消耗其他 profile 的 cap。不能删掉 mandatory witness、
调高 cap 或压掉 delivery 来把既有失败改为通过。

另有这些边界：

- 初态 sealed plan 假设目标 raw closure 已验证；这里不重新证明复制/Seal 协议。
- `remove_retired` 是受限显式 fixture，要求退休谓词已成立。这里不重新实现 checkpoint
  UNKNOWN、条件 DELETE、批次清理或跨 key recovery。旧 PR43 的这部分模型保持独立。
- K06 held G1 先通过真实模型 HEAD CAS 加 hold，再 Promote；故障是受控存储/读取
  corruption，不是允许 GC 删除被 hold 的对象。
- 关闭 lineage 的知识保存在有限历史中供审计；这不是生产无限 HashMap，也不证明
  refcount/缓存重建的内存回收界限。没有跨进程 durable incident 广播假设。
- deadline 是显式 local-stop 抽象，不能证明真实 `received + duration`、meter 消耗、
  等待队列或 HTTP/TCP 时序。
- 普通新 cold closure/read/write、两种窄 management publication 和独立抽象 lookup
  属于本轮；warm Session SQL、Catalogue Name/Control/Proof、Provisioning bootstrap
  和真实 RecoveryMeter 的全部生命周期仍需要生产接入时的专项 refinement。
- 本轮 profiles 的业务生命周期保持 Ready。输入中的 required-rights 表记录必要的
  授权合同，不代表这里已经穷举 Maintenance/Deleted/Provisioning；例如生产 policy
  可用于 Maintenance 的路径仍由生产单元/既有状态机验收负责。

`source-inputs.json` 是最初静态设计的历史来源清单（包括 f6 生产和管理片 handoff），
其中当时的 NOT_EXPANDED 不作为当前运行状态。当前程序状态以 `inputs.json` 和本轮
receipt 为准。旧十四文件的 SHA 在每次独立审计中重新核对，不挪用旧通过分母。

## 实现与独立检查

`model.py` 是 producer；`run.py` 对冻结的 actor programs 做 BFS，将每个完整 state
和全部 edge 写入有哈希绑定的压缩原始图。token ID 来自 actor+原 pc，避免让无关
全局发号顺序制造额外状态；没有 partial-order reduction，也不丢 pending 网络边。

`oracle.py`、`oracle_protocol.py`、`oracle_witnesses.py` 不导入 producer 或 explorer。
它们从原始图重新检查：准确初态、每个 state 的原字节/知识来源、每条 backend 的
原 condition/body、每个 actor 的 allowed delta、原公开出口及完整 enabled-choice
集合。允许修改某字段并不代表可以任意伪造其值；latch/proof/view/token/native 都有
独立来源约束。每个 state 必须有一条实际存在的父边连接到初态，不能注入不可达正例。
mandatory witness 输出引用原图 SHA 和实际连通 prefix，不用统计名字代替可达路径。

负控在原完整图中选取可达 edge/prefix，保持原 source state 和 event，修改目标语义，
要求在声明的边界被同一冻结 oracle 拒绝。包括跨 lineage poison/clear、误留全局读
禁令、view/label 伪造、UNKNOWN 回写、健康 permit 与 stop 混淆、native/公开出口、
foreign proof、held/active expiry、raw frame/完整物化、metadata 字段越权和退休
target 再 hold。合法的另一种管理/技术候选也不能替换原 command 的动词；技术 capture
必须逐字段绑定它自己刚观察的 HEAD，失败原 attempt 的普通门禁不能删掉专用 probe。
当前修正版定义 **47 个语义负控、2 个图级负控和 35 个 focused unit tests**；
当前执行结果见下文，不能继承原 `e396d48` 的 19 项单位通过结果。
图级负控删掉关闭 caller 后仍 enabled 的 delivery，或重复一个 choice。
每个负控的原 edge 先作为正例验证，另保留一个原完整 choice 集合正控。控制只调用
实际独立规则，不提供绕过 source/identity 检查的“接受覆盖”模式。

## 原始失败与拒绝规则修正

原冻结源码 `e396d48011a69628fe47186549a390aad1f145b6` 的全部 46 份输入完成
BFS：57,420 states / 136,266 edges。其独立审计在 K05 的
`fixture_remove_live_generation` 拒绝边停止，**整个模型门禁 FAILED**；原始
图、completion、错误日志及源码身份当时已保存，controls 当时 NOT_RUN。
2026-11-10 环境恢复后，旧完整图及原临时目录在当前环境不可用；仓库中的历史失败
摘要和身份记录保持不变，不从摘要重造原图，也不重新解释原失败。
producer 的 ENUMERATED 不能覆盖这个失败。

该边来自原 Promote CAS 被后端 discard 后的原始 fixture 删除指令。generation
仍 active，删除应被拒绝；缺失的是独立 oracle 对这条拒绝的明确义务。
随后只读检查原全部 46 图的 stopped 原因，又找到 7 条具有原始连通路径的拒绝：
2 条 `freeze_not_available`、4 条 `no_retained_hold`、1 条
`get_not_in_original_closure`。输入、调度 barrier、producer 和枚举 cap 均未改。

修正逐条核对角色、原命令、domain/full Scope、同一次原 GET 的 body/ETag
和实际 token。Freeze 绑定当前 attempt 自己已观察到的 occupied plan；retained
read 绑定原 HEAD 的 hold=None；closure GET 绑定原 read context 的 typed roots
及其自己的已验证 frame prefix。不得借后来的全局 HEAD、foreign domain、另一
actor 的 token 或更早的旧 context 来制造拒绝。拒绝边不能修改 world、tokens、
lineage 知识或本 actor 除 pc/stopped/outcome 外的字段。

新增正反例保留 Applied abort 后的 Freeze、Applied hold 后的 retained read、
Applied writer 后的合法 GET/Missing 及既有 ACK；负控分别伪造拒绝、删除 active
对象、修改 foreign authority，或在拒绝时偷换 context、授予读取权、发出 GET。
这不是把所有安全失败加入白名单。两轮静态审阅无阻塞；本修正的单位、完整 BFS、
独立 oracle 和 controls 在该静态记录形成时 **NOT_RUN**。其后首次执行的单位
失败及本次测试窄修见下节；静态审阅不替代运行验收。

原失败、静态源、精确增量和原图边身份见[修正证据](../../docs/evidence/handle-knowledge-rejections-static-local-2026-11-09.json)。

## 2026-11-10 单位失败与测试路径修正

在恢复并验证完整 commit/tree 后，冻结源码
`bc9f9e6af7a9024a39a39ced7b59969ffe66cfda` 实际运行全部 35 项 focused units：
**34 通过、1 失败，退出码 1**。前后源码校验通过。按首失败停止规则，本轮完整
BFS、独立 oracle 和 47+2 controls 均 **NOT_RUN**；不能据此把模型门禁记为通过。

失败测试选用了 `K05_materialized_return`，却断言 foreign authority D1 的 active
generation 为 1。固定输入中 D1 初态已经为 2，且该程序不会修改 D1。D0 成功
Promote 后 G1 在两域都退休，所以仅把断言改成 2 不能保持原来要检验的域间差异。

本次只改该测试函数，使用已有的 `K06_aborted_target`：原 `m:6` Abort CAS
使用 `m:2` 的原 ETag，成功后 `m:8` exact GET 提供下一次原 Snapshot；原
`m:12` Freeze CAS 使用 `m:8` 的原 ETag。两次 Applied 后，D0 为 A1/M3/T3、
无 hold，G2 已退休；D1 仍为 A2，同一个 G2 仍 active。测试先检查合法删除，
再构造假拒绝，要求独立 oracle 拒绝借用 D1 权威，命中
`fixture rejected already retired generation`。该路径已由下节 c8 的单位执行确认。

35 个测试名称、46 个固定输入及全部 caps、producer、独立 oracle 和 controls
保持不变。该测试修正发布为 `c8f65f6631c0acf62f9ea14ae696e7587c6b39c3`，
其新冻结门禁结果见下节。原 bc9 单位失败和更早的 e396 完整门禁失败各自保留。
原 driver、日志、exit、源码及输入身份见
[本次失败摘要](../../docs/evidence/handle-knowledge-units-failure-local-2026-11-10.json)；
原始运行日志不提交到仓库。

## 2026-11-10 c8 完整有限门禁

精确 commit `c8f65f6631c0acf62f9ea14ae696e7587c6b39c3`、tree
`02565092aaaff0a4ff4d4058837e580efdc8db0d` 的本轮门禁已完成，结论为
**PASS_WITHIN_DECLARED_MODEL_SCOPE**。35 项单位先通过，随后才执行完整枚举、
独立审计和负控；全部九个阶段命令退出码为 0，444 个 tracked source 文件在前后
校验中保持不变。

| 门槛 | 本轮实际结果 |
| --- | --- |
| Focused units | 35 / 35 PASS |
| 完整固定输入枚举 | 46 profiles；57,420 states；136,266 edges；无截断 |
| 独立 oracle | 全部状态、边、enabled choices 和 119 mandatory witnesses 通过 |
| 语义负控 | 47 个均在声明边界拒绝；47 个原 edge 正例均通过 |
| 图级负控 | 2 个均拒绝；原完整 choice set 正例通过 |
| 源码与输入 | 原 46 输入和全部 caps 未变；前后源码校验通过 |

本轮与独立目录中的 jobs=1 Rust 正确性任务并行。保留原每 profile 120 秒等全部
上界，没有为并行调高 cap；这不是吞吐、延迟或性能资格验证。有限模型通过不等于
生产多世代 admission、SQLite/native、HTTP/S3、GC 或 AWS Standard 已完成验收。

本轮完整新图、日志、审计和负控输出、444 文件源码与 driver 已归档；788 个 member
全部流式读回并核对 SHA256/长度。归档也保存仍可用的 bc9 单位失败原件和完整源码
恢复映射。旧 e396 大图在恢复环境不可用，历史摘要仍保持 FAILED；不把本轮新图
当作旧图，也不覆盖两个原失败。精确阶段 exit/hash、输入、并行说明和归档身份见
[完整验收摘要](../../docs/evidence/handle-knowledge-acceptance-local-2026-11-10.json)。

## 运行命令与证据

```sh
python3 -B -m unittest discover -s experiments/object-handle-knowledge-model -p 'test_model.py'
python3 -B experiments/object-handle-knowledge-model/run.py --output /tmp/scap-handle-model-run01
python3 -B experiments/object-handle-knowledge-model/oracle.py \
  --graph /tmp/scap-handle-model-run01 --output /tmp/scap-handle-model-audit01
python3 -B experiments/object-handle-knowledge-model/controls.py \
  --graph /tmp/scap-handle-model-run01 \
  --audit /tmp/scap-handle-model-audit01/receipt.json \
  --output /tmp/scap-handle-model-controls01
```

新输出目录必须不存在。源码变更后创建新运行目录，原 FAILED/INCOMPLETE 记录不
覆盖、不改标签。单个 `--profile` 开发运行必须保持显式 scope，不能当成全部 46 组
完成。独立审计与 controls 都绑定 source、inputs、图、日志和原始失败；producer 的
完成状态不能代替这两项验收。

裸 `send_head` 指令未声明 `uncertain` 时，冻结程序的缺省值明确为 false；声明 true
的原 UNKNOWN 分支保持 enabled。重复或不存在的 `--profile` 在创建运行目录和枚举
之前拒绝。首轮静态审阅发现的实现缺口保留在 static01 清单中，属于未执行前的静态
发现，不改写为运行失败或通过；修正版另行冻结并验证，46 份输入原字节保持不变。
