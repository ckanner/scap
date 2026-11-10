# HEAD9 retained snapshot / fresh Scope restore：固定有限分母

状态：独立模型源码与固定验收计划；运行结论仅以对应源码指纹manifest为准。产品实现、native SQLite、HTTP/S3、AWS均为 **NOT_RUN**。设计见 [retained-snapshot-restore.md](../../docs/architecture/retained-snapshot-restore.md)，输入产品固定为 `3e850357478133ae2b76007c3e0e9609d3d8ac02`，不继承HEAD8的700个单位或旧模型结果。

## 选择与原子边界

保留点只有当前A中的数据树边，不引入旧generation永久pin。HEAD9的snapshot_limits是持久策略，普通本地copy预算耗尽只能Budget。每个snapshot有固定creator/operation、capture_serial=原S+1、原HEAD/ETag与point；release前持久accepted proof，释放后不能复用ID。source Deleted仍保留points，terminal须空表。

目标先取得自己的Provisioning slot，才开始跨Scope复制。每个frame重封装，自底向上重算hash；目标ACL只含新creator，sequence=0、request_epoch=1、请求结果为空。已授权、完整且独立的复制才能形成不可变CompletionRecord；record接受后源release/ACL/GC不再是目标的依赖，但每次目标resume仍须新目标授权和自己的Name/HEAD屏障。target abort不能被迟到record或旧CAS绕过。

release禁止新source attempt/context；原未失败context可继续。完成后用HEAD1→descriptor/proof→HEAD2稳定屏障，当前ADMIN+READ优先；变化先Conflict，稳定同身份hash/point矛盾或缺失依赖才Corrupt。最终屏障后不补payload读。旧g物理失败只有新鲜退休证明才SnapshotExpired；current/protected g缺失失败关闭，目标故障不借源退休掩盖。

## 具体有限域

主模型有2个live snapshot上限、每棵数据树0至3页、最多3个source physical generations、source和两个新target身份。主要copy竞争使用同creator的两个进程；独立`different_creator_name`家族使用不同creator、不同operation的两个进程争同Name，最多同时两个调用参与竞争。另有一个source管理员。每个history至多1次compute crash；技术/业务计数默认63，cleanup极限例用5、6、8。对象内容是带Scope与页号的规范JSON符号页，SHA256真实计算。它不是SCAPOBJ2、压缩、native SQLite B-tree或Rust serde的实现等价证明。

所有读写保留prepare / invoke / durable effect / response；Unknown可以先于effect，已invoke的请求在compute crash后仍可生效。新进程不继承旧unsent候选、source cursor或已失败前缀。metadata ETag在有限存储机内不ABA；所有依赖是exact GET，mutable publication固定原ETag，不在412/Unknown后换condition。

GC通常作为继承HEAD6的“已证明永久退休generation+exact候选ETag+条件DELETE”宏操作；不在这里重证LIST分页或32条生产checkpoint。另有明确checkpoint子例，按真实`gc_resume`一次整体settle、一次clear建模，以验证terminal后的q余量以及Unknown DELETE不能持久化Applied。目标取消抽象现有合法creation/control，原Name双读、FenceAbsent/FenceOwn、stable OwnDeleted/ForeignOccupied proof与Name释放全部展示；未重做哈希派生full Scope五元组或所有Catalogue创建identity碰撞域。

外部target creator/provision资格每个新操作重新admit，模型有真实权限撤回事件；已经admit的调用不声称能被异步撤销。source ACL是HEAD内权威，并在copy前后重新验证。模型不提供共享进程知识谱系的完整证明；physical/semantic/Budget分类只覆盖本文失败投影与禁止失败前缀恢复，HEAD6/8 handle隔离仍须产品单位及真实验收。

## 固定正向矩阵：789 histories

| 家族 | 完整有限枚举 | Histories |
| --- | --- | ---: |
| `capture` | 两个固定原HEAD候选的3+3阶段全部20交织 × 4回复丢失组合 | 80 |
| `release_sql` | 原release与SQL候选3+3阶段20交织 × 4回复丢失组合 | 80 |
| `bind_abort` | 同Name原ETag的Bind/Abort Accept，20交织 × 4丢失组合 | 80 |
| `provision_abort` | 已Reserved后的原Absent Provision与FenceAbsent，20交织 × 4丢失组合 | 80 |
| `two_completion` | 两个独立完整copy的同first-winner记录，20交织 × 4丢失组合 | 80 |
| `different_creator_name` | 不同creator/operation、各自fresh目标权限，争同Name原Absent CAS的20交织 × 4丢失组合；败者不能借对方Ready/abort | 80 |
| `migration` | begin/copy/seal/promote/GC与page1/page2/validate/completion，两条保序chain全部126交织 | 126 |
| `late_completion` | release/delete/terminal/GC与Completion PUT三阶段全部35交织 × 2回复结局 | 70 |
| `copied_abort` | Abort Accept/Fence/Release与原Copied CAS三阶段全部20交织 × 2回复结局 | 40 |
| `restart` | capture/release/provision/completion/copied/bind/ready/abort × prepare/invoke/effect/response后退出 | 32 |
| `boundary` | `cases.py::SPECIALS`固定41个独立边界，逐例进入inventory | 41 |

同步宏内的每个原始GET、PUT、DELETE都被observer重放，但scheduler不在所有内部I/O处插入对手；最终source屏障的中间HEAD变更用专门hook边界展示。未枚举的任意多actor、任意时长、无限release/capture/GC或所有时序不是本实验的结论。

41个边界包括：两点不同页数与current quota降低；copy冻结表/limits；同名新ID；Deleted恢复；零/部分payload budget后新attempt；protected/source/target/semantic不同失败；release前后在途prefix；已释放失败点不能重启；源撤权的5个位置；proof错误稳定Corrupt/变化Conflict；descriptor有entry/proof见证却Missing；descriptor延迟GET后撤权优先Denied；持久limits不能低于live；新target quota；first-winner输入/Name冲突；ForeignOccupied保留foreign且释放Name；referenced Completion Missing；proof不是release ACK；cleanup余量；迟到PUT新轮清扫；3世代迟到DELETE；同身份错hash的稳定/变化屏障；terminal checkpoint整体settle/clear/Unknown及余量不足；target撤权后的新resume拒绝；撤源权限仍可合法取消target；不同creator复用Name后原target/旧Bind仍fenced。

## 固定负控：38 histories

完整列表在`counterexamples.py::MATRIX`，每例固定`name / expected rule / category`。成功标准是独立observer在自身预期rule拒绝，任意解析异常、其他rule或构造失败均不算通过。

类别明确区分故意改变协议执行的`protocol`、外部损坏权威后故意忽略错误的`metadata_and_protocol`、仅篡改观察结论/原始回包的`observer`。未把任何反例声称为现有HEAD8合法API能产生的状态。具体包括遗漏snapshot闭包、CopyBasis不绑列表、释放无proof、ID复用、跨Scope原字节、Empty提前Bind/Ready、不完整prefix、旧权限、忽略HEAD2、错误expiry/Budget、条件重绑、删除受保护A、terminal漏points、普通SQL改point、损坏依赖重建、释放后新attempt、crash后前缀/unsent复用、伪造ACK/NotApplied、限额/计数越界、导入旧request、错误completion根、同身份hash矛盾、坏几何、terminal忽略q、目标权限撤回、Missing引用record继续Bind、原expected Name revision重绑、拿本人creator gate借用他人plan。

## HEAD尺寸与cleanup reserve

`codec_budget.py`直接按候选HEAD9字段与现有HEAD8上界编码：1024 ACL、64互异128-byte labels且全部需转义、CopyBasis完整重复、3结果窗口、owner marker、Copied origin、32条1024-byte ETag与完整最长key。

| 布局 | 规范JSON bytes |
| --- | ---: |
| live COPY | 164,934 |
| live sweep | 199,324 |
| terminal sweep | 157,799 |
| 所有互斥optional字段同时出现的不可达保守上界 | 242,467 |
| 既有HEAD cap | 262,144 |

最保守上界仍余19,677 bytes。该上界不是合法Rust HEAD样例；实际validator与真实serde编码必须在生产阶段独立验收，字段变更后重算。

`p=owner pending ? 1 : 0`，`c=copy plan ? 1 : 0`，`d=尚未Deleted ? 1 : 0`，`t=尚无terminal ? 1 : 0`。`q=0`（无checkpoint）、`2`（存在Pending，整体settle+clear）、`1`（已settled，仅clear）。统一checked要求：

```text
R + p + d <= MAX
S + live_points + p + c + q + d + t <= MAX
```

终态idle才没有cleanup债务；terminal后的checkpoint仍有q。Unknown局部DELETE前缀不推进HEAD，q不变；settled CAS丢ACK后新exact观察可证q=1。有限reserve不保证有计数进行无限late PUT/无限sweep；极限正例特意保留terminal中的未扫orphan，显示拒绝新checkpoint而不冒称永久全空。目录owner_epoch/Name原有计数限制须在后续产品中保持，本模型不单独证明其完整状态空间。

## 证据与后续门禁

explore一次只用1个进程，最多120秒/256MiB证据，拒绝覆盖已有目录。manifest记录789/38固定inventory、源码SHA256前后、每个原始history、具体negative rule、Python版本、尺寸报告与观察计数；失败和原history保留。测试包含独立oracle在仅有自身文件的空目录执行，不可导入model、scheduler或产品。

最终模型验收通过也只允许进入设计审查。S1生产snapshot authority/closure、S2 fresh-Scope restore，以及HTTP/SDK、四维精确单位、原生/HTTP/S3故障注入、进程退出/全冷恢复、独立oracle与controls仍须分别完成。不会把当前文档或模型预先算成PITR产品交付。
