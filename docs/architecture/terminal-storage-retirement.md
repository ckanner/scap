# Deleted 最后一代数据的永久终态退休

状态：**HEAD7 产品候选接口与核心实现已完成，源码尚未冻结，正式验收 NOT_RUN**。本稿以 `66f452ec73111f8c9dc7509883717828ba883e8a` 的 HEAD6 产品为基线；HEAD7 在独立工作树中实现，不修改已经冻结的 HEAD6 源码，也不授权旧 HEAD6 清扫 Deleted 的最后 active generation。开发阶段定向单位与模型自测用于继续审查，不能继承 HEAD6 的正式通过结论。

HEAD6 已有 live database 压缩、放弃 target 的永久退休和可重启 GC checkpoint。这里补齐另一个独立条件：一个逻辑数据库永久删除后，如何明确解除最后物理世代的保护，同时保留目录恢复与旧请求的屏障。本文沿用 [HEAD6 压缩与 GC 协议](head6-compaction-gc.md)，不重做复制、conditional DELETE 或普通读 pin 协议。

## 1. 当前产品的准确边界

以下是基线源码的行为，而不是未来设计假设。

| 现有合同 | 源码与含义 |
| --- | --- |
| 新 lookup、status、SQL 在 Deleted 后不可进入 | [`Database::authorize`](../../crates/scap-object/src/lib.rs) 先拒绝 Deleted/Provisioning，再检查权限；`lookup` 在创建数据 context 前调用它。因此当前合同没有“删除后仍可新查 retained Result”的承诺。 |
| 直接删除与具名删除入口不同 | `Database::set_lifecycle` 禁止给 `creation.is_some()` 的 HEAD 直接设置 Deleted；具名删除必须经过 [`Catalogue::delete`](../../crates/scap-object/src/catalogue/control.rs)。直接删除目前不强制清除历史 `active` 标志，但新请求仍由 Deleted 拒绝。 |
| 最后 A 尚未退休 | [`Storage::retired`](../../crates/scap-object/src/storage.rs) 仅接受 `1 <= g <= M && g != A && g != current_target`。[`maintenance_base`](../../crates/scap-object/src/reclamation.rs) 还要求 Ready，所以目前不能给 Deleted HEAD 安装 GC checkpoint。 |
| 名称释放依赖真实删除记录 | `Catalogue::delete` 在新 admission 或旧 operation 重入时都检查当前 ADMIN；若 HEAD 已引用删除 mark，先 `delete_source` 核对已存在的原 control，不能用调用者字段重新创建一个缺失 control。 |
| 取消证明绑定原业务 transition | [`Catalogue::barrier`](../../crates/scap-object/src/catalogue/mod.rs) 对 `OwnDeleted` 要求 `head.transition == proof.transition`；`Head::validate_named` 还要求正常删除的 `expected_head_revision + 1 == revision`。 |
| HEAD 位置永久占用 | [`head_key`](../../crates/scap-object/src/format.rs) 由 deployment/tenant/database 定位，完整逻辑 Scope 另含 incarnation/generation。删除 HEAD 会重新开放 Absent 创建条件；不能把它当 payload 清理。 |
| 目录可以只靠元数据恢复 | `Catalogue::view`、`deleted`、`barrier`、`tombstone_view` 与 [`recovery_job`](../../crates/scap-object/src/catalogue/recovery_job.rs) 对 Deleted 的分类不需要重新物化 SQLite 数据根。 |

在当前封闭 mutator 集合中，Deleted 已不可逆；不能声称“只要直接删 A 就一定存在一个当前可执行的复活路径”。但当前格式仍把 A 定义为受保护的数据 namespace，没有显式解除根依赖的状态，也没有允许这种清扫的验证器。必须新增一个可识别、不可撤销的协议边界，才能使旧 context 的失败分类、checkpoint 验证器、目录恢复和所有消费者达成一致。

## 2. 最小协议：一次显式终态 seal

新增终态技术转移 `RETIRE_STORAGE`：**在真实 own Deleted HEAD 上，用该次 exact GET 的原 ETag 做一次 CAS，安装永久 terminal seal。** 不复制数据，不增加业务 revision，不产生新的 SQL 请求身份，也不删除永久 HEAD。

| 转移前 | 转移后 | 允许改变的字段 |
| --- | --- | --- |
| HEAD6、Deleted、无 plan/sweep、当前 ADMIN、完整删除来源已核实 | HEAD7、Deleted、inactive、terminal 已安装 | `format`，`head_serial += 1`，`active = false`，`storage.terminal` |
| HEAD7 terminal、无 sweep | HEAD7 terminal、有 sweep | `head_serial` 与 `storage.sweep`，仍使用原 HEAD CAS |
| HEAD7 terminal、有 sweep | HEAD7 terminal、确定 dispositions / 无 sweep | 仅 `head_serial` 与 `storage.sweep`，沿用 HEAD6 checkpoint 合同 |

从 terminal 没有返回 Ready、Maintenance、Provisioning、HEAD6 或重新分配世代的转移。`A` 与 `M` 永久冻结；A 留作历史最后世代编号，**不再表示有一个必须保留的数据 namespace**。`owner_epoch`、`owner_instance`、`auth_epoch`、policy、sequence、revision、transition、quota、retention、request_epoch、windows、data_root、creation、deletion 均保持原值。现存根字段是删除历史记录，不再是允许新的 payload 读取或必须保留的闭包边。

对于 decode 成功、完整 Scope 相同的权威 HEAD，退休谓词变为：

```text
valid_generation(g) := 1 <= g <= allocated_through

retired(g) := valid_generation(g) &&
  (terminal_present || (g != active_generation && g != current_target))
```

这是对验证过的 HEAD 的判断，不能从调用者提供的 `terminal=true`、LIST 内容或独立 Storage struct 推断权限。terminal 之前仍按 HEAD6 保护 A/T；terminal 之后所有已分配世代均永久退休。`g > M` 不能因 terminal 自动获得清扫授权，未分配 namespace 与 losing Scope 的 bootstrap orphan 仍需单独证明。

### 2.1 HEAD7 wire schema

只为终态引入 format 7；未退休的 HEAD 仍保持精确 HEAD6 schema，不做全库格式迁移。HEAD7 保留 HEAD6 顶层字段，storage 增加一个必填且非空字段：

```text
format: 7
storage:
  active_generation: A
  allocated_through: M
  plan: null
  sweep: null | <现有精确 SweepCheckpoint>
  terminal:
    serial: s
```

完整校验要求 `1 <= A <= M < s <= head_serial` 且 **`revision < s`**，lifecycle 必须 Deleted，active 必须 false，plan 必须 null。首次 seal 的 `s` 等于新 `head_serial`；后续技术转移不得修改 s/A/M。最后业务 revision 不超过封口前的 head_serial，seal 再把 serial 加一，因此 `revision >= s` 是单份 HEAD 就能识别的不可能状态，不能作为 final-A 退休证明。seal 的 admission 不接受旧 sweep，因此后续 checkpoint 还必须满足 `s < sweep.serial <= head_serial`。没有 holds 字段；当前片段的 holds 固定为空。未来若增加 retained snapshot / PITR roots，必须修改终态 admission 与保护集，不能自动沿用“全部退休”。

HEAD7 草稿采用一次从原始 bounded bytes 进行的 typed serde 解析，并在严格验证器中交叉检查版本与字段是否存在。`storage.terminal` 缺失时取 None；字段存在时，专用 `present_terminal` 必须解析出非空的 `TerminalSeal`。因此 HEAD6 显式 `terminal:null`、HEAD6 带 seal、HEAD7 缺字段或 null 都拒绝。`deny_unknown_fields` 与 serde 字段重复检查继续生效，不通过宽松 `Value` 重编码后再解析。编码仅为 Some seal 输出字段，再由格式验证保证 HEAD6 不输出 terminal、HEAD7 必须输出它。这与两个严格 wire schema 的合同相同，不依赖宽松的版本回退。

旧 binary 收到 HEAD7 必须格式失败关闭。它此前准备的 HEAD6 CAS 仍保留原 ETag，必定被后继 HEAD fence；旧 Absent HEAD PUT 被永久存在的 HEAD 阻挡。升级不要求旧请求已经消失，不从进程死亡、租约或 TTL 推断安全。要在部署启用此操作，全部读取 HEAD 的产品消费者必须理解这个版本边界。

### 2.2 terminal 数据根不能重新成为可执行 authority

新的强读、lookup、SQL、owner activation、compaction、请求窗口修改和 ACL 修改继续被 Deleted 拒绝。目录元数据读与专门的 terminal 管理读允许进入，但不能返回可用于 payload 遍历或重新发布普通业务的 token。

实现时应明确区分普通 `DataAuthority` 与 `TerminalAuthority`，或者让所有 payload context 工厂显式拒绝 terminal；不得只依赖某条 HTTP 路径曾检查过 lifecycle。封装终态技术候选的私有构造器只能改变上述字段。必须审计 `ObjectContext::from_snapshot/capture/target`、closure/recovery 工厂和 `PreparedHead::new/technical` 的全部调用点，证明任何新建 terminal 数据 context 都失败，旧 context 仍绑定原 namespace。

## 3. admission：直接数据库与具名数据库

输入只包含受信 admission 的 principal、完整数据库身份和 expected_head_serial；具名入口另外引用原 Creation。客户端不能传 prefix、key、ETag、业务 transition、原 control 的替代 body 或一个“已验证”布尔值。

建议接口分工如下，具体 HTTP action 沿用现有 service 分发结构：

```rust
Database::retire_storage(
    principal, expected_head_serial, deadline
) -> Result<Head, Error>;

Catalogue::retire_storage(
    caller,
    RetireNamedStorage { creation, expected_head_serial },
    deadline
) -> Result<Head, CatalogueError>;

Database::storage_status(principal, deadline) -> Result<Head, Error>;
Catalogue::storage_status(caller, &Creation, deadline)
    -> Result<Head, CatalogueError>;
```

直接入口要求 `creation == None && deletion == None`。具名入口必须由 [`catalogue/terminal.rs`](../../crates/scap-object/src/catalogue/terminal.rs) 构造私有 `VerifiedDeletionSource`，随后把该次 exact HEAD snapshot 交给私有 `retire_named_storage/retire_deleted` 技术候选构造；它不能调用一个只检查 lifecycle 的公共通用退役函数。`publish_technical` 再限制终态之后只有 serial 与 sweep 可变，最终仍由持有原 ETag 的 `PreparedHead` 一次发布。

`storage_status` 是专门的 Deleted 管理元数据观察，要求当前 ADMIN；直接与具名路径分别执行自己的身份/来源检查，不能替代普通 status/lookup，也不授予可执行 Snapshot。service 复用现有状态投影，增加必填 `storage.terminal: null | {serial}`；这是 API 的归一字段，不表示真实 HEAD6 wire 允许 `terminal:null`。直接 HTTP action 为 `storage_status/retire_storage`，具名 action 为 `named_storage_status/retire_named_storage`，避免 SDK transport 的全局 operation 分类冲突。两个客户端均可公开 `storageStatus/retireStorage` 方法。

seal 仅做普通 Objects 的 HEAD CAS，不依赖 GC enabled；实际 `gc_prepare/gc_resume` 继续要求已有独立 collector。成功 seal 的 `head_serial == expected_head_serial + 1 == terminal.serial`，没有 plan/sweep。序号冲突或已经 sealed 返回 Conflict；直接入口的非 Deleted/具名对象拒绝为 Lifecycle，具名来源冲突沿用 Catalogue 的 Conflict/IdentityConflict；缺失权威为 Corrupt，不增加新的错误枚举。Unknown 原样保留，status 只陈述已观察状态。

具名 admission 沿用真实 descriptor、Control、Name、AbortProof 的关系，不能只信 HEAD 内嵌 mark。`Catalogue::view` 的 Name→Proof→HEAD→Name 顺序与 Name 双读必须保留：证明先于所验证的 HEAD，后一次 exact Name 检查区分变化中的名称与稳定但矛盾的元数据。任何必需 record 缺失、scope/origin/nonce/operation 不同、Head 与 proof 矛盾都失败关闭，不重建原 intent。

### 3.1 正常具名删除

必须确认 own Scope 与 creation origin、当前 ADMIN、真实 durable delete control、HEAD 内 mark 与该 control 完全相同，以及原 expected name/head revisions 的关系。允许以下状态安装 seal：

- HEAD 已 Deleted，原 Name 仍 Bound，等待原操作 Release。
- 原 Name 已成为 Deleted tombstone。
- 名称已被合法新 Creation 复用，旧 HEAD/descriptor/control 仍完整，名称 revision 已严格越过旧释放屏障。

seal 不等 Name Release，避免把目录进度引入物理安全条件；但原删除操作必须能在 seal 后继续 Release/Done。当前 `delete_plan` 在入口 blanket 拒绝 `storage.sweep.is_some()`；后续实现要把 guard 移到**可能 Publish 业务 HEAD 的分支**。已验证的 terminal Deleted 分支只能更新 Name 或返回原删除进度，可以与 terminal sweep 共存，不能改原业务字段。

### 3.2 创建取消：OwnDeleted 与 FenceAbsent

只有原 Name 已接受 Aborting、own HEAD 已完成 Fence 或 FenceAbsent，才可进入 terminal admission。FenceAbsent 先持久化一个永久 Deleted HEAD，因此没有 HEAD 不是“可直接清空”的状态。`ControlAdmitted`、Reserved 或 Provisioning 都不够。

若 `OwnDeleted` proof 已存在，seal 必须保留 proof 所引用的完整 transition；若 proof 尚未产生，seal 后原取消仍可生成同一 proof，再 Release。两条路径都只使用元数据，允许与 terminal checkpoint 共存。原 operation 再入仍核对原 control，不替换 nonce，不拿新 expected revisions 把旧操作改造成另一个意图。

### 3.3 ForeignOccupied 不属于这次 final-A 回收

`ForeignOccupied { scope, creation }` 表明旧创建没有获得这个永久 HEAD 位置。它可以支持旧名称取消，但**没有授予对 foreign Scope 的 ADMIN，也没有证明 foreign A 已退休**。终态入口应返回 IdentityConflict；原取消入口仍核对 creator、真实原 control 和 foreign barrier，只执行 Name Release/Done，不能因为终态入口拒绝而阻断原取消。foreign 数据库继续使用自己的 authority。模型包含丢 Name Release 回复后重启并恢复原 Aborted 结果的正例，同时核对 foreign HEAD/payload/proof 原样保留。

失败创建可能已在自己的完整 Scope 下写入 bootstrap orphan，而当前 HEAD slot 属于另一个 Scope。回收这些 losing Scope orphan 需要一个永久绑定该旧 Scope 的 retirement proof，且不能改 foreign HEAD；这是另一个明确剩余项，本稿不会借终态标记顺便放开。

## 4. 读、知识谱系和原回执

没有 ordinary read pins。terminal seal 与 HEAD6 的可中止读一致：已进入的旧读可以完成它已经完整、正确物化的原结果；若后续 raw 依赖因清扫失败，该执行前缀立即关闭，不换代继续读取，也不重放 SQL。

[`ObjectContext::physical`](../../crates/scap-object/src/object_context.rs) 继续只允许一次原 backend/meter/deadline 的 exact HEAD 调查。完整 Scope、serial/A/M 单调性、同 serial 的 body/ETag 一致性、后继 serial 与原 ETag 的 fence 都必须核实。只有这次证明原 g 已退休，才返回 `SnapshotExpired`。调查 UNKNOWN、超预算、超时或仍为 HEAD6 protected A 时保留原故障；hash-valid 内容语义坏、native InvalidImage 和 authority 矛盾仍进入全局 latch，不能用 terminal 转成正常过期。

旧 context 必须从非 terminal 的 HEAD6 入场，因此新鲜 HEAD7 的 `terminal.serial` 还必须严格大于原 `basis.head_serial`。例如原 HEAD6 revision=2、serial=100、A=M=1，随后调查得到 HEAD7 serial=102、terminal.serial=3：该 HEAD 单独满足 `revision < terminal.serial`，但结合原 context 就是一个不可能历史。它意味着终态之后曾出现新的 HEAD6 authority，必须全局隔离，不能正常 expiry。物理失败调查仍返回原 raw 错误；若原失败是 Missing，对外保持 MISSING，同时该谱系进入全局隔离。静态 HEAD7 格式矛盾则由普通解码直接返回 CORRUPT。

知识谱系仍遵守 HEAD6：Database clones/Session/context 共享知识；独立构造是新谱系，必须从新鲜 authority 开始新的尝试。每-g 物理 incident 不能升级成所有新 namespace 的损坏，也不能凭“terminal 已观察到”清掉无关 semantic latch。

这里需要一个明确的健康检查差别：

- **安装 seal** 是从原 protected A 退出的发布，仍执行原 A 与全局知识门禁。
- **seal 后的终态 GC 技术发布** 没有 active payload namespace，只检查全局 authority/content-semantic latch，不因历史 A 的旧物理 incident 阻止永远退休 namespace 的 checkpoint 进度。

后者不是清除 incident，更不是 `healthy_in(A)` 失败后重试绕过。应在 `PreparedHead` 的类型中表达 `LiveGeneration(A)` / `TerminalMetadata` 发布域，让 `publish_healthy` 按候选的真实域检查。已准备或已发出的原具体请求仍按原条件执行；另一个操作后来的 latch 不会撤销网络请求。

原 SQL 已知 durable receipt 的后续结果物化/native 失败，仍必须返回 committed-unavailable 并保留原 receipt。终态不能把已知提交降成 Unknown、NotApplied、cancelled 或 SnapshotExpired。删除后的新 lookup 继续返回 Lifecycle；如果产品未来要支持删除后结果查询，必须另行保存独立结果闭包，不能在这里偷偷改变保留合同。

## 5. GC、迟到请求与 UNKNOWN

terminal GC 复用现有最多 32 项的 checkpoint、原 ETag 和 dedicated Garbage 能力，不引入第二套删除器。GC prepare 可接受 Ready 的 HEAD6 已退休世代，或 HEAD7 terminal 的已分配世代；不得只把现有 `ready()` 删除而允许所有 lifecycle。

| 在途操作 | seal / GC 后允许的结果 | 必须维持的条件 |
| --- | --- | --- |
| 旧 HEAD If-Match PUT | 原条件 412；无新 authority | 永远保留原 ETag，不重新基于 terminal 生成旧业务候选 |
| 旧 initial HEAD Absent PUT | 永久 HEAD 存在，条件失败 | 永不回收 HEAD slot |
| 旧 payload GET | 已物化有效值可完成；实际 raw 失败可经严格证明转 SnapshotExpired | 原 namespace、原 deadline、一次诊断；没有跨世代拼接 |
| 旧 payload Absent PUT | 可在已扫 namespace 重建 orphan | 不能更改永久退休；后续从起点再扫 |
| checkpoint 的原条件 DELETE | Applied、typed NoSuchKey、实际 Conflict 或 Unknown | exact inspect 不能刷新 checkpoint ETag；不同 ETag 也要发原条件 DELETE 才能登记 condition_mismatch |
| checkpoint 已 clear 后才落地的旧 DELETE | 仍只会作用于原退休 key/条件 | 安全来自不可逆退休，不来自“每个 DELETE 前再读 HEAD” |
| seal CAS 丢响应 | 原调用 Unknown；随后可能仍落地 | fresh status 只报告 terminal observed / unsealed，不能把 unsealed 观测变成原调用永久 NotApplied |
| DELETE 丢响应，进程重启 | 原调用仍 Unknown；新 exact NoSuchKey 可成为新 observed_absent 证据 | NoSuchBucket、普通 404、异常 body 不能代替 typed NoSuchKey |
| 旧 Name Release / AbortProof PUT | 可继续完成同一原意图 | 原 Name ETag / immutable Absent、原 descriptor/control/proof 身份不变 |

GC resume 的新鲜 exact 同 batch 授权覆盖一次有界最多 32 项前缀，不是每个 DELETE 再读一次 HEAD。全部确定 disposition 必须以原 HEAD CAS 持久化并 exact 观察，之后才能 clear。checkpoint 安装、settle 或 clear 的响应丢失都不得自动 rebase。status 与新调用重入只描述当前状态，不伪造旧调用回执。

ETag 不必是每次重新写入都不同的 payload 版本号。同 bytes 重建可能得到相同 ETag；迟到原 DELETE 此时可能删除重建的 orphan，仍安全，因为这个完整 Scope/g/key 永远不会重新成为 protected。HEAD 另有单调 serial 与原条件发布，不允许 authority ABA。

“扫描一轮结束”不是“以后永久为空”。成本收敛还要求旧操作数量有限、在途 PUT 最终结束、存储持续可用、公平重复从起点扫描，以及 GC 服务能力高于持续 orphan 到达率。永不删除小型永久 HEAD/目录记录意味着本方案保证 payload 可回收，而不是每个删除数据库占用零字节。

## 6. 有界模型与继承假设

独立模型位于 [`experiments/object-terminal-retirement-model`](../../experiments/object-terminal-retirement-model/README.md)。它不导入生产代码，oracle 也不导入 model、候选构造器或 scheduler。它是协议设计的有限投影，不是实际 S3、SQLite、serde 或 Rust 实现的证明。

模型显式记录四阶段 `prepare → invoke → storage effect → client response`。超时可以先于 effect；进程 crash 丢弃未发送候选和本地 handle，却不撤销已调用的请求。它保留 raw 条件、body、GET 观测、原 caller、checkpoint ETag 和各 response，oracle 从事件重放存储与客户端知识，不能只相信“已验证”“已退休”标签。

范围包括 own direct/delete/abort/abort-absent 与 foreign occupied、两个固定终态候选的竞争、旧 GET/PUT/HEAD CAS、一个 checkpoint 项、实际目录元数据读取与原 intent、UNKNOWN、一次重启、知识故障和保留回执。Name 的 Proof→HEAD 与双读顺序被记录；该同步复合步骤内部的每次 GET 交织没有穷举。新名称对应新的永久 HEAD slot，是一个已验证创建完成的抽象转移，不重建全部创建协议。

继承条件与本模型展示的边界如下：

| HEAD6 基础条件 | 本片如何使用；没有证明什么 |
| --- | --- |
| 所有合法 HEAD 满足 `1 <= A <= M <= serial`，分配只用 M+1，退休 A/T 永不复用 | 模型验证计数器/terminal 单调性，展示 A/T/abandoned 的退休谓词；不重新穷举完整 COPY/Seal/Promote/Abort。 |
| immutable frame 按完整 Scope/g/key 隔离，Absent PUT 与 HEAD/DELETE 原条件语义正确 | 有 fresh/content 两种 payload ETag 行为，原网络条件独立重放；不证明 AWS 或兼容端点实现。 |
| 旧 context 绑定实际 backend、Scope/g、原 HEAD body/ETag 与原 deadline | 模型跟踪一个旧读前缀和独立 post-crash 谱系；不覆盖生产 64 context/slot 的容量组合或所有线程交织。 |
| hash-valid 语义错误与物理错误、Budget 来源分开 | 使用有限 fault 类别验证错误投影；不测试实际 hash、JSON、typed-edge 或 native SQLite validator。 |
| 目录 immutable records 与 Name revision 单调、当前管理员 admission 正确 | own/foreign、原 control、业务 barrier 与元数据恢复参与 trace；不替代现有 Catalogue 全状态模型与实际 HTTP/S3 门禁。 |
| 无 retained roots / holds | 因而 ordinary 读可中止；本片不能用于宣称 PITR snapshots 可随源库一起删。 |

当前工作树只含较早的 [`object-authority-model`](../../experiments/object-authority-model/README.md)。PR43/49 的 GC/handle 模型不在本树，本片没有取回并证明它们与 HEAD6 等价；引用设计思路或 core unit 覆盖不能冒充该证明。

模型计数、实际运行命令、原始输出目录与已保留反例记录在新模型 README 和每次运行 manifest 中。已发布 `1219d35700c0a634f5876ae033bbeb9e0a6b79f8` 的旧有限域有 43 个自测、1,212 正向 histories 与 19 条预期反例；这些历史结果不覆盖随后发现的 `revision < terminal.serial` 规则。HEAD7 工作树对 model 与独立 observer 分别补上该规则，并增加独立 malformed HEAD 自测和第 20 条 metadata/observer 变异。新的 `terminal-model-validation-20261110-03` 已通过 44 个自测、完整 1,212 正向 histories 和 20 条预期反例，正向历史仍记录 51,571 events、3,697 个宏状态与 3,778 条宏边；其源码指纹与 manifest 独立保存，不追认旧结果。旧 Provisioning ordinary-read 不可达前缀及先前源码也保持独立诊断。没有使用这些研究测试补生产单位覆盖，更不把有限模型通过标为 HEAD7 产品已经验收。

## 7. 后续产品实现与验收顺序

这是一个可连续交付的小型协议扩展，但必须一起接通所有 authority 消费者，不能先放开 DELETE 再补格式与目录恢复。

| 批次 | 拟修改文件 / 责任 | 完成条件 |
| --- | --- | --- |
| 核心格式与候选 | `crates/scap-object/src/{format.rs,storage.rs,head_publication.rs,object_context.rs,reclamation.rs,lib.rs}` | 严格 V6/V7 wire、私有 terminal candidate、payload context 拒绝终态、新退休谓词、live/terminal 健康域、原 receipt/expiry 语义全部贯通。 |
| 真实目录组合 | `crates/scap-object/src/catalogue/{mod.rs,control.rs,inspect.rs,recovery_job.rs,types.rs}` 及相关 discovery 消费者 | own 删除来源、proof-before-HEAD / Name 双读、原意图重入；terminal sweep 不阻止纯元数据 Release/Done；ForeignOccupied 不获清扫权。 |
| service 与 SDK | 现有 service control/recovery admission、status/wire 与 `sdk/node` 对应 decode/client/types | 专门的 terminal 管理观察与一次 POST；不自动重试旧操作；不暴露 ETag/key；已删除普通调用仍是 Lifecycle。 |
| 真实验收 | 新的 terminal runtime fixture，与冻结 HEAD6 fixture 分开 | 正式 binary、native SQLite、签名 HTTP/S3、真实进程退出、原始独立 history oracle 与定向负控。 |

必须覆盖的验收事实：

1. 正常具名删除、OwnDeleted 取消、FenceAbsent 三条真实目录路径，都能在 Name Release 前后 seal；proof 已存在与稍后产生两种次序都保持原 transition；名称复用后旧 intent 仍恢复为原结果。
2. 缺 descriptor/control/proof、错误 nonce、不同 creation、foreign slot、改变中的 Name 都失败关闭，绝不从请求补造缺失权威。
3. 终态前 A 无法 GC；seal 的原 CAS 丢响应并晚于 status 观测落地，仍保留原 Unknown；两个固定候选只有一个条件成功；旧 owner/initial-create 请求都不能复活库。
4. 已保存原结果不变；旧 GET 在删除后失败要 fresh-prove 才 Expired；hash-valid 语义坏和 authority 矛盾始终坏；seal serial 必须晚于最后业务 revision 与旧 HEAD6 context，checkpoint serial 必须晚于 seal；Budget 不读额外 HEAD、不 latch；同谱系/独立谱系与 terminal metadata 发布域均有针对测试。
5. 最后一代和既有 abandoned 代都可安装/恢复 checkpoint；32 项、分页、重启、DELETE 丢响应、真实同 bytes 不同 ETag、实际原条件 412、NoSuchBucket、迟到 PUT 再扫、clear 后迟到 DELETE 都有原始证据。
6. 永久 HEAD/descriptor/control/proof 不在 payload GC 的 key 集合；邻接新 Scope、新同名数据库及 foreign 当前数据库字节完全不受影响。
7. 所有新增/受影响产品文件继续满足逐文件行、函数、region、分支精确 100% 单位覆盖；独立 actual 门禁通过后才启用。模型通过不是替代项。

终态 final-A 之外的明确剩余项包括：foreign slot 下 losing Scope bootstrap orphan 的永久证明、独立 Scope archive/PITR、长期 retained roots/holds，以及自动 owner 调度。这些不能由 terminal seal 顺带宣称解决。
