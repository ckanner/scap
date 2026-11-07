# 名称目录与创建生命周期：待实施工作包

- 日期：2026-11-07。
- 审查基线：`e2c44b099132700e1305c275c6551c8e156fe510`，已合并 PR #27。
- 状态：**待实现、待模型审查和原生验收。本文不增加生产能力，不宣布 N1/N2 退出。**
- 范围：落实[完整方案第 10 节](object-storage-native-proposal.md#catalogue)的可恢复名称绑定；保持 S3 为唯一持久权威，不增加 PostgreSQL、etcd 或必须存活的本地目录。
- 本次执行环境在源码审查后变为 unavailable；Rust 编译、名称协议运行、覆盖率和真实 S3 名称合同均为 `NOT_RUN`。本工作包不能用主线 #27 的历史证据认证。

## 1. 当前主线与本工作包的边界

当前 `scap-object` 已有不可变 Scope、条件建库、原子 HEAD 发布、权限、显式接管/激活、取消、结果退休及 Deleted 屏障。HTTP/Node SDK 已经使用 deployment、tenant、database、incarnation、generation 五元组接入，客户端可以保存原请求并查证 UNKNOWN。参见[运行时](../engineering/object-runtime.md)、[HTTP ADR](../adr/0023-authenticated-http-and-node-sdk.md)及[路线图](../engineering/roadmap.md)。

主线没有名称 reservation、Provisioning HEAD、名称解析、名称删除/重用或名称枚举。主线 `Lifecycle` 只有 Ready、Maintenance、Deleted，`Database::create` 直接创建 Ready、inactive 的 HEAD。文档中的“名称目录在单独推进”不表示已存在可运行实现；本次核对全部远端分支后没有发现名称目录分支。

本工作包不顺带实现自动 owner 路由、长运行结果窗口协调、冷热资源硬隔离、GC、PITR 或 lazy VFS。它也不能替代完整 OT-01–OT-08 和真实 AWS Standard 验收。涉及这些能力的接口只在明确协议后增加。

## 2. 身份与权威对象

名称是可复用的人类标识；Scope 是不可复用的数据库身份。任何新建、恢复或重试都不能仅凭名称重新分配 Scope。

建议采用以下最小记录：

| 记录 | 必需内容 | 作用 |
| --- | --- | --- |
| 名称记录 Binding | 格式版本、deployment/tenant、完整名称、单调 revision、Reserved/Bound/Tombstone、固定创建意图、创建默认配额/结果留存、终态删除转换 | 名称归属与多步创建进度 |
| 固定创建意图 CreateIntent | 原名称、完整 Scope、原 principal、operation ID、预期前一名称 revision | 同一次创建在超时、崩溃和换进程后保持身份 |
| HEAD CreationIntent | 名称键的规范摘要、operation ID、原 principal；HEAD 自身保存完整 Scope | 防止把已有数据库接到另一个创建意图 |
| HEAD 生命周期 | 新增 Provisioning；继续使用 Ready/Maintenance/Deleted | 未完成目录发布的数据库不能提前开放 |
| 名称 Tombstone | 前一 Scope、单调名称 revision、原创建意图、对应 HEAD 删除转换 | 禁止旧创建/旧删除覆盖新名称归属 |

名称对象使用 deployment/tenant 前缀和规范名称的摘要寻址。摘要只是键编码；读回还必须逐字节比较完整名称和租户字段，不能以摘要相同替代记录身份核对。客户端不得传任意 S3 key 或 HEAD body。

建议第一版名称接受 1–128 字节的有效 UTF-8，拒绝控制字符，大小写与 Unicode 字节完全区分，不执行隐式 trim、大小写转换或 Unicode 归一化。这个边界需要随协议正式冻结；界面显示名可另行处理，不能让不同 SDK 自行决定同名规则。

名称记录初始只条件创建。后续修改只使用同一次 exact GET 返回的完整 body/ETag；每次转换推进 revision，溢出失败关闭。对象记录有独立编码上界，建议 64 KiB；不在单个租户 JSON 中累积全部库名。

HEAD 与 Binding 是两个 key，S3 不提供跨 key 原子事务。本协议通过单调中间态和幂等协调恢复，不能把两次 PUT 说成一次事务。

## 3. 创建顺序与同意图恢复

固定顺序为：

1. **Reserved：**按名称条件创建 reservation，或在准确匹配的名称 Tombstone 上 CAS 新 reservation。记录完整创建意图、当时确定的默认配额和结果留存。
2. **Provisioning HEAD：**在指定数据库 HEAD key 上条件创建，保存与 reservation 一致的 CreationIntent。HEAD 不处于可服务状态，owner 未激活。
3. **Bound：**确认 HEAD 属于同一创建意图后，以 reservation 的原 ETag 将名称记录推进 Bound。
4. **Ready：**重新核对当前 Bound 与 HEAD 的创建意图，以准确 HEAD ETag 将 Provisioning 推进 Ready。恢复闭包校验通过后才允许这个转换。
5. **显式激活：**继续遵守当前 takeover/activate 语义；名称 Ready 不等于执行进程已经取得活跃写者资格。

执行器每次调用只推进能够证明正确的固定意图。发生 UNKNOWN、冲突或进程退出后，后续调用读取持久状态，恢复同一意图；不更换 operation ID、Scope 或 principal，不重放 SQL，也不把原候选套到新 ETag 上。

| 观察到的持久状态 | 允许的处理 |
| --- | --- |
| 名称不存在，首次创建没有前序 revision | 条件创建 reservation |
| 名称不存在，但请求声称替换既有 Tombstone | 冲突；不能把丢失的权威记录当首次创建 |
| Reserved，HEAD 尚不存在 | 仅同一创建意图可以执行原条件建库步骤 |
| Reserved，HEAD 为同意图 Provisioning | 跳过已完成建库，尝试原名称 CAS |
| Bound，HEAD 为同意图 Provisioning | 校验后继续 Ready 转换 |
| Bound，HEAD 为同意图 Ready | 返回经过当前授权和身份核对的结果；不重建、不清空、不重新设置权限 |
| Bound，HEAD 缺失、损坏或意图不匹配 | 失败关闭；绝不自动创建空库 |
| 任意记录属于另一 Scope/operation/principal | 冲突或拒绝；不能“修复”为本次请求 |
| HEAD 已 Maintenance/Deleted | 不因 create 重入而恢复 Ready |
| PUT 响应不明确 | 保留 UNKNOWN；显式 inspect 后再决定同意图续作 |

reservation 保存创建时的配额/留存，避免另一台机器用新的进程默认值完成同一创建。数据库 Ready 后配额和权限可以由现有有序控制 API 修改；重复 create 不能回写最初值。

### 3.1 不允许绕过 Provisioning

`set_lifecycle` 不能将普通库变为 Provisioning，也不能把 Provisioning 直接变为 Ready。普通 `takeover`、`activate`、`execute`、`query`、`session`、配额/权限修改和窗口关闭都必须明确拒绝未完成创建的 HEAD。

这点不能仅靠 HTTP 层判断：主线 query/session 没有统一要求 Lifecycle Ready，未来增加 Provisioning 时必须同时修改正式 core 的全部入口。否则知道 Scope 的客户端可能绕过名称协调阶段。

仅目录协调器持有正式的 complete-provisioning 原语。它检查准确创建意图、当前权限、生命周期、恢复闭包及原 revision，再发布 Ready。这个原语不得作为接受客户端任意 intent/key 的裸 HTTP 接口。

### 3.2 竞争与迟到动作

两个不同意图争同名，最多一个 reservation 成功；失败方不能另建同名空库。两个进程续作同意图，可能出现明确 CAS 冲突，但不得形成第二个 Scope 或重复发布 SQL。

Ready 转换与删除以同一 HEAD 串行化。名称只有在原 HEAD 已成为不可逆 Deleted 后才能 Tombstone/重用。因此，一个曾读取旧 Bound 的迟到完成动作，不能在名称重用后把旧 HEAD 激活：它的 HEAD CAS 必须被删除转换 fence。

这个论证要求 Deleted 不可逆、旧 HEAD 不做 DeleteObject、名称重用必须采用新的 database ID。仅换 incarnation/generation 而复用原数据库 key 不满足本工作包的初版规则。

## 4. 名称解析与权限

`resolve(name)` 先 exact GET 名称记录，再 exact GET 其 Scope 的 HEAD，要求：

- 认证 deployment/tenant 与记录作用域相同；
- 名称记录为 Bound；
- HEAD scope 与创建来源精确匹配；
- HEAD 已 Ready；
- 当前 HEAD 对当前 principal 仍授予 READ；
- 缺失、损坏、不认识的格式或权威不可达均返回错误。

名称绑定本身不授予 READ/WRITE/ADMIN。原创建 principal 不享有绕过当前策略的永久权限。撤权后不能凭早前缓存的名称结果、旧 token 的历史授权或旧创建回执读取数据。

Ready 名称解析只返回身份/当前控制状态；SQL 执行仍走正式 Session、完整数据校验、fresh HEAD 和提交协议。不能把成功 resolve 描述成整个数据库已物化或依赖已经完成恢复。

名称缓存只允许作为寻址提示。每次需要强语义的调用最终验证 HEAD 的完整身份；不能把缓存名称指向的新 Scope 悄悄替换到已有 tracked request。旧 SDK 保存的原请求永远属于原 Scope，即使名称已经重用。

`inspect` 是 UNKNOWN 后的只读进度查询。HEAD 尚未建立时仅原创建主体或明确受信的协调角色能查看 reservation；HEAD 已建立后按当前权限授权。若允许检查 Deleted 进度，应只开放必要身份和删除转换，不能为此恢复业务数据访问。

## 5. 删除、重用与未完成创建

### 5.1 已绑定名称的删除

删除请求固定 name、预期 Binding revision、预期 HEAD revision 和 nonce：

1. exact GET Binding，核对名称、Scope、创建来源与原预期 revision；
2. 按当前 HEAD ADMIN 权限和准确 revision，以 CAS 发布 Deleted 并推进 writer fence；
3. 以原 Binding ETag 将名称推进 Tombstone，记录已持久 HEAD 的删除转换；
4. 返回成功；如果响应丢失，原身份查询/重入只核对持久事实，不再次删除另一数据库。

若第 2 步已完成而第 3 步失败，名称仍可能 Bound，但 resolve 必须因 fresh HEAD Deleted 而拒绝。续作只接受准确的原 HEAD 删除 revision/nonce；不能把另一次删除或最新状态猜作本次成功。

名称 Tombstone 已完成后，重复原删除可以返回同一终态。若名称已被新意图重用，旧删除必须冲突，不得触及新 Scope。

同名重建要求准确预期 Tombstone revision、新 operation ID、新 database ID，以及新的固定创建意图。原 HEAD/旧身份屏障永久保留；不依赖墙钟、缓存淘汰或 List 不再出现来证明旧请求失效。

### 5.2 未完成创建的取消仍须补协议

初始 create 可能在 Reserved 阶段遇到已存在但属于另一意图的 HEAD，例如受授权客户端选了冲突的 database ID。只提供“resume 到 Ready 再 delete”不能解决这种情况；不能把不可完成 reservation 永久占名而宣布生命周期完整。

因此，在 N2 整体退出前还必须冻结 `abort_create` 的规则：

- 取消 reservation 也要封闭迟到 Provisioning/Bound/Ready 动作；
- 如果 HEAD 尚不存在，必须处理在途条件创建与取消屏障的竞争；
- 不得删除/修改属于另一意图的 HEAD；
- 旧 Scope 即使没有成功建库，也不能被静默重新分配；
- 名称重用前必须证明旧意图不可能再变为可服务数据库；
- 超时只是状态未知，不能当作 reservation 自动过期。

候选是增加持久的创建取消/身份 reservation 屏障，并让 HEAD 建库与完成步骤校验同一身份；具体对象位置、CAS 顺序及回收规则需要先做模型审查。**本文不宣称仅凭 TTL 或删除名称记录就能安全取消。**

在该协议完成前，可以交付明确受限的“创建/续作/解析/删除已绑定名称”候选，但不得把名称冲突取消、无人工介入生命周期或 N2 整体标记完成。

## 6. 建议模块与 API

建议新增独立 `crates/scap-catalogue`，依赖正式 `scap-object-store::Objects` 与 `scap-object`。core 只增加最小 CreationIntent/Provisioning 及不可绕过的正式转换；目录不复制 SQL、恢复、HEAD 发布或权限算法。

以下是接口草案，不是当前可调用 API：

```rust
pub struct Create {
    pub name: String,
    pub scope: Scope,
    pub operation: u64,
    pub expected_name_revision: Option<u64>,
}

pub struct Named {
    pub binding: Binding,
    pub head: Head,
}

pub struct Inspection {
    pub binding: Binding,
    pub phase: Phase,
    pub head: Option<Head>,
}

impl Catalogue {
    pub fn new(
        objects: Arc<dyn Objects>,
        deployment: u64,
        tenant: u64,
        worker: u64,
        options: Options,
    ) -> Result<Self, Error>;

    pub fn create(
        &self,
        principal: u64,
        intent: &Create,
        deadline: Instant,
    ) -> Result<Named, Error>;

    pub fn inspect(
        &self,
        principal: u64,
        name: &str,
        deadline: Instant,
    ) -> Result<Inspection, Error>;

    pub fn resolve(
        &self,
        principal: u64,
        name: &str,
        deadline: Instant,
    ) -> Result<Named, Error>;

    pub fn delete(
        &self,
        principal: u64,
        name: &str,
        expected_name_revision: u64,
        expected_head_revision: u64,
        nonce: u64,
        deadline: Instant,
    ) -> Result<Inspection, Error>;
}
```

`create` 可以在一次调用内推进多个已证明安全的创建步骤，但不是自动 SQL 重试器。它不得在 UNKNOWN 后更换身份、延长 deadline 或无条件覆写。原意图由 SDK 在发送前持久保存；调用方明确要求续作时才以原意图恢复。

HTTP 从 bearer token 派生 principal/deployment/tenant；“允许创建”继续使用受信 provision 权限，不允许客户端自授。所有 u64 继续用规范十进制字符串；不能将 JSON number 当精确身份。SDK 不暴露 S3 key，不把名字绑定变化写回既有请求。

建议错误至少区分 invalid、denied、not_found、provisioning、deleted、conflict、corrupt、limit、unknown；不能把 Bound 的 HEAD 404 归为“名称未使用”。wire 与 SDK 必须保留这一差别。

## 7. 枚举、恢复与预算

主线 Objects port 只有 exact GET/条件 PUT，没有 LIST。这批 exact-name 设计即使落地，也只能按已知名称从 S3 恢复；不能凭客户端保存的名称列表宣称全目录重建。

后续枚举可以使用 S3 LIST **发现候选键**，再逐个 exact GET 校验 Binding、Scope 和 HEAD；不能按 LIST 顺序、LastModified 或缓存 ETag 选择当前权威。分页、续传、删除屏障、重复键、读取失败和权限失败都要保留明确状态。

在线分页枚举不天然具有跨 key 的一致快照。需要区分：

- 全计算丢失后、已确认名称记录集合的恢复；
- 与并发创建/删除交错的在线列表。

后者可以声明有界分页/最终发现，但不得声称完整瞬时目录。若产品需要准确的一致 inventory，必须先设计相应协调/索引协议。遗漏、403、未知结局和截断不能返回“完整空目录”。

预算应在实现前固定，并计入实际证明：

| 资源 | 要求 |
| --- | --- |
| 名称/记录 | 字节和编码上界；拒绝重复/未知字段、非法 UTF-8/数字及溢出 |
| 创建/删除调用 | 单一绝对 deadline；有限状态步骤；无无限自动 CAS 循环 |
| 并发 | 使用独立有界控制准入，不能让大量 reservation 挤占 lookup/cancel |
| 枚举 | 分页条数/字节、在途 exact GET 数、总调用预算和明确 continuation |
| 持久规模 | 名称 Tombstone 与 ID 屏障的长期数量/成本有独立说明；不因“无 SQL 数据”而视为免费 |
| 进程缓存 | 名称只是可丢提示；重启无需保存唯一映射，不常驻一库一线程 |

权威 key 不配置通用 TTL。名称 Tombstone、旧 HEAD 和未发布对象何时可物理回收属于 N3 协议，不由本工作包默认删除。

## 8. OT-11 / OT-14 验收工作单

每个真实场景必须调用正式 crate/HTTP/SDK，保存原 create/delete 意图、观察到的成功响应、准确对象历史与原失败。模型、单元和真实进程验证各自报告，不能混 profile 填满覆盖率。

| 场景 | 独立判定 |
| --- | --- |
| 两个不同意图争同名 | 最多一个 Scope 能成为当前可服务绑定；失败方不自动分配第二 Scope |
| 两个进程续作同意图 | 不重复创建/重置 HEAD，不重设权限/配额，不重复执行 SQL |
| Reserved PUT 前/后成功但回包丢失 | 原意图查回精确状态；UNKNOWN 不冒充失败 |
| Provisioning HEAD 前/后切点 | 未完成绑定不能通过 direct query/session/activate 开放 |
| Bound CAS 前/后切点 | Bound+Provisioning 始终不可用；恢复后使用原 Scope |
| Ready CAS 前/后切点 | Ready 已持久时原意图可查证，重启不重新初始化 |
| 全计算/本地缓存丢失 | 新进程仅凭 S3、必要配置与原意图续作；已有 ACK 对应原数据库内容 |
| Binding 存在但 HEAD 缺失/损坏/错意图 | 拒绝；观察零自动空库创建和零无条件 PUT |
| 名称/租户/数据库/creator/op 不匹配 | 拒绝，不能借另一名称绑定取得授权 |
| 当前 READ/ADMIN 撤销与查名/创建续作/删除竞争 | 依 fresh HEAD 和同 HEAD CAS 排序；旧名缓存不恢复权限 |
| HEAD 删除已成功，名称 CAS/回包失败 | resolve 拒绝旧库；原删除可按准确 transition 继续 |
| 同名重建后旧 create/delete/SDK 到来 | 旧 Scope/旧条件不能操作新库；原请求不被重写为新 Scope |
| 旧 Bound 完成动作与删除/重建交错 | 删除后的旧 HEAD 永不 Ready；迟到 CAS 不换 ETag |
| 过期名称缓存、数据库别名 | 缓存只能提示，最终身份不一致拒绝 |
| 未完成创建取消与迟到条件创建 | 在 abort_create 协议冻结后补完整切点；缺失时 N2 不退出 |
| 全目录候选枚举 | 分页发现后逐项 exact GET；缺项/错租户/截断/异常与并发边界明确 |
| 资源耗尽/超时/403/409/412/5xx | 原 deadline 内失败关闭；冲突、UNKNOWN 与不存在不混同 |
| 原始证据负对照 | 故意丢 ACK、重复身份、错根/错 principal/漏分页等必须使审计器拒绝 |

在所有实际发布边界分别暂停/终止进程。前/后端 200 后应明确区分，不从最终名字能查到推断所有切点正确。需包含并发历史，而不仅是顺序 happy path。

新 crate、所有 core 改动、HTTP/SDK 入口都进入正式生产文件分母；逐文件行/函数/region/分支精确 100% 单元门禁保持不变。真实 S3兼容端点与 AWS Standard 分开，候选冻结前后源码、构建、native archive 与原始证据按[本地验证规范](../engineering/local-validation.md)核对。

## 9. 实施次序与仍需决定的事项

1. 先冻结创建取消/身份占用模型、名称字节规则、错误与预算；列出可达与禁止状态，验证迟到创建/完成/删除的交错。
2. 增加 core CreationIntent/Provisioning 和入口阻断测试，确认旧直接 create 的显式接口仍可用，不能把旧直接 HEAD 收编为命名创建。
3. 实现独立 catalogue、严格格式与原子状态转换，测试故障注入、同意图恢复和名称重用。
4. 接入有界 HTTP 控制操作与保存原创建意图的 SDK；SDK 的现有 tracked SQL 身份保持原 Scope。
5. 完成真实 OT-11/OT-14 与独立账本/历史审计，再记录阶段性完成。
6. 独立实现、验证名称枚举和完整启动恢复；推进自动 owner 路由、冷热活性，最后才能判断 N2 是否退出。

未完成决定包括：未完成创建取消的持久屏障、全局不可复用 ID 的分配/占用机制、在线列表的一致性合同、协调角色跨 principal 的权限、名称 Tombstone 长期成本和紧急撤权时的协调方式。不能用进程内映射、随机 ID“几乎不碰撞”、墙钟 TTL 或无界重试替代这些合同。

本文件是可审查的下一步实现工作单；最终能力以正式代码及与候选绑定的实际验收为准。
