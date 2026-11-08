# 全目录元数据发现：协调器合同

状态：N2-B 开发实现。本文不宣布全目录冷恢复或 N2 整体退出。真实 S3 发现、全计算丢失后的 data/result/native 验收，以及合并候选的完整单元覆盖门禁仍须独立运行。

## 权威与范围

`RecoveryInventory` 只从配置中的 `scap-object/v1/{deployment}/` 开始。调用者不提供已知 tenant、名称、Scope、对象键或数据库数量。它按有序 LIST 发现 tenant，再逐个处理 `name/`、`create/`、`control/`、`abort-proof/` 和该 tenant 的数据库子前缀。数据库子前缀用 delimiter `/`，不枚举全部业务块。

元数据对象必须 exact GET、严格解码并核对实际 key、完整来源及 namespace。名称、创建意图和控制意图复用正式 `Catalogue::view` 的 `Binding → AbortProof → HEAD → Binding` 稳定读取顺序及原有来源、屏障校验。名称在候选读取与稳定视图之间变化时保留原前沿并返回 Conflict。LIST 的 ETag、Size 和 LastModified 均不作权威。

发现覆盖 direct create、历史同名重用留下的永久 HEAD、尚未 reserve 的创建意图、未完成控制及取消证明。仅有上传子前缀且没有 HEAD 的候选明确为 `OrphanPrefix`，不会建立空库。被名称等权威引用的 HEAD/descriptor/control/proof 缺失仍为 Corrupt。

记录按种类保留语义：Name/Create 显示创建和名称状态，Control 区分仅准入的意图与由实际名称、HEAD、proof 确认的接受/终态，Head 显示其物理生命周期。旧控制 descriptor 存在不代表它赢得了竞争。各记录是独立观察；记录集合不是跨 key 一致快照。

可信 inventory 的 Control 项同时返回 `ObservedControl`：实际持久准入的 kind、principal、operation、expected_name_revision、可空 expected_head_revision 和 nonce。结合该项的完整 Creation，恢复客户端能够保存原控制意图，不能自行重造条件。其他种类的 control 字段为空；这些只读元数据不授予替原主体续作的权限。

## 能力与普通列名

`RecoveryCapability::trusted_deployment` 必须来自可信恢复配置或经过验证的专属部署 inventory 能力。`provision`、数据库 ADMIN、普通用户 JSON 均不是该能力。恢复能力只允许元数据分类，不允许执行 SQL、自动 takeover、替换 creator 或续作控制动作。用于分类的 Objects 包装器拒绝任何 PUT。

`VisibleNames` 绑定由可信认证选择的 deployment/tenant。每页传入当前真实 Caller。每个名称共享正式 `resolve` 使用的稳定视图与 `Database::permission` 原语，在该视图实际读到的 fresh HEAD 上检查 READ，不再为元数据分类和授权重复读取两套证据。ADMIN 和 provision 不隐含 READ。中间态和明确 READ 拒绝项不输出名称、Scope 或失败计数。永久 Binding 丢失为 Corrupt；合法换绑或删除使名称视图变化时返回 Conflict，并不推进前沿。权限的读取线性化点是本次 HEAD GET；与其重叠的后续撤权不会追回此前合法观察，下一页仍重新读取权限。

原始 inventory key、成本计数和内部 cursor 均不是普通用户 wire DTO。HTTP 层负责只投影授权数据，并隐藏被过滤名称的键前沿。

## 预算与前沿

单次调用最多 4 个 LIST 页、128 个候选、512 个 exact GET、4 MiB LIST 响应、16 MiB 解码元数据。调用者可以调低预算，不能提高。单次绝对 deadline 同时受调用者期限和 5 秒上限约束。所有嵌套目录 GET 共用同一计数器、字节预留和原始 deadline；没有隐藏重试。

LIST port 的每页上限为 32 项、1 MiB。为在发请求前保证字节预算，剩余 LIST 预算小于完整一页上限时不发请求。LIST 发请求前保留整页上限，GET 保留本次 allowance；成功收到有界 body 后才按实际 body 大小返还差额。Objects/Listings 的失败结果不携带可靠的已消耗字节数，因此失败保留全部预留；已收到成功 body 后才检测到 deadline 的调用仍按该 body 已知大小计费。候选和 GET 的失败尝试消耗调用次数。usage 是保守预算消耗，不是实际网络计费、进程 RSS 或底层 HTTP 开销；实际传输字节须另外读取原始 wire 证据。

协调器只在该候选完整分类后推进前沿。候选 GET 失败、名称竞争或预算不足时，已经完成的条目随原始 continuation 返回，未分类尾项下一页重读。`ListEnd::More.after` 只是网络页末，不能用于跳过未分类项。每个 tenant 的全部阶段完成后才提交父级 tenant 前沿，常驻状态不包含整个 tenant 列表。截断零项、错误或不明结果不变成完整空目录。

每次调用的并发是串行，恢复服务仍须在外层实施全局/tenant 准入和总作业预算。可重放 cursor 不是硬性计费配额，不能阻止用户重复支付同一段扫描成本。

## 内部 checkpoint

`checkpoint` 生成私有格式的规范 JSON；`resume_authenticated` 拒绝大于 8192 字节、未知/重复字段、非规范编码、错误 schema、namespace、principal、阶段或前沿的状态。方法名明确要求服务先验证包裹它的 AEAD cursor，包括 view、部署配置、当前身份、启动 epoch 和过期时间。结构校验不能证明调用者声称的“此前已分类”历史，明文 checkpoint 不得直接接受为用户凭据。

原始内存 cursor 还绑定创建它的实例。实例丢失后可以从 deployment 根重新扫描；不能把无法恢复的 cursor 解释为空目录或完成。HTTP 负责编码保护和重启后的明确 `CURSOR_INVALID`。

## 完成语义

- `traversal_exhausted`：所有阶段均观察到有效未截断终页，当前没有未分类候选。
- `preexisting_slots_covered`：在权威键永久保留、支持的后端提供有序完整 LIST 的前提下，覆盖首次扫描开始前已存在的全部权威槽。扫描期间新增的键可能在本轮出现；字典序不大于已提交前沿的新键可以留到下一轮。
- `metadata_classified`：此条扫描 continuation 中累计完成的记录分类数，包含明确 orphan 候选，不是数据库总数或某个瞬时快照数量。
- `data_recovery = NotRun`、`recovery_complete = false`：元数据分类始终保持这些值。没有验证任意业务页、全部保留结果或 native SQLite 文件。

永久键被物理删除、无序后端或后端用合法响应隐瞒未知键都会破坏上述覆盖推导。协调器不提供不信任 LIST 时的密码学完整性证明。后续 GC 不能回收本合同所依赖的永久 authority key。

严格冷恢复作业必须另外从这份发现结果逐项读取当前权限，验证所有应恢复数据库的完整 data/result 闭包、原始结果及 native SQLite 结构。permission_blocked 必须保留为未验证项并使严格 `recovery_complete` 为 false；元数据恢复能力不会代替 SQL READ。按需物化或只查询几个已知名称，均不能替代该门禁。
