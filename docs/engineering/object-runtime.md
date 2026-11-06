# 对象原生运行时 v2

主入口是 `scap_object::Database`，用 `Arc<dyn scap_object_store::Objects>`、不可变 Scope、非零 worker identity 和 `Options` 装配。`Database::new` 使用默认配置；`with_options` 在构造时校验显式配置。S3 adapter 拥有异步 runtime，给独立阻塞 SQL 线程提供同步对象 port，不应从同一异步 executor 直接阻塞调用。

## 容量与执行预算

单库业务配额持久化在 HEAD 的 `quota.max_bytes`，默认为 **10 GiB = 10,737,418,240 字节**。这是 SQLite 主文件的逻辑大小，包含 schema、B-tree 和 overflow 页；不是用户 BLOB 净容量，也不是整个 bucket 的对象总量。管理员可通过绑定原 `expected_revision` 的 `set_quota` 调大或设为 `None`；`None` 取消 SCAP 的业务容量配额，SQLite 的页号边界仍然存在。配额必须页对齐，缩小到当前已提交文件以下会拒绝，绝不截断数据。

| 配置或格式边界 | 默认值 / 能力 | 作用 |
| --- | --- | --- |
| 数据库页 | 4096 字节 | 固定物理格式 |
| 单库业务配额 | 10 GiB，可调整或 `None` | 持久 HEAD 配置；重新打开不使用新的创建默认值覆盖它 |
| 引擎页号上界 | 4,294,967,294 页 | 4 KiB 页约 16 TiB，是物理能力边界，不是已验收的服务容量 |
| SQL 结果 | 每事务 50 MiB | 可调整，v2 保留结果格式最多 64 MiB |
| SQL 文本 / 聚合请求 | 每事务 1 MiB / 64 MiB | 聚合请求包含类型、长度和容器编码开销 |
| 单个参数/返回 Text/BLOB | 2 MiB | 网络值预算；不等于数据库内所有值或整行的存储上限 |
| 语句 / 参数 / 列 / 结果行 | 256 / 每语句 32,766 / 2,000 / 每事务 1,000,000 | 可在格式能力内配置 |
| 事务变化页 | 16,384 页，即 64 MiB | 独立事务预算；不能把它当成单库上限 |
| SQLite page cache | 64 MiB 目标 | 与变化页预算共同约束 native cache；不是进程 RSS 硬隔离 |
| VM 步数 | 100,000,000 | 每次执行的原生计算预算 |
| 操作 / 冷恢复期限 | 30 秒 / 1,800 秒 | 与调用方绝对 deadline 取较早值；不是延迟承诺 |
| 当前请求世代 | 4,096 条终态、256 MiB 原结果字节 | 任一剩余预算不够时有序关闭，不静默丢结果 |
| closed 世代 | 最近两个完整世代 | current 加两代；不承诺正的墙钟保留时长 |
| HEAD / 单对象编码 | 256 KiB / 64 MiB + 64 KiB | 格式解码上界；对象实际大小通常远小于上界 |
| policy 主体 | 最多 1,024 | 严格身份与权限列表 |

默认值是可运行的配置，不是吞吐、可靠性或容量测试结论。真实测量使用[独立容量实验](../../experiments/object-capacity/README.md)，必须区分当前配置、实际完成的负载和 SQLite 理论边界。默认关闭配额的 Rust 装配示例：

```rust
let mut options = scap_object::Options::default();
options.quota.max_bytes = None;
let database = scap_object::Database::with_options(objects, scope, worker_id, options)?;
```

已有库通过 `set_quota(principal, expected_revision, nonce, DatabaseQuota { max_bytes: None }, deadline)` 修改。配置的 `quota` 和 `retention` 仅是显式创建默认值；打开既有库始终遵守 HEAD。准入与执行预算属于本地进程配置，可以独立调整。降低新的结果准入预算不会让原先已经提交的结果变得无法解码，历史结果使用固定格式能力读取。

## 权威与数据布局

HEAD key 固定绑定 deployment/tenant/database；incarnation 和 authority generation 放入 body，每次读取校验。key 的既有 `scap-object/v1/.../head` 命名空间不随帧版本迁移，避免通过换 key 绕过既有身份或删除屏障。v2 帧不兼容 v1 对象，不自动迁移旧库，不自动重新初始化缺失或不兼容 HEAD。

不可变对象 key 包含全部 scope 和 SHA-256。GET 的 ETag 是 opaque 条件比较令牌，不当成内容摘要。HEAD 包含 revision/transition、SQL sequence、owner、policy、lifecycle、quota、retention、数据根和三个以内的请求世代索引 root。内部 u64 JSON 字段保持精确；未来 JavaScript 网络入口需要无损编码。

数据 Manifest 只保存 `page_count` 和树根。每块最多 **32 页 / 128 KiB**，树节点最多 256 个子引用，零起始 level 最高为 3，足以覆盖整个原生页号空间。节点的 level、范围、子引用数量和块的起始页、长度逐项绑定。增长必须提供所有新页，不能用空洞或补零掩盖缺失页。唯一的引擎格式例外是 SQLite 第 262145 页锁字节保留页：原生适配器只在首次跨越时显式提供该页的确定零字节，计入变化页预算；已存在的权威字节不被覆盖。数据树本身仍要求页齐全。截断只改变引用，不删除远端对象。热修改只加载受影响块和祖先路径，未变化子树继续引用原不可变对象。

v2 使用固定 framing、严格元数据 JSON 和原始字节区；数据块及原结果不是 JSON 字节数组。解码校验实际 wire 长度、版本、scope、摘要、类型、字段及几何，不接受未知或重复字段。请求索引绑定 epoch/id、原 principal 和精确 SQL 指纹；相同 ID 更换主体或参数被拒绝。

<a id="recovery-closure"></a>
## 恢复闭包与热提交

完整冷激活校验当前 Manifest、全部 Node/Chunk，以及所有保留窗口的 Index 和 Result。`activate_session` 在同一次恢复期限内流式写入全新私有文件，执行原生结构校验，检查保留历史，重新读取 HEAD 并比较 body 和 ETag，然后以原 ETag 激活并返回已准备好的 Session。它避免激活后再次下载整库。

`session` 为既有根准备可复用连接，也在恢复期限内验证保留历史。每次 Session 读写都重新读取 HEAD、校验当前权限并要求数据根与持久配额匹配；写还绑定 owner epoch。不同根或配额返回 `StaleSnapshot`，必须重新建立会话。HEAD 不可达时失败关闭，缓存不是授权租约。

热提交先为所有新增数据、结果和索引对象执行条件创建及精确回读，再发布新 HEAD。旧引用继承原 HEAD 已建立的不可变闭包，不逐次重新下载全库或全部历史结果。其归纳前提与数据树相同：所有 HEAD 由协议产生、先持久后引用、对象键不可变、可达对象不被删除、当前没有物理 GC。对象被非协议进程删除或覆盖违反这些前提；热事务不承诺主动扫描并发现一个未访问的历史对象损坏。任何实际访问到的缺失、类型/摘要错误仍失败；同一 `Database` 及其 clone 记忆已观察到的对象/语义损坏，并阻断后续新写、取消及控制 HEAD 发布，最终 CAS 前再检查共享隔离状态。该隔离只阻止后续发布，不是自动维护模式：已验证的本地快照在 fresh HEAD、当前权限和准确数据根仍匹配时可继续只读，status 与目标 lookup 也保留诊断能力。它不能撤回已经发出的在途 CAS。该隔离是进程内状态，不是跨 worker 的持久仲裁；排障后用新 handle 完整冷校验再服务，不能靠重新包装旧 Session 清除错误。目标请求的 `lookup` / 重复提交始终读取当前 HEAD、相应 Index 和 Result，冷恢复检查整个当前闭包。

`StoredResult.data_root` 保留原 receipt 的数据根身份，不提供历史快照读取或 PITR。冷恢复不继续遍历每个旧结果指向的历史数据根。当前根、历史快照、pin 与 GC 的完整关系须在 N3 单独设计，不能直接启用 bucket TTL。

## 执行与错误

`ImageBuilder` 将连续验证过的块流式写入新私有目录，校验总长度和文件首部并同步。原生打开执行完整 `integrity_check`，此后热读写复用连接；没有整库 `Vec`、整库 clone 或按需 VFS。冷恢复仍是 O(DB) 下载和结构扫描，需要足够本地文件空间。

SQL 在私有事务执行，最终物理变化页和精确原结果先进入 commit gate。只有依赖持久并回读、原 ETag 的 HEAD CAS 成功、native publication 成功且检查点完成后，调用方才观察成功。每次 native commit 后核验 `wal_checkpoint(TRUNCATE)` 的实际完成状态，防止长期会话积累无界 WAL。接受后本地发布、checkpoint 或期限失败返回 `CommittedButUnavailable`，停止连接；原结果通过原身份查证，不能重做 SQL。

cache spill 开启，尚未提交的 `xFrames` 在当前 adapter 中安全拒绝，不能提前发布。变化页预算、VM、SQL 和结果预算都是真实执行限制，但不是整个进程的硬 RSS 上限。64 MiB 变化页也不是总上传预算：128 KiB 块中每块只变一页时，16,384 个脏页可以重写约 2 GiB 块数据，另外还有路径、索引和回读。当前由 deadline 约束总操作时间，没有单次对象总流量/次数硬预算。结果、typed 输入、SQLite 及对象编码还有独立内存开销；公平调度和进程资源隔离尚未完成。

`Database::execute` / `query` 保留单次便利接口，冷物化也计入它们同一个操作 deadline。GiB 库应显式准备 Session。查询的静态输入校验在冷下载之前执行。任何自动 SQL 或 CAS 重试均禁止；条件失败只描述本次 CAS，UNKNOWN 不证明未提交。

## 控制与留存

- `create` 只显式条件创建 HEAD；既有库 404 不自动建空库。初始 writer 处于 Recovering。
- `takeover` / `activate_session` 以当前管理权限、原 revision 和同一 HEAD 排序 owner epoch、恢复及激活。
- `lookup` 保留 committed、cancelled、unknown、closed、retired 的差异；absent 不是取消证明。
- `cancel` 与提交竞争同一 HEAD，没有成功 CAS 不返回 cancelled。
- `close_full` 是可信协调器接口，只关闭已满的当前世代。满窗口由条数或剩余结果空间决定，保留两代完整索引，不删除对象。
- `set_policy` / `set_lifecycle` / `set_quota` 使用同一个 HEAD 排序；旧在途候选不能替换 ETag 继续提交。Deleted 保留身份屏障并拒绝后续操作。

结果预算计量精确编码结果字节，不包含索引/帧开销；满窗口为最大 64 MiB 结果预留空间。请求终态格式最多 65,536 条，默认 4,096 条属于可配置留存合同。对外自动协调、SDK 能力协商和按小时留存尚未实现，不能把内部关闭 API 描述成完整生产网关。

## 部署边界

`principal` 必须来自可信鉴权，不接受外部客户端直接自报身份；S3 凭据只给可信协议进程。命名目录、HTTP/Node SDK、多库调度、硬资源隔离、GC/PITR、真实 AWS Standard 及生产 SLO 仍有独立退出门禁。关闭物理 GC 时，旧块、旧索引和失败上传 orphan 持续占用远端空间，单库当前文件配额不代表 bucket 总量或长期成本有界。

相关决定及官方产品容量对照见 [ADR-0022](../adr/0022-production-capacity.md)。
