# 原始对象闭包的有界内存游标

## 状态与用途

本切片在 `crates/scap-object/src/closure.rs` 实现私有、只读的完整闭包校验，并接入现有 `Database::activate` 与 named Complete 的 `verify_closure`。它以同一次 exact HEAD GET 得到的原始 `Snapshot` 为起点，保留原 `ObjectContext` 和绝对 deadline。现有调用方在闭包校验之后的 fresh exact HEAD 检查、原 ETag 条件发布顺序不变。

这一步提供后续按原始字节复制对象需要的校验基础。当前没有 copy sink、checkpoint、promotion、generation 切换、pin、GC DELETE 或公开维护接口。HEAD5 仍只接受 `storage.active_generation = storage.allocated_through = 1`。不能把这里的 `Complete` 当成维护授权、SQL ACK 或可安全删除源对象的证明。

## 三层校验

| 层次 | 检查的事实 | 不能推出的事实 |
| --- | --- | --- |
| 单个 `ValidatedFrame` | 总长度、SCAPOBJ2 framing、完整 Scope、对象 hash、类型内结构及 raw 长度 | 父边是否引用了正确范围、子对象是否存在、完整根闭包 |
| `Cursor` 完成 | 原 Snapshot 的全部当前数据边和 retained request/result 边均通过校验，累计数量一致 | SQLite B-tree/native 可打开性、当前调用权限、原 HEAD 仍为最新、可提交或回收 |
| 既有操作流程 | 原有权限、owner、生命周期、最终 HEAD/CAS 和 native publication 要求 | 本切片没有添加新的成功出口，也没有替代这些检查 |

对象 metadata 的 serde 解析仍有受对象格式上界约束的分配。这里借用的是 raw payload 和整个原始 frame，不宣称无分配解码或全进程 RSS 上界。

## 固定根集合与每条边的意义

游标首先遍历 `HEAD.data_root`，然后按 HEAD 中已有顺序遍历全部 `windows[*].root`，最多三个窗口。没有访问历史 data root 的隐式边，没有以 LIST 寻找额外对象，也不以对象 hash 去重后跳过父边检查。

| Incoming role | 必须命中的对象及校验 |
| --- | --- |
| `Manifest` | Manifest；page count 满足原 HEAD quota，空库没有 root，非空库继续到唯一规范高度的数据根 |
| `Node` | Node；level、first chunk、子节点数量与父边传下来的 page span 完全一致 |
| `Chunk` | Chunk；first page 与该位置一致，完整块及最后一块长度均精确匹配，无越界页或少页 |
| `Window` | RequestIndex 根；epoch、entry count、result bytes 与该 retained Window 一致 |
| `Child` | RequestIndex 子节点；epoch、level 递减、非根最低占用率和完整 `IndexSummary` 与原父边一致 |
| `Result` | StoredResult；完整 Request 身份、原始结果长度、sequence/revision 上界和 SQL wire 均通过校验 |

RequestIndex 是有序 B+ tree。每个 frame 自身验证节点内的严格顺序与区间不重叠；每个父子边验证子节点的实际 summary；遍历还检查每个窗口的 request ID 严格递增。不能用一个“hash 已访问”集合绕过这些上下文相关条件。例如同一正确 Chunk hash 被放到另一个页位置时，第二条边仍必须拒绝。

数据树的纯 geometry 规则与现有读写路径共用 `data_tree::check_node`、`check_chunk` 等函数；索引共用 `request_index::check_root` 与 `check_child`。这避免为维护遍历重新定义另一套树格式。

## Retained Result 的边界

保留结果使用与正常 lookup 相同的 `check_retained_result`。该函数验证完整 `Request`（epoch、id、principal、fingerprint），`sequence <= original HEAD.sequence`，`transition.revision <= original HEAD.revision`，以及 allocation-free 的 `scap_sql::validate_result(raw, durable_sql_limits())`。游标另外将 raw 长度与索引 Entry 的 `result_bytes` 比较，并在完成时核对每个窗口的总数量、结果字节和 committed/cancelled 数量。

历史结果按 durable wire 上界校验，不能因当前请求 admission 配额调低而把原先合法的 retained Result 判为损坏。取消项沿用原有 transition revision 校验，不能因为没有 Result 对象便跳过。

`StoredResult.data_root` 是原 receipt 的身份字段，不是本次完整闭包的边。它可指向现在没有对象的历史根，也可与当前 HEAD 根不同。本切片不会读取、修补或重新生成它。以下条件也不是现有协议保证，遍历不能自行加上：request ID 顺序等于提交 sequence 顺序；不同请求 sequence 必然唯一；历史请求的 principal 仍在当前 ACL；通过重新运行 SQL 验证结果。

## 生命周期与续进

`Cursor::new` 返回不透明的 `Box<Cursor>`。它不实现 Clone、序列化或外部恢复；其 Basis 借用原 `Snapshot`、原 `ObjectContext`、原 absolute deadline 和 stop 回调。对象 namespace 的 Scope 与 physical generation 必须与该原 HEAD 完全一致。

`advance(self, budget, visitor)` 消费原游标，只有 `Pending(Box<Cursor>)` 返回同一内存状态供续进。任何错误都丢弃该游标，不能拿部分 prefix 冒充成功。`Complete(VerifiedClosure)` 仅在所有根与边完成、累计数量一致后产生；`finish` 再检查 stop/deadline 以及调用方提交的原 HEAD body 和 ETag 身份。它不重新读取 HEAD，也不制造由 PUT 回执拼出的 Snapshot。

此设计没有可伪造的磁盘进度。未来若需要进程重启后的续进，仅重新验证路径并不足以证明“前缀曾完整复制”。持久化 checkpoint 必须额外绑定完整 plan/source/target/root 集合、已经接受的权威进度及其历史，再经过单独设计和验证。

## 每步资源边界

当前驱动使用每步最多 64 个 frame、最多 `2 * MAX_OBJECT_BYTES` 的读预算。每次 GET 前预留完整 `MAX_OBJECT_BYTES`；成功后按实际返回长度退还差额。剩余额度不足以预留下一次完整 GET 时返回 Pending，不依赖服务端预报长度。零 frame 额度或小于单次完整预留的字节额度拒绝为 Limit。

深度优先状态使用固定六个 path slot，各层只持有一个已经过格式上界校验的 metadata 子列表或 entry 列表。每条 frame 校验完即移动 metadata 到路径中，raw 缓冲区随后释放；没有随数据库大小增长的 visited set、全量 Result 图或全量 SQLite image。

Leaf 最多含 128 个 Entry；每次准备下一条对象边时至多消耗当前 leaf 的剩余取消项，并逐项检查 stop/deadline。索引层级与数据树层级受格式限制。完整格式范围是有限的，但本切片不宣称最大数据库能在某个固定服务 deadline 内完成；耗尽原 deadline 返回 UNKNOWN，不能延长为新的操作期限。

最大数据几何结构测试只构造并验证最高合法高度的有限首路径，随后确认缺失的未构造后缀不能得到 Complete。这是 prefix 测试，不是完整容量或吞吐验收。完整最高层 request index 则使用实际完整子树遍历测试。真实后端性能、S3 请求成本和 native 恢复仍由各自的实际合同检验。

## 原字节与错误归属

`ObjectContext::with_raw` 只进行一次 GET。`ValidatedFrame::into_parts` 移出已验证 metadata，同时借用该 GET 返回的原始完整 frame 与 raw suffix。visitor 在缓冲区存活期间同步运行，得到实际 key、完整 Scope、captured physical generation、hash、incoming role 和原始 bytes。非规范但合法的 JSON 空白、字段顺序、escape 与 raw 浮点符号位都保持原样；没有 decode→encode 来制造另一个 hash，也没有为校验再创建 owned raw payload。

visitor 得到的只是当前 frame 和 incoming edge 已通过的事实。其后某个子对象仍可能缺失或损坏，故 visitor 成功不是整个闭包证明。stop/deadline 在 visitor 后再次检查，检查失败时不推进已验证 prefix。

错误归属分开处理：源 GET、frame 解析和 incoming-edge 语义错误保留既有 source quarantine 规则；visitor 自己返回的错误原样传播，包括名为 Corrupt 的错误，也不会由通用 raw port 自动隔离源。这样未来若加入目标写入回调，目标失败不会误报为源损坏。当前 stop、deadline 与传输不确定仍为 UNKNOWN，不伪装成 Corrupt。

现有 `S3::put` 会复制传入切片为 owned request body。未来若把本 visitor 接到 PUT，这个传输边界仍存在；本切片只消除了遍历校验中的 raw payload 再物化，不声称端到端零拷贝上传。

## 验证范围

单元测试覆盖逐 frame 续进与批量遍历等价、每个 GET 的 UNKNOWN/Missing 切点、原 key/Scope/generation/deadline、访问次数与字节预算、callback 与 source 错误隔离、重复 hash 的不同父边、完整索引 occupancy/range/epoch、retained Result 身份与 wire、最大合法 raw Result、非规范原字节以及完成凭证的原 Snapshot 身份。

新增生产代码正常进入精确单元覆盖分母。单元源码/LLVM 证据、全工作区验收和真实 HTTP/S3/native 验收分别记录；不能由一个通过结果替代另一个层次。
