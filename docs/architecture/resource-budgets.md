# 资源预算、租约与失败语义

## 1. 状态与适用范围

本文记录已核实的资源边界，并规定后续实现和验收要求。
主线基线为 `c5ed0c2ff1b3dfa1fd200edcf3a055d64e711e16`。最初设计引用的
本地 intake 检查点 `bc2ebcf495635d62f4f473b27a5c58b44c97d5f2` 已无法从远端
或当前工作区取得，不能继承其代码或验证结论。

本轮 [PR #37](https://github.com/ckanner/scap/pull/37) 在真实远端基线上重新实现
intake 生命周期及单次 typed-result graph 预算；修正版为
`4506ef24d0e7e6b375751eebf2ec9f12c504f065`。真实资源合同和独立负对照已通过，
完整组合门禁仍按最终源码继续验证；初始覆盖缺口和测试夹具竞态的失败记录保留。
[PR #38](https://github.com/ckanner/scap/pull/38) 加入连接及 header 边界，
[PR #39](https://github.com/ckanner/scap/pull/39) 的 owner SDK 复用现有服务入口。
最新源码、范围和未完成项见[实施状态](../engineering/status-2026-11-09.md)。

响应字节池、对象解码的全局存活字节池、native heap 和全局临时盘预留仍未形成
完整保护。PR #38 限制了连接任务及 HTTP/1 header/解析缓冲，不是整个运输层或
进程 RSS 上限。本轮 typed graph 仍是一次物化的预算，不是跨 actor 共享的
存活字节租约；下文关于总体资源向量的要求继续适用。

## 2. 入口必须分别接入

| 入口 | 已确认的边界 | 后续接线要求 |
| --- | --- | --- |
| 普通 /v1 data/control/recovery | PR #37 使用三个独立请求池，鉴权后、读 body 前预留 | 分别增加响应及工作区预算，保留各类独立额度 |
| /v1/catalogue | PR #37 使用独立 catalogue 池，复用同一租约实现 | 单独证明其解析、响应及实际 worker 生命周期 |
| /v1/discovery | 已有独立工作租约和有界请求/响应设计 | 单独核对预算归属，不能自动计入普通三类池 |
| owner SDK 的 status/takeover/activate | PR #39 复用普通 /v1 control/recovery 和原始 deadline，没有新增独立 controller 入口 | 现有 body/Job 预算随真实 class 生效；未来 controller 仍须独立定义资源与公平性 |
| 直接库 API、部署恢复作业 | 可能不经过 HTTP | 必须显式接入被声明为全局的同一计费域 |

旧本地 owner 候选设计中的全局 2 / tenant 1 运行额度不等于 body 准入或响应字节额度，
也不代表这些入口已经存在于远端代码。普通服务合并不能证明未来 owner 入口自动获得相同保护。
未鉴权连接尚无可信 tenant；连接保护与鉴权后的租户公平分别验收。

## 3. 不同资源使用不同计量单位

| 资源 | 计量对象 | 当前事实与限制 |
| --- | --- | --- |
| 原始 request body | 实际原始字节 extent | PR #37 先预留最大 body，完整读取后退还未用部分 |
| 请求解析图 | JSON、typed SQL、字符串及 Base64 解码副本 | body 字节数不包含这些分配 |
| typed result graph | `Vec<Vec<Value>>`、列名、String/Blob capacity | PR #37 单次预算默认 128 MiB；并非全局存活字节租约 |
| SCAPRES1 / 编码工作区 | 二进制结果与编码期间同时存活的缓冲区 | 需要按实际转换路径预留 |
| serialized response | 最终 HTTP body 及仍被运输层持有的副本 | 当前没有独立响应字节池 |
| immutable decode | GET 原始对象、解码 payload、元数据和增长副本 | 当前单对象上限不等于全进程并发预算 |
| SQLite allocator | 经过固定 native allocator 的分配 | hard heap 防护需独立实现和证明 |
| 私有磁盘 | SQLite 镜像、WAL、排序临时文件及残留缓存 | 当前没有全局临时盘预留证明 |
| 进程 RSS | 上述资源、线程栈、allocator、运输层等的实际驻留 | 不能由某一项配额或采样值推导为硬上限 |

原始 body extent 继续保留其明确语义；Vec 额外容量及复制另行计入工作区或运输预算。
SQLite cache target、保留结果总量、累计恢复 I/O 与上述存活字节是不同指标。
相关源码见 [HTTP](../../crates/scap-service/src/http.rs)、
[结果表示](../../crates/scap-service/src/wire.rs) 和
[native 结果收集](../../crates/scap-object-sqlite/src/sql.rs)。

## 4. 已有冷恢复行为

[Database::restore](../../crates/scap-object/src/lib.rs) 调用
[data_tree::walk](../../crates/scap-object/src/data_tree.rs)，每次处理 32 页、128 KiB 数据块。
[ImageBuilder](../../crates/scap-object-sqlite/src/file.rs) 将块顺序写入私有文件，再同步并打开。
这条路径没有把完整 10 GiB 数据库收集成一个常驻 Vec。

历史请求索引采用有界深度的遍历，逐条读取并验证 retained Result 后释放。
[validate_result](../../crates/scap-sql/src/result_validation.rs) 不构造完整 decoded row graph。
但 [decode_object](../../crates/scap-object/src/format.rs) 会同时持有原始对象与 payload 副本。
单个历史结果仍可达到 64 MiB；普通 GET 上限为 64 MiB + 64 KiB。
两路恢复可叠加这些缓冲区、Vec 剩余容量和运输开销，并没有对应的全局 resident-byte reservation。
[RecoveryBudget](../../crates/scap-object/src/catalogue/recovery_budget.rs) 是累计 I/O 消耗预算，不是内存租约。

## 5. 按阶段在分配前预留

下表是后续实现协议；新增预算名称均为**草案**，不是现有配置字段或已冻结 API。

| 阶段 | 分配前必须获得的额度 | 释放依据 |
| --- | --- | --- |
| 连接 / header | 独立连接和协议缓冲额度 | 实际连接、socket 与其缓冲区结束 |
| 鉴权后、读取 body 前 | request_body_bytes 及请求计数 | HTTP、Job、响应等最后持有者结束 |
| JSON / Base64 / typed request 解析前 | request_parse_bytes | 实际解析图和副本销毁 |
| 原生结果收集前 | result_graph_bytes | 对应 typed graph 及增长副本销毁 |
| GET / 对象解码前 | object_decode_bytes | 原始对象、payload 和临时副本销毁 |
| 结果编码前 | response_work_bytes | 本阶段实际编码缓冲区销毁 |
| 最终响应序列化前 | response_body_bytes | 最后 body、frame、Bytes 或运输副本释放 |
| 冷镜像创建及临时盘增长前 | 独立磁盘预算或等效强制边界 | 文件实际删除并完成可靠记账 |

阶段切换不自动退款。旧对象仍存活时，旧额度与新额度必须同时存在。
只有实际所有权转移或对象销毁才能转移、缩减或归还额度。

## 6. Response-byte pool

普通 data、control、recovery、catalogue 以及 owner 各入口保留独立额度。
同一 (deployment, tenant, class) 的不同 principal 共享额度，不能通过换凭据绕过。
每类同时受全局与租户上限约束；不得通过多个局部“全局池”增加总额度。

选择预算前必须解析并验证实际 operation，检查它与原 admission class 一致。
query/execute 的预算不能依赖客户端声称的结果大小或 SQL 文本长度。
lookup/cancel 可能返回既有大结果，必须按持久格式 **64 MiB** 边界处理。
当前新执行的默认 50 MiB 结果预算不能用于推断历史结果更小。
完整结果路径在派发实际工作前，按 operation 的最坏边界取得响应及转换工作区额度。
阶段表规定后续如何细分和缩减，不能解释成先提交 SQL 再申请唯一的大响应额度。
额度预留不能保证网络交付成功，运输故障仍遵守原提交状态与 UNKNOWN 协议。

令 R 为相应路径允许的 SCAPRES1 最大字节数，Base64 长度为 B(R) = 4 × ceil(R / 3)。
最终 JSON 上限 J 必须从实际 wire schema、Base64、转义规则和有界元数据推导。
编码工作区预算必须覆盖该阶段真实共存的表示及增长时的旧、新缓冲区。
不得先构造超大 Json/String/Vec，再检查最终长度；序列化应使用有界 sink。
不改变既有 codec；若需新增响应上限或接口字段，必须另行冻结兼容性设计。

metadata、status 和错误响应保留小而有界的独立额度。
错误路径不得等待已耗尽的大响应池，否则“报告资源不足”本身可能死锁。
若连最小响应也无法安全发送，只能关闭运输连接；客户端继续按原 UNKNOWN 规则处理。

## 7. Typed result 与 object decode

旧实现将 NULL 按一个结果字节收费，却把它保存为完整 Value 容器元素。
PR #37 已将 wire 限制与 typed graph 预算分开：外层 rows、每行 values、列名及
String/Blob 的实际 capacity 均计费；在复制与扩容前预留，用可失败分配接口，
扩容期间计入旧、新缓冲区重叠。格式校验先于物化，合法历史结果的预算不足返回
原提交 receipt 的 `CommittedButUnavailable`，不标记 Corrupt 或重放 SQL。

该预算在一次 native collection 或 retained decode 内累计，并在 native 提交后的
再次 decode 前明确销毁原图。直接 API 调用者可以保留多个返回值；服务的多个 actor
也可以同时产生结果。因此，跨请求共享的 graph lease 与最终编码/响应字节池仍需接入，
不能把单次上限乘以某个局部并发值就当成整个进程的内存上限。

对象预算须覆盖原始 GET body、decoded payload、元数据解析和运输层的可归属副本。
可从已验证的 Manifest、索引 Entry 和预期对象类型收紧读取上限。
不能相信未验证的 Content-Length 或对象内容来降低预留后再无界增长。
块、HEAD、索引和 Result 的上限分别验证，不能把 128 KiB 块大小推广为所有对象上限。
降低内存预算不能将合法的历史大 Result 标为损坏；允许拒绝本次物化或返回已知提交证明。
所有被声明受保护的 actor、恢复作业和直接库调用必须共享同一预算 owner。

## 8. 原子预留与租约生命周期

跨全局、租户、class 和资源种类的预留必须原子成功，或完整回滚。
可以使用同一短锁核对计数；分离的管理器必须使用不等待的 try-reserve 和完整回滚。
不得持有部分 permit 再等待另一池，也不得在锁内等待 body、对象 I/O、SQLite 或响应发送。
拒绝不得插入无限增长的 tenant map；零用量条目需要有界回收。

提交到 scheduler 时，租约绑定原始可信 Principal、实际 class 和唯一 Job。
HTTP 超时、断连、取消接收结果或返回错误，不代表实际 worker 已停止。
已开始的 Job 必须持有其额度直到实际工作结束；队列内取消则按实际移除点归还。
原 deadline 不因排队、资源等待、重新编码或恢复重试而延长。

慢客户端持有的 body、frame 和最后 Bytes clone 继续持有响应租约。
若 HTTP 库复制大帧，副本必须仍由该租约或另一项已证明有界的运输预算覆盖。
仅证明上层 Body 已 drop，不能证明所有响应字节已释放。
连接强制关闭也不释放仍在运行的 Job 所持资源。

## 9. 资源不足与提交状态

| 已知阶段 | 必须保留的语义 |
| --- | --- |
| 必需预算未配置 | 拒绝启用相应能力；兼容默认值须显式版本化和冻结 |
| 执行前无法预留 | 返回既有准入拒绝语义，不提交 SQL，不等待部分 permit |
| 已执行、确定尚未尝试业务发布 | 按既有资源限制出口失败；不能伪称已经提交 |
| HEAD 发布可能被接受、结果未确定 | 保留原 request/fingerprint 的 UNKNOWN，不自动重跑 SQL |
| 已有可信提交证明、结果无法物化或发送 | 保留原 receipt，使用已提交但不可用语义 |
| lookup 尚未取得相应协议规定的证据 | 不能据局部读取宣称已提交、损坏、不存在或回滚 |
| 冷恢复资源不足 | 保留 pending、未验证项和不完整状态，不能发布 healthy/complete |

已知提交的判定必须有原协议允许的完整证据，不能由“请求发出过”或部分对象推断。
原协议允许仅凭 fresh HEAD 判定的 Retired 等状态仍按原证明规则处理。
未收到响应的客户端使用原身份 lookup；资源恢复后查询结果不构成执行 SQL 的授权。
任何新错误码或 HTTP 字段均须单独设计；本文不发明已经存在的 wire 接口。
预算不足不能默默缩小既有业务结果上限或丢弃已 ACK 的结果。

## 10. SQLite allocator 边界

全局 hard heap limit 需在第一条业务/文件连接前一次性建立，冲突配置必须失败关闭。
若使用安全 PRAGMA 引导连接，必须承认该引导连接本身已是 native connection。
固定 native 依赖启用的 bMemstat/MEMSTATUS；默认开启不等于运行时始终有效。
宿主不得修改 MEMSTATUS、allocator 或 PCACHE 来绕过已经声明的边界。
PRAGMA 读回值只证明配置值，不能替代实际分配被拒绝的证明。

必须用隔离进程和固定实际 native binary 验证受控分配、明确 NOMEM 及进程闭合。
SQLite allocator 不覆盖 Rust、JSON、Base64、HTTP、TLS 或内核 socket 内存。
共享 heap 也不提供租户硬隔离；需要硬隔离时另行设计 worker 进程、受限 IPC 和 kill/recovery 合同。

## 11. 私有磁盘是独立上线条件

默认 10 GiB 是单库逻辑数据库配额，不覆盖活跃库私有镜像的合计大小。
它也不覆盖 WAL、排序临时文件、恢复中间镜像和崩溃残留目录。
pages_per_actor 是缓存保留/淘汰阈值，不能当成创建镜像前的全局磁盘预留。
当前没有已证明的全局 DiskLease，本文不声明已经实现。

后续必须规定全局及租户磁盘额度、扩容前检查、失败时关闭与可靠清理流程。
单纯扫描空闲空间后开始写入存在并发竞争，不能充当原子预留。
空间不足不得删除对象 authority、改写原 ACK 或把未完成恢复报告为成功。
临时文件、残留缓存和后端持久对象必须有明确且可审计的不同归属。

## 12. 总预算合成与默认配置

总体预算应基于每阶段同时存活的资源向量和真实并发上限计算。
只有共享同一管理器、没有绕过入口且所有副本被计费的部分，才能进行可证明的合成。
SQLite cache target、累计 GET 字节、保留窗口总量不能直接加入 resident-byte 租约公式。
实际 allocator capacity、线程栈、运输缓冲和文件页缓存需要另列。

例如 64 MiB 的历史结果，单份 Base64 已约 85.34 MiB。
多个 data 和 control 请求可以同时持有这种结果；body 很小不影响这一事实。
本文不填入尚未验证的服务总体峰值、安全并发数或“某内存规格可承载多少库”。
新增默认值须在表示生命周期清单完成后冻结，不能为了通过负载测试而事后降低业务上限。

## 13. 实际验收要求

- 在分配前拒绝，而非大对象已分配后才报超限；检查边界值、整数溢出和扩容旧/新副本。
- 同 tenant 不同 principal、不同 deployment、各 class 独立额度以及多池失败完整回滚。
- 大结果耗尽时 metadata/status/错误响应仍有独立有界路径，所有拒绝路径无持锁等待。
- 慢上传、队列取消、HTTP 超时、连接强制关闭后，实际 running Job 的额度继续存在。
- 慢读响应、保留 frame/Bytes clone、运输复制与最后持有者释放逐阶段核对。
- 大量 NULL、小值、短行和多列验证 typed graph 限制，不能只用大 BLOB 测试。
- 历史 64 MiB lookup 在当前新执行预算较低时仍按持久格式处理。
- 对象超限、截断、错误 hash、错误类型及错误 ETag 均不能绕过预留或伪造恢复完成。
- HEAD 发布前后分别注入内存/编码/运输失败，核对原 ACK、UNKNOWN 和 retained Result 完整字节。
- 全计算丢失后按原 request/fingerprint 证明结果，不重放 SQL，不根据最终状态重建输入分母。
- native OOM、临时盘不足和进程回收分别使用实际路径验证，保留每个 owned child 的结束证据。
- 本地负载采用预先冻结的开环计划，保留 missing、notSent、拒绝、UNKNOWN 和迟到完成。
- 原始输入、完整效果、原始日志、源/构建/native 身份由独立 oracle 重算，并加入行为负控。
- 每个新增生产文件遵守既有单元与四维覆盖门禁；模型测试不替代真实 HTTP/native 合同。
- owned /proc 采样、owned wait4 峰值和共享 cgroup 指标分别报告，不互相冒用。
- 未验证的虚拟 /proc 视图不能证明实际进程存活、退出或 RSS；关闭证据来自 owned 子进程回收。
- 生产 AWS、长时间运行、总体 RSS 与全局临时盘门禁未执行时明确标记 NOT_RUN。

不同源码、配置或持久格式必须重新冻结对应合同，不能继承旧 strict decoder 的通过记录。
在入口接线、原子预留、失败语义与实际证据全部闭合前，只能报告各已验证子范围。
