# ADR-0018（提案）：有序请求窗口与安全结果回收

- 日期：2026-11-05。
- 状态：**待实施、待验证的协议提案**。没有修改现有数据库行为或容量上限，没有通过 Rust/服务故障验收。
- 基线：main `b9f512819358494f178b01d7f1d960dff8222c1c`；物理基线见 [ADR-0017](0017-bounded-physical-history.md)。
- 目标：解除有限请求记录导致的持续写入停顿，不能以破坏去重、取消或 UNKNOWN 合同为代价。

## 1. 当前代码中的两个不同问题

ADR-0017 已使物理恢复材料由完整基线与有限 tail 组成，旧物理页不必一直驻留。但数据库仍保留最多 128 个逻辑请求身份，且 `RequestRecord::Accepted(sequence)` 指向 `transactions` 中的原提交；revision、commit hash、恢复基线与归档校验也依赖逻辑前缀。

所以不能仅对 request map 或 transaction Vec 做 FIFO/LRU 删除。删除结果后，旧请求再次到达时若被 Lookup 解释为 Unknown，就可能再次执行 INSERT 或 randomblob。删除取消记录后也可能让本来已取消的请求复活。把相同数据搬到 S3 只能转移成本，不会自动提供有限的长期结果存储。

这不是把 128 改成更大数字能够解决的问题：要有界运行，必须明确**原结果可查询的保留范围**和**越过范围的旧请求仍不可重新执行**这两个合同。

## 2. 候选协议：数据库级显式请求窗口

为支持该能力的数据库引入独立 `request_epoch: u64`。完整请求身份为：

```text
(cell identity, database identity/incarnation, request_epoch, request_id)
```

`request_epoch` 不复用 owner epoch、auth epoch、Raft term 或 revision。writer 切换、权限撤销和选举不应无意中过期客户端结果；权限仍须独立按当前状态校验。

默认保持 `LegacyPinned`：现有客户端和现有原结果合同不变，到达原有上限仍安全拒绝。只有管理员显式启用 `Windowed`，且应用已升级为携带稳定 epoch 的客户端，才能推进窗口并回收结果。第一版不实现多会话窗口，不宣称多个不协调调用方可以无感共享轮换。

新窗口内，相同 ID + 相同指纹返回原回执/原结果；不同指纹拒绝。旧 epoch 的写在状态机内拒绝，不能仅在 HTTP 或 preflight 拒绝；网络中已经排队的旧 proposal 同样受有序裁决约束。 大于当前 epoch 的请求同样拒绝，不能由客户端猜测窗口编号推进服务端状态；只有已授权的有序管理操作能够改变活动窗口。

| 操作 | 同一活动窗口 | 已退休窗口 |
| --- | --- | --- |
| Execute / Commit | 维持原去重和权限检查 | `REQUEST_EPOCH_RETIRED`，不执行、不提案或在 apply 时拒绝 |
| Lookup | Unknown / Committed / Cancelled | `RESULT_RETIRED`；不能伪装成 Unknown、Cancelled 或未提交 |
| ResolveOrCancel | 原有有序查证/取消 | 返回退休状态；不产生对旧结果的虚假断言 |
| 新鲜状态读取 | 返回当前 epoch、保留模式和 head | 不唤醒数据库，也不把旧请求自动换成新 epoch |

`RESULT_RETIRED` 说明旧原始结果不在服务承诺的查询范围中，并且旧身份不能再产生新的接受；它**不能说明该请求过去没有提交**。应用需要永久业务去重时，应另设业务唯一键/账务记录，不能依靠窗口内 RPC 去重永久推断。

## 3. SDK 身份必须在首次发送之前固定

`RequestIdentity` 增加 epoch，连同 request ID、原 SQL/参数、原 deadline 一起固定并传播到 Lookup/ResolveOrCancel。字段必须按 u64 字符串或 BigInt 无损处理，禁止 JS number 失真。

只有确认未提案的 NOT_LEADER 才允许沿用原身份和原 deadline 换地址。任何 UNKNOWN、断连、超时、退休响应都不能自动获取新 epoch 后重发同一业务写；即使 ID 相同，新 epoch 也已经是新的协议身份，可能重复业务效果。

已有原生 `@libsql/client/http` 没有稳定 epoch 的调用不能在服务端为每次请求补上“当前 epoch”然后声称安全兼容。窗口模式下缺少该字段应在 SQL 开始前返回 `REQUEST_EPOCH_REQUIRED`。LegacyPinned 继续支持原接入方式。应用迁移必须明确选择新 SDK/请求头策略，不能静默改变承诺。

## 4. 轮换必须是同 cell 的原子有序操作

拟新增内部或独立管理员接口 `RotateRequestWindow(expected_epoch)`，仅允许数据库 ADMIN。数据库级窗口会影响该库所有调用方，普通 SQL 用户不得代替其他用户轮换；第一版禁止容量满时由 SDK 自动执行此操作。

同一 Raft 应用候选应按以下顺序完成校验和构造，最后一次发布：

1. 验证当前权限、完整身份、格式模式以及 expected epoch；检查 epoch/owner 计数溢出，禁止回绕。
2. 从同一权威视图的物理 base/tail 构建覆盖当前 head 的完整恢复基线；冷库须有精确、已发布的可恢复材料，不能凭空制造镜像。第一版可明确拒绝 Cold 轮换，要求先完成受控 hydrate。
3. 将 head 固定为独立的 revision、commit hash 与最后提交位置，不能因移除 Vec 前缀而倒退或重置 revision。
4. 原子推进 request epoch、失效旧 writer 的有效所有权，并清除被退休窗口的结果/取消记录与已被新基线覆盖的旧逻辑前缀。新 owner 只能从新权威基线恢复到新目录后激活。
5. 校验候选总预算和所有索引/恢复不变量，成功后与 applied 一起持久化。失败保留旧 epoch、结果、fence 和恢复材料，不允许先删除再尝试建立基线。

轮换前已经有序接受的写必须包含在基线中；轮换后的旧 proposal 必须拒绝。这也包括“服务已接受但客户端未收到 ACK”的写。原请求的返回结果可能在轮换后已无法查证，因此轮换策略必须允许业务知晓这个保留期限。

失效旧 owner 不等于阻止已经持久接受的事务在其私有旧 SQLite cache 内完成 native publication；那份缓存不能再为新读写提供授权。测试必须区分本地不可达旧副本的物理发布与新的权威接受，不能要求已经提交的数据被回滚。

轮换重试通过 expected-epoch CAS 和有界的最近轮换证明处理。不得为每次轮换追加一个永久 AdminRecord，否则只是把 128 请求上限换成 4096 行政记录上限。较老轮换收到已超越状态，不应伪造原始回执。一般 owner/auth/行政操作记录的长期退休是另一个必须处理的容量门禁，本提案不能单独宣称无限长期运行已经实现。

## 5. 数据结构与物理恢复需同时解耦

拟把当前混合的 `transactions` 表拆为：

- `DatabaseHead`：独立、单调、权威的 revision / commit hash / position。
- `RecoveryBase` 与连续有限物理 tail：只承担恢复，跨窗口维持 head 连续性。
- 当前窗口的 `RequestResults`：保存该窗口的原 fingerprint、receipt、result 或 Cancelled。
- `RequestWindow`：活动 epoch、保留模式及有界轮换证明。

目前 `Accepted(sequence)` 对 Vec 的寻址和 base 对逻辑前缀末记录的证明都要改为明确的 anchor，不允许只改长度或做下标偏移修补。纯物理算法仍复用正式 `scap_core::physical`，不能另写 SQL 重放恢复器。原 receipt 中的旧 epoch/owner/position 均不可改造为新票据。

## 6. Snapshot、归档、升级与灾备

Raft snapshot 必须包含当前 request epoch、head、物理基线、窗口结果以及取消信息。安装 snapshot 的 applied/term 与身份校验仍由正式 Store/driver 执行；不能仅凭“epoch 较新”跳过 Raft 的位置合同。

旧 S3 对象可能含已退休结果。Hydrate 只补授权恢复所需的物理材料，不得用旧对象覆盖当前 request epoch、权限、owner 或取消状态。归档摘要和覆盖证明要区分物理 head 与逻辑结果窗口。没有新格式及迁移证明前，不修改旧 archive 的解释。

迁移采用 ADR-0017 的原则：旧日志先按旧规则追赶，在独立有序激活条目之后才启用新语义；不能在 decode 中删除旧逻辑记录，也不能让不同 applied 位置的副本各自决定退休。正式 Initialize/Join 的固定旧 genesis 合同不得改变。需独立的状态/对象/命令/回执格式版本与 peer 世代隔离；第一版采用全 cell 停机升级，不宣称混版本滚动兼容。

只从过旧 S3 点恢复、永久丢失多数派时，可能丢失较新的退休 fence。这是灾备恢复世代问题：必须拒绝沿用旧数据库身份继续接受旧请求，或提供覆盖全部 fence 的独立恢复根。未经该证明，不能把旧对象恢复宣传为 RPO 0，不能自动回退 request epoch。

本提案不引入对象删除，也不授权 S3 GC。对象引用、备份保留、pin 和删除许可需另行实施。

## 7. 实施拆分与必需证据

| 阶段 | 改动 | 合入前必须得到的证据 |
| --- | --- | --- |
| A | head / 恢复 anchor 与逻辑结果分离，外部行为不变 | 正式 Rust 精确四维 100%；旧格式生产 fixture、snapshot、真实重启与 archive 往返 |
| B | 新格式与有序激活，LegacyPinned 默认不变 | 不同旧 applied 追赶后字节一致；旧 binary 拒绝新盘；不能混代形成 quorum |
| C | epoch 绑定与管理员 CAS 轮换 | 乱序/重复/迟到 Commit、取消及 UNKNOWN；轮换前后 SIGKILL、预算失败原子性和旧 writer fence |
| D | Node SDK、明确结果退休响应、状态观测 | SDK 完整覆盖；缺 epoch 拒绝；未知写绝不自动换窗口重发；64 位值无损 |
| E | 长期循环与故障合同 | 真实三进程执行远超 128 次请求且多次轮换；资源保持有界；全部 ACK 效果保留；旧 ID 永不再次接受；冷对象不复活旧窗口 |

所有阶段继续保留失败与 UNKNOWN 分母，不用模拟器输出代替正式服务证明。状态机数据结构变化和格式激活应在独立可审查增量中完成，不把整个平台目标一次性标记完成。

## 当前结论

这是下一阶段的具体安全约束和实施顺序，不是已上线的结果回收功能。当前每库 128 个请求身份、每 cell 4096 个行政记录等限制保持不变。多 cell、GiB 级库、三 AZ 性能、自动副本调度、GC/PITR/完整 DR 仍各有独立目标。
