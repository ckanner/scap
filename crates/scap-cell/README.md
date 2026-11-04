# scap-cell

有界、确定的 cell 状态机。权限、owner epoch、请求身份、物理提交接受、原结果和取消 fence 都由同一份有序持久应用状态裁决。该模块不执行 SQL、访问对象存储或自行授予本地文件读取权限。

## 业务位置与身份

每个读取方先完成 Safe ReadIndex，再用同一个 Store 持久视图的 cell 身份和 applied term/index 调用 `CellState::decode_bound`。snapshot-only 安装也必须经过这个绑定检查；不能拿较新的外层 applied 位置授权旧的业务镜像。

`CellIdentity` 与 `DatabaseIdentity` 从 `scap-core` 原样 re-export。数据库身份、incarnation、placement generation、owner token 和当前 auth epoch 的校验顺序保持不变。历史 request ID 命中之前仍检查当前主体与权限，不能使用旧权限取回别人的结果。

## v3 物理基线与有界 tail

完整的逻辑事务 metadata、原 receipt、结果、原 admission 和 commit hash 继续保留在有界事务表中。`RequestRecord::Accepted(sequence)` 仍准确索引这张表；数据库 revision 仍是已接受记录总数。取消 fence 和管理 receipt 不会因物理折叠而删除。

物理恢复材料独立表示为：

| 类型 | 内容与合同 |
| --- | --- |
| `RecoveryBase` | `source`、`revision`、`commit_hash`、`image_digest` 和完整 SQLite image bytes；source 等于所覆盖末次提交的应用位置 |
| `RecoverySource` | 可选的基线及从 `base.revision + 1` 开始的连续物理 tail；不是从 revision 0 开始的完整历史 |
| `DatabaseView` | 原 head/owner/lifecycle 之外，提供 `base_revision`、`tail_entries`、`tail_bytes` 的有限观测 |

仅受信恢复代码使用 `CellState::recovery_source`；它仍要求当前 READ 权限，Cold 状态返回 `Reject::Cold`。外部请求结果查询继续使用 `lookup`，不从 tail 推导原结果是否存在。旧的 `recovery_transactions` 接口已移除，以免调用方把被折叠的前缀误当作仍可从空镜像重放的历史。

每次新 Commit 的候选状态达到以下任一条件时，确定地折叠当前全部 tail：

- tail 至少 8 条；
- tail 的物理 bytes 达到 `min(max_state_bytes / 4, max_transaction_bytes * 4)`。

阈值只来自已有复制 limits 和固定 v3 规则，不受 worker 本地配置影响。重放使用与正式 engine 相同的 `scap_core::physical` 算法，从已有合法基线或空镜像重建，逐条检查 receipt、SCAPIMG envelope、页转换及镜像摘要。最多页数由 `max_state_bytes / 4096` 推导并受物理格式上限约束；事务上限沿用复制的 `max_transaction_bytes`。

基线只在这次重放成功后建立。新基线、尾部和完整结果表同属本次 Commit 的候选 application，并由现有 Store applied 路径原子持久化。折叠失败或候选状态超限时，原已接受历史、结果和 fence 不变，不会先清除旧 bytes。native SQLite publication 仍只能由精确的持久接受结果授权，不能用内存中的基线替代 quorum ACK。

普通 Commit 继续采用既有的 opaque payload 摘要校验边界；需要折叠时才进行上述完整物理重放。因此任意自定义 opaque bytes 不能声称具备 SQLite 基线恢复能力。正式 SQLite writer 生成的 SCAPIMG payload 可经同一个纯算法验证。

## 编码与旧格式

| Envelope | 写入版本 | 读取范围 |
| --- | --- | --- |
| `SCAPCELL` | 激活前 2，激活后 3 | 1、2、3；升级先保留旧裁决语义 |
| `SCAPARC!` | 激活前 2，激活后 3 | legacy 阶段 2；激活后 2、3 |
| `SCAPCMD!` | 2 | 原有 1、2 规则 |
| `SCAPOUT!` | 2 | 原有 1、2 规则 |
| `SCAPIMG!` | 1 | 原正式物理格式，不因 cell v3 改写 |
| `SCAPACT!` / `SCAPACR!` | 1 | 独立内部激活 entry / 精确持久结果，不是普通业务 command/outcome |

v3 在每个数据库原 lifecycle/archive 字段后追加 optional base；归档在原逻辑事务字段后追加 optional base。所有长度、记录数量、位置、前缀覆盖、基线摘要和 tail 上限均在解码时核查。

读取 v1/v2 状态后，`physical_history_version()` 仍为 2，重新编码、容量判断、Commit、Publish 和 Hydrate 都保留原 v2 语义。仅加载旧磁盘不会启用折叠。这样落后副本重放旧 quorum 已裁决的 Capacity 拒绝、v2 对象发布和 hydrate 时，仍产生原结果与原字节。

受信 catalogue 通过 Raft 提交独立 `SCAPACT!` entry。状态机重新核对 cell 和不可变 bootstrap administrator，再在同一个候选状态中逐条验证所有热库的完整物理历史，按与 v3 Commit 相同的 8 条/bytes 阈值形成基线并保留未满 tail。只有所有库重放及总预算检查成功，才原子发布 phase 3；不能按每台副本任意的升级 head 强制全部折叠。失败返回绑定 cell 与精确 term/index 的内部拒绝结果，保留 phase 2、原结果和全部旧恢复 bytes，不中断后续 Raft apply。重复激活单调幂等，普通 `SCAPOUT!` 不能冒充激活结果。

公开 `bootstrap` 默认建立 phase 3；服务的 Initialize、Join 和固定 genesis hash 使用明确的 `bootstrap_legacy`，其空 genesis 与旧服务逐字节相同。新的 learner 因而可以从原 v2 前缀重放到激活 entry。catalogue 只有在精确持久激活结果之后重新完成 Safe ReadIndex、确认 phase 3，才开放业务；SQL lane 不自行激活。无法物理恢复的旧 opaque payload、损坏历史或不足的配置预算会使激活失败关闭，不能伪造空基线或自动放宽 limits。

旧 Cold 状态在激活时保留原 archive 引用和全部逻辑 metadata，不猜测或合成缺失的物理 bytes。激活后的 Hydrate 读取并核验准确旧对象，再使用相同规范切点恢复 base 与 tail。旧归档的 `metadata_digest` 继续绑定原不可变逻辑记录；权限更新和新取消 fence 不改变这个覆盖证明，Hydrate 也不能覆盖它们。

旧对象可以继续支持 Prune/Hydrate；迁移后的物理表示与旧归档不同，不等于旧归档已经失效。新的 Publish 生成 v3 对象并使用原 previous-object CAS；所有旧对象继续保留，没有 GC。

**旧磁盘读取兼容不代表混版本写入兼容。** v3 折叠改变容量接受行为，而 Commit envelope 保持 v2。新 Raft peer envelope 使用版本 2，拒绝旧版本 1；本轮要求停止整个 cell 的业务写入、升级 voter 后，由有序激活操作开启新语义。不提供混版本滚动激活协议，也不能用 peer 隔离替代对旧日志后缀的语义保留。

## 归档、日志与容量

Publish 仍核对准确 owner、head、previous object、可恢复覆盖和对象 bytes；对象上传及 readback 在 `scap-archive` 完成。Prune 只释放被该已发布对象覆盖的物理 base/tail。Cold 的 resident tail 数量与 bytes 为零，基线 anchor 可继续保留；请求结果和取消记录仍可查询。

数据库折叠不是共享 Raft log 压缩。完整 application 的持久 checkpoint、ConfState/applied 原子安装以及 log purge 仍由 driver/Store 的原有协议负责。

本轮不提高数据库大小、请求数量、结果大小或全 cell 状态上限。完整编码/校验、metadata 与结果保留、checkpoint 的总镜像预算仍有成本；达到上限继续拒绝新增长。该能力不证明 GiB 恢复性能、无限请求寿命、PITR、对象 GC 或生产 SLO。

## 验证来源

单元测试包含正常折叠、错误候选的原子保留、基线损坏、原结果/取消、Cold 生命周期、旧归档覆盖及编码边界。`test-fixtures/provenance.json`、`server-provenance.json`、`canonical-provenance.json` 和 `semantics-provenance.json` 记录由实际旧 main `662f04133f6a869d0dae5b05467656e6deca5c12` 已编译库生成的 v2 样本与 SHA；包括各升级前缀、原 Capacity/归档生命周期结果及 server genesis。这些固定 hex 并非通过把新编码版本字节改为 2 生成。真实 native SQLite 和 daemon 升级、故障恢复采用独立实验，不混入单元覆盖率。
