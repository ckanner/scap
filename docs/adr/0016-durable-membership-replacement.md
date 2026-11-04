# ADR-0016：持久成员变更与故障副本替换

- 日期：2026-11-04。
- 状态：已实现并通过完整本地门禁（2026-11-04）；范围为受控三 voter 替换，不代表完整生产平台或跨 AZ SLO 已验收。
- 关联：[Raft 接合门禁](../engineering/raft-rs-integration.md)、[故障矩阵](../operations/failure-matrix.md)、[ADR-0012](0012-bounded-raft-network-runtime.md)、[ADR-0015](0015-incremental-blocks-and-isolated-execution.md)。

## 问题

固定三个 voter 能在一个节点停止后继续提交，但无法替换永久损坏的副本。修改本地 peers 或在旧目录重新初始化不能成为成员变更协议。已有 Store 和 driver 会原子保存业务状态、ConfState 和 applied，网络/运行时却只接受固定成员；服务也缺少受控加入、成员管理和完成确认入口。

需要在保留 durable quorum、Safe ReadIndex、owner fencing、原请求结果和当前权限的前提下，恢复三个有效持久副本。单元覆盖率仍要求第一方行、函数、region 和分支全部精确 100%；真实进程/网络/磁盘验证独立执行。

## 决策

### 1. 可信通信目录与实际成员分离

一个配置可预注册 3–16 个 peer 身份、地址和 leaf pin，数量有界；node ID 不受 16 的数值限制。该目录授予特定 cluster/cell/incarnation 内的通信资格，不授予投票权、leader 身份或 SQL 执行权。实际角色始终来自持久 ConfState。

保留固定 Policy 的原行为，动态模式必须显式构造。两种模式继续执行实际证书链、DNS、有效时间、当前 pin、消息 envelope、大小、deadline 和消费时重新授权。动态模式仅开放有界 ConfChangeV2 和合法 learner/joint snapshot；旧式 V1 配置消息、未知 enum、重复/零/未注册 ID 和非法集合关系被拒绝。

目录中的 peer 是受信 Raft 节点，不是允许发送任意共识消息的普通租户。协议仍针对非拜占庭故障；预注册身份不构成拜占庭容错承诺。

### 2. 显式加入，不从损坏介质推断初始化

`bootstrap_voters` 始终恰好三个，且都是可信目录成员。旧三 peer 配置可省略该字段并沿用原行为；更大的目录必须显式指定。

Initialize 仅用于 bootstrap voter 的新目录。Join 仅用于不在 bootstrap voters 中的新身份和新目录，沿用同一 bootstrap configuration/genesis，但自身没有选举、提案和 SQL 服务资格。后续只通过已运行 quorum 接受 AddLearner 获得 learner 角色，再通过日志或快照追赶。OpenExisting 以已持久化的配置为准，不把初始配置重新写回磁盘。

Join 在创建目录和启动 peer listener 前，必须使用独立管理凭据向健康 leader 取得新鲜 Safe ReadIndex 视图，核对完整 cluster/cell/incarnation、原三个 bootstrap voters、规范 genesis 摘要和新 ID 大于当前所有成员 ID。摘要包含完整初始 CellState，因此管理员身份、复制 limits 和初始应用位置也必须相同；不能仅凭 term/index 相同接受不同初态。`SCAP_JOIN_MANAGEMENT_URL` 只能是 loopback 管理端点；跨主机操作通过受控转发连接健康 leader。查询失败或同一 ID 已经是 learner/voter 时拒绝，不用本地 bootstrap 配置猜测它仍是新节点。正常顺序为先 Join，再 AddLearner。

源节点重开时从持久 CellState 核对不可变 bootstrap administrator，decode 同时验证 cell、limits 和应用位置。原始 bootstrap voter 列表仍是必须保持不变的受信部署配置；现有 Store 没有额外永久保存原始配置摘要，本轮也不将源端错误重写该配置宣称为已被独立持久证明防护。当前 ConfState 始终读取实际持久状态，不能用 bootstrap 字段覆盖它。

该检查阻止把已使用的 voter ID 换一个空目录直接重新上线；它不替代主机身份管理。部署者仍必须保证同一私钥/node ID 只有一个运行实例，不能并发克隆未登记身份或借用另一成员的证书。

损坏的 data directory 保持失败并供诊断。替换使用新 ID、新证书和新目录，不在损坏目录上强制 Initialize，也不使用仅有一个副本的数据强开多数派。

### 3. 三步变更，保持三个 voter

| 操作 | 前置条件 | 持久结果 |
| --- | --- | --- |
| AddLearner | 稳定三个 voter、没有已有 learner 或 pending 配置；新 ID 已受信且大于当前全部成员 ID | 原三个 voter 不变，新增一个 learner |
| ReplaceVoter | 唯一 learner 已追到当前 commit；被替换者是其他当前 voter；没有 pending 配置 | 一条 JointExplicit 同时晋升 learner、移除目标；incoming 三 voter，outgoing 保留原三 voter |
| LeaveJoint | 当前为合法显式 joint 配置，没有 pending 配置 | 持久退出 joint，只保留新三个 voter |

所有操作都比较完整预期 ConfState，集合顺序不影响比较，重复或非法结构拒绝。配置不匹配、已有 pending 和 learner 未追上分别给出明确拒绝，不把这些条件转换为普通成功。

新 ID 严格单调增加，且一次只存在一个 learner；晋升后的最大 ID 保留在新 voter 集合。因此离开 joint、重启或裁剪后，都不能用已移除的旧 ID 再次加入，也不能让同一 ConfState 经一轮替换回到原值。这个有界入口不提供任意删成员、降低 quorum、移除未完成 learner 或复用身份的能力；需要这些操作时必须另外设计恢复协议。

ReplaceVoter 不主动选择当前 leader 为移除目标。joint 期间仍可能换主，所以 LeaveJoint 允许最终移除当时的 outgoing-only leader，不能因此把合法配置卡死。配置和应用水位持久化、完成 `advance_apply_to` 后，driver 对已非 voter 的本机执行真实 step-down，并撤下 SQL readiness；不能仅检查上游的 `role == Leader`。

### 4. 完成确认与 UNKNOWN

成员管理读使用独立 Safe ReadIndex，读取当前持久 ConfState 和应用水位。管理写的响应等待本次精确配置条目被持久应用；提案进入队列、网络 Received、learner 连接成功都不是完成。

原 deadline 覆盖排队、共识和等待。超时、取消、失去领导或断连后，已经提出的配置仍可能提交；未取得本次精确持久完成证明时返回 `MEMBERSHIP_UNKNOWN`，从健康 leader 查询权威配置，客户端不自动重发 POST。若在原 deadline 内取得本次精确 durable apply，换主或 LeaveJoint 恰好移除本机不妨碍返回 `applied`。应用配置与回复之间崩溃不会把一个已完成变更当作回滚。

### 5. 管理面单独鉴权

管理 listener 默认关闭。显式开启时仅绑定 loopback，使用独立的 token SHA-256，不能复用数据库 token。管理 API 不挂在公共 SQL listener 上，普通租户凭据不能查询或改变成员。

同一鉴权下的 `/v1/admin/status` 返回本机应用、snapshot 和角色信息，并明确 `authoritative:false`；learner 也能供运维检查。该观测不能代替 Safe ReadIndex，也不能用来确认一次成员变更已完成。

CLI 从环境 `SCAP_MANAGEMENT_TOKEN` 读取 token，不把 token 放在 argv 或配置明文中。远程管理需要受控主机通道；本轮不增加公共管理服务或自动故障探测控制器。GET、POST 都保留响应大小、总 deadline 和禁止重定向的边界。

## 格式、升级与限制

复用已有 Raft ConfChangeV2、ConfState 和 Store 原子持久格式，不改数据库 incarnation、业务请求格式或已确认写历史。首次出现动态配置后，旧的固定成员 runtime/wire 不能处理它，禁止直接降级回旧二进制。

必须先在所有原 voter 上部署支持此 ADR 的程序，并统一预注册新 peer 的身份与 pin，再启动 Join 和管理变更。尚未完成 joint 时不删除旧成员身份、磁盘或证书；完成后旧节点不能靠重开旧目录恢复服务资格。成员变更期间仍要求 incoming/outgoing 各自的法定多数，失败时修复实际副本和网络，不缩小 quorum。

本次有界入口维持三个 voter、至多一个 learner，可信目录最多 16 个身份。完整证书控制面、目录在线扩展、跨 cell 迁移、自动坏盘发现/采购、GC/PITR/DR 与跨 AZ SLO 不由这项改动自动完成。

## 验证出口

单元测试覆盖输入/CAS/资源/错误/取消和每个持久化边界，包括配置持久失败、精确 proposal completion、角色失效、变更中换主及最后移除当前 leader。新代码进入原覆盖率分母，不以实验替代。

[真实四 daemon 合同](../../experiments/membership-network/README.md)已完成 8/8：初始 quorum 与未加入节点；管理权限和陈旧 CAS；落后 learner 拒绝晋升；原三个 voter 都裁剪过 learner 初态后的真实快照追赶；旧 voter 停止时 joint 替换；joint 全组重启；退出 joint 后旧节点重现；新 voter 成为新 ACK 唯一可用磁盘来源的重启恢复；少数派无法获得强读或成员变更完成确认。在追赶、配置切换和重启等关键阶段逐项重读已 ACK 的随机 SQL 行，最终 135 行全部保留。少数派请求实际返回 UNKNOWN 后在 quorum 恢复时晚提交，该原始响应和后续状态都保留。

同一最终源码通过 452 个 Rust 单元、51 个生产文件四维精确 100%、11 个 SDK 单元、58 个工具单元和 9 套 Rust 实验共 80 项。固定 release 还通过原有 8 项服务合同、5 项真实 SDK 子测试、17 次冷唤醒隔离请求和 360 个恢复负载样本。完整计数、失败尝试和构建身份见 [执行证据](../engineering/g0-evidence.md)与[机器可读收据](../evidence/membership-local-2026-11-04.json)。

这些结果是本机故障与恢复证据，不替代三 AZ、介质断电或生产延迟/RTO 的分位验收，`production_slo_passed=false`。维护者已授权本地门禁通过后合并，远端 CI 未执行不记为通过。

## 固定上游依据

检索与本机锁定源码核对日期：2026-11-04。SCAP 实际锁定 raft-rs git commit `ad13f3d90780f53aea2488c6a4b76c0d334bf136`（package version 0.7.0），不将同版本号的 crates.io 发布物当成相同源码。以下说明该 commit 的 API 和联合配置算法；SCAP 的审批、预注册、ID 退休、持久完成与管理鉴权属于本项目责任。

- [固定 RawNode 源码：配置提案与应用](https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/raw_node.rs)。
- [固定 Changer 源码：进入与退出 joint、learner 关系校验](https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/confchange/changer.rs)。
- [固定 Raft 源码：成员应用、promotable 与 leader 退位边界](https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/raft.rs)。
