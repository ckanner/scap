# 持久 Raft driver 与有界成员替换

正式 driver 独占 `RawNode<Store>`，在专用阻塞线程中串行接受输入并 drain Ready。持久化和应用顺序是所有输出的前提：先保存 Ready 的日志/HardState/snapshot，再 advance append，应用已提交条目，最后把 application、完整 ConfState 与 applied 一起同步保存。随后才释放消息、Safe ReadIndex barrier、业务 proposal result 或配置 result。

## 成员管理接口

| 接口 | 成功的含义 |
| --- | --- |
| `membership_status()` | 本机的 durable ConfState、进度和协议观察；权威管理读取须由 runtime 先完成 fresh Safe ReadIndex |
| `change_membership(expected, change)` | 唯一配置请求已经准入，返回本 boot 的 ticket；还不是配置完成 |
| `Output::memberships` | 对应 ticket 的精确配置条目已原子 durable apply |
| `cancel_membership(ticket)` | 只撤销本机 waiter；日志条目仍可能提交 |
| `Status::is_voter` | 本节点在实际 incoming/outgoing voter 集合中；trusted peer、learner 和被移除节点不会因此取得服务资格 |

`MembershipChange` 只提供 `AddLearner { node_id }`、`ReplaceVoter { remove_id, learner_id }` 与 `LeaveJoint`。所有动作要求当前 leader、没有未应用配置条目、完整 ConfState CAS 匹配。固定三 voters 的稳定配置最多有一个 learner。learner ID 必须大于原最大成员 ID，替换时新的更大 ID 留在 voters 中；该不变量随 ConfState 跨 checkpoint、snapshot 与重开保留，避免旧 ID 重新加入与 CAS 的配置回退。

替换前 driver 在同一次串行准入中检查 learner 的 `matched >= 当前 Raft commit`，再构造单一显式 joint 配置变更：加入新 voter 并移除旧 voter。它不把 `matched` 宣称为 remote applied，且不允许普通配置修改绕过 learner。初次替换不能选择本 leader 为被移除节点；joint 期间换主后，显式退出仍允许移除这时的 outgoing-only leader。

固定上游版本在移除 leader 后只更新 promotable。因此本 driver 在 ConfState 成功落盘后执行同 term 的明确退位，并丢弃尚未释放的旧 leader Append/Heartbeat/Snapshot。未持久化成功时仍然停止整个 driver，不提前发布配置或回执。非 voter 的 campaign、proposal 和 ReadIndex 均被拒绝。

## 结果、容量与失败

配置结果匹配完整 entry context、term、编码和目标配置。ticket 包含 boot identity，重开不能复用旧等待者；取消或 snapshot 安装不能制造一个未观察到的精确条目结果。失败或超时后的状态由 fresh management read 解决，不能由 admission、网络 `Received` 或 `UNKNOWN` 推断。

成员视图最多容纳 16 个 progress 项；CAS 各集合有相同有限上界，重复/零 ID 和未知 protobuf 字段被拒绝。固定 4096 字节保守预算覆盖配置结果与 runtime 管理响应；单个配置 waiter 不引入无界队列。输出预算不足时结果留在 driver 中，新的输入须继续 drain。

身份注册、pins、pool membership、管理鉴权及 fresh Join 前检查属于 wire/runtime/server。新的 Joining Store 使用原 bootstrap3 的相同创世 application 和配置，本机 ID 不在该配置；加入实际成员只可能经共识条目完成。损坏目录不得借 Join 自动重新初始化，永久失去多数也不能通过此接口自动缩小 quorum。

完整决策见 [ADR-0016](../../docs/adr/0016-durable-membership-replacement.md)，运行时接线见 [runtime README](../scap-raft-runtime/README.md)。单元测试执行真实 RawNode 和 Store，在窄存储/时钟/消息边界注入故障；生产源码全部计入四维精确 100% 单元门禁。真实四进程、mTLS、RocksDB、snapshot 和 SIGKILL 契约独立验证，不填补单元覆盖缺口。
