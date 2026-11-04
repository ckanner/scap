# 成员管理与故障副本替换

状态：随 [ADR-0016](../adr/0016-durable-membership-replacement.md)通过完整本地门禁（2026-11-04），含真实四进程替换、快照追赶与重启恢复。该操作仍要求先完成部署升级并存在健康多数派；跨 AZ 与生产规模另行验收。

## 适用范围

一个 cell 的稳定配置保留三个 voter，允许先添加一个 learner，再以显式 joint consensus 替换一个 voter。joint 期间 incoming/outgoing 各有三个 voter，成员并集可为四个，必须分别满足两组多数派。故障副本可以停止或损坏，但原组仍必须有两个健康且可持久化的 voter。不会用过期 S3 状态或人工减少成员数恢复可写。

这是受控操作入口。当前没有自动故障检测、云实例采购、证书签发或跨 cell 调度服务；operator 负责选择目标、新身份及故障域放置。默认没有开放管理 listener。

## 配置与升级顺序

在所有原 voter 上部署支持 ADR-0016 的程序，保持原数据目录、cluster/cell/incarnation 和初始三个 voter。先逐个重启并确认健康多数派仍在，再执行成员变更。不能在旧固定成员程序仍运行时写入第一条动态配置。

新增配置字段：

| 字段 | 约束 |
| --- | --- |
| `peers` | 3–16 个预注册身份，每项仍包含 node ID、HTTPS peer endpoint 和实际 leaf DER pin；所有节点需一致覆盖待加入身份 |
| `bootstrap_voters` | 恰好三个原始 voter ID，均在 peers 中；原三个 peer 的旧配置可省略，超过三个 peer 时必须明确指定 |
| `management.listen` | 管理 listener 的 loopback socket 地址，与 SQL/peer listener 分开 |
| `management.token_sha256` | 独立高熵管理 token 的 SHA-256；非零、不能与数据库凭据 digest 相同 |

`management` 省略或设为 false 时关闭。配置只保存 digest，CLI/Join 的 token 由 `SCAP_MANAGEMENT_TOKEN` 环境注入。不同节点的配置文件仍按各自主机路径、证书和监听端口填写，参见 [server README](../../crates/scap-server/README.md)。

预注册只建立通信许可。真实 voter/learner 来自 Raft ConfState；改 peers 文件不能加入、删除或提升一个节点。新 node ID 必须严格大于当前所有成员 ID，且不能让同一私钥/node ID 同时运行两个实例。

## 操作步骤

### 1. 读取健康 leader 的当前配置

在能访问该节点 loopback 管理 listener 的受控主机上，注入管理 token 后执行：

```bash
./target/release/scap-server --membership node-1.json
```

节点必须能完成 Safe ReadIndex；非 leader 或无 quorum 不会返回可用于变更的成功视图。响应包含 scope、原始 `bootstrap_voters`、`genesis_sha256`、完整 `conf_state`、应用位置、commit、snapshot 位置、leader 和复制进度。

`GET /v1/admin/status` 是单独的本机诊断，响应带 `authoritative:false`。它可用于查看 learner 的持久追赶，但不能代替上述权威配置读取，也不能证明一次变更完成。

### 2. 在新身份、新目录启动 Join

准备与原 cell 相同的身份、genesis 配置和可信 peer 目录，为新节点使用独立证书及全新 data directory。不要清空故障副本目录后继续使用旧 ID。

```bash
export SCAP_JOIN_MANAGEMENT_URL=http://127.0.0.1:19701
./target/release/scap-server --join node-4.json
```

这里的地址须指向健康 leader 的管理 listener；跨主机操作可通过受控 SSH 端口转发，使其在加入主机上以 loopback 可达。Join 在创建数据目录前先使用管理 token 获取新鲜配置，校验完整 scope、原始 bootstrap 列表、完整 genesis 摘要、新 ID 和原 deadline。远端与输入预检失败不会初始化新目录。预检通过后，在建目录前与开监听前仍复核原 5 秒预算；磁盘初始化后超时或其他启动失败时保留已创建目录供诊断，不执行破坏性回滚，也不把失败当作可重用旧 ID 的许可。

所有节点都要保留原始 bootstrap 配置。源端启动会核对持久 CellState 中的管理员身份与 limits，但现有 Store 没有另存原始 voter 列表供恢复推导；禁止把当前替换后的三个 voter 改填为新的 bootstrap。该字段与实际当前 ConfState 是不同信息。

Join 成功启动后仍不是 voter，不能提供 SQL。之后该节点的正常重启使用默认 OpenExisting：

```bash
./target/release/scap-server node-4.json
```

再次使用 `--join` 不是重启或坏盘修复方法。

### 3. 添加唯一 learner

从新鲜成员视图复制完整 `conf_state` 到请求的 `expected_conf_state`。下面示例仅适用于权威视图确实为原三个 voter 的情况；实际身份和集合必须以读取结果为准。

```json
{
  "action": "add_learner",
  "node_id": 4,
  "expected_conf_state": {
    "voters": [1, 2, 3],
    "learners": [],
    "voters_outgoing": [],
    "learners_next": [],
    "auto_leave": false
  },
  "deadline_ms": 5000
}
```

将该请求保存为 `add-learner.json` 后，通过当前 leader 的配置执行一次：

```bash
./target/release/scap-server --membership node-1.json add-learner.json
```

只有精确配置条目持久应用后才返回 `outcome: applied`。learner 会通过原 peer 通道追赶日志；已经裁剪的前缀通过完整 Raft snapshot 恢复，而不是从不可靠 worker 文件重建。

### 4. 等待追赶，再进入 joint

重新读取成员视图。learner 的 `matched` 至少达到当前 commit 后，才允许替换；服务端还会在实际提案时再次检查，不能依赖客户端旧进度。被替换者必须是另一个当前 voter，不主动移除发起变更的 leader。

请求使用 `action: replace_voter`、`node_id: 4`、`remove_id: 3` 和刚读到的完整 `expected_conf_state`；其他字段与上一例相同。输出 incoming voter 集合含新节点，outgoing 保留原三个 voter，`auto_leave` 为 false。

此时仍同时需要新旧两组多数派。不要删除旧身份、改小配置或假定 joint 已自动结束。进程崩溃后按 OpenExisting 重启，持久 joint 必须保留。

### 5. 显式退出 joint

再次读取当前完整配置，发送 `action: leave_joint` 和相应 `expected_conf_state`，不携带 node/remove 字段。成功后 outgoing 清空，新的三个 voter 成为稳定配置。

如果 joint 期间换主，最后离开 joint 可能恰好移除当时的旧 leader。这个转换仍经过完整持久应用；被移除节点实际退位并撤下 SQL readiness。回复丢失时到新 leader 查询，不能把旧 leader 的连接断开当作回滚。

确认新配置、三个副本的追赶和已确认业务数据后，再按运维保留策略处理旧介质与身份。旧节点使用原目录重开不能自行恢复当前 quorum 的投票或 SQL 权限；它可能尚持旧 ConfState 并发出选举消息，不应把启动完成当成获知了移除。已移除 ID 不得再次加入。

## 失败和并发语义

| 结果 | 处理 |
| --- | --- |
| `MEMBERSHIP_CONFLICT` | 预期配置已经改变；重新读取和审查当前状态，不自动套用旧操作 |
| `MEMBERSHIP_PENDING` | 已有配置在提交/应用中或处于不允许的阶段；先查询已有变更 |
| `LEARNER_NOT_CAUGHT_UP` | 修复连接、磁盘或快照追赶；原 voter 配置继续保留 |
| `MEMBERSHIP_UNKNOWN`、超时或断连 | 提案可能提交；从健康 leader 做强读查证，不盲重发 POST |
| Join scope/身份/权限/时间失败 | 修复输入或访问健康 leader；不将失败解释成允许初始化 |
| 无 quorum | 停止管理与新的强读写，修复原组；不强制修改 ConfState |

配置 CAS 按集合比较，但零、重复、越界和非法关系会拒绝。每个控制请求的等待保持原 deadline；新的 GET 是查证操作，不会撤回旧 POST。默认管理预算为 5 秒，接受的请求上限为 30 秒。

## 验证与剩余目标

对应 [真实四进程合同](../../experiments/membership-network/README.md)。验收包括坏/停节点替换、联合配置重启、真实 snapshot 追赶、新 voter 独占来源的 ACK 重启恢复、旧 ID/空盘重用拒绝，以及少数派行为。

这个入口不扩大 32 库、256 KiB 镜像、128 请求记录或 4096 管理记录的现有 profile，也不实现自动坏盘运维、在线任意证书目录编辑、PITR、GC、跨 cell 调度或生产三 AZ SLO。后续能力按 [路线图](roadmap.md)继续，不能用这次替换成功代替所有平台目标。
