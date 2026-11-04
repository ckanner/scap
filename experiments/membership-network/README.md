# 真实成员变更与副本替换合同

该实验启动正式 `scap-server`、固定 Node SDK、真实 SQLite/RocksDB 和 mTLS/TCP。初始三个 voter 加一个 Join 进程，另预注册一个不启动的后续候选身份；只在实验层操纵进程和 TCP 黑洞，不实现第二套成员或恢复算法。

## 运行

```bash
cargo build --release -p scap-server --locked
npm --prefix sdk/node ci --ignore-scripts
npm --prefix sdk/node run build
export SCAP_SERVER_BIN="$PWD/target/release/scap-server"
export SCAP_MEMBERSHIP_EVIDENCE_DIR="$PWD/target/evidence/membership-network"
node experiments/membership-network/run.mjs
```

需要 Node.js 24.22.1、OpenSSL 和本项目固定 native 构建依赖。`SCAP_SERVER_BIN` 必须为绝对路径；证据目录应为本次新目录。禁止带 `LLVM_PROFILE_FILE` 或 `NODE_V8_COVERAGE` 执行，真实故障不进入单元覆盖率分母。

## 完整合同清单

| 历史编号 | 实际验证 |
| --- | --- |
| 01 | 原三个 voter 提供服务；新 Join 身份不会因为预注册而投票或提供 SQL |
| 02 | 独立管理 token、租户凭据拒绝、未知 peer 和完整预期配置 CAS |
| 03 | 隔离 learner 并提交新写，未追到 commit 时拒绝晋升 |
| 04 | 先从 fresh tenant metadata 观察双库非零 physical base，再记录权威 membership.applied 上界 B；等待原三个 voter 的生产 checkpoint 全部越过 B 后解除隔离，learner 真实安装带 base 的 snapshot 并持久 apply |
| 05 | 停止一个原 voter，进入 JointExplicit；全部进程 SIGKILL 后保留 joint 并恢复 ACK |
| 06 | 显式退出 joint；旧节点原目录重开不能恢复服务，旧 ID 不能再次加入；现有新 voter 换空目录 Join 在建目录前被拒绝；CLI 强读真实管理接口 |
| 07 | 停止一个幸存原 voter，以另一个原 voter 加新 voter 提交；再 SIGKILL 两个 ACK 持有者，只重开新 voter 和写前已停止的旧副本，验证只能从新 voter 磁盘恢复的新 ACK |
| 08 | 隔离当前 leader；新的强读和成员变更不能在少数派得到成功确认，恢复后查询真实最终配置 |

每个管理 POST 只发送一次；超时不会被当作未提交或安全重试。第 08 项特意使用合法、已预注册且更大的新 ID；恢复 quorum 后迟到配置可能提交，记录最终配置而不把 UNKNOWN 改写成原请求成功。

随机 SQL witness 在两个数据库中累计，所有成功返回的写逐行精确重读。写入数量保持在现有每库 128 请求上限内，同时跨过真实 checkpoint 的日志距离，不修改产品容量或持久化模式。

当前 base 迁移验收是联合证明：双库 base 先在权威读取中出现，随后取得上界 B；三个可能的 snapshot 来源都裁剪到 B 之后，而 learner 仍位于 genesis；之后 learner 持久安装实际 snapshot，最终通过含该新 voter 的 quorum、全组重启和只能从 node 4 磁盘取得的新 ACK 核对全部 135 条 witness。没有把 leader 上的 tenant status 冒充直接读取 learner 的 DB metadata，也没有为测试添加新的 runtime 诊断接口。每次 SQL 核验同时检查非零 base、原 tail 上限和未 cold-prune 状态。

## 证据与边界

公开证据包含固定二进制 SHA-256、每项开始/结束/失败历史、关键 ConfState/复制进度、ACK 核验数量和最终 summary。私有临时目录中的证书、密钥、token 配置、数据库和 daemon 原始日志不上传，不进入仓库。

缺少完整八项完成标记、任何断言失败、进程意外退出或原 ACK 行丢失都会失败。已失败的执行使用单独目录保留，不把重跑的成功覆盖原结果。

本机四进程不构成跨 AZ、介质断电、长期可用性或生产性能验收，`production_slo_passed` 保持 false。实际管理配置、操作顺序与限制见 [ADR-0016](../../docs/adr/0016-durable-membership-replacement.md)。

## 2026-11-04 V2 成员替换执行记录

以下保留的是本次 base/tail 增强之前的真实执行，不作为新增 base 断言已经通过的证据。增强后的结果另由新构建身份和执行记录给出。

固定正式 release 二进制 `9a9df3656d99e5275ca4cee74ceb7e8c85ba37156d5e24e605011728c7064dbb` 首次执行完成全部 **8/8** 合同。75 项生产输入的聚合 SHA-256 为 `5d9c2d210970e0c9363e187c15ddefd7397708fd1560623174b703f5d4b8bd17`，构建与运行前后一致；未使用旧 PR 的二进制或其测试结果。

原三个 voter 在解除 learner 隔离前的 snapshot 水位分别为 **129、138、138**，均超过 learner 的 genesis applied **1**。node 4 随后安装 snapshot **129**，持久应用到 **144**；因此这次追赶确实需要 snapshot，不能由另一个未裁剪的旧 voter 提供完整日志解释。

本轮替换 node 2，joint incoming 为 `[1,3,4]`，outgoing 为 `[1,2,3]`。全组 SIGKILL 后按原目录恢复，保留 joint；显式 LeaveJoint 后稳定为 `[1,3,4]`。旧 node 2 重现不恢复服务权，node 4 换空目录重复 Join 在创建目录前被拒绝。

两个库最终保留 **135 条成功返回的随机 witness 行：alpha 68、beta 67**。第 07 项新写只在 node 3 和 node 4 存活时获得确认；随后两个持有者都被 SIGKILL，仅重开 node 4 与写前已经停止的 node 1，并保持 node 3 关闭。恢复后逐行数据一致，证明这笔新 ACK 的可用来源是 node 4 的持久介质，而不是另一个保留全部数据的进程。

第 08 项在隔离 node 4 时发出唯一一次 AddLearner(5)，原请求返回 **HTTP 503 / `MEMBERSHIP_UNKNOWN`**。恢复 quorum 后，新的权威配置确实出现 `learners:[5]`。这次观测保留为“原响应未知、配置随后可见”，没有改写为原请求成功，也没有声称超时变更未发生。全部原 ACK 再次核对保留。

该执行没有生产 SLO 结论；完整来源、原始历史、分母和最终门禁见 [执行证据](../../docs/engineering/g0-evidence.md)。
