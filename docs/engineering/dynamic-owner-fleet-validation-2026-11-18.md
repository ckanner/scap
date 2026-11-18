# 受信动态 fleet 的实现与实际验收（2026-11-18，UTC）

有限部署名单的在线更新、不可撤销的 worker 退役、端点复用和旧 owner 计划处理，已经
通过正式 `scapd`、Node controller、原生 SQLite、真实 HTTP 与签名本地 S3 的完整合同。
冻结组合 `a2cc536770d7fc2e1b155d439616e29d25ad724a` 的实际运行用时 **66.517秒**，
固定全程180秒和阶段75秒预算没有调整；独立原始审计通过，**13项反例全部拒绝、1项正控通过**。

[机器可读证据](../evidence/dynamic-owner-fleet-local-2026-11-18.json)保存来源、二进制、日志、
原件清单摘要和精确分母。完整协议见[动态 owner fleet](../architecture/dynamic-owner-fleet.md)，
实验边界见[固定实际合同](../../experiments/object-dynamic-fleet-runtime/PLAN.md)。

## 已实现的行为

version=2 配置由可信部署器提供完整 `previousPolicies` 与严格递增的 `revision`。CLI
响应 SIGHUP，库调用方可使用 `OwnerControllerFleet.replace()`。校验完整配置后才停止
旧 admission；原 tick 和 transport 的 request、socket、DNS callback 全部归还后，再安装
一个完整新快照。无效配置、回退、旧历史遗漏、身份重绑和退役复活都在干扰旧快照前拒绝。

新 worker 必须保留永久新身份，并使用更高 rank。复用旧入口需要先显式退役原身份；
`TARGET_MISMATCH` 仍然阻断，不能据此改写 guard 或推断旧 worker 死亡。历史策略只能
核对原计划的完整输入；退役目标只允许沿原 recipe 查证、取消，不能 claim/resume。
controller 不发送业务 SQL，已有业务请求也不会因为 reload 自动改路由后重新执行。

历史的权限、Scope、authority、principal、自动模式、TLS选择和预算固定，不能借加入旧
policy 扩大授权。原 `pastUnknown` 与 `lastUncertainCall` 在本进程 reload 和 Scope 暂时
移除后保留。新 owner 后来 Active，不会被记作原 UNKNOWN 调用已经收到 ACK。

这次自审补上了 transport 的 `quiesce()`：tick Promise 结束以后，DNS 或 socket 仍可能
占有原请求资源，所以只等待 Promise 不足以完成切换。公共库调用方仍需在 `finally`
中 `await fleet.close()`；`snapshot().closed` 只表示停止 admission，不能代替 join 证明。

## 来源与独立门禁

| 项目 | 本次结果 |
|---|---|
| SDK unit | 182/182；22个生产 JS 文件逐文件 line/function/branch 与全部 V8 raw ranges 精确100% |
| HTTP / CLI | 14/14，独立于 unit profile；包括真实 ClientRequest/socket、可控 DNS 回调延迟、严格 TLS、SIGHUP join、配置回退与信号退出 |
| TypeScript | 严格检查公开声明及 `sdk/node/test/types.ts` 通过 |
| 独立 observer unit | 7/7，包括原 recipe/guard、退役目标禁止 resume、真实 `policy` wire operation 与撤权修订 |
| 完整实际 | 4个 worker 进程、1个 controller、4个业务调用进程及4个 S3 后端进程全部回收；cleanup errors为空 |
| 原始审计与反例 | `PASS_DYNAMIC_TRUSTED_FLEET`；13负控+1正控；170个原件逐一哈希前后相同 |

完整 tracked source 为 **864个文件**，指纹
`9dd8cd4cfdb687026c511803cf40802908549b0853e1b25489e08d7638ef4eb3`。
正式 release receipt 绑定 **309个构建输入**、原 Cargo 完成记录、实际 executable 和 native
SQLite archive，源码在运行前后没有变化。SDK unit 候选的所有 `sdk/node/` 文件另与该
冻结 manifest 逐文件比对，内容相同，未用真实运行 profile 补 unit 覆盖。

- `scapd` SHA-256：`8d99dd7380aa1aa34270edf34748e16025fc06a6144b9b870ede398ee78ad47b`。
- 原 build record SHA-256：`16cfbae97cfee89163cea62ae82f0eefdadbb2694dfabaf86451960b48ff06b5`。
- 固定工具：Rust1.90.0、Node22.16.0、SeaweedFS4.51；工具字节摘要保存在机器证据中。
- 原始实际 summary 继续保留 `OBSERVED_NOT_AUDITED`，后续 oracle/controls 单独记录成功；
  没有改写原运行结果或覆盖旧失败。

## 固定实际历史

初始 A/B/C 分别使用9601/9602/9603。前三个业务 execute 使用保存的原请求身份，包含
计数器与随机结果；前两个得到 ACK，第三个真实提交后丢失 HTTP 回复，业务保留 UNKNOWN。

随后同一个 controller 处理如下部署变化：

1. A 健康时只读。加入 C、退役 A 后，B 按原 guard 和 HEAD 条件接管；B 的 claim 已经
   生效但回复被丢弃，controller 记录原 UNKNOWN。
2. 退役 B 并保留 P1/P2 历史后，controller 核对并 abort 原 B 计划；随后使用新 policy
   的完整 nonce 让 C 接管。没有 resume 已退役 B。
3. 退役 C、把原 A 入口配置给新身份 D=9604。入口仍由 A 服务时得到 TARGET_MISMATCH，
   此阶段零 owner mutation，guard 不变。
4. A 实际退出、原 cache 删除后，D 使用空私有 cache 在同一入口启动。新 guarded status
   成功后，D 接管并从原 S3 数据恢复。
5. 回退 revision 与复活旧 C 的两份配置均拒绝，当前 revision 保持5。撤回 controller
   principal12权限后，新的权威读取得到 DENIED，之后没有 owner mutation。
6. controller 收到 SIGTERM 并 join。业务在 D 使用三个原身份 lookup，结果逐字一致；
   计数器仍为3，保留的快照仍为 sequence2。向该入口发送原 A guard 仍被拒绝且没有 S3副作用。

独立审计重算 **52次 controller HTTP、12份 tick报告、71次总HTTP、269次 S3请求**。
owner mutation 分母固定为 prepare3、claim3、resume2、abort1，共9次；4次 reload成功、
2次配置拒绝。全部 HEAD 原 ETag、owner descriptor、phase、实际状态和 worker身份由
原始 HTTP/S3 字节核对，controller 输出本身不充当持久权威。

反例分别篡改完整历史、revision接受结果、退役复活、UNKNOWN保留、SQL发送、恢复结果、
原 HEAD 条件、替代进程退出、原 guard、退役目标 resume、descriptor reference、旧 policy
nonce 和构建来源。每项都在指定的独立语义检查拒绝；原件没有被修改。

## 保留的失败与边界

第一次旧候选实际完成后，独立 auditor 把 SDK 的 `policy` 操作误写成 `set_policy`，因此
审计失败。原失败和59.472秒的旧运行记录保留；修正 auditor 并增加回归案例后，使用含
quiesce 的新组合重新完成上述整轮实际。这次结论只引用新的66.517秒运行。

全仓 unit 门禁另发现 GC 单测要求40ms总期限内的第三个 TCP请求必定到达，调度暂停时
可能与正确的发送前超时冲突。只修改测试：暂停 Tokio 时间控制异步 timeout，继续保存
同一个原 `std::Instant`，严格检查请求数、原条件、未知结果和禁止重试；另测真实墙钟的
完成后期限检查。同一 future 的及时/逾期两条完成路径都补测，生产 deadline 与覆盖门禁
保持。原测试失败和后续单态 region 缺口也记录在机器证据中；全仓 Rust 最终覆盖结论
属于组合验证，不能从本页的 SDK/实际结果推导。

此交付是**可信部署器驱动的有限在线成员更新**。已见 Scope最多128、worker incarnation
最多256、每Scope最多16个 previous policy；合计 canonical policy与配置文件各最多64KiB。
达到上界就拒绝，不能静默丢弃历史。revision只在本进程检查单调性，重启和多 controller
仍要求部署器提供当前完整配置并协调更新；旧配置未完成退出前不承诺固定排空 RTO。
分布式 S3 registry、自动发现/扩缩容、无限历史迁移、AWS Standard/IAM、真实NFS环境及
生产吞吐/资源/RTO SLO均不由这份本地结果证明。业务 RoutedClient 仍保留自己的显式快照。

## 复现

先生成新正式 build receipt，然后使用全新的 evidence目录运行固定合同，最后分别执行
oracle和controls。整个过程不写入源码目录：

```bash
python3 experiments/object-service/build.py --target-dir /absolute/new/release --evidence /absolute/new/build
python3 experiments/object-dynamic-fleet-runtime/run.py --server /absolute/new/release/release/scapd --build-record /absolute/new/build/build.json --weed /absolute/pinned/weed --node /absolute/pinned/node --evidence /absolute/new/dynamic
python3 experiments/object-dynamic-fleet-runtime/oracle.py /absolute/new/dynamic
python3 experiments/object-dynamic-fleet-runtime/controls.py /absolute/new/dynamic
```
