# 持久 owner 计划 HTTP 合同

本接口实现[HEAD8 设计](../../../docs/architecture/accepted-owner-plan.md)的显式管理步骤。
它仍需对应提交的生产覆盖与实际网络验收；独立有限模型通过不能替代这些门禁。
自动探测、选择新实例和后台循环属于后续 controller，不能由本接口的存在推定已实现。

## 身份与请求

所有步骤使用 `POST /v1`、`version: 1`、原完整 Scope 和当前 bearer 主体。每一步重新
要求当前 HEAD 中的 ADMIN。历史操作的 creator 可以不同于现在的管理员；新的 descriptor
创建必须以当前主体作为 creator。不能从已复用的名称重新推断旧 Scope。

| operation | 独立字段 | admission | 接收实例 |
| --- | --- | --- | --- |
| `owner_prepare` | `input` | control | 任意有相同对象存储配置的服务 |
| `owner_inspect` | `identity: {creator, operation}` | control | 任意服务，纯元数据 |
| `owner_claim` | `plan: {creator, operation, descriptor_hash}`，`expected_worker_instance` | control | descriptor 的目标 worker |
| `owner_resume` | 相同 `plan` 与必需的 `expected_worker_instance` | recovery | descriptor 的目标 worker |
| `owner_abort` | 相同 `plan` | control | 任意服务 |

上述所有 u64 均为非零规范十进制字符串，不能使用 JSON number；hash 为 64 个小写
十六进制字符。重复、未知、缺失或不规范字段均拒绝。claim/resume 的 worker guard
在 S3、缓存和恢复槽位操作之前与实际配置比较；不匹配返回 `TARGET_MISMATCH`。
该数值比较要求不复用 worker identity。daemon 启动通过[永久条件登记](../../../docs/architecture/worker-instance-claim.md)，在同一 bucket 内拒绝再次使用已登记 ID；可选[自动分配](../../../docs/architecture/worker-instance-allocation.md)先用持久计数器预留新 ID，再执行相同登记。首次采用前的历史 ID 与旧版混合部署仍须显式处理，不能由新 marker 或 counter 自动推断。

调用人在第一次网络请求前保存完整 Scope 和以下 input：

```json
{
  "creator": "3",
  "operation": "7001",
  "expected_revision": "21",
  "expected_head_serial": "24",
  "mode": "takeover",
  "target_worker": "5002",
  "nonces": {
    "claim": "8001",
    "cancel": "8002",
    "activate": "8003",
    "abort": "8004"
  }
}
```

`mode` 为 `takeover` 或 `activate`。takeover 接受时增加 owner epoch；activate 仅允许
原 owner 已 inactive 且目标仍为原 owner instance，保持 epoch。四个 nonce 两两不同；
输入固定后不能更换 operation、原 revision/serial、目标或 nonce 来重试同一意图。

prepare 成功只返回以下一种分支：

- `state: "prepared"`，以及 `prepared: {scope, input, reference}`。reference 为实际
  持久 descriptor 的 `{creator, operation, descriptor_hash}`。
- `state: "pending"`，以及当前阻塞计划的 `reference`。它不是本次 input 准备成功，
  不授予本次调用人新计划的派发资格。

descriptor 存在只证明原输入已保存，不代表 claim 已接受。若第一次 prepare 的回复丢失，
可以携带相同 input 再查询，或按原 creator/operation inspect。即使当前 HEAD 已推进，
已有记录也不得按新 HEAD 重建。SDK 从 inspect 取回 ref 之前必须比较实际 scope 和全部
原 input；不能把任意保存 JSON 当成经过验证的 mutation ref。

## 阶段、观察与 UNKNOWN

inspect/claim/resume/abort 返回相同的观察结构：`{state, status, prepared, accepted}`。
status 是本次当前 HEAD 的公开状态；accepted 为 null 或该原计划的稳定历史 marker。
所有普通 status 也有必需的 `owner_plan` 字段，旧 HEAD6/7 为 null。

| state | 含义 | 调用人可明确选择的下一步 |
| --- | --- | --- |
| prepared | 原 descriptor 存在，原 base 仍可竞争 | 对原 ref claim，或以 abort 取消 |
| claimed | HEAD 已接受原计划，inactive | 目标实例完整 resume，或当前 ADMIN abort |
| cancelling | 取消已占用原 HEAD 条件，inactive | 再显式 abort 形成终态 |
| active | 原计划曾完成激活 | 依据当前 status 决定使用或新计划；不再派发旧激活 |
| aborted | 原计划永久终止 | 当前状态允许时创建另一个明确的新计划 |
| fenced | 原 admission 已不能再生效，缺少可确认的原终态 | 保留过去 UNKNOWN；不能据此声称过去从未生效 |

未接受计划的 abort 最多执行一次 HEAD CAS：第一次形成 Cancelling，下一调用形成
Aborted。原 claim 已在途时，与 Cancelling 竞争同一个原 ETag。进程退出、客户端超时、
HTTP 断开和本地 sent 标记都不能撤销已经 invoke 的 S3 请求。

accepted marker 保留原 admission/phase 的 revision、head serial、nonce 和 owner tuple。
当 status.revision 等于 phase.revision 时，status.transition.nonce 必须等于 phase.nonce；
只增加 head serial 的技术变化保持这项绑定。业务 revision 已推进时可以有新的 nonce。
status 中的 revision、owner epoch、lifecycle、active 可能已变化。历史 `state: active`
不代表现在 active，也不代表新进程已有 Session。重复 resume 观察到终态时只返回元数据；
只有本次完整恢复、最终原 HEAD barrier 和 Active CAS 成功后才在 Engine 中保存新 Session。

UNKNOWN 后先查询原身份。服务不自动换 ETag、不自动循环下一阶段，也不重放 SQL。
业务写入结果仍按原 request lookup/cancel 处理，不由 owner 计划的成功替代。

## 兼容、权限与删除

首次接受 Claim 或 Cancelling 后，库永久使用 HEAD8；旧 binary 对未知格式失败关闭，
新 binary 也永久拒绝该库的 legacy takeover/activate。旧格式数据库可继续显式使用旧入口。
部署时服务和严格 SDK 必须一起更新，不能让旧 SDK 丢弃 owner_plan 字段继续构造旧意图。

pending 时停止新的写 SQL、未知请求取消追加、生命周期、窗口、存储维护和目录删除。
原 READ 权限允许 fresh query/lookup 和只读恢复；当前 ADMIN 可以撤回权限或调整 quota，
但必须保留 inactive、marker 和终态计数空间。控制接口使用独立调度准入，recovery 满时
inspect/abort 仍不需要 payload 恢复。

Deleted 或 terminal sealed 后，当前 ADMIN 仍可 metadata-only inspect 原 owner 历史；
这不恢复普通 SQL/lookup 访问，也不授予 GC。永久 descriptor/proof 与 HEAD 不属于
payload 清扫范围。新 marker 覆盖旧终态前必须保存并 exact 回读旧 proof；缺失或损坏的
永久权威不能通过重建记录掩盖。
同一 creator/operation 对应不同 descriptor hash 属于权威矛盾：双读 HEAD 稳定后返回
CORRUPT；若 HEAD 在观察间变化，先返回 CONFLICT。单份 HEAD 内部 nonce 不一致则
由严格格式校验直接拒绝。

## 恢复预算

可选服务配置如下；省略时采用相同默认值：

```json
{
  "owner_recovery": {
    "payload_gets": 1048576,
    "payload_bytes": 68719476736
  }
}
```

两个配置可降低到零，不能超过默认值。零表示禁止新的 owner payload 恢复，并不禁止
metadata-only inspect/abort。每个明确的新 resume 有独立预算；它不能在同一调用内耗尽后
重置。恢复槽位仍使用 `cache.parallel_recoveries`，总期限仍从原 HTTP 接收时开始。

每次 payload GET 先把返回 cap 收窄为原 cap 与剩余字节中的较小值，再预留一次请求与
授予的 cap。成功仅退回实际未使用的字节；失败不退。因本地 cap 收窄而发生的对象大小
拒绝属于 `LIMIT`，不会把健康数据库隔离为损坏。metadata 的 HEAD/owner I/O 另有每调用
8 次上限。预算耗尽不发布 Active、不返回可写 Session；后续新调用仍需完整恢复和鉴权。

这计量 Objects 接口的 GET 与返回体，不等同于底层 HTTP 重试流量。SQLite、本地镜像、
CPU、typed 结果与总 RSS 另有边界；不能把 64 GiB 累计读取预算解释成 64 GiB 同时驻留内存，
也不能把它解释成进程硬内存限制。完整进程与临时盘总预算仍须独立设计和验收。
