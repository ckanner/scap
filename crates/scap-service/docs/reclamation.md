# 显式压缩与已退休物理代回收

此接口把 HEAD6 的 compaction、checkpoint GC 和 HEAD7 的终态存储退休接入 HTTP 与 Node SDK。
它提供管理员手动控制：每次调用只执行一个阶段或一个最多 32 项的删除批，不自动重放 SQL、
更新旧候选 ETag、重新分配 plan/batch 身份，也不根据 LIST、进程消失或等待时长推定退休。

## 身份与状态

普通 `scope.generation` 是数据库的逻辑身份，业务请求和 receipt 继续绑定它。
`status.head_serial` 是每次 HEAD 发布的物理序号；`status.revision` 是既有逻辑转换序号。
压缩和 GC 的技术发布只推进 `head_serial`，不能用 `revision` 代替其预期条件。

`status.storage` 返回以下有界摘要：

- `active_generation`（A）：当前权威对象所在的物理代。
- `allocated_through`（M）：永久已分配到的物理代；中止目标也不能复用。
- `plan`：`null` 或 `{serial,source,target,phase}`，phase 为 `copying` / `sealed`。
- `sweep`：`null` 或 `{serial,generation,next_after,exhausted,pending,applied,observed_absent,condition_mismatch}`。
  四个 disposition 计数之和为 1..32；不返回对象 key、ETag 或捕获的请求窗口。
- `terminal`：`null` 或 `{serial}`，表示已发布的永久终态存储屏障。响应中始终带此字段；
  未退休的 HEAD6 状态也投影为 `terminal: null`。

plan 与 sweep 互斥。terminal 只能出现在 inactive、Deleted、无 plan 的状态，且满足
`M < terminal.serial <= head_serial` 且 `revision < terminal.serial`；其后安装的 sweep 必须有
更大的 serial。终态屏障晚于最后一次业务转换，不能接受在屏障之后又推进业务 revision 的历史。
公开 serial、代号和其他 u64 都是规范十进制字符串；计数是小整数。
删除能力只接受 core 从退休证明和当前 checkpoint 推导出的物理对象。
客户端没有 bucket、endpoint、prefix、key、ETag 或批量任意删除参数。

## 明确的 compaction 阶段

全部操作为 `POST /v1`，带原完整 scope 和 `version: 1`，每次均按当前 HEAD 校验 ADMIN。

| operation | 额外 JSON 字段 | admission | 成功结果 |
| --- | --- | --- | --- |
| `compact_begin` | `expected_head_serial` | `control` | 新 status；分配 M+1、固定源闭包和 plan serial、owner 置 inactive |
| `compact_copy` | `plan_serial` | `recovery` | 验证并复制同一完整闭包，回读目标，持久封口后的 status |
| `compact_promote` | `plan_serial` | `control` | A 切到封口目标；清 plan；owner 保持 inactive |
| `compact_abort` | `plan_serial` | `control` | 清 plan；目标永久不复用；A 保持原值，owner inactive |

BEGIN 的响应中保存原 `plan.serial`、source 和 target。COPY 重启后重新遍历和验证固定闭包；
本地文件和上次已复制到哪一页都不能代替 seal。并发 ACL 更新仍按当前 HEAD 校验，promotion
不会把旧 policy 从 copy basis 恢复。当前数据、原始结果、请求身份、取消屏障和窗口语义一起
复制；既有业务 receipt 不因物理搬迁而换 scope、request、result hash 或逻辑转换。

BEGIN 与 PROMOTE 都丢弃该 Engine 自己的旧私有 Session；其他 Engine 的缓存继续受到 fresh
HEAD 检查。PROMOTE 不自动调用 `activate`。应用要恢复写入，须把显式 activation 发到当前
owner；若更换 worker，先按原 owner 协议显式 takeover，再 activate。此接口不包含自动故障
转移、后台压缩调度、group commit 或单库多写者。

COPY 与 GC 共用 `cache.parallel_recoveries` 的全局 semaphore，使用 recovery intake、原
recovery deadline 和数据库 actor；不会消耗为短 control 操作预留的队列名额与执行线程。
实际工作未结束时，HTTP 超时或断连不会提前归还工作配额，也不取消已接受的 authority 转换。

## 删除后的终态退休

`lifecycle: deleted` 会拒绝普通 SQL、`lookup`、`open` 与 `status`，但它本身不允许删除最后
一个 A。管理员须显式发布 terminal seal；后台对象读取或丢失不会代替这一步。

| 路径 / operation | 额外 JSON 字段 | admission | 作用 |
| --- | --- | --- | --- |
| `/v1` / `storage_status` | 无 | `control` | 查询直接创建库的 Deleted 元数据和终态状态 |
| `/v1` / `retire_storage` | `expected_head_serial` | `control` | 在精确原序号上发布永久终态屏障 |
| `/v1/catalogue` / `named_storage_status` | 完整 `creation` | `catalogue` | 核实原目录创建和删除/取消意图后查询 Deleted 状态 |
| `/v1/catalogue` / `retire_named_storage` | 完整 `creation`、`expected_head_serial` | `catalogue` | 在相同目录证明下退休原物理库 |

四个入口都校验 fresh HEAD 的当前 ADMIN；目录入口不要求 provision，也不要求管理员等于
原 creator。直接入口只接受 `creation: None` 的库；命名库必须携带原 Creation 走目录入口。
名称后来重用不会把新库当成旧库，也不能把只属于另一个 HEAD 的 ForeignOccupied 取消屏障
用作本库的退休授权。详细目录身份约束见[名称目录接口](../catalogue.md)。

退休调用不读取 SQLite 数据闭包、不执行 SQL，也不需要启用 GC。成功只将 `head_serial`
推进一位并写入 `terminal.serial = head_serial`，同时保持 owner inactive；业务 revision、
transition、请求窗口、数据根、权限与原创建/删除身份保持原值。调用前应保存完整 scope 或
Creation 和原 expected serial。序号不符或已经存在 terminal seal 返回 `CONFLICT`，不会把
再次提交解释成同一次成功。响应丢失后用 `storage_status` / `named_storage_status` 查证；
SDK 不自动重发退休请求。

终态屏障发布后 A、M 和 terminal serial 永久固定，HEAD 本身不会被删除，旧 scope 不复用。
GC 才能扫描 `1..M` 中的物理代，包括原最后一个 A。长期保留的 HEAD 以及目录 descriptor、
control 和 proof 是身份与退休依据，不属于此 payload GC 的删除范围。服务缓存不是退休授权；
旧读取得到确切退休证明时返回 `SNAPSHOT_EXPIRED`，不返回一个由缺页拼成的成功结果。

## 独立可选 GC 凭据

默认省略 `gc` 或设为 `null`，`gc_prepare` / `gc_resume` 返回 `GC_DISABLED`。
启用时在服务配置顶层增加：

```json
{
  "gc": {
    "deployment": "1",
    "access_key_env": "SCAP_GC_ACCESS_KEY",
    "secret_key_env": "SCAP_GC_SECRET_KEY",
    "session_token_env": null
  }
}
```

这里省略了同一文件的其他必需配置。GC 固定复用普通 `s3` 的 endpoint、region、bucket、HTTP
设置、对象预算和请求期限，不接受覆盖。所有 Bearer 凭据须属于这个 deployment；需要多个
deployment 时使用分别绑定的服务配置。GC 的环境变量名和 access-key 身份必须区别于普通
读写凭据。普通 `S3` / `Objects` 没有 DELETE 方法，只有单独构造的 `GcS3` 具备受限删除能力。
直接 Rust `Prepared` / `assemble_with_storage` 调用也拒绝配置与能力不一致，不能借程序组装
入口默认启用删除。受信 Rust 调用者仍须把 Objects/Listings/Garbage 绑定同一后台。

当前删除 transport 只接受无 versioning、无 Object Lock 的受支持后台；每次 inspect/delete
重新进行固定配置检查。它不删除历史 version、不绕过 governance，不将 NoSuchBucket 或
通用 404 当作候选对象不存在。配置不支持返回 `GC_UNSUPPORTED`，不是“已经清空”。

## 安装并恢复有界删除批

| operation | 额外 JSON 字段 | admission | 作用 |
| --- | --- | --- | --- |
| `gc_prepare` | `expected_head_serial`, `generation`, `after` | `recovery` | 最多一个 LIST 页、32 次精确 inspect，保存原 ETag checkpoint；不 DELETE |
| `gc_resume` | `batch_serial` | `recovery` | 精确观察同一 checkpoint 与退休证明，条件删除/分类，再持久 disposition 并清 checkpoint |

`generation` 指物理代。Ready 状态不能扫描 A、当前复制目标或未分配代；已经中止的目标
可能大于 A，仍可由 core 证明已退休。Deleted 状态须先有 terminal seal，才允许扫描包括 A
在内的已分配代。`after` 必须显式给出 `null` 或上一页的 64 位小写 hash；它不是任意 key。
每次返回：

```json
{
  "status": { "scope": "见完整 status", "head_serial": "17", "storage": "见上文" },
  "generation": "1",
  "scanned": 12,
  "next_after": null,
  "exhausted": true
}
```

这个 JSON 只展示返回字段，不是可直接用于严格 decoder 的完整 status 样例。
`scanned` 表示本页分类的 LIST 项，可能大于实际 checkpoint 项数：精确 inspect 已确认 Missing
的项不需要保存原 ETag。整页都已不存在时可以没有 checkpoint、`head_serial` 不变，同时
`scanned > 0`、`exhausted = false`；调用者保存 `next_after` 后明确决定是否继续下一页。

RESUME 只使用持久候选的原 ETag。当前对象已不存在记录 `observed_absent`；条件不匹配记录
`condition_mismatch`；未知 DELETE 不写成 `applied`，也不换一个刚读到的新 ETag 重删。
删除批进度会跨 worker 重启保留在 HEAD。后续页和下一轮重新扫描都是新的显式调用。

`exhausted` 只表示这次遍历到达当前 listing 边界。延迟旧 PUT 仍可能在退休 namespace 产生
orphan；一次清扫不证明 prefix 永久为空，也不证明总体存储永不增长。迟到对象需要后续显式
扫描。HEAD6 的未封口 Deleted 最后一个 A 仍受保护；HEAD7 必须经上述显式终态退休才能
回收其 payload。永久权威元数据不随 payload 删除。retained snapshot、持久 reader pin 和
PITR 尚未开放，当前格式不接受非空 holds。

## UNKNOWN、快照过期与原业务结果

管理响应丢失后先保存原 serial，再显式 `status` 检查 Ready 的 plan/sweep，或用专用
`storage_status` / `named_storage_status` 检查 Deleted 的 terminal/sweep；不要自动换新的 serial
重发。观察到同一未完成 batch 时，可以明确调用 `gc_resume`；batch 已消失或被替换时返回
CONFLICT，不能据此断言旧 UNKNOWN 从未执行。SDK 的 `UnknownError.reference` 保留操作、
原 serial、物理代和 frontier，每个新方法最多一个 POST。

普通 reader 没有持久 pin。旧物理代在读取中退休并被删时，经过 exact authority 判定的
`SNAPSHOT_EXPIRED` 独立返回，不混入 CORRUPT、业务请求的 RETIRED 或提交 UNKNOWN；SDK
将其保留为 `RemoteError`、outcome `unresolved`，不自动重放查询或 SQL。应用重新发起新的
读操作是新的决定。已有提交结果继续用原 request `lookup`，物理搬迁不授权重做原写入。

本地兼容 S3 和原生进程验收与单元覆盖分开；实际运行与失败证据由
`experiments/object-reclamation-runtime` 独立记录，不能由状态字段或单元 profile 代替。
HEAD6 的通过记录不自动证明新增 HEAD7 终态路径；后者仍需固定新候选的独立验收。
