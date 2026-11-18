# 从保留快照恢复成新数据库（S2）

本接口创建新 Scope，并从 S1 retained snapshot 完整复制数据；它不覆盖源库，也不把源库
旧请求、ACL、owner 或取消屏障带入目标。调用者必须具备 provision，且 prepare 与每次
新复制 admission 都由核心重新检查源库的 ADMIN + READ。源与目标限定同 deployment/tenant。

这是 S2 实现候选的协议说明。实际通过范围、冻结源与未运行项由对应验收记录维护；接口
文档本身不代表 AWS、容量、吞吐或完整四维覆盖已经通过。

## 1. 配置与调度

四个操作使用同一个 `POST /v1/catalogue`，协议版本仍为 1。`prepare_restore`、
`inspect_restore`、`abort_restore` 使用 `x-scap-admission: catalogue`；`resume_restore`
使用 `x-scap-admission: recovery`。服务在读取 body 前选择准入池，解析后再次核对实际
操作所属池。长复制不会占用普通 catalogue worker，也不能伪装成短控制调用。

启用复制需要已有 `catalogue` 配置及以下独立 `restore` 配置。省略 `restore` 时复制
入口返回 UNAVAILABLE；保留 catalogue 仍可检查和取消持久操作。

```json
{
  "restore": {
    "admission": {
      "workers": 2,
      "queued_total": 16,
      "queued_per_tenant": 8,
      "queued_per_name": 2,
      "intake": 8,
      "max_body_bytes": 16384,
      "timeout_ms": 30000
    },
    "recovery_timeout_ms": 1800000,
    "max_staging_bytes": 34376515584,
    "max_staging_bytes_per_tenant": 17188257792,
    "budget": {
      "source_gets": 1048576,
      "source_bytes": 68719476736,
      "target_puts": 1048576,
      "target_put_bytes": 68719476736,
      "target_gets": 1048576,
      "target_get_bytes": 68719476736,
      "max_image_bytes": 17179869184
    }
  }
}
```

示例每次最多一个 16 GiB 逻辑镜像，另计 8 MiB sidecar 余量；tenant 一份、全局两份。
这些是逻辑准入预算，不是 OS 磁盘配额、物理块占用或 RSS 上限。需要硬隔离的部署仍须
使用实际本地磁盘额度、容器内存/进程限制与独立故障域。复制与普通恢复共用
`cache.parallel_recoveries`，同时具有自己的队列、线程和租户 staging 预算。

上传及解析受 admission 短期限约束，复制总期限从同一接收时刻开始。HTTP 超时返回
UNKNOWN 时，正在运行的 Job 继续持有 intake、recovery 和 staging 资源，直到真实 native
句柄与私有目录释放；不能按客户端断线提前归还额度。每次复制使用全新的私有文件。

source GET、target PUT、target 回读分别计调用数和字节，不借用另一个方向的剩余额度。
硬上限各 1,048,576 次、64 GiB；配置只能降低，零也合法。预算中断不能把部分验证
包装为完成。镜像之外仍有一块 chunk、有限树遍历栈、元数据与 native 缓冲。

只有观察到 Copying 的 resume 才为 native 镜像预留 staging。其他阶段调用将三个复制
方向次数置零；若并发调用恰在检查后把状态推进到 Copying，本次返回 LIMIT，不能绕过
预留去打开镜像。调用者保留原 reference，显式检查后再发新的 resume。

## 2. 四个原始意图

所有 u64 使用规范十进制字符串；null 是明确的名称首次绑定条件。未知字段、缺失条件、
重复字段、跨租户 Scope、非规范哈希都会被拒绝。

```json
{
  "version": 1,
  "operation": "prepare_restore",
  "name": "notes-before-migration",
  "restore_operation": "1001",
  "expected_name_revision": null,
  "options": {"quota": {"mode": "default"}},
  "source_scope": {
    "deployment": "1", "tenant": "2", "database": "30",
    "incarnation": "40", "generation": "1"
  },
  "snapshot": {
    "creator": "3", "operation": "900", "capture_serial": "12",
    "descriptor_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
}
```

示例哈希仅展示格式，必须替换为真实 retained reference。prepare 返回：

- `reference`：`{creation, descriptor_hash}`，绑定全新目标 Scope 与持久恢复 descriptor。
- `input`：保存原名称条件、配额选择、源 Scope、snapshot reference。
- `initial_quota`、`retention`：本次创建的有效初始策略，之后不会随配置重启漂移。
- `point`：被恢复的源 data root、页数、原 sequence 和 source revision。

其余操作的必填字段如下；客户端不能提交 CompletionRecord、ETag、目标 data root 或
已验证证明。检查与继续只允许原 creator，删除已完成目标仍遵守通常 ADMIN 规则。

| operation | 原始字段 | 返回 |
| --- | --- | --- |
| `resume_restore` | `reference` | `{prepared, phase, binding_revision, head_revision}` |
| `inspect_restore` | `creator`, `restore_operation` | 相同 progress；只读观察 |
| `abort_restore` | `reference`, `control_operation`, `expected_name_revision`, `nonce` | 既有 AbortProgress；保留原 Creation 与控制身份 |

prepare 与普通 Empty 创建共享同一个 `(creator, operation)` first-winner 槽；同一编号不能
从 Empty 改成 Restore、换源 snapshot、换名称或换 quota。发生 UNKNOWN 之后必须保存
原意图，查证该槽。新编号是新的业务操作，不是安全重试。

## 3. 发布与取消

正常推进为 `not_reserved → reserved → copying → copied → bound → ready`。一次
`resume_restore` 最多发布一个 mutable Name/HEAD CAS；它不会自动循环到 Ready。
Copying 一步可能耗时较长，只有完成整次数据复制、回读验证、本地 native integrity
检查以及源权限终检后，才允许产生完成证明并安装 Copied。

SCAP 的对象 frame/hash 绑定 Scope。跨 Scope 不能只复制根指针，必须逐层重封装 chunk、
node 和 manifest。源页面内容保持不变，目标对象身份重新计算。目标最终可以完全独立
于源库运行；目标 Ready 的 sequence 为 0，旧源请求不会出现在目标 lookup 中。

源权限终检使用同一次 GET 的 body/ETag，以 HEAD1 → descriptor/proof → HEAD2 的顺序
确认权限和稳定权威。释放快照阻止新的复制 admission。已被准入的完整尝试仅能按其
有效原 proof 和最后权限屏障完成；任何失败的前缀不允许续接。完成后目标拥有独立数据，
源库后续释放、删除或 ACL 变更不应破坏它。

取消只有在名称仍处于当前恢复的 Reserved 时能赢得屏障。先持久化 Aborting，再保留
目标 Deleted 的永久 fence；迟到完成记录或复制输出不能重新绑定或 Ready。已经 Bound
的创建返回 cannot_abort_bound，应按正常具名删除路径处理。恢复来源是 provenance，
目标后续写入仍保留它，但旧 provenance root 本身不构成永久 GC 保留边。

| 结果 | 调用者行为 |
| --- | --- |
| `UNKNOWN` | 保存原 reference/control intent，显式 inspect；不重放业务 SQL、不刷新旧 CAS 条件 |
| `CONFLICT` / `IDENTITY_CONFLICT` | 原条件或原身份不成立；不自动改名称 revision、源或 operation |
| `DENIED` | 当前授权不足；不依据旧 snapshot 元数据继续 |
| `LIMIT` / `RECOVERY_BUSY` | 本次资源或预算未满足；已上传对象可能成为 orphan，当前权威没有因此证明完成 |
| `CORRUPT` / `SNAPSHOT_EXPIRED` | 核心按当前权威区分损坏与已证实的源物理退休；不得自动建空库 |

## 4. 与 Turso 和后续工作的边界

本功能借鉴对象存储持久化、私有计算镜像和明确快照来源；它没有实现 metadata-only
瞬时 clone、lazy VFS、任意时间 PITR、同库 MVCC 或跨事务 group commit。原设计与模型
依据见[保留快照／恢复](../../../docs/architecture/retained-snapshot-restore.md)，取舍见
[Turso 对照](../../../docs/architecture/sqlite-s3-turso-review.md)。
