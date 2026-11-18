# 有界、受信的动态 owner fleet

本页定义可在线更新的部署配置、worker 退役和旧计划续进。数据库持久权威仍是原
S3 HEAD，owner fencing、原结果、ACK、强读和 UNKNOWN 语义不变。
这项能力不包含一个新的分布式 registry、fleet leader、heartbeat 租约或自动扩缩容器。

## 1. 配置来自谁

配置文件由可信部署控制器提供，控制器不能从服务响应学习一个新 URL 或把凭据转发到
响应建议的地址。`authorityId` 是部署配置的命名空间标识，不替代 TLS、当前 bearer
权限或对实际 worker 的 guard。服务启动继续永久登记非复用 worker ID；新目标的真实
`guardedStatus(expectedWorkerInstance)` 必须成功，之后原 owner claim/resume 仍带相同 ID。

部署器应在确认新进程身份后发布配置。若提前发布或入口误绑，`TARGET_MISMATCH` 直接
阻断本次状态机，既不累计死亡，也不从响应更新 guard。只有可信部署输入和后续新操作
能改变配置。任何旧业务 SQL、原身份和过去 UNKNOWN 均不因此重发。

## 2. 版本化配置与完整历史

原 version=1 配置与 API 保持固定快照行为。version=2 文件增加规范十进制 `revision`，
每个 Scope entry 必须显式给出 `previousPolicies`（首次为空）。policy 可以增加
`retiredWorkers`，其值为仍存在于 `workers` 中的永久身份列表。

```json
{
  "version": 2,
  "revision": "1",
  "scopes": [{
    "tokenEnv": "SCAP_OWNER_CONTROLLER_TOKEN",
    "previousPolicies": [],
    "policy": {
      "scope": {"deployment":"1","tenant":"2","database":"3","incarnation":"1","generation":"1"},
      "authorityId": "example-deployment",
      "principal": "7",
      "metadataEndpoints": ["https://worker-a.example.invalid/v1"],
      "workers": [{"workerInstance":"1001","endpoint":"https://worker-a.example.invalid/v1","rank":0}],
      "modes": {"takeover":true,"activate":true,"cancel":true}
    }
  }]
}
```

更新时将原 current policy 原样追加到 `previousPolicies`，然后发布新 current policy。
若仅更换凭据环境值或重新发布同一策略，增加 revision，保留原 policy/history 即可。
凭据不会进入 policy 摘要、配置文件正文或 controller 报告。

每次更新校验以下关系：

- 完整 Scope、authorityId、principal、自动模式、TLS/HTTP选择和全部预算固定。
- 老 worker 的 ID、endpoint、rank 逐字不变，不能删除历史身份；新 worker rank 必须
  大于该 Scope 已见的最大 rank。
- retirement 只增不减，所有活动 Scope 对同一 authority 下 worker 的退役决定一致。
- 一个 endpoint 只能对应一个未退役 incarnation；旧身份已显式退役后，新的永久身份
  可以使用相同 endpoint。旧记录仍在，旧 guard 仍为旧数值。
- 新 history 必须以本进程已接受的完整 history 为前缀。临时移除 Scope 再加入，也不能
  丢掉其旧 policy 或重新激活旧 worker。
- policy 未设置 retirement 时，原 v1 canonical bytes 和 nonce 完全不变。非空 retirement
  列表进入完整摘要；四个 nonce 仍是整个摘要的四个 u64 字，不截断、不刷新。

单个 Scope 最多16个 previous policy；全进程已见（含暂时移除）Scope最多128个、
worker最多256个，所有保留的 canonical policy 合计最多64 KiB。配置文件读取自身仍
最多64 KiB。达到上界时拒绝更新，不截掉老 history；无限历史压缩/永久策略迁移尚未实现。

## 3. 旧 owner 计划如何处理

状态机只在原 descriptor 的完整输入匹配 current policy 或明确保留的某个历史 policy
时收养。历史 policy 的固定权限和预算与 current 相同，不能通过增加 history 扩大自动
权限。纯 history 观察继续不构成 SDK mutation brand；inspect/reprepare 仍完整核对原
Scope、creator、operation、nonce、hash、原 HEAD 等条件。

| 当前观察 | 动态策略动作 |
|---|---|
| 未退役的健康 active owner | 只读，无偏好迁移 |
| owner 被显式退役 | 这是部署授权的排空决定；fresh HEAD 后选择更高 rank 的未退役目标 |
| 旧 Prepared，目标未退役 | 按完整原输入重新核验，保留原目标/guard与原故障阈值 |
| 旧 Prepared/Claimed，目标已经退役 | 只允许原输入查证与原 ref 的 abort，不 claim/resume |
| Cancelling | 原 ref 继续 abort 到 Aborted |
| 旧 Active/Aborted 终态 | 可识别历史；下一新计划使用当前 policy 摘要和新的原 HEAD 条件 |
| 未知 creator、未保存 policy、缺失/矛盾的旧 descriptor | 阻断，不猜测、不重建原意图 |

明确退役可以迁移仍然健康的 owner，因此它与网络故障判断分开。旧进程可能仍有在途
CAS，仍由相同 HEAD 原条件排序；配置 reload 不撤销已发出的请求，不制造过去 ACK。
新控制器会保留本进程知道的 `pastUnknown` 与原 `lastUncertainCall`，包括 Scope 暂时移除
后再加入的情况。进程重启仍只从真实持久 owner 记录查证，不能凭空恢复未保留的响应知识。

## 4. reload 的生命周期与资源

CLI 在 SIGHUP 后重新读取同一个配置路径。信号只设置一个布尔请求位，不累计 reload
队列；部署器应先对完整文件做 atomic rename。大小/mtime/ctime、schema、revision、history
和组合上限全部验证成功后才停止旧 admission，关闭并等待所有旧 tick，再调用 transport
`quiesce()` 等待原 request、socket 与尚未返回的 DNS callback 全部归还，最后一次性安装新快照。
在切换中 `poll()` 不启动工作；并发 `replace()` 返回 BACKPRESSURE。

库入口为 `OwnerControllerFleet.replace({revision, entries})`，可观察 `revision` 和
`updating`。初始 `revision` 必须明确提供才能使用 replace；静态 v1 fleet 不会隐式变为
动态模式。`readControllerConfiguration` 返回完整快照；`readControllerEntries` 保持原接口。
动态 fleet 的自定义 transport 必须实现可复用的 `quiesce()` 所有权合同；仅仅拒绝 fetch
Promise 不算完成资源归还。运行时 join 失败会停止整个 fleet 的后续 admission，不把已经
停止的旧 controller 当作仍在工作的快照。此时 `snapshot().closed` 不证明资源已经归还；
库调用方必须在 `finally` 中 `await fleet.close()`，包括 `replace()` 拒绝的路径。CLI 已经
执行该清理。内置 transport 的普通网络失败不会让 `quiesce()` 拒绝；它仍等待原资源结束。
静态 v1 的自定义 transport 只需已有 `close()` 合同。

无效文件、相同/较小 revision、历史遗漏、身份重绑和退役复活均在关闭旧 controller 前拒绝，
保留当前快照。成功/失败分别输出 `fleet_reloaded` / `fleet_reload_rejected` JSONL，不输出
原异常或配置内容。SIGINT/SIGTERM 优先停止后续 admission，仍 join 原 tick/transport；
旧服务请求的实际额度继续由服务自身持有。

在更新期间可能同时保留新旧 controller 对象，但只允许旧一组存在在途工作；全局8 tick、
每tenant4 tick、一个恢复RPC的上限不变。历史、旧不确定观察和最新报告都由已见 Scope
上限约束。系统 DNS 与阻塞输出原有的关闭时间边界保持，逻辑上限不等于 OS RSS 硬隔离。

## 5. revision 的精确保证

revision 是一个 controller 进程对可信部署快照的单调防回退检查，没有写入 S3，也不是
所有 controller 的全局 epoch。重启时部署器必须提供当前完整配置和历史；产品不会自动
从任意旧文件恢复“最新配置”。并发运行旧配置的 controller 仍可能提交旧策略允许的计划。
HEAD fencing 保持安全，但在部署器完成协调更新前，不保证排空迁移的活性或固定 RTO。

因此，该交付支持部署器驱动的有限在线成员更新、退役、端点复用与旧计划处理；跨进程
配置共识、无界历史压缩、自动成员发现、弹性伸缩决策与全局资源调度仍需独立协议。
业务 RoutedClient 当前使用其显式路由快照；应用可创建新实例处理后续调用，原在途请求
仍沿原客户端/身份收敛。本切片不会偷偷刷新旧请求的目的地或自动再执行 SQL。

## 6. 验证

单元、精确 V8、真实 Node HTTP/进程和真实 native/S3 分别记录。182项SDK单位、22个
生产模块精确V8及14项真实controller HTTP/CLI检查已有本地开发结果；它们不替代
[固定动态S3合同](../../experiments/object-dynamic-fleet-runtime/PLAN.md)的完整实际、独立
原始审计与反例。最终冻结源码和各门禁状态以本轮工程证据为准。真实AWS、分布式registry、
自动扩缩容与生产SLO不由此宣称完成。

