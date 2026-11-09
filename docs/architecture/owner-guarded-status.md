# 接收实例身份受保护的 status

本片在现有数据库 `status` 上增加可选 `expected_worker_instance`，并提供
`Client.guardedStatus` 与 `OwnerClient.probe`。它是只读探测入口；自动故障检测、后台接管、
持久 owner plan 和 controller 尚未在本片实现。

实现基线为
[`778a4d25dc186b3afc7958cbd522e5e0316703c8`](https://github.com/ckanner/scap/commit/778a4d25dc186b3afc7958cbd522e5e0316703c8)。
原 `79b5b4a` 的首次 Node 单位运行是 64/65：同步编码越过期限后没有派发 Fetch，
但内层 transport 把外层 deadline 的 abort signal 归类为 `ABORTED`，使原预期
`DEADLINE` 的测试失败。该原失败与单独通过的类型/Node HTTP 检查见
[首次 SDK 回执](../evidence/guarded-status-sdk-failure-local-2026-11-09.json)。
`65d48cb` 的 66 个 Node 单位全部通过，但 V8 分支门禁仍拒绝 try/catch/finally
之间一个计数为零的空白区间，见[原覆盖失败](../evidence/guarded-status-sdk-coverage-local-2026-11-09.json)。
后继改用 finally 之后的统一正常返回点，没有加入排除或过滤计数。
本次后继的 Node 重验、Rust 单位/覆盖及实际 HTTP/S3 门禁仍待独立冻结与运行；
基线结果不能代替新增输入的验证。

## 1. Wire 与服务顺序

沿用 `POST /v1`、`version: 1`、完整五字段 Scope 和原 status 响应：

```json
{
  "version": 1,
  "scope": {
    "deployment": "1",
    "tenant": "2",
    "database": "3",
    "incarnation": "4",
    "generation": "5"
  },
  "operation": "status",
  "expected_worker_instance": "1002"
}
```

| 输入 | 行为 |
| --- | --- |
| 无 `expected_worker_instance` 字段 | 与原 status 一致 |
| 字段为规范、非零 u64 十进制字符串 | 检查本次接收服务配置的 worker identity |
| 显式 `null`、JSON 数字、`"0"`、前导零、符号或溢出 | `INVALID`，不能用这些值关闭 guard |
| 有效字段与接收 worker 不同 | `TARGET_MISMATCH`，HTTP 409 |

[`wire::Action`](../../crates/scap-service/src/wire.rs) 复用已有 `present_worker` 和
`Action::validate`。takeover / activate 的 guard 不变；其他 operation 不接受这个新字段。
status 仍属于 `control` admission，不占用 native recovery permit。

[`Engine::execute`](../../crates/scap-service/src/engine.rs) 保持原顺序：先检查请求版本、
deadline、完整 Scope 与 action 值，再检查已认证 principal 的 deployment/tenant 准入，
随后核对接收 worker。错误 guard 在本次数据库缓存访问、路径序号推进、S3 或恢复动作前返回。
HTTP token 认证与有界调度仍属于外层既有流程；这不承诺外层没有资源分配。

guard 通过后，原 [`Database::status`](../../crates/scap-object/src/lib.rs) 执行一次 exact HEAD GET，
按当前 HEAD ACL 检查 READ，并返回原 `DatabaseStatus`。guard 不授予 READ/ADMIN，不绕过
S3 不可得、错误 Scope 或损坏 HEAD；也不创建 lease、观察票据或新的 HEAD 转换。

## 2. 接收 worker 与数据库 owner 是两个字段

假设 route 中 `1002` 指向 worker B，当前 HEAD 的 `owner_instance` 为 worker A 的 `1001`。
对 B 发 `expected_worker_instance: "1002"` 的 status 可以成功，并返回 `owner_instance: "1001"`。
此时证明的是 B 接收了本次请求、身份匹配且在当前 READ 权限下读到了该 HEAD。
不能据此声称 B 已拥有数据库、A 已失效或数据面恢复已完成。

部署必须为启动实例分配并可信配置 worker identity。字段核对防止错误 route 或旧地址意外指向
另一个配置实例；它不代替 endpoint 信任、TLS 或实例身份分配规则。SDK 继续拒绝 redirect，
不会从服务响应取得新的凭据目的地。

## 3. SDK 合同

```ts
Client.guardedStatus(workerInstance: Decimal, options?: CallOptions): Promise<DatabaseStatus>
OwnerClient.probe(workerInstance: Decimal, options?: CallOptions): Promise<DatabaseStatus>
```

`Client.guardedStatus` 使用该 Client 的固定 endpoint 与原单次 status transport，至多一个 POST。
worker 输入使用现有规范非零十进制校验；原 `status(options?)` 不改变请求字节或 options 形状。

`OwnerClient.probe` 从已复制、规范化的静态 `RouteRegistry` 选择指定 worker 的 endpoint。
没有对应 route 时返回 `UNROUTABLE`，不发网络请求，也不先向 bootstrap 做 status。
它创建一个普通 `OperationBudget`，在进入调用时固定绝对期限；路由、Client 构造、同步编码、
Fetch、响应读取和校验消耗同一总预算。底层 Fetch 前再次检查该期限，成功或错误出口前再次检查，
所有退出都关闭 timer/abort 监听。未指定 timeout 时使用普通 `timeoutMs`，不使用 recovery timeout。
外层 OperationBudget 保留先发生的 deadline／调用者 abort；其停止原因不能被内层对
该 signal 的通用 `ABORTED` 解释覆盖。若外层预算仍有效，原服务拒绝或传输错误原样保留。
这项错误优先级只用于本次只读 probe，不改既有管理 intent 的已知／未知结果分类。

服务拒绝、传输丢失、调用者取消或 deadline 只结束该次探测。SDK 不换 endpoint、不去掉 guard，
不发 takeover、activate、恢复或 SQL。服务返回 UNKNOWN 也没有获得新管理派发资格。
低版本服务若不接受新字段，调用失败；没有自动降级为无 guard status。

现有 `observe`、`inspect`、`reconcile`、OwnerIntent schema、registry digest 与
`restoreIntent` 的 inspect-only 约束均不变。一次 probe 不消费或创建 intent，探测结果不能
证明旧管理 HTTP 已不可能迟到。技术 `head_serial` 前进也不能关闭尚未 server-admit、仍只携带
原 `expected_revision` 的旧 HTTP；完整边界见[owner-controller 设计](owner-controller-plan.md)。

## 4. 验证范围

| 层 | 本片测试输入 |
| --- | --- |
| Wire | 缺省兼容、完整 u64 worker、显式 null/0/非规范、非允许 operation 拒绝字段 |
| Engine | 错误目标零数据库 I/O/cache/恢复、跨 tenant 准入优先、直接构造零值 INVALID |
| Engine fresh READ | 在非 owner worker 上成功、READ-only 凭据可用、ACL 撤回后拒绝、authority UNKNOWN 不重试、没有 native session |
| Node Client | 原 status body 不变、单次 guarded body、完整目标身份、规范输入、本次远端拒绝保留目标引用 |
| Node Owner | 复制后的可信 route、不匹配/不可路由/响应丢失无 fallback、同一普通绝对期限、超时前禁止新 Fetch |
| 类型 | 两方法返回 DatabaseStatus；worker 必填且使用字符串；options 不增加 retry 等字段 |

这些测试只在各自实际运行且绑定冻结源码后计入通过。Rust 生产仍进入原每文件四维精确单位分母，
Node 仍进入全部生产模块的原 V8 精确门禁；本片没有新增排除项。实际 endpoint 更换、fresh S3
权限和进程生命周期证明需要独立 HTTP/S3 验收，不能从单元替身或探测成功本身推导。
