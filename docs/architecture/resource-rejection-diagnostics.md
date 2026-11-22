# 资源拒绝诊断：原判定快照与有限负载曲线

状态：2026-11-22 实施；以本次候选自己的验证记录为准。前置主线为已合并的
[PR #69](https://github.com/ckanner/scap/pull/69)，其固定短负载的结果及限制保留在
[原报告](../engineering/sqlite-s3-review-2026-11-22.md)。

## 1. 要解决的问题

此前多类准入拒绝共用 `BACKPRESSURE`，无法从真实 HTTP 结果区分 intake、队列、
actor、响应预算和 discovery 的首个拒绝门槛。#69 第一组竞争负载中组提交提高成功
事务的完成速率，同时原 ACK 数从 64 降至 58；这些结果不能单独证明是哪项资源受限。

尤其原夹具 `data_intake=80` 使用兼容默认 profile，实际租户请求上限为 **40**；
单库数据队列额度为 `72 - 8 = 64`。请求在进入队列前就可能被租户 intake 拒绝。
本次保持原容量与持久化协议，先报告实际触发预算，再扩展固定分阶段负载。

实现入口为 [rejection](../../crates/scap-service/src/rejection.rs)、
[intake](../../crates/scap-service/src/intake.rs)、
[scheduler](../../crates/scap-service/src/scheduler.rs)、
[HTTP](../../crates/scap-service/src/http.rs) 和
[SDK parser](../../sdk/node/src/resource_rejection.js)。

## 2. 采集与可见性

服务顶层配置增加可选 `resource_diagnostics: bool`，省略为 `false`。开启后，仅在
已经认证的资源失败路径返回可选响应头 `x-scap-rejection`；JSON body、HTTP status、
错误码、receipt 与原请求结果语义不变。成功、认证失败、UNKNOWN 及携带已提交回执的
失败不附加过期的拒绝信息。没有新增日志 I/O、对象请求或读取权限的额外前置检查。

这是部署者的明确开关：部分预算在数据库 HEAD 权限检查之前触发，开启后认证主体
可以观察该服务选定池的匿名共享容量与占用。字段没有租户 ID、数据库 ID、名称、
SQL、路径、对象 key 或凭据，但仍存在共享负载信息可见性；需要隐藏这些信息的部署
保持默认关闭。它不是管理员专用指标接口，也不额外授予数据库访问权限。

计数只来自**发生拒绝的原判断、原 mutex 和原计数器**。保留已有判断顺序，例如
全局先于租户、总队列先于数据队列；一次返回第一个实际触发项。不会释放锁后重读
当前值，不会跨多个池拼接所谓原子快照，也不会为了统计改变调度公平性或预留。

`global` 指该路由／操作使用的池。普通 `/v1` recovery intake 与目录 S2 recovery
intake 分别由不同配置建立，二者均可报告 `intake_recovery_*`；观察者必须用原请求
路由与操作关联正确配置，不能把它们相加或理解为整个 daemon 的统一 recovery 池。

队列 `used` 表示**仍被收取的额度**，并非物理等待队列长度。组成员出队后仍可能
持有额度，直到可信 consumed 边界以及规定的 native 清理完成。read pool 的 active
限额决定调度而非入队拒绝，因此不伪造 `read_active_*` 原因。

## 3. 固定 wire 合同

仅允许一个不超过 256 ASCII 字节的响应头，v1 字段顺序固定：

```text
x-scap-rejection: v=1;reason=intake_data_requests_tenant;used=40;limit=40;requested=1
x-scap-rejection: v=1;reason=native_recovery_busy
```

第一种为计数型。`used` 是本次尝试之前已占用额度；`limit` 是被检查的实际上限；
`requested` 是本次要增加的额度。全部为规范 u64 十进制：无前导零、正负号或指数；
只有 `used` 可以为零。必须满足 `used <= limit`、`limit > 0`、`requested > 0` 及
数学意义上的 `used + requested > limit`。两个 u64 相加可以超过 u64 上限，判定
使用更宽的整数，不能因加法溢出丢掉正确的拒绝证据。单次需求大于整个容量是合法拒绝。

第二种仅有来源。分配器失败、actor draining，以及 native semaphore 的
`NoPermits`／`Closed` 没有原子占用快照；因此不在失败后读取 semaphore 数量来冒充
原判定数据。所有原因来自固定枚举，总计 **41 个计数型、5 个来源型**。

| 原因族 | 数量 | 错误码 | 单位／本次需求 |
| --- | ---: | --- | --- |
| `intake_{data,control,recovery,catalogue}_{requests_global,requests_tenant}` | 8 | BACKPRESSURE | 请求；1 |
| `intake_{data,control,recovery,catalogue}_{body_global,body_tenant}` | 8 | BACKPRESSURE | 字节；配置的最大 body 预留 |
| `queue_{global,tenant,database}_{total,data}` | 6 | BACKPRESSURE | 收费队列额度；1；data limit 扣除 control 预留 |
| `actors_{global,tenant}` | 2 | BACKPRESSURE | 活跃／待清理 actor 槽位；1 |
| `output_base_{shared,control}_{global,tenant}` | 4 | BACKPRESSURE | 响应基础字节；65,536；shared 池扣除 control 预留 |
| `{catalogue,restore}_queue_{global,tenant,name}` | 6 | BACKPRESSURE | 队列额度；1；name 保留已知／未知名称的原保守计数 |
| `discovery_{global,tenant,threads}` | 3 | BACKPRESSURE | 请求／原生线程；1 |
| `output_growth_{global,tenant}` | 2 | LIMIT | 编码共享字节；实际新增 extent |
| `restore_staging_{global,tenant}` | 2 | RECOVERY_BUSY | 字节；镜像大小加既有 sidecar 预留 |
| `actor_draining`、`output_base_allocation` | 2 | BACKPRESSURE | 仅来源 |
| `output_growth_allocation` | 1 | LIMIT | 仅来源 |
| `native_recovery_busy`、`native_recovery_closed` | 2 | RECOVERY_BUSY | 仅来源 |

错误与元数据一起经过 `Failure → Encoded → Reply → HTTP`。编码中再发生失败时，
按最终实际错误重新选择信息：最终 LIMIT 可报告本次编码资源失败，已提交回执保留
其原 CBU 语义。类型与数值不匹配的内部元数据被过滤，不输出自相矛盾的头。

快照是固定大小的 Copy 值，不随数据库和租户数量增长。HTTP 扩展存储和开启时的
格式化存在小额分配，不能称零开销；这些固定有界 header／allocator 开销仍处于
[既有 body 预算](../../crates/scap-service/docs/intake-reservations.md)声明范围之外。
没有新增无限标签、全局采样历史或后台队列。

## 4. SDK 与请求结果

SDK 先完整验证原 JSON envelope、HTTP status、错误码以及可选 receipt；只有已经
成立的 `RemoteError` 才可增加只读 `resourceRejection`：

```javascript
// error.outcome 仍为 'unresolved'；此对象不授予自动重试权限。
{
  version: 1,
  reason: 'intake_data_requests_tenant',
  used: '40',
  limit: '40',
  requested: '1',
}
```

数字保持字符串，用 BigInt 校验，不能经过 JS Number 舍入。来源型对象没有三个
计数字段。对象及其属性绑定不可修改。缺失、未知版本／原因、错误码不配对、重复、
超出 256 字节或语法／数值不合法时，仅忽略可选诊断，保留已经验证的原错误。

Fetch 将重复头组合成逗号值，严格语法拒绝它。`ControllerHttp` 对这个可选头使用
相同组合规则；其他重复头继续拒绝，全部头仍受既有 64 项／16 KiB 与 framing 约束。
可选 metadata 的容错不放宽整体 HTTP 输入边界。

UNKNOWN、已提交回执、成功结果和无效 envelope 不会因这项诊断取得新结果。
`RemoteError.outcome` 仍为 `unresolved`；保留原 ID、SQL、参数和指纹，用既有 lookup／
cancel 处理不确定性。服务中没有自动重放、换 ETag、换 ID 或客户端自动 backoff/retry。

## 5. 真实实验与解释边界

[group-commit-load](../../experiments/group-commit-load/README.md) 有两个明确固定 profile：

| profile | 每轮固定到达 | 全部测量事务 | 用途 |
| --- | --- | ---: | --- |
| `short-v1` | 32 次 @ 4/s；128 次 @ 64/s | 640 | 维持 #69 原短窗口的容量和到达规则，增加新诊断 |
| `admission-curve-v1` | 64 次 @ 4/s；192 次 @ 12/s；512 次 @ 32/s | 3,072 | 每档 16 秒，四个 4 秒窗口；原到达、客户端未完成请求与拒绝 |

均采用 off/on/on/off 四轮，每轮一个新后端和新库；组大小、intake、队列、payload、
执行期限、原随机 SQL 以及控制探针规则不变。长 profile 显式增加总期限、独立
SQLite 重建页数及留存 entry 审计上界（161 → 769），以容纳固定更大工作量；生产
请求窗口仍为 4,096。请求成功率的分母不删除客户端拒绝。
每档共用该轮原库，保留结果和数据库逐档增长，报告累计已提交 INSERT 身份（本夹具
每身份插一行）、留存身份与 page_count，
不能把后段称为相同数据库体积下的稳态容量。

观察器保存 HTTP 层看到的 header 值及 SDK 对象，原值另有内容摘要绑定。独立 Python
oracle 不导入服务／SDK parser，按固定原因字典、原操作、HTTP status、实际配置、
需求量和拒绝不等式核对，再对 SDK 投影逐字段比较。观察到的 header 值不是原始
TCP framing；二者区别不能省略。原到达账本、原请求身份、random() 返回值、S3
闭包重建、所有 ACK 与取消、控制进展和 negative controls 保留。

计数型诊断可确定该条拒绝的首触发预算，来源型只确定拒绝来源；未带有效诊断的
其他失败不能据此归因。分窗报告客户端未完成请求及 offer 前占用，不冒充 server
queue／active 峰值。HTTP/S3 外部
时钟没有 native 内部决策时间；组发布与 intake 拒绝同时出现，只能报告时序共现，
不能据此断言唯一因果或把对象调用减少直接换算成 TPS／成本改善。完整队列持有
时序另由定向 runtime 单元验证。目标 AWS、不同租户数、长期工作集与生产 SLO 另验。

## 6. 验收与后续决定

必须通过原锁位置／首触发顺序、精确 count 与来源分类、编码替换、默认关闭、认证
失败不泄露、旧错误不变、原资源清理生命周期的定向单元；每个 Rust 生产文件四维
精确覆盖及每个 SDK 模块精确 V8 单元覆盖单独执行。真实 HTTP/S3、短长 profile、
原字节 oracle 与诊断伪造负控独立于单位 profile，不能互相补覆盖。

数据回来后先区分 intake 饱和、队列饱和、输出预算、恢复槽位和客户端生成器限制。
任何容量／调度调整另设固定对照和资源上界，不能在本次对照中途调大额度。
FULL、受检 TRUNCATE、不可变对象回读、原 ETag 条件 HEAD 和最终 native completion
继续位于成功确认之前；诊断不能改变 SQLite on S3 的权威与持久化设计。
