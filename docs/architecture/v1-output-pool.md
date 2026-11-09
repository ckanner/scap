# 普通 `/v1` 编码缓冲池

状态：**已接入 daemon。冻结运行时 `f074897` 的格式检查和严格 Clippy 通过；
stable 编译完成，但单位执行控制丢失，完整门禁为 INCOMPLETE_EXECUTION_CONTROL_LOST。
没有取得完整单位或本片四维结果，实际服务合同仍 NOT_RUN。** 基线为
`acec129c51c7d51f019fbaf34ff4ea0bd0509cb0`；基础编码器的独立门禁不替代本片验收。
本片落实[结果输出预算](result-output-budget.md)第1、3–7节；不打开新存储世代或 GC。

## 1. 实际接线和承诺范围

每个 daemon 创建一份 `output::Pool`。只有普通 `/v1` 的 data、control、recovery
请求进入它；`/v1/catalogue`、`/v1/discovery`、`/healthz` 保持各自现有路径。
计费对象是 service 新建的 SCAPRES1 wire、Base64 backing、最终 JSON backing，
以及每次请求固定预留的小型公开投影与 owner 信用。它不是进程 RSS 上限。

| 调用点 | 本片行为 |
| --- | --- |
| `config::Config::prepare_using` | 在凭据解析前检查 `output`；缺省使用明确的 version 1 配置 |
| `daemon::serve` / `assemble_with_listings` | 直接调用者也接受相同检查；在 S3/worker 创建前拒绝无效配置；所有普通路由 worker 共用同一池 |
| `http::admitted` | 保留认证、body、解析、class 和 Scope 拒绝顺序；取得 E 和预备小缓冲后才提交 Job |
| `Scheduler::submit_encoded` | 再核对原 intake 的 Principal/class 和 output 的可信 tenant/分区，构造独立 WorkHold |
| `Worker::execute_budgeted` | 新能力默认 UNAVAILABLE，不调用旧的未计费 execute；真实 Engine 明确实现 |
| `Engine::execute_using` / `dispatch` | 复用原业务检查和 SQL/CAS 路径，只在结果投影处分支到 budgeted wire/resolution |
| `wire::budgeted_result` | 同一 borrowed plan 计数 R，先收费、一次精确分配，再取得 B 信用并编码 |
| `OwnedValue::finish` | 执行成功/业务失败在原阻塞 worker 上计数和写最终 JSON，保留原 deadline；排队工作未执行即被关闭时只编码固定小错误；oneshot 只交 status 与已拥有 Bytes |
| `http::reserved` / `ReservedBytes` | intake 仍独立跟随 body/data frame；内部 Bytes 同时保留 output owner |
| resource fixture `ObservedWorker` | 原 entered/completed 观测包住同一 Engine 调用，原样转发 context 与 deadline |

公开 `Engine::execute`、`Worker::execute`、`Scheduler::submit` 继续返回原来的
`Result<Value, Failure>`，不因为该 Rust API 收到结果便宣称它全程受此池控制。
旧 crate-private 的裸 Value HTTP submit helper 已被 encoded 路径取代，不保留仅供
测试调用的生产死代码。外部 Worker 的当前受支持适配方式是原样转发
`Engine::execute_budgeted`；不能以默认方法调用旧 execute 后再追账。

native/core 在 publication 前产生的 wire、typed result graph、S3/raw frame 和
retained lookup Vec 仍是独立输入。typed graph 的128 MiB默认预算、SQLite分配、
TCP/header/body intake 也各自独立。allocator rounding、malloc元数据、内核/TLS缓冲
及固定小 Arc/Map/Bytes owner 的 infallible allocation 不包含在大 Vec fallible 保证内。
尚未取得 E 的认证、上传、解析、admission 错误，以及 missing-reply 的 HTTP 小错误，
继续走原 `failure()` 有界 JSON 路径，不由本池逐个申请 backing；transport/intake 的
原上限仍独立适用。不能把 Job 输出池描述成每一条 HTTP 错误或所有 socket 缓冲的总预算。

## 2. 配置与容量边界

可省略整个 `output` 对象；一旦给出，五个字段都必须出现，未知字段被拒绝：

```json
{
  "output": {
    "version": 1,
    "bytes": 536870912,
    "bytes_per_tenant": 268435456,
    "control_bytes": 8388608,
    "control_bytes_per_tenant": 1048576
  }
}
```

| 分区 | global | 每个可信 `(deployment, tenant)` |
| --- | ---: | ---: |
| 总额 | 512 MiB | 256 MiB |
| protected control/recovery 基础信用 | 8 MiB | 1 MiB |
| shared：data 基础信用与全部动态 backing | 504 MiB | 255 MiB |

分区合计就是总额，不能重复相加。每个请求先取 E=65,536 B；control/recovery 的
E 来自 protected，其他 E 和所有 R/B/J 增量来自 shared。因此大 lookup 仍可能因
共享额度不足返回 CBU；这里不保证一份最大 control 结果的专用槽。

同一个短 Mutex 事务同时检查 global/tenant，失败不插入 tenant、不留部分扣账。
大额度立即成功或失败，不排队；锁不跨 allocator、serializer、SQL 或 S3 调用。
只有活跃基础 lease 才保留 tenant 记录；任一 backing 的 charge 都持有该基础 lease，
最后 owner 消失后才删除记录。poison 拒绝新申请，但 Drop 仍完成原 owner 的退款。

启动检查 version、`isize::MAX`、分区减法、tenant≤global 和各分区的相对上限；
protected 的两个上限都至少为 E。global/tenant 的 shared 空池各须容纳
`2*B(MAX_RESULT_BYTES)+711+E = 179,023,223 B`。durable 64 MiB 结果上限没有缩小；
并发额度不足是有界失败，不是改变业务格式。各请求实际按 R、B、J 申请，不预占最大结果。

新 Vec 都从空开始，调用一次固定 Rust 1.90.0 的 `try_reserve_exact` 后 resize，
实际写入只用固定 slice。Rust 可见 capacity 与 planned 长度的工具链前提及来源见
[原始推导](result-output-budget.md#capacity-保证的准确前提)；单位定义核对真实 capacity。
这里不把标准库一般的“至少保留”保证扩大成跨 allocator/工具链的 RSS 承诺。

## 3. backing 所有权和退款

`OutputContext` 初始持有 fallible 预备2,048 B缓冲和基础 lease。Job 另持一个
`WorkHold`，与 context 共用同一个 E，不重复计费。没有 TLS、全局 allocator hook
或可无限增长的字符串 side ledger。

| 所有者 | 声明顺序与释放条件 |
| --- | --- |
| `Buffer` | `bytes` 在 `CapacityCharge` 前，先销毁真实 backing 再退款 |
| `OwnedValue` | `value` 在 `context` 前，Base64 String/公开 receipt 投影先消失，固定 `value_charge` 后释放 |
| `FinalOwner` | `buffer` 在基础 lease 前；JSON backing 及其动态 charge 先释放，最后再释放 E 引用 |
| Job | WorkHold 留到实际执行/丢弃 Job 结束；oneshot 唤醒或 HTTP 放弃不提前退款 |
| `Bytes` clone/slice | 共享同一 FinalOwner；按原 backing capacity 收费，不随剩余 slice 长度退款 |

Base64 用 `encoded_len` 的 checked 长度先申请 B，再 `encode_slice`。Vec 被消费为
String 后显式 move 入 Value，不深拷贝。临时 wire 的 R 在 Base64 转换返回后才 drop，
所以 R+B 的重叠完整计费。最终 JSON 计数只借用原 Value；同一个 compact serializer
再写入已收费的固定 slice，B+J 重叠也完整计费。最大路径仍为
`max(R+B, B+J)+E ≤ 2*B+711+E`。

J≤2,048 B 时直接消费预备小缓冲，不再申请一个最终 Vec。它的原 capacity 仍随最终
Bytes 持有，不按 truncate 后 len 回收。较大的 J 独立申请。构造 FinalOwner 的基础
引用先于销毁 OwnedValue，避免小回复在两者交接之间短暂退款；最终 E 只有在
WorkHold 与所有结果 owner 都结束后才能消失。

## 4. 原 deadline 与结果知识

HTTP 的原 deadline 包括上传、解析、排队、执行和最终编码。finalizer 在编码前、
编码与旧 Value 销毁后检查同一个 Instant，scheduler 在发送 oneshot 前再检查一次。
过期则销毁本地结果并关闭 sender，HTTP 原 missing-reply/timeout 路径给 UNKNOWN。
这不取消已派发 SQL、native 收尾或 S3 请求；CPU编码执行时会继续占用该 worker 和信用。

| 失败时已有知识 | 回复 |
| --- | --- |
| 基础 E/预备缓冲不足，尚未 Job dispatch | BACKPRESSURE |
| query 的 R/B/J 不足，无提交证明 | LIMIT，无 receipt |
| execute 已拿到可信 receipt | COMMITTED_BUT_UNAVAILABLE + 原 receipt |
| lookup/cancel 已返回 Committed | 同一 CBU + 原 receipt |
| 原 Failure UNKNOWN、原 reply 丢失或原 deadline 已过 | UNKNOWN 不升级，不补造 receipt |
| metadata 或 Cancelled 的固定小成功值 | 使用预备缓冲；若内部形状不变量破坏导致最终编码失败，关闭回复，HTTP 为 UNKNOWN |
| 已有 error envelope 连预备回复也无法表达 | 关闭回复，不重写成另一个提交结论 |

可信 Receipt 由内部 budgeted Engine/resolution 直接 move 到私有 context；不从
任意 Value、客户端 request、最新 HEAD 或另一个请求重建。正常输出只复制小型公开
receipt 投影。最终 J 申请失败时，先销毁大 Value/B backing，再把原 CBU/LIMIT写入
预备缓冲。保留 SDK 已识别的 code、decimal string、HTTP503和字段形状，不重放SQL。

固定 JSON slice 的不可达写失败使用内部不变量断言：计数和写入借用同一不可变
`serde_json::Value`/error投影，类型不含自定义 Serialize 回调，两遍 formatter一致。
可达的计数上限、信用不足和 Vec reserve错误正常返回。公开工作失败不会因为本地
额度不足被写成 durable CORRUPT。
SDK `sdk/node/src/wire.js::envelope` 的现有映射保持：503+UNKNOWN 是 `UnknownError`，
CBU的原 receipt 经既有 Scope/request 校验后是 `CommittedResultError`；不是 INTERNAL
或新的成功结论。该结论来自当前源码静态核对，本片未运行 SDK/实际网络门禁。

## 5. 验证计划与当前限制

本片定义的有意义单位包括：global/tenant原子失败、protected隔离、先收费再allocator、
真实 TryReserveError、poison退款、wire/Base64/JSON重叠、原capacity与最终clone/slice、
worker仍运行时HTTP timeout不退E、排队放弃、发送失败与原deadline、默认Worker拒绝、
真实Engine的query/commit/lookup/cancel、真实HTTP finalizer的CBU/UNKNOWN及启动接线。
小型账本 fixture 只缩小单元计数域；公开 Profile 的合法最小值另行核验，不改变产品默认。

覆盖清单加入 `output/tests.rs` 与 `http/output_tests.rs` 两条单位源码；新的
`output.rs` 与所有服务生产改动正常进入四维分母，没有生产豁免。若正式 map 仍有
缺口，保持 FAILED，不能借集成 profile 补齐或隐藏不可达代码。

接下来必须执行完整 workspace 的 stable/nightly/strict Clippy与逐文件四维门禁，
并重跑受影响的真实 service/resource/slow-consumer 合同。resource fixture 的适配改变了
输入身份，旧14负/1正控制结果不能作为本片验收。旧基础、旧资源、旧传输结果各保留
原 source/binary 身份；本静态候选尚没有 aggregate output 实际验收结论。

## 6. 2026-11-09：执行中断与保全

冻结运行时为 `f074897403e7e85e7612584027bbbfd680353a43`。attempt01 的原记录
保留：format 和严格 Clippy exit0，stable 编译完成；原日志只证明一个 core unit
程序开始，未观察到任何 unit 程序完整退出。工具会话随后无法恢复，原 completion
仍为原样 running；另列 INCOMPLETE_EXECUTION_CONTROL_LOST，不补造退出码，
不把它写成代码失败或门禁通过。

6 个当前 stable ELF 以“已编译、执行未完成”身份封存。当前 coverage 的 6 个 ELF、
93 份 raw 和 1 份 merged 逐字节属于上一次已验收的 `acec129`，不能计入 f074。
保全归档的 214 个成员全部读回，450 个 source members 验证通过；root 随后独立
重算归档 SHA 一致。187 个待替换 target artifacts 具备交接记录，native OUT_DIR
引用保留。历史 c6 Clippy 失败、d012 四维失败及 acec 的 546+546 通过各保留原身份。

随后执行环境被标记 unavailable，新的命令不能启动。attempt02、当前模型修正版
及两组新的实际 fixture 都没有因此开始执行。环境恢复后先验证原保全和目标身份，
再在独立新 evidence 目录运行同一冻结源码的完整门禁；旧 profiles 不进入新分母。
本次文档提交不修改 f074 的生产 Rust 或测试输入。

[中断与归档身份记录](../evidence/service-output-pool-incomplete-local-2026-11-09.json)
列出最后成功验证的产物及当前执行边界。归档内容在环境失去访问前已验证；此时不宣称
仍可从不可用环境重新读取这些本地文件。
