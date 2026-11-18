# 目录发现：分离请求接收与认证日志时刻

2026-11-13 的 b15 服务发现原尝试保留为 FAILED。原 429 个 HTTP 调用通过身份、次数与
区间核验；25,292 个签名 S3 请求中，serial 17717 被代理记录于前一 HTTP 响应后
2.291901 ms、下一调用开始前 6.907092 ms。前一调用正常返回 UNKNOWN cursor，耗时
4.205692417 秒，没有超过原 5 秒期限。

旧代理在读取请求、SigV4 校验和锁之后才写入 `request.monotonic_ns`。原件没有更早的
请求观察，也没有产品 dispatch 时间，因此只能判定原观察区间不能为这条请求归属。
不能断定它必然合法，也不能断定产品在返回后才发出请求。旧日志不能补写新字段，
原失败不能因新工具存在而回填为成功。

## 本次改动

只修改 `experiments/object-service` 的专用 discovery proxy、独立 oracle 和夹具测试。
不改变生产 Rust、HTTP/SQL API、S3 条件写、场景或 4 秒／5 秒预算。

代理在共同 `Handler.dispatch()` 入口首先调用真实 `time.monotonic_ns()`，保存局部的
`request_received_monotonic_ns`。此时标准库已经解析请求头；尚未读取 body、验证签名、
取得共享锁或写日志。随后只有真实签名验证成功，才把这个局部值与同一请求的 serial、
method、path、body 摘要及 signing witness 写入原 request 记录。认证失败不发布该见证。

| 时钟 | 精确定义 | 使用位置 |
| --- | --- | --- |
| `request_received_monotonic_ns` | 已解析 headers 后的 handler 入口观察 | HTTP 归属、分页索引、请求因果依赖、原预算与 no-post-return 检查 |
| 原 `monotonic_ns` | 认证与观察器处理后的原事件日志时刻 | 原事件编号和顺序、转发／后端响应关系、故障／延迟选择、版本线性化 |

新时钟是 GET 开始已被代理观察的外部上界，不是产品发送时刻、TCP accept 时刻，也不
是 PUT body 收齐时刻。接收发生在 HTTP 返回前，才能提供相应的原区间归属证据；
真实接收发生在返回后时仍拒绝。没有扩大原 HTTP 窗口，也没有新增 held 请求例外。

oracle 要求新字段存在、为正整数且不晚于原认证日志时刻，无旧格式 fallback。
全部相关归属和因果检查一致使用同一接收见证，避免只修最前面的归属判断而漏掉
分页预算或 no-post-return。原 authlog 的字节和事件顺序原样保留。

反例中的移时与克隆同时更新两种时钟；新造的返回后请求不得借用旧接收时间。
原 29 个 actual controls 的名称及相对顺序全部保留，增加缺失、非法和晚于认证日志
三个接收时钟负控，共 32 个；原不变正对照保留。

## 验证与来源

完整 object-service 夹具单元 243/243 通过，其中原 232 项、新增 11 项。
新增测试分别检查 GET/PUT 的真实时钟与真实 fixture SigV4 接线、认证失败、归属
不能跨 Scope、严格原 5 秒 held 窗口、迟记日志仍计入原页、真正 post-return 请求
仍被拒绝、缺失／非法／倒序字段，以及反例双时钟移动。

正式 service 构建输入从 277 项变为 278 项，包含新增测试文件。因此必须在新冻结
源码上执行正式 `experiments/object-service/build.py`，生成新 build receipt 与二进制
工件；不能编辑或借用 b15 的旧 receipt。新实际使用新目录、原完整合同、原独立
oracle 与全部 32 个 actual 负控。小型夹具单元通过不能替代这一步。

工具提交 `642383c` 时实际仍为 NOT_RUN，精确文件身份、旧失败和单位结果见
[机器记录](../evidence/discovery-request-clock-local-2026-11-13.json)。
这份工具记录保持原提交时点的含义，旧 b15 原件和原 oracle 拒绝保持原样。

### 接续的完整实际：通过

随后在冻结 `642383cbd27e72c940fb565064d5b127e3186f22` 上新建正式 service release，
278 个构建／夹具输入和 730 个跟踪源码文件分别核对。原完整入口于 2026-11-13
16:57:11 至 17:27:58 UTC 执行，actual、独立 oracle 和全部 32 个负控／原正控合计
1,847.424 秒；这不是只有客户端阶段的耗时。原 4 秒读预算、5 秒 HTTP 预算和全部
工作量、并发、准入限制未改。

结果为 424 个 HTTP 调用、25,278 个签名 S3 请求、144 个 LIST，原 32 个指定负控
全部拒绝，原正控核对同一份 424 调用历史。26 个 SDK 子进程正常退出；3 个 service
和 4 个 backend 按原夹具 SIGKILL 结束且均有 owned wait4。cleanup_errors 为空，
私有夹具已移除，源码最终核验通过。32 控在原入口中对内存变异历史执行，不能描述
成 32 次新的实际故障运行或虚构其独立目录。

新报告、正式工件、原结果 SHA 和旧失败关联见
[实际机器记录](../evidence/discovery-request-clock-actual-2026-11-13.json)。它只认证
新观察 schema 的服务发现合同，不将 b15 原失败改为通过，也不认证完整数据恢复、
AWS、生产 SLO 或整体合入。
