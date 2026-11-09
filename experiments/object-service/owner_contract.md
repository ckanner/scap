# 显式 owner 路由与接管的真实传输合同

本实验装配正式 `scapd`、正式 `RoutedClient` / `OwnerClient`、原生 SQLite 和固定
SeaweedFS 4.51。它验证一次显式管理意图的安全边界，不实现故障探测器、自动接管
controller、动态 registry 或数据库协议。设计背景见
[owner-reconciliation](../../docs/architecture/owner-reconciliation.md)。

## 冻结范围与运行

固定输入在 `owner_spec.py`。实际 Node 进程只接受固定 command ID，由
`owner_probe.mjs` 调用正式 SDK；`owner_contract.py` 只负责进程与故障编排。
`owner_proxy.py` 原样转发真实 HTTP/S3，保存完整字节，并在明确的进入/释放点暂停
一次原请求或丢失一次已经收到的原响应。它不会生成成功的 S3 响应。

唯一主动生成的 HTTP 响应是标记为 `fault_redirect` 的 307；这是验证 SDK 不把
bearer token 发往 registry 外地址的测试输入，不被计为正式服务响应。其接收端
必须没有请求。所有其他 HTTP 响应必须来自实际服务，所有 S3 响应必须来自实际后端。

使用固定 Rust 1.90.0、Node 22.16.0 和 SeaweedFS
`4.51 153ab668c99731a6d29492bf6c61d0b4fa701101`，先提交并冻结全部源文件，再构建：

```bash
python3 experiments/object-service/build.py \
  --target-dir /tmp/scap-owner-release-NEW \
  --evidence /tmp/scap-owner-build-NEW
python3 experiments/object-service/owner_contract.py \
  --server /tmp/scap-owner-release-NEW/release/scapd \
  --weed /absolute/path/to/weed \
  --build-record /tmp/scap-owner-build-NEW/build.json \
  --evidence /tmp/scap-owner-observation-NEW
python3 experiments/object-service/owner_oracle.py \
  --evidence /tmp/scap-owner-observation-NEW
python3 experiments/object-service/owner_controls.py \
  --evidence /tmp/scap-owner-observation-NEW \
  --output /tmp/scap-owner-controls-NEW
```

每次正式构建与运行使用新的目录，运行前后核对完整源码输入、release 可执行文件、
构建日志及实际 native archive。不得启用 LLVM 或 V8 覆盖插桩；这些实际进程证据
不贡献生产单元覆盖率。缺收据、源码变化、观察不完整、审计或清理失败均非零退出。
保留首次失败及原输入，修复后用新的源码身份和证据目录重新验证。
`owner_controls.py --output` 是新的目录，保存各对照证据副本与 `controls.json`；
修改通过原子替换打破硬链接，不更改原始成功证据。

私有凭据和本地缓存创建在 evidence 的同级独立目录。建议运行时都放在 `/tmp`；
只在独立审计完成后复制公开 evidence。不得上传私有目录。公开服务配置只含
bearer 摘要和 S3 环境变量名称，Node 的明文凭据配置留在私有目录。

## 固定分母

合同有 **70 个 SDK 工作命令、144 个实际 HTTP POST**。13 个独立 scope 的 seed
各执行 create、activate、一次包含两条 SQL 的 execute、policy，共 52 次 POST；
其余命令共 92 次。每个原始 Fetch 与代理收到的 POST 必须一一对应，额外 dispatch、
重试、缺失响应或少执行一个阶段都不能被成功计数隐藏。

第一个实际 Node 进程完成 61 个工作命令和 135 次 POST，正常退出并由父进程
`wait4` 回收；第二个全新 Node 进程完成剩余 9 个命令和 9 次 POST。两个显式
shutdown 控制输入不计入工作命令。健康探针、版本查询和后端建桶/签名就绪探针
也不计入 SDK POST 分母。

固定 SQL 创建 `witness(n INTEGER PRIMARY KEY)`，先插入 1；被许可的新增写入只
插入 2。它们仍须保存和比较完整 SCAPRES1 原字节、列名、列数、单元类型和值、
affected_rows、last_insert_rowid 及完整 receipt。原始 request 的 principal、epoch、
ID 和 SCAPSQL1 指纹不能改变。取消的旧写不能因路由或管理步骤被重放。

正常成功路径有 12 个被父进程直接持有和回收的工作子进程：4 个 SeaweedFS
进程、4 个 `scapd`、2 个 Node，以及 2 个用于显式损坏/修复的签名 curl。Node
在自身第一条日志中报告 PID，父进程记录 Popen 前的单调时间及 owned-child
身份，最后保存内核 wait4 结果。服务 A 被明确 SIGKILL 后回收，其他服务正常
SIGINT 退出；不能用 `kill -0`、PID 猜测或 `/proc` 采样代替回收事实。

## 实际场景

| 对应设计 | 可观察切点 | 必须成立的结果 |
| --- | --- | --- |
| OR-01 | 非 owner A 提供 fresh status，业务由 B 执行 | 恰好一次原 execute；lookup 保留完整原结果，无隐含 takeover |
| OR-03 | 将 B 的受信任地址故意绑定到实际 C | `TARGET_MISMATCH`；该调用无 S3 请求，C 的文件和目录清单不变 |
| OR-03 | 401、403、真实 control intake 429、未知路由、307 | 无业务 execute，无夺主；redirect 接收端无 token 或其他请求 |
| OR-06 | B、C 的原 HEAD PUT 都进入门控 | 两者使用同一个原 ETag；B 接受后 C 得到真实 412/CONFLICT，C 不刷新候选 |
| OR-04 | A 的原写停在 HEAD PUT 前，B 已 takeover/activate | 释放 A 后不能 ACK；按原身份 lookup、cancel、再 lookup，最终只有 seed 数据 |
| OR-07 | 后端已接受 takeover，完整服务响应被丢失 | 原调用 UNKNOWN；inspect 证明 exact claim；新 activation-only 意图不增加 epoch |
| OR-08 | activation 已接受但响应丢失，随后 quota 推进 HEAD | inspect 只报告仍为 target_active，不能把后来的 transition 当作原 nonce 的证据 |
| OR-09 | takeover 的真实 200 已收到，activation 尚未开始 | 对原 manifest 做真实条件覆盖；activation 拒绝 CORRUPT，不发布 active |
| OR-09 | 用原字节和损坏后 ETag 实际条件修复对象 | 等待普通 idle 回收销毁隔离缓存；新 activation-only 成功，不再 takeover |
| OR-10 | 保留一次原 status 响应，管理员权限随后撤销 | 放行原观察后实际 takeover 按当前权限拒绝；同一意图不能再次 reconcile |
| OR-10 | 意图保存后 lifecycle 进入 maintenance | fresh preflight 拒绝；检查保持 blocked，业务 SQL 不 dispatch |
| OR-11 | 有暖状态时阻断实际 fresh HEAD GET | 真实失败保持 UNKNOWN；不授予缓存写权，也不发 SQL |
| OR-12 | B 的冷恢复 manifest GET 被明确阻塞 | 另一已热库 query 和独立 control 在释放门之前完成 |
| OR-14 | 原 routed status 响应被保留超过 250ms 总预算 | 原调用以 ABORTED/DEADLINE、not_sent 结束；不续期、不发送 execute |
| OR-05 / OR-15 | Node1 退出；A 被回收且缓存删除；D 以空缓存启动 | Node2 经存活 bootstrap C 检查原 intent；显式 D 接管恢复全部既有 ACK |
| OR-15 | Node2 从 Node1 fsync 的同一文件 restore | 只允许 inspect；重复 reconcile、修改目标绑定或完整 scope 均拒绝 |

损坏实验只在 takeover 已完成其 manifest 验证并得到真实 200 后改变对象。否则
失败的是 takeover 自身，无法证明“已 claim 后恢复失败”的边界。修复不直接改
HEAD、不清除服务内部状态、不延长 deadline。cache 目录消失仅证明 Engine/cache
已销毁；不将它夸大成 scheduler reaper 已完成 join。之后的一次原 activation
若仍因退休窗口拒绝，就保留失败，不偷偷重试来满足固定分母。

## 原始证据与独立审计

`owner_oracle.py` 独立固定同一分母并重新计算判断，不导入 controller、probe、proxy
或 `owner_spec.py` 的场景逻辑。通用严格 wire 解码和 build 审计可以复用，但不能
把 producer 的 `passed`、行数或阶段汇总当作结论。

| 文件 | 原始事实 |
| --- | --- |
| `owner-plan.json` | 冻结的 scope、principal、nonces、SQL、预算和命令计划 |
| `owner-configuration.json`、`service-*.json` | 受信任地址、实际 worker、权限身份摘要和真实服务配置 |
| `owner-tools.json`、`build-*` | 工具实际 executable SHA、源码归档、Cargo 日志、release/native 身份 |
| `node-1.jsonl`、`node-2.jsonl` | SDK 调用前后、原 Fetch 请求/响应/错误、保存/恢复意图的 fsync 日志 |
| `events.jsonl` | 原 Node stdout 字节、真实 HTTP、故障进入/释放、缓存观察、owned-child 退出和清理 |
| `history.jsonl` | 每次 S3 请求、实际后端响应和交付的完整字节、同一次 GET 的 ETag、原条件 PUT 和签名结构 |
| `intent-*.json`、`request-*.json` | 调用之前保存的完整原身份；Node1 退出后父进程独立读回，再交给 Node2 |
| `corrupt_manifest.*`、`restore_manifest.*` | 显式运维损坏/修复的实际 curl 返回、响应头与完整 payload 引用 |
| `owner-summary.json`、`owner-oracle.json` | 编排完成状态与重新计算的独立结论；不能替代上述原始记录 |

独立审计须重算所有 SQL 指纹、原 receipt/result、完整依赖闭包、HEAD 状态变化与
同 ETag 竞争，绑定每个 S3 请求到唯一原 HTTP 调用的时间区间和 worker。签名证据
使用实际 executable 身份和 access-key 摘要；另保留直接向真实后端发送未签名 GET
得到 403 的原响应，不能仅凭配置宣称后端启用了认证。

所有 fault 都是一次性的。成功路径不允许 gate 过期、自动释放、未观察退出、
重复原操作、跨 endpoint token 或遗漏调用。清理记录须包含原目录身份、全部 owned
wait4 之后的删除顺序和立即观察到的不存在；runner 在最终通过前再次检查当前
目录确实不存在。离线审计只解释冻结的历史证据，不依赖另一机器上同名路径的
偶然存在与否。负对照从完整成功证据复制后篡改不同安全边界，必须被独立审计拒绝。

## 结论边界

这是小库、固定输入、本机兼容对象后端上的确定性合同，不是 AWS Standard、
生产 RTO/RPO、吞吐、P99、跨 AZ 或容量 SLO。AWS 与生产 SLO 始终单列为 `NOT_RUN`。

OR-02、OR-16、OR-17、OR-18 涉及尚未实现的自动探测/controller/registry 协议，
不从显式 SDK 成功推导通过。OR-13 的 job 与最后 Bytes 持有者生命周期由生产单元
和独立 [resource-limits](../resource-limits/README.md) 合同验证，不借本实验的
timeout 结果替代。OR-09/10 这里覆盖明确的损坏、权限、lifecycle 和 scope 边界，
不声称穷尽所有 native-open、缺失对象或代际变化故障排列。
