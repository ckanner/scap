# 独立事务 group commit：固定开环配对测量

本实验执行正式 release `scapd`、公开 Node SDK 与固定 SeaweedFS 4.51 本地 S3。
它填补 #68 的**性能测量**缺口，并为接纳拒绝保留独立诊断证据，不改变提交、取消、ACK 或 native durability。
S3 为真实进程端点；AWS Standard、云端成本、跨 AZ 和生产 SLO 均为 `NOT_RUN`。

## 冻结工作量

每个 profile 的顺序为 **off-1 → on-1 → on-2 → off-2**，构成两组反向配对。每轮新建后端、服务、
私有缓存及同样的数据库；只改变 `admission.group_commit`，其他准入、队列、缓存、
输出和连接容量完全相同。新运行两边都显式开启 `resource_diagnostics: true`；生产默认关闭。
seed/建表在测量窗外，测量使用同一暖 writer。

`short-v1` 为默认 profile，保持原来的 **640 个测量事务 + 4 个 schema execute**、
容量与 720 秒全套期限。它的新诊断运行使用新的证据目录，不替换或修改已归档的原短样本、失败和源码。

| 阶段 | 独立事务 | 预定到达率 | 到达窗 | 独立 status 探针 |
| --- | ---: | ---: | ---: | ---: |
| low | 32 | 4/s | 8 秒 | 4 |
| contended | 128 | 64/s | 2 秒 | 4 |

独立新增的 `admission-curve-v1` 使用以下固定输入，四轮共 **3072 个测量事务 + 4 个 schema execute**。

| 阶段 | 独立事务 | 预定到达率 | 到达窗 | 独立 status 探针 |
| --- | ---: | ---: | ---: | ---: |
| low | 64 | 4/s | 16 秒 | 4 |
| steady | 192 | 12/s | 16 秒 | 4 |
| contended | 512 | 32/s | 16 秒 | 4 |

长 profile 的每档分为四个固定四秒窗口；短 profile 的窗口为两秒。各档在**同一数据库连续执行**，
后档包含前档产生的数据和请求索引，因此这是累计负载曲线。16 秒有限样本不构成长期稳态验收，
三个点也不是只改变到达率的容量实验。报告同时给出各档开始和结束时，原 HEAD 可达 Manifest 的页数、
保留身份数以及已提交 INSERT 身份数。反向 ABBA 不能消除数据库增长或观察器开销。

每个原请求只有一条 `INSERT … random() … RETURNING`，各有互不复用的请求身份。
每条都是独立事务，不把多条 SQL 塞进一个 batch。固定输入为 256 字节
payload；随机 witness 实际存入表并返回。到达时间复用
[`object-overload/schedule.mjs`](../object-overload/schedule.mjs)，不等前一个完成，
不阻塞 S3/HTTP 凑组，不触发重试。客户端上限保持 192；配置 `data_intake=80`，
但省略的 v1 intake profile 实际使**同租户请求上限为 40**，早于单库普通队列的 64 个计费额度。
data body 的全局及租户上限均为 5 MiB；尝试接纳时预留的是 `max_body_bytes=65536`，
不是该 HTTP 正文的实际长度。全局/租户/单库 queue 的 total 上限为 96/80/72，普通额度为 88/72/64。
这些原容量保持不变，不能先把 ACK 差异归因于 group 的 queue 持有。
服务拒绝、期限或传输失败均保留为原终态，不从分母中删去。

短 profile 每阶段全部调用最多 132，严格小于 192 个客户端槽。长 profile 没有这个先验保证，
必须以真实 offer/active 上下界和完整 HTTP 分母证明没有 generator rejection；一旦发生即审计失败，
保留全部原证据，不能增大容量、改变阈值或用重跑取代原结果。

所有原身份在 drain 后逐一 lookup；仅 UNKNOWN 走一次 cancel、再 lookup，绝不重新
执行 SQL。全部成功响应的原结果必须和 lookup 逐字节相同；最终查询核对原随机
witness、id 和 payload。独立审计从原 S3 字节重建最终 SQLite 文件，再执行
`integrity_check` 与完整行比较，不以 runner 的汇总声明作为正确性证据。
短 profile 的 SQLite 重建上限仍为 32 页、161 个保留身份；长 profile 固定为 128 页、769 个身份。
长 profile 独立检查最多四个连续 32 页 chunk 的哈希、起始页与末块实际长度，缺页不补零。
服务原请求窗口仍为 4096 个身份、256 MiB 结果保留上限，并从原 HEAD 核对；实验无需放宽该容量。

## 原 HTTP 拒绝诊断

`probe.mjs` 分别保存原 JSON body、Fetch 实际观察的 `x-scap-rejection` 值、该值的原字节副本及摘要，
以及 SDK `error.resourceRejection` 在 `call_finished.error.resource_rejection` 中的副本。
Fetch 的 header 值不是 TCP header framing 的原始字节。`diagnostics.py` 不导入生产或 SDK parser，独立验证：

- ASCII 最长 256 字节；counted 形式严格为 `v=1;reason=…;used=…;limit=…;requested=…`。
- source-only 形式只有 `v=1;reason=…`，不捏造 semaphore 或分配失败的占用快照。
- 固定 41 个 counted、5 个 source-only 原因；各数字为规范十进制 u64 字符串，`limit>0`、`used<=limit`、
  `requested>0` 且 `used+requested>limit`。求和使用可超过 u64 的精确整数。
- 绑定原 HTTP error code/status、原 admission class 和实际配置限额；intake body 的 requested 必须为 65536。
- 开启诊断的本候选每个 `BACKPRESSURE` / `RECOVERY_BUSY` 都须有合法原头；普通 `LIMIT` 可能来自其他原有限制。
- SDK typed 值须与独立解析一致；原 HTTP 晚于 SDK deadline 时继续保留原 `UNKNOWN` / `DEADLINE`，不更改业务分类。

每个计数型原因描述**原互斥锁内第一个失败约束的单个计数器**，不是所有资源池的同时快照。
queue 的 `used` 是 charged credits，包含组尚未释放的额度，不是物理队列长度。
报告保留每个原 HTTP gate observation 的身份、占用/限额、请求增量和原字节引用，
也报告与独立验证的多成员 HEAD 发布区间的重叠。该重叠只是时序共现：没有内部判定时钟，
尚未发布的组也不在此关联里，不能从 header 或重叠本身证明某种额度持有造成吞吐差异。

## 输出和判定

每轮、每阶段分别报告成功率、全部终态计数、scheduled→terminal 与 invoke→terminal
的 p50/p95/p99、offer lag、控制探针延迟，以及原 HEAD PUT 尝试/接受数、全部 S3
请求和请求/响应 body 字节。组尺寸来自实际 HEAD sequence 增量，必须有等量独立
原身份、连续成员版本和原结果支撑；不能从配置值或执行速度推断实际组批。

**不设必须成组或必须提速的门槛。** 如果所有组尺寸为一，报告清楚未实际测到组收益。
`short-v1` 的 low 只有 32 条，p99 是 nearest-rank 样本最大值；contended 128 条的 p99 也不是稳定
生产尾延迟。吞吐分母包含到达后 drain 的时间，避免用 2 秒到达窗除以之后才完成的工作。
每种失败保留自己的延迟；空成功集输出 `null`，不伪造零延迟。
固定窗口将**预定到达 cohort 的最终结果**与**该时窗内真正完成的调用**分列，并报告窗口末尚未完成的原调用。
`maximum_observed_active_before_offer` 是新请求发起之前采到的客户端槽位，不是服务并发峰值。
`original_http_gate_observations` 包含可能晚于 SDK deadline 的原响应，不能直接当作 SDK `RemoteError` 的计数。

原字节保存、fsync、本地 HTTP 转发和资源采样会增加观察器开销。四轮使用同样的观察器，
但开销可能与对象次数相互作用，因此此结果不等同无观察器部署或 AWS 生产性能。
字节只计 body，不包含头、TLS 或 S3 账单；资源峰值为采样值，不是硬上界。
scheduled→terminal 含客户端、网络和服务排队，不能冒充服务内部排队时间。

## 执行

先通过 [`object-service/build.py`](../object-service/build.py) 构建并绑定正式 release、
SDK、源码和构建日志。实验固定 Node 22.16.0、SeaweedFS 4.51；固定后端版本在复用的
backend 构造中检查。单阶段最大 180 秒，全套原始期限 720 秒，保留一切原失败。
长 profile 的全套期限预先固定为 1200 秒，单阶段仍为 180 秒。两个 profile 都保留旧 observer 上限：
每轮 raw 2 GiB、S3 请求 30000、32 个 proxy handler；trace 200000 条 / 128 MiB、单 body 64 MiB；
100 ms 采样、最多 15000 个样本；启动空闲磁盘至少 2 GiB、运行至少 1 GiB。它们全部写入固定 plan，
oracle 不接受证据中自行增大的 page/entry/trace/时间界限。本地实际成本按完整 S3 请求和 body 字节报告。

```bash
python3 -B -m unittest discover -s experiments/group-commit-load -p 'test_*.py' -v
python3 -B experiments/group-commit-load/run.py \
  --profile short-v1 \
  --binary /absolute/release/scapd --build-record /absolute/build/build.json \
  --weed /absolute/weed --node /absolute/node --evidence /absolute/new-evidence
python3 -B experiments/group-commit-load/oracle.py /absolute/new-evidence
python3 -B experiments/group-commit-load/controls.py /absolute/new-evidence

python3 -B experiments/group-commit-load/run.py \
  --profile admission-curve-v1 \
  --binary /absolute/release/scapd --build-record /absolute/build/build.json \
  --weed /absolute/weed --node /absolute/node --evidence /absolute/new-curve-evidence
python3 -B experiments/group-commit-load/oracle.py /absolute/new-curve-evidence
python3 -B experiments/group-commit-load/controls.py /absolute/new-curve-evidence
```

`run.py` 仅记录 `OBSERVED_NOT_AUDITED`；`oracle.py` 独立检验后才输出 `PASSED`。
oracle 和 controls 从证据中的 profile 名选择固定 registry，再逐字段比较完整 plan；不接受自定义容量。
`controls.py` 保留原 25 个精确反例投影，增加原 header capture/admission 两项，以及按实际观察到的诊断增加
header/status/SDK 反例，逐个要求命中指定规则，并保留原样正对照。未观测到某类诊断时明确标 `NOT_OBSERVED`，
不伪造一次真实拒绝。独立 selftests 另覆盖完整原因字典、格式/范围/触发算术、配置绑定、迟到原响应和多 chunk 重建。
这些反例不增加真实执行数量，也不计入 Rust/Node 产品单元覆盖。完整源码归属、配置、
运行二进制摘要、独立 observer 来源、所有 HTTP/S3 原字节与 owned process wait4 结果
随证据一起保留。实际执行状态和结果由后续正式记录给出，此 README 本身不声称已运行。

SDK promise 的终态时间另记；观察的请求完成区间等待其原 fetch 终态，不将提前返回
的 deadline 冒充已排空 HTTP。原始 HTTP envelope 与 SDK 成功/失败类型必须一致；
例外须有原期限、错误 cause 支撑，保留先返回的写 UNKNOWN / 读 DEADLINE，即使原 fetch
之后排空了完整响应。已提交 decode deadline 还必须有原 receipt、原结果。阶段 S3 成本绑定实际
runner 的不重叠阶段时段；配置原字节、Node 和 backend 运行摘要均核对来源记录。
客户端槽位以真实调用区间的上下界核对，允许 Promise 清理微任务的尾部；不能伪造客户端满额拒绝来删去原请求。
四轮 ABBA 顺序另以原 backend 起止单调时钟交叉核对，不只接受 runner 的顺序声明。
