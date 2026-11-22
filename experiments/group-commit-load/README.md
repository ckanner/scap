# 独立事务 group commit：固定开环配对测量

本实验执行正式 release `scapd`、公开 Node SDK 与固定 SeaweedFS 4.51 本地 S3。
它填补 #68 的**性能测量**缺口，不改变提交、取消、ACK 或 native durability。
S3 为真实进程端点；AWS Standard、云端成本、跨 AZ 和生产 SLO 均为 `NOT_RUN`。

## 冻结工作量

顺序为 **off-1 → on-1 → on-2 → off-2**，构成两组反向配对。每轮新建后端、服务、
私有缓存及同样的数据库；只改变 `admission.group_commit`，其他准入、队列、缓存、
输出和连接容量完全相同。seed/建表在测量窗外，测量使用同一暖 writer。

| 阶段 | 独立事务 | 预定到达率 | 到达窗 | 独立 status 探针 |
| --- | ---: | ---: | ---: | ---: |
| low | 32 | 4/s | 8 秒 | 4 |
| contended | 128 | 64/s | 2 秒 | 4 |

每个原请求只有一条 `INSERT … random() … RETURNING`，各有互不复用的请求身份。
四轮共 **640 个测量事务**，另有 4 个测量窗外的 schema execute；每条都是独立事务，
不是把 640 条语句放入几个 SQL batch。固定输入为 256 字节
payload；随机 witness 实际存入表并返回。到达时间复用
[`object-overload/schedule.mjs`](../object-overload/schedule.mjs)，不等前一个完成，
不阻塞 S3/HTTP 凑组，不触发重试。客户端上限 192，服务单库普通排队槽为 64。
排队满、期限或传输失败均保留为原终态，不从分母中删去。

所有原身份在 drain 后逐一 lookup；仅 UNKNOWN 走一次 cancel、再 lookup，绝不重新
执行 SQL。全部成功响应的原结果必须和 lookup 逐字节相同；最终查询核对原随机
witness、id 和 payload。独立审计从原 S3 字节重建最终 SQLite 文件，再执行
`integrity_check` 与完整行比较，不以 runner 的汇总声明作为正确性证据。

## 输出和判定

每轮、每阶段分别报告成功率、全部终态计数、scheduled→terminal 与 invoke→terminal
的 p50/p95/p99、offer lag、控制探针延迟，以及原 HEAD PUT 尝试/接受数、全部 S3
请求和请求/响应 body 字节。组尺寸来自实际 HEAD sequence 增量，必须有等量独立
原身份、连续成员版本和原结果支撑；不能从配置值或执行速度推断实际组批。

**不设必须成组或必须提速的门槛。** 如果所有组尺寸为一，报告清楚未实际测到组收益。
low 只有 32 条，p99 是 nearest-rank 样本最大值；contended 128 条的 p99 也不是稳定
生产尾延迟。吞吐分母包含到达后 drain 的时间，避免用 2 秒到达窗除以之后才完成的工作。
每种失败保留自己的延迟；空成功集输出 `null`，不伪造零延迟。

原字节保存、fsync、本地 HTTP 转发和资源采样会增加观察器开销。四轮使用同样的观察器，
但开销可能与对象次数相互作用，因此此结果不等同无观察器部署或 AWS 生产性能。
字节只计 body，不包含头、TLS 或 S3 账单；资源峰值为采样值，不是硬上界。
scheduled→terminal 含客户端、网络和服务排队，不能冒充服务内部排队时间。

## 执行

先通过 [`object-service/build.py`](../object-service/build.py) 构建并绑定正式 release、
SDK、源码和构建日志。实验固定 Node 22.16.0、SeaweedFS 4.51；固定后端版本在复用的
backend 构造中检查。单阶段最大 180 秒，全套原始期限 720 秒，保留一切原失败。

```bash
python3 -B -m unittest discover -s experiments/group-commit-load -p 'test_*.py' -v
python3 -B experiments/group-commit-load/run.py \
  --binary /absolute/release/scapd --build-record /absolute/build/build.json \
  --weed /absolute/weed --node /absolute/node --evidence /absolute/new-evidence
python3 -B experiments/group-commit-load/oracle.py /absolute/new-evidence
python3 -B experiments/group-commit-load/controls.py /absolute/new-evidence
```

`run.py` 仅记录 `OBSERVED_NOT_AUDITED`；`oracle.py` 独立检验后才输出 `PASSED`。
`controls.py` 对原账本做 25 个精确反例投影，逐个要求命中指定规则，并保留原样正对照。
这些反例不增加真实执行数量，也不计入 Rust/Node 产品单元覆盖。完整源码归属、配置、
运行二进制摘要、独立 observer 来源、所有 HTTP/S3 原字节与 owned process wait4 结果
随证据一起保留。实际执行状态和结果由后续正式记录给出，此 README 本身不声称已运行。

SDK promise 的终态时间另记；观察的请求完成区间等待其原 fetch 终态，不将提前返回
的 deadline 冒充已排空 HTTP。原始 HTTP envelope 与 SDK 成功/失败类型必须一致；
例外须有原期限、错误 cause 支撑，保留先返回的写 UNKNOWN / 读 DEADLINE，即使原 fetch
之后排空了完整响应。已提交 decode deadline 还必须有原 receipt、原结果。阶段 S3 成本绑定实际
runner 的不重叠阶段时段；配置原字节、Node 和 backend 运行摘要均核对来源记录。
客户端槽位以真实调用区间的上下界核对，允许 Promise 清理微任务的尾部；本计划每阶段
全部调用数最多 132，小于 192 个槽，不能伪造客户端满额拒绝来删去原请求。
四轮 ABBA 顺序另以原 backend 起止单调时钟交叉核对，不只接受 runner 的顺序声明。
