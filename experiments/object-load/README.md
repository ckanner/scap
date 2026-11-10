# 本机吞吐与冷恢复隔离基线

本夹具执行 [固定计划](PLAN.md)，使用正式未插桩的 `scapd`、正式 Node SDK、native
SQLite 和 SeaweedFS 4.51。计划为八库、两个租户、871 个固定 POST，其中 185 份原始
execute、288 次测量调用。任何原 execute 都只发送一次；后续只用原身份 lookup/cancel。
夹具不实现数据库的恢复、提交、重试或复制算法。

2026-11-10 的固定本地运行已完成：产品 `66f452e`、夹具 `f8a40d7`，独立 oracle、14 个
负对照及三个正向核对通过；185 原 execute 全部 committed。单库 C1/C4 写入分别为
8.795/8.750 req/s，四库 C4 为 14.376 req/s；完整时延、排队、S3 放大、冷恢复与采样
局限见[本轮验收](../../docs/engineering/head6-runtime-validation.md)和[机器记录](../../docs/evidence/head6-runtime-local-2026-11-10.json)。
本段是后续结果说明，不改变原固定计划、夹具运行身份或 raw summary。

## 执行与身份

需要 Python 3.12、Node 22.16.0、正式 release 服务及其完整 build receipt、SeaweedFS
4.51 可执行文件。先提交并冻结本目录，使用新的证据目录：

```sh
python -m unittest discover -s experiments/object-load -p test_contract.py
node --check experiments/object-load/probe.mjs

python experiments/object-load/run.py \
  --source-root /absolute/frozen-product-checkout \
  --server /absolute/release/scapd \
  --build-record /absolute/service-build/build.json \
  --weed /absolute/weed \
  --evidence /absolute/evidence/object-load-attempt-1

python experiments/object-load/oracle.py /absolute/evidence/object-load-attempt-1 \
  > /absolute/evidence/object-load-attempt-1-oracle.json
python experiments/object-load/controls.py /absolute/evidence/object-load-attempt-1 \
  --output /absolute/evidence/object-load-attempt-1-controls \
  > /absolute/evidence/object-load-attempt-1-controls.json
```

`--source-root` 是正式产品的冻结 checkout；运行目录可以是稍后单独提交的本夹具
checkout。两者不能混成同一个来源声明。runner 保存全部产品 build inputs、源码
archive、Cargo 日志、二进制摘要，以及本夹具的 commit、逐文件摘要和独立源码 archive。
运行前后再次验证这些字节。独立 oracle 要求自己的全部夹具源码与原 archive 相同，
使用同一份计划和独立 wire reader；不导入产品或 runner，也不读取 runner 的成功汇总
作结论。负控制修改独立副本，原始证据通过前后都重新审核。

runner 成功仅产生 `OBSERVED_NOT_AUDITED`。独立 oracle 与全部 14 个负控制都通过之后，
才可报告这次本机实验完成。单位测试验证观察器边界，不能替代真实运行，也不是产品
单位覆盖。失败保留原始目录及退出信息；修复后另开 attempt，不能覆盖旧失败。
每个负控制及修改 summary 的正控制都有持久副本与结果，失败也不自动删除；原始大 body
用 hardlink 共享，修改总以替换文件进行，不会改坏源证据。S3 请求分母还必须等于代理
全部 handler join 后记录的最终计数，不能整条删掉最后一个 exchange 后仍通过。

## 输出含义

`oracle.py` 从原始历史重算：

| 字段 | 含义 |
| --- | --- |
| `http_posts`、`all_outcomes` | 全部 871 次 POST，包含种子、激活、查询、恢复、lookup 与 cancel |
| `measured` | 单库串行、单库四并发、四库四并发及两组暖读，全部请求的延迟与状态分母 |
| `request_latency_ms_including_service_queue` | SDK 调用开始至成功/错误返回，包含服务排队、HTTP、SQLite、S3、SDK 解码及采集开销 |
| `latency_ms_including_generator_queue` | 还包含固定 closed-loop 调度中等候客户端 lane 的时间 |
| `outcomes` | success、rejected、unknown、committed_unavailable、transport_error；后续解析不会改原状态 |
| `s3_requests`、各阶段 S3 字节 | 全部正式产品 S3 GET/PUT 和完整 request/response body；不是网卡协议字节 |
| `cold_recovery` | 丢弃 compute cache 后 32 MiB 数据恢复时间、人工 gate 时间、完整依赖下载与热库/control 探针 |
| `results` | 原始 receipt/随机结果、160 份写入最终解析、全部 cold BLOB 与各库全部行的核对 |
| `resources` | 每次 daemon 的采样 RSS/HWM/FD/线程/缓存与后端磁盘，实际采样间隔及独立 kernel wait4 maxrss |

未出现的状态在 JSON 的计数字典中可能省略，解释时其计数为零；总分母始终显式保留。
`rejected` 仅表示 SDK 收到明确服务错误，不能推导“允许生成新身份重试 SQL”。
`unknown` 包括不可用或期限结束；`committed_unavailable` 保留原 receipt，无法解码也
不撤销提交。原 Result 已可得时，完整字节也先写入 ACK 账本再结束 SDK 计时。

所有产品 S3 调用均经过有界观测代理，保存签名的公开摘要、条件头和完整原始字节。
SeaweedFS 用随机私有凭据启动，既有 HEAD 的无签名读取必须得到 403。签名摘要验证不是
另一套密码学认证实现；实际签名校验由兼容端点执行。后端自身的 bucket provisioning、
服务 `/healthz` 及进程管理不是这 871 次 POST 的一部分；就绪 GET 另行保留原始观察。

## 资源与测量边界

owned launcher 在 exec 前打开自身 `/proc/self` directory fd，经私有 Unix socket
传父进程；父进程核对原 stat/start ticks 和 exec 后正式二进制。不能用未经证明的
数字 Popen.pid 采另一个 PID namespace 的进程。资源采样针对该 fd，不把 Node、代理、
后端或共享页缓存当成 `scapd` RSS。采样在服务就绪后开始，在发送正常 SIGINT 前结束；
报告首尾缺口与每次采集耗时。owned `wait4` 在退出后提供整段生命周期 kernel maxrss，
并独立于取样最大值。所有服务和 SDK 子进程的真实 wait4、后端退出及代理 join 都是
必要证据，强制杀死正式 daemon 不能冒充正常停机。

目标取样周期为 100 ms，加上实际采集开销；间隔内的短峰值不保证被观察。磁盘目录扫描
也不是原子快照，遇到正常文件/子目录消失会单独计数 races，拒绝 symlink。`VmHWM`
发生回落时保留全部样本并报告次数，不据此降低已观察到的峰值。正数的有限采样与
kernel maxrss 都不能证明任意负载下的 RSS、FD、线程或磁盘硬上限。

原始 body 由 Python 与 Node 共用同一个 2 GiB 预算，跨进程锁内先预留再写入；异常可
消耗剩余额度，但不能提前归还。证据写入和代理转发会增加延迟。这是包含观测开销的
本机固定小规模 closed-loop 基线，不是无插桩的网络 TPS 或开放环过载 SLO。四并发的
每组样本较少，nearest-rank p99 接近最大值，不能据此估计生产尾延迟置信区间。

`aws_standard=NOT_RUN`、`production_slo_passed=false` 和
`sampled_resource_peak_is_hard_bound=false` 固定保留。GiB 冷恢复、持续公平性、GC 竞争、
硬资源隔离及云端测试见 [组合门禁设计](../../docs/engineering/resource-recovery-stress-plan.md)。
