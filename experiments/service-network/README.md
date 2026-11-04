# 正式 SQL 服务、SDK 与生命周期的真实部署验证

本实验启动三个真实 `scap-server` 二进制，使用独立 RocksDB 目录、正式 HTTP/Hrana/Node SDK、临时 CA 和双向 TLS 连接。实验层只负责部署、透明 TCP 故障注入、请求生成和断言；没有替代 SQL 引擎、Raft、鉴权、归档或恢复的实现。

## 运行

先按仓库固定工具链和锁文件构建正式二进制与 Node SDK。以下 target 目录和 evidence 目录可按机器调整；每次运行使用新的 evidence 目录，避免把旧完成标记当成新结果。

```bash
cargo +1.90.0 build --release -p scap-server --locked
npm --prefix sdk/node ci --ignore-scripts
npm --prefix sdk/node run build

SCAP_SERVER_BIN="$PWD/target/release/scap-server" \
SCAP_SEAWEEDFS_BIN=/absolute/path/to/weed \
SCAP_SERVICE_NETWORK_EVIDENCE_DIR=/tmp/scap-service-network-evidence \
node experiments/service-network/run.mjs
```

需要 Node.js 24、OpenSSL、curl 和允许绑定 loopback 的环境。S3 契约使用固定 SeaweedFS **4.51 / `153ab668c99731a6d29492bf6c61d0b4fa701101`**，启动时验证版本。该固定后端与签名、条件 PUT、HEAD 大小、重启持久性相关的独立验证见 [archive-s3](../archive-s3/README.md)。缺少 `SCAP_SEAWEEDFS_BIN` 时明确记录 S3 未运行，不把非 S3 测试冒充冷库验证。

默认使用上游 `mini` 启动方式。如果执行环境允许 loopback TCP、但不允许创建 Unix socket，可显式设置 `SCAP_SEAWEEDFS_MODE=separate`。这个选项通过固定二进制的正式 `master`、`volume`、`filer`、`s3` 子命令启动四个独立进程，使用显式 HTTP/gRPC TCP 地址，并在同一组目录重启全部组件。数据、鉴权、签名与不可变对象语义仍由相同 SeaweedFS 后端承担。`s3-backend.json` 记录实际版本、拓扑和进程清单；无法启动真实后端时合同失败。

此适配遵循上游固定版本的 [本地 gRPC socket 选择](https://github.com/seaweedfs/seaweedfs/blob/153ab668c99731a6d29492bf6c61d0b4fa701101/weed/pb/grpc_client_server.go)和 [显式 HTTP/gRPC 端口地址格式](https://github.com/seaweedfs/seaweedfs/blob/153ab668c99731a6d29492bf6c61d0b4fa701101/weed/pb/server_address.go)，子命令参数以同一二进制的 `-help` 核对（2026-11-04）。它不修改系统权限或上游源码。

所有数据库、生成的密钥、合成凭据和进程日志位于唯一临时目录；不会写进仓库。配置中的 token 使用哈希，S3 凭据通过子进程环境注入。实验只监听 `127.0.0.1`。日志不输出认证 token 或私钥。

故障定位时可用 `SCAP_SERVICE_NETWORK_ONLY=measurement` 单独运行双库测量，或 `SCAP_SERVICE_NETWORK_ONLY=lifecycle` 单独运行冷库验证。完成清单明确记录选择范围。

## 实际校验的合同

| 历史 | 正式路径与断言 |
| --- | --- |
| `01-three-real-daemons` | 三个独立 voter、每方向独立 TCP 代理、实际 mTLS 与自动选主 |
| `02-real-node-sdk` | 真实固定 `@libsql/client` 的五组测试：标准 execute/cache/batch、参数与整数/BLOB、原子回滚、稳定 ID 与原随机结果、强读、丢失成功响应后的显式查证、取消 fence |
| `03-tenant-and-read-permissions` | 已配置的两个真实库之间拒绝跨 token 访问；只读令牌允许强读和元数据、拒绝写入 |
| `04-acknowledged-write-leader-kill` | ACK 后 SIGKILL 当前 leader；客户端选择新 leader；数据、原始 RETURNING 和新写可用；旧进程同目录重开 |
| `05-real-minority-tcp-blackhole` | 对当前 leader 双向断开并黑洞新连接；直接访问该进程绕过 ready 提示仍拒绝新强读和写；多数派继续 ACK；有序取消防止原未知写在网络恢复后晚提交 |
| `06-all-processes-reopen` | 三个进程全部 SIGKILL，同目录重新打开；两个数据库、原随机结果和取消 fence 保留 |
| `07-s3-cold-publication-and-wake` | 新集群的冷库以受鉴权强一致 metadata 证明 archive publication/prune 已完成；前景冷唤醒到达真实 S3 TCP 黑洞后，13 个重叠 beta 请求受单库 8 槽限额控制，alpha 两组写入加强读必须在原冷请求结束前完成；杀死实际 S3 后热库继续读写、冷库唤醒拒绝；同目录重启 S3 后精确恢复数据及原请求结果；新 revision 遇到后台归档黑洞时保持未裁剪，热库在 1.5 秒 deadline 内继续读写，网络恢复后自动归档/裁剪/唤醒 |
| `08-local-recovery-measurement` | 独立小库集群，固定 alpha/beta 受影响集合；每库每秒一条强读和一条带稳定 ID 小写；30 秒热基线、SIGKILL leader 后 60 秒观察，查找完整 30 秒无错误窗口并核对全部 ACK |

少数派请求的结果未知不会重放 SQL。客户端显式调用 `resolveOrCancel` 建立终态后才继续；`lookup` 返回 unknown 从不被解释成可以安全重试。S3 冷状态由正式 `GET /db/{database}/v1/status` 取得，不用对象 PUT 成功或固定 sleep 推断已完成裁剪。

## 证据与性能口径

每个历史保存结构化事件，并只在所有断言通过后追加末行 `verification passed`。`completed.json` 列出确实运行并完成的合同；任何异常会以非零状态退出。证书和进程诊断日志与可归档证据分开。

`binary.json` 记录实际二进制 SHA-256、构建 profile 和输入说明；release 与 debug、优化前后的结果分别保留，不能把同时变化的因素当成单因素对照。

`cold-wake.samples.jsonl` 单独保留前景冷唤醒隔离合同的全部 **17** 次计划请求：beta 的 13 条强读，包括单库限额拒绝与对象不可用结果；alpha 的两条写入和两条强读。TCP 代理必须先观察到实际被黑洞接收的 S3 连接，再发起热点请求。alpha 每个请求使用 1,500 ms deadline，并按请求完成时刻逐条核对早于原 beta 请求完成；不能用先结束冷请求、随后恢复的热点请求冒充隔离。此合同不替换下面的 360 个性能样本，也不宣称满足 50/100 ms 生产延迟目标。

`latency.samples.jsonl` 保存每次请求的计划、调用、deadline、结果时刻、稳定请求 ID 和结果类别。逻辑延迟从计划发起时刻计算，包含调度与队列等待；所有 UNKNOWN、超时、无 leader、平台错误和准入拒绝都保留。没有对未知写进行自动重放，也不会把事后查证成功改写为原请求成功。

`measurement.json` 分库、阶段和操作报告样本分母、结果计数、成功请求的 min/p50/p95/p99/max，并明确这些成功分位数没有删掉失败分母。它记录首次成功，以及固定两库连续 30 秒、每类至少 30 个探针的窗口起点；1 秒探测周期造成的分辨率也写入报告。先前短功能合同中的单库短窗口只叫首次短窗口观察，不构成正式 RTO。

该部署仍是**同一宿主机、loopback、小数据、4 请求/秒、单次故障事件**。它没有达到 [性能验收规范](../../docs/engineering/performance-slo.md)的三 AZ、500 请求/秒、长期样本和延迟目标要求，因此即使 30 秒功能窗口合格，也不宣布生产 SLO、RTO 分位数或 SLA 通过。进程 SIGKILL 不等于设备断电。

## 与单元覆盖率隔离

脚本拒绝在 `NODE_V8_COVERAGE` 或 `LLVM_PROFILE_FILE` 已设置时执行；真实服务部署的计数不进入单元门禁。Rust 协议层与 Node SDK 的 100% 单元覆盖分别由各自命令重新生成。实验结果不能用于补齐未覆盖的第一方生产分支。

## 2026-11-02 本机执行记录

最终格式化后的正式 release 二进制完成 **8/8** 部署合同，包含 **5/5** 真实 Node SDK 子测试。全部 history 的终止标记、完成清单、360 个唯一请求身份和每库各阶段的样本数量已经独立核对；所有已确认小写逐条重读保留。

该轮的精确二进制 SHA-256：

```text
6012c2366632ecad0de381c6382d4b6000f98bd6f14f9ca1a9f03dab26f43150
```

生产源码输入指纹为 `0681df93b2539a45bcaab2c952fa828a89b002db43378fc6a09b2a665991485e`；68 项生产 Rust/协议/manifest/锁文件/Node SDK 输入在运行结束后仍全部匹配。原始源码快照、验证脚本、二进制标识和样本归档在该轮 evidence 的对应 JSON/tar 文件中。

测量环境是同机 Linux 6.18.57 / x64，9 个可见 CPU、约 9.73 GiB 可见内存、Node.js 24.22.1、Rust 1.90.0 release、loopback TCP_NODELAY 代理。固定两库，每库每秒一读一写，单请求 deadline 为 8 秒，热基线 30 秒，故障后继续观察 60 秒。

**360 次计划请求全部保留：348 次成功、12 次 NO_LEADER；这 12 次均来自故障后的最初三个采样秒。** 热基线 120/120 成功；故障段 228/240 成功，UNKNOWN 和 OVERLOADED 均为零。窗口起点为故障后 **3,008.588 ms**，连续 30 秒核验后在 **33,008.588 ms** 确认；首次成功为 **3,049.644 ms**。这是单次本机恢复观察，探测分辨率为 1 秒。

以下分位数是每组成功样本的 nearest-rank 描述；分母包含完整请求数。每组仅 30 或 57 个成功样本，p99 在这些组中等于最大观测值。

| 阶段 | 数据库 | 操作 | 成功/总数 | p50 ms | p95 ms | p99 ms | 成功范围 ms |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 热基线 | alpha | 强读 | 30/30 | 37.871 | 151.252 | 190.762 | 23.518–190.762 |
| 热基线 | alpha | 小写 | 30/30 | 104.628 | 164.286 | 164.479 | 37.054–164.479 |
| 热基线 | beta | 强读 | 30/30 | 105.684 | 161.575 | 188.405 | 25.579–188.405 |
| 热基线 | beta | 小写 | 30/30 | 94.214 | 189.106 | 201.415 | 48.804–201.415 |
| 故障观察 | alpha | 强读 | 57/60 | 52.303 | 281.500 | 429.871 | 28.539–429.871 |
| 故障观察 | alpha | 小写 | 57/60 | 165.286 | 350.274 | 436.686 | 66.600–436.686 |
| 故障观察 | beta | 强读 | 57/60 | 199.279 | 338.433 | 398.228 | 50.801–398.228 |
| 故障观察 | beta | 小写 | 57/60 | 179.218 | 392.116 | 682.467 | 61.980–682.467 |

这组热延迟没有满足既定的低延迟目标，也没有执行三 AZ、500 请求/秒或足够故障次数的验收。结果中的 `production_slo_passed` 明确为 false；不能从一次合格的 30 秒功能窗口推导生产 RTO p99 或对外 SLA。

S3 生命周期同时得到真实验证：revision 2 发布并裁剪为 Cold 后，S3 进程退出不影响热库读写，冷库恢复按预算拒绝；S3 重启后原随机结果和数据恢复。接着生成 revision 3 并黑洞对象存储 TCP，观察到 `suspended=true`、`cold=false`、归档仍为 revision 2；热库五组写入加强读分别耗时 **56、60、77、85、64 ms**，每条请求使用 1,500 ms deadline。解除黑洞后后台归档达到 revision 3，随后正确唤醒，原请求结果仍保留。

早期失败与不同构建的结果分别保留：两轮 debug 测量没有找到合格恢复窗口；早期 release 测量的末尾 HTTP 校验失败，也没有标记整轮通过。后续修复包括测试代理的 NODELAY、热路径重复屏障、HTTP 连接寿命与复用的竞争，以及归档 I/O 隔离。不同 profile 和不同源码同时变化的结果，不用作单因素性能归因。最后两轮格式化前的完整成功证据也保留其原二进制和源码身份；本节仅报告最终格式化后精确二进制。
