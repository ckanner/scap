# 请求结果显式确认与安全退休：真实网络合同

本目录验证有界请求结果保留窗口的回收与旧身份 fencing。测试启动三个真正的 `scap-server` 进程、各自独立的持久目录、实际 mTLS Raft 连接、正式 Node SDK、固定版本的 SQLite 与 SeaweedFS S3 后端。部署和 TCP 故障工具复用 `../history-network/deployment.mjs`；请求确认、世代轮转、归档合并、snapshot 安装和恢复全部执行生产实现。

这是一组正确性与故障合同，不是性能测试，也不声称达到生产 SLO。它不把 `UNKNOWN`、超时或响应丢失删除后再计算成功率。`RequestAcknowledged` 指调用者在处理终态之后显式提交的应用确认；普通 SQL 成功响应本身不会确认或释放结果。

2026-11-04 最终同源本地运行九项全部通过；精确尝试分母、失败记录、二进制/源码身份及其他回归见 [G0 执行证据](../../docs/engineering/g0-evidence.md)和[机器可读摘要](../../docs/evidence/retention-local-2026-11-04.json)。

## 固定输入与边界

- 旧生产者必须从 V3 `main` 提交 `b9f512819358494f178b01d7f1d960dff8222c1c` 独立构建，启动时只有第一次空目录使用 `--initialize`。旧进程真实产生 SQLite 数据、已提交随机结果、取消位置、Raft 持久状态和 V3 S3 对象，不通过编辑序列化字节制造旧版本状态。
- 默认旧二进制 receipt 是 SHA-256 `87080fbf3ef7a5ea1615f8f70559ceb94114b9d1e0d42a85ccaecb31ed503bc2`。在另一台机器按同一固定旧提交构建时，必须用该次独立构建的 receipt 设置 `SCAP_RETENTION_OLD_SERVER_SHA256`；只接受 64 个小写十六进制字符。源码与二进制之间的对应关系还需保留该次构建记录，单独的可执行文件哈希不代替源码来源证明。
- 新、旧二进制必须是不同文件内容，输入哈希在运行开始与结束时比较。旧 wire envelope 为 2，当前新 envelope 为 4；V3 旧应用经有序激活进入 V5，物理归档继续使用 V4。运行前须已完成新生产源码的独立单元覆盖率门禁。
- 原 profile 不增加：32 个数据库，每库 256 KiB，每库 128 条保留请求，8 MiB 状态上限。alpha 连续填满三个 128 条窗口再回收，证据分别记录每个窗口的实际 retained/unacknowledged 计数。
- 只有原三个 voter；不提交成员变更，不借重建目录替代落后副本恢复，也不修改生产计数上限来使实验通过。
- SeaweedFS 必须是 `4.51`、提交 `153ab668c99731a6d29492bf6c61d0b4fa701101` 的真实可执行文件。所有凭据、私钥、配置、数据库、Raft 文件与原始 daemon 日志留在权限为 `0700` 的临时 fixture 目录，公开证据只包含本实验产生的随机合成数据、计数、哈希和脱敏事件。

## 九个合同

| 合同 | 实际操作与通过条件 |
| --- | --- |
| 1. V3 热数据与冷归档生产者 | 三个旧 daemon 建立 alpha/beta 表，返回 `randomblob` 生成的实际 SQL 结果，分别创建 ordered cancellation；beta 按实际 idle/archive 路径进入 cold。签名 GET 核对 S3 对象内容地址与 V3 格式。 |
| 2. 协议世代隔离 | 保留原目录，将一个已追平的 follower 换成新进程，另两个保持旧版，TCP 代理全部畅通。新副本 `readyz` 必须是 503，绕过 readiness 直接提交的一次读与一次写收到明确服务拒绝。旧两副本 quorum 仍返回成功写，并用原身份有序取消新副本收到的写。新副本不能应用旧 quorum 的更新 prefix。 |
| 3. 停机升级与 128/129 边界 | 所有新旧进程完全停止后，用三个新进程打开原盘。V3 成功结果和取消位置仍可查询。alpha 填到 128 条，第 128 条写在服务完整成功返回后故意丢掉响应，SDK 必须报告 `COMMIT_UNKNOWN` 且只发送一次 SQL POST；随后原身份 lookup 观察其实际 committed 结果。第 129 条写拒绝且不重发，计数仍为 128，完整 SQL 状态不含失败行。 |
| 4. 显式应用确认与退休 | 错 sequence proof、其他 principal、同 principal 的只读 token 都不能确认原结果，普通 writer 不能轮转。先确认 127 条，故意留下响应丢失的 committed 请求未确认，轮转仍被拒绝；显式处理并确认最后一条后才能从 epoch 1 轮转到 2。逐条验证原 128 身份返回 `retired`，旧 execute/cancel/ack 均拒绝，SQL digest 与 revision 不变。 |
| 5. 多轮窗口与离线副本 | 在两轮写之前 SIGKILL 一个已追平的 follower。其余两个副本分别完成 epoch 2、3 的 128 次写、终态查询、显式 ACK 与轮转，达到 epoch 4。一条新请求复用 epoch 1 的 request ID，旧世代仍然退休。三个完整窗口合计退休 384 条身份。 |
| 6. Snapshot 恢复退休屏障 | 恢复前要求两个可用 source 的实际 `snapshot_index` 都超过落后副本停止时的 `applied`。同盘启动落后副本，验证其安装先进 snapshot、追平已见证的 quorum prefix，强读验证完整 alpha SQL 及各旧世代的退休屏障。beta 仅查 metadata，仍保持原 V3 冷归档，留待下一合同。 |
| 7. 冷 ACK 与跨版本归档水合 | beta 仍引用原 V3 冷对象时，显式确认旧成功/取消结果。确认操作不得唤醒 SQLite，cold 轮转拒绝。真实 S3 TCP 黑洞使一次冷读唤醒失败，同时 alpha 热读成功；恢复连接后新服务水合旧对象，最新 ACK 必须保留。轮转 beta 到 2 清除旧 live archive 引用，随后新写、自动归档并水合真实 V4 对象；旧不可变对象仍保留。 |
| 8. 轮转 UNKNOWN 与 crash 恢复 | alpha epoch 4 的结果处理并确认后，故意丢弃一次完整成功轮转响应。SDK 得到 `COMMIT_UNKNOWN`，只有一次 POST，由新的 metadata 读取确认 epoch 5，不能自动重复原轮转。再产生一个当前未确认结果，分别执行 leader SIGKILL、三个进程全部 SIGKILL 和原盘恢复，核对全部 SQL、旧世代退休屏障及当前未确认结果。恢复使用新的 writer 实例目录。 |
| 9. 降级拒绝与再次恢复 | 先确认三个盘都应用最新 prefix，停止全部新进程，再让固定 V3 binary 分别 `OpenExisting` 三个当前 V5 目录。必须因 `STORE_APPLICATION` 退出，配置/锁/端口失败不算。然后新 binary 再次原盘启动，核对相同 SQL 与结果身份。 |

第 8 合同另退休 alpha 的 1 条结果，第 7 合同退休 beta 的 3 条结果。因此一次完整通过的运行有 **388 条显式应用确认并退休的身份**、**2 条当前仍未确认的结果**；其中三个 128 条满窗口是边界压力部分。一个丢失成功响应的 committed 结果单独计数，不能冒充成功 SQL 响应。

### 凭据与旧格式配置

旧集群保持 alpha 原 principal 200 / READ|WRITE 权限 3，beta 原 principal 300 / 权限 3。另在旧初始化时加入 alpha 同 principal 200 的普通 READ token，以及另一个普通 writer principal，用于确认权限的负向合同。

停止所有旧进程后，升级配置才增加 `retention_admin: true` 的独立凭据：它必须绑定原有 bootstrap administrator 100，权限恰为 READ|ADMIN，即 5，且 credential ID 不等于内部 service credential。旧数据库的既有 policy 已包含 administrator；激活过程不提升普通用户的权限。普通 token 不接受 ADMIN。

降级探针使用保存的 **旧兼容配置副本**。若拿含新 token 字段的配置直接运行旧程序，`CONFIG_TOKEN` 只能证明配置不兼容，不能证明当前存储安全拒绝降级。

### 请求身份与 UNKNOWN

所有 SQL、lookup、cancel、ACK、rotate 与 metadata 调用保留实际逻辑记录和 HTTP 记录。新请求明确使用对应的 `requestEpoch: bigint`。原请求的 request ID、epoch、statements 与同一调用的 deadline 不自动刷新；lookup 的 `unknown` 不等于确定未提交。SDK 只允许对明确的 before-proposal `NOT_LEADER` 做有界重新路由。

两种响应丢失都发生在服务已返回完整成功响应之后，之后向正式 SDK 抛出传输失败。实验没有给 SDK 伪造成功，也不让 SDK看见被丢弃的结果。实际成功 body 只用于确认故障注入点；原始逻辑尝试仍记为 `COMMIT_UNKNOWN`。写结果只能经原身份 lookup 观察，轮转只能经新的 metadata 操作观察，二者都不得重新提交原 mutation。

SQL 状态比较包括全部 `id,value` 行，按主键分页读取后计算摘要；它不仅比较行数。退休前后的 revision 与完整 SQL 摘要必须相同。公共服务 metadata 不暴露 commit hash，因此精确物理 head/commit hash 的保持由对应 core 单元合同覆盖，不把 SQL 摘要声称为公开 commit hash。

## 本地运行

先独立构建并冻结旧 binary，构建当前 binary 和 SDK。以下命令假定已准备可运行的本地路径，工具链/依赖获取方式沿用仓库构建说明；命令中的路径需替换为当前机器的真实绝对路径。

```sh
npm --prefix sdk/node ci
npm --prefix sdk/node run build

SCAP_SERVER_BIN=/absolute/current/scap-server \
SCAP_RETENTION_OLD_SERVER_BIN=/absolute/frozen-v3/scap-server \
SCAP_RETENTION_OLD_SOURCE_COMMIT=b9f512819358494f178b01d7f1d960dff8222c1c \
SCAP_RETENTION_OLD_SERVER_SHA256=the_64_lowercase_hex_digest_from_the_old_build_receipt \
SCAP_SEAWEEDFS_BIN=/absolute/seaweedfs-4.51/weed \
SCAP_SEAWEEDFS_MODE=separate \
SCAP_RETENTION_EVIDENCE_DIR=/absolute/fresh-retention-evidence \
SCAP_SERVICE_BUILD_DESCRIPTION=local-retention-candidate \
node experiments/retention-network/run.mjs > /absolute/retention-run.log 2>&1

python3 experiments/retention-network/check_evidence.py \
  /absolute/fresh-retention-evidence
```

`SCAP_RETENTION_OLD_SERVER_SHA256` 可在使用上述默认冻结 receipt 时省略；另一构建环境应使用其明确记录的旧 binary SHA。`SCAP_SEAWEEDFS_MODE=separate` 启动独立 master/volume/filer/S3 TCP 服务，适用于禁止 Unix socket 的执行器；默认 `mini` 仍使用同一真实后端。运行必须清除 `LLVM_PROFILE_FILE` 与 `NODE_V8_COVERAGE`，不得把故障测试混入独立单元 profile。

每次尝试使用新的证据目录。stdout 日志应放在证据目录外，以免在 manifest 计算后继续追加。失败运行保留已产生的所有记录及 `failure.json`，重新运行不覆盖它；进程结束时会关闭本次启动的 daemon 与代理。checker 只读，不重启服务或补做失败步骤。

## 证据文件

| 文件 | 内容 |
| --- | --- |
| `01-*.history.jsonl` 至 `09-*.history.jsonl` | 各合同的时间、故障点、真实计数与断言结果。仅完整通过后追加 `verification passed`。 |
| `requests.jsonl` | 每次逻辑调用的原始身份、epoch、语句摘要、开始/结束时间、成功/错误状态和公开错误码；metadata 与终态 proof 按原样保留。 |
| `http-attempts.jsonl` | 每次实际 HTTP 尝试的 replica、route、身份、epoch、deadline、状态码、错误码和响应丢失标记；不包含 token 或请求 SQL body。 |
| `write-results.jsonl` | 成功 SQL 返回的完整合成结果，另标记通过 lookup 才观察到的丢失响应结果；不会把两者混算。 |
| `application-acks.jsonl` | 应用明确确认的 request identity、原世代、终态 sequence/position 与结果摘要；与真实 ACK 成功调用对应。 |
| `windows.jsonl` | 每次实际轮转的前后 epoch、retained/unacknowledged 计数、revision、完整 SQL 摘要及归档引用清除结果。 |
| `binary.json`、`s3-backend.json` | 新旧生产 binary、旧 source commit、所选构建 receipt、harness 与真实对象后端的固定身份。 |
| `summary.json` | 所有尝试的准确分母、全部失败记录、最终世代、保留结果与故障结论；`production_slo_passed` 固定为 false。 |
| `artifacts.json` | 除本文件外完整公开证据的大小与 SHA-256。只在九合同全部通过后创建。 |
| `failure.json` | 失败位置、已完成合同与已有尝试分母；失败样本不能用成功 summary 覆盖。 |

`check_evidence.py` 独立核对 manifest、九合同完整性、尝试分母、128/129 容量边界、每个 ACK 的终态 proof、三轮满窗口、两次响应丢失各只有一次 POST、旧世代 fencing、snapshot prefix、真实 S3 格式与对象保留、全部 SIGKILL、三盘存储版本拒绝和输入哈希。它不会把本地 progress 状态当作 quorum commit 证明，也不会从 `UNKNOWN` 推导可安全重试。
