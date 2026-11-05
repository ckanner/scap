# 有界物理历史与旧 V2 盘升级的真实部署合同

此实验同时使用固定旧版和当前版 `scap-server`，实际三节点 RocksDB/mTLS、正式 Node SDK 与固定 SeaweedFS S3 后端。夹具只负责进程、透明 TCP 故障和断言；不生成假的旧状态镜像，不实现物理恢复，也不把 SQL 重放到其他副本。

旧 producer 固定为提交 `662f04133f6a869d0dae5b05467656e6deca5c12`。本机冻结旧 release 的 SHA-256 为 `9a9df3656d99e5275ca4cee74ceb7e8c85ba37156d5e24e605011728c7064dbb`；其全部 75 个生产输入与该提交逐项相同。CI 应从这个精确提交构建旧 binary，保存构建来源、锁文件和实际 SHA；不同构建路径不要求得到相同的二进制字节。不能用当前代码加旧版本标志代替真实旧 producer。

## 运行入口

先构建、冻结旧二进制，再构建新二进制，禁止后一条构建覆盖前一份实际执行文件。旧、新构建均使用 Rust 1.90.0、各自锁文件和 `--locked`。可以复用依赖构建缓存；跨版本运行的 binary 必须是两个独立、已核验的文件。正式 SDK 按当前仓库锁文件构建。

```bash
cargo +1.90.0 build --release -p scap-server --locked
npm --prefix sdk/node ci --ignore-scripts
npm --prefix sdk/node run build

SCAP_OLD_SERVER_BIN=/absolute/frozen-v2/scap-server \
SCAP_OLD_SERVER_SOURCE_COMMIT=662f04133f6a869d0dae5b05467656e6deca5c12 \
SCAP_OLD_SERVER_SHA256=the_actual_sha256_from_the_pinned_old_build \
SCAP_SERVER_BIN="$PWD/target/release/scap-server" \
SCAP_SEAWEEDFS_BIN=/absolute/path/to/weed \
SCAP_HISTORY_EVIDENCE_DIR=/tmp/scap-history-evidence-new \
node experiments/history-network/run.mjs

python3 experiments/history-network/check_evidence.py /tmp/scap-history-evidence-new
```

`SCAP_OLD_SERVER_SHA256` 缺省时仅接受上述本机冻结旧 release，CI 自行构建时必须显式传入该构建的实际 SHA。旧源码提交固定，不能随环境变量改成任意版本。`SCAP_SERVICE_BUILD_DESCRIPTION` 可写入新 binary 的构建说明；源码清单和前后身份核对仍应由运行包装器提供。

需要 Node.js 24、OpenSSL、curl 和 loopback TCP。S3 后端固定 SeaweedFS **4.51 / `153ab668c99731a6d29492bf6c61d0b4fa701101`**，启动时核验版本，证据记录 executable SHA。默认 `mini`；环境不能创建 Unix socket 时可设 `SCAP_SEAWEEDFS_MODE=separate`，经正式 master/volume/filer/s3 子命令和显式 TCP 地址运行。没有真实后端时失败，不静默跳过。

## 九项合同

| 历史 | 实际断言 |
| --- | --- |
| `01-old-v2-hot-and-cold` | 旧 binary 创建 alpha 热库、beta 冷库、随机 RETURNING 和取消 fence；fresh metadata 证明 beta 已 publication/prune，签名 S3 GET 核对真实 `SCAPARC!` V2 对象及内容地址摘要 |
| `02-mixed-versions-cannot-form-quorum` | 停一个旧 follower，同目录启新 binary；直接向新节点发送一次强读和一次写，必须拒绝。旧两个节点仍产生一个真实 ACK；新节点本机 applied 不得跟进。再停一个旧节点，只剩一旧一新时，直接旧节点的强读也必须拒绝。原写 ID 在旧 quorum 有序 ResolveOrCancel，保存真实取消终态。停下新节点并保留其落后目录，再恢复旧 quorum |
| `03-stop-upgrade-preserves-history` | 所有版本进程完整停止后，新 binary 只用 OpenExisting 打开同一组目录。落后目录实际追上旧 quorum 已确认的前缀，正式服务完成有序格式激活后，原结果、SQL revision、取消 fence 与精确恢复尾部保持；旧 beta 保留冷 archive 引用 |
| `04-overwrite-exceeds-original-history-budget` | 8 行 × 24 KiB BLOB、64 次真实覆盖；只返回小结果，在原 128 请求和 256 KiB 库限制内，多次推进 base；观测到的未折叠 tail 正增量之和本身超过旧 8 MiB cell 预算 |
| `05-old-s3-archive-hydrates-with-new-fence` | 旧 archive 产生之后再取消一个请求；错误租户不能唤醒；真实 S3 TCP 黑洞使 cold wake 失败，alpha 可读；恢复网络后精确 hydrate V2 对象，新 cancel 和原结果不回退 |
| `06-new-v4-archive-roundtrip` | beta 新提交形成新 base，再经真实 S3 发布、裁剪和 hydrate V4 archive；旧 V2 对象未被覆盖或删除；旧结果和新 fence 保留 |
| `07-sigkill-recovers-from-base-and-tail` | 全组三进程 SIGKILL；新 binary 同盘重开，正式 owner 恢复使用新的 worker instance 和私有目录，核对全部原结果、完整当前 BLOB 字节和 SQLite 文件大小 |
| `08-old-binary-rejects-v4-storage` | 全部新进程停止后，每个节点只尝试旧 binary OpenExisting；必须因 `STORE_APPLICATION` 非零退出，锁冲突或端口冲突不算通过；不使用 initialize、不清空磁盘 |
| `09-new-binary-reopens-after-rejected-downgrade` | 旧版被拒后，新版仍可同盘重开并读回全部 ACK、当前 SQL 值和取消 fence；前后 old/new binary 与 harness SHA 一致 |

混合版本阶段专门检验拒绝边界，不是滚动升级可用性承诺。旧、新 peer Envelope 版本分别为 1、3，TCP 代理在此阶段全部连通，没有用人为分区替代版本拒绝。直接 SQL 探针跳过 SDK `/readyz` 提示，仍使用真实 libSQL HTTP 协议、租户身份和固定 2,500 ms 服务 deadline；额外 1,500 ms 只用于读取实际错误响应，不改变服务 deadline。每个探针只发送一次 SQL POST。新写无论返回确定的路由拒绝或 UNKNOWN，都由旧 quorum 对原 ID 执行一次有序 ResolveOrCancel；如果实际已提交，立即保留该结果并让合同失败，不能改写为取消。

拒绝必须有实际服务响应，HTTP 断线和无监听端口不算通过。新节点的两个探针只接受 `NOT_LEADER`、`COMMIT_UNKNOWN` 或 `EXPIRED`。旧节点已有 writer 在查询期间失去 ReadIndex quorum 时，原服务器可能映射为 `QUERY_FAILED`，因此仅“一旧一新时直接向旧节点强读”的断言额外允许此码；恢复旧 quorum 后，同一 SQL 必须成功并返回原 ACK 的值，不能把任意 SQL 错误当作隔离证据。

旧 quorum 的恢复准备使用固定 30 秒总 deadline，在旧节点上获取两次同 leader、同 term、applied 不回退的 fresh membership 读取，中间还须观察到 readiness 200。每次 GET 的失败及返回码都保留；等待只用于部署准备，不循环提交 SQL，也不把 readiness 单独当作 quorum 证明。准备完成后，对照 SQL 仅发起一次逻辑调用。这段等待不是可用性或恢复时延 SLO 测量。

已有 loopback 管理监听器使用独立管理 token，实验只发 GET。启用该监听器选择动态 peer policy，但实际配置从始至终保持原三名 voter，无 learner、joint 或成员变更。本机 `/v1/admin/status` 的 `authoritative:false` 被保留，只用于观察复制进度；旧 quorum 的 ACK、fresh membership read 和租户强读提供各自的提交／读取依据。停止新节点时的本机 applied 与原进度相同，全升级后它必须超过该值并至少到达旧 quorum 见证的 applied，不能用重建目录冒充追赶。

旧状态的解码不等于新语义激活。正式服务通过持久的内部 Raft activation entry 切换格式；旧日志后缀在激活前必须保持 V2 的容量拒绝和归档字节规则。SQL lane 同样检查激活状态，因此绕过 readiness 不能提前使用新语义。该门禁由生产实现和对应单元／真实合同共同验证；实验不自己转换状态或伪造 activation entry。短旧历史允许保留未满阈值的 tail，不要求一开旧盘就出现非零 base；后续 64 次真实覆盖必须独立证明多次折叠。

64 轮覆盖不会保留每次被业务覆盖的旧 BLOB 为当前值；验收分别核对每个 ACK 的原始结果，以及最终完整 SQL 状态。最后存活的 8 个 BLOB 分别通过小于单值上限的强读取得，逐个核对完整 SHA，不仅比较短前缀。

物理字节的累计值是**保守下界**：仅在 `base_revision` 不变时累计两次 fresh metadata 之间 `tail_bytes` 的增量。触发折叠的那笔提交因 tail 清空而不计入累计值；不会从 SQL 字符串长度或随机数大小估算为已观察到的物理历史。每次写后的 base、tail 和 revision 均写入 `overwrites.jsonl`。条目阈值保持 8，生产 profile 的字节阈值保持 1,228,800；观察到的 tail 应严格小于触发阈值。

独立检查器把每一行 overwrite 绑定到同 ID 的唯一成功 SQL 调用，以及紧接着的真实 metadata 调用，四个计数必须完全相同。两个迟到取消请求还必须取得实际服务 `COMMIT_UNKNOWN` 响应，再由相邻 Lookup 确认原 ID 仍为 Cancelled；传输失败或缺少 leader 不能代替 fence 拒绝。允许的确定 `NOT_LEADER` 路由续传始终沿用原 deadline。

租户 HTTP API 不提供动态 AuthFence 管理。真实权限撤销与旧 archive 之间的排序另由 [sqlite-network](../sqlite-network/README.md) 的 `folded_archive_hydration_preserves_later_auth_and_cancel_through_network_restart` 验证：正式 Client、三独立进程、RocksDB/mTLS 和真实 native SQL，cold 期间提交 AuthFence 与新取消，随后 hydrate 只导入原 physical bytes。那条合同明确不启动 S3；本实验独立证明真实 S3 旧、新对象路径，二者形成组合证据。

## 证据及边界

每项历史仅在所有断言完成后写入 `verification passed`，完成清单必须恰好包含九项。完整成功运行应有 **80 个 ACK**（alpha 69、beta 11）、**5 个取消 fence**、**85 个保留请求身份**；7 个故意失败的逻辑调用全部保留在原分母。`requests.jsonl` 保存全部逻辑调用及失败，`http-attempts.jsonl` 保存实际 HTTP 发送、节点、原 deadline 与返回码，`acknowledgements.jsonl` 保存每个成功写的稳定身份和原结果。SQL UNKNOWN、传输错误、超时不盲重放；只有 SDK 原有的确定 before-proposal `NOT_LEADER` 路由拒绝允许在原 deadline 内选另一个节点。混代直接 SQL 探针没有该选址循环。显式尝试已取消的 ID 仅用于证明 fence，失败后再 Lookup 确认，没有把 UNKNOWN 改写成原调用成功。

认证 token、证书、私钥、业务 DB、完整对象内容和 daemon 私有日志只在单独临时目录，禁止打包或提交。公共证据只有合成结果、计数、状态和摘要。没有增加生产容量常数、没有丢弃逻辑原结果或取消记录、没有 S3 GC。RocksDB 打开自身可能更新日志或内部元数据，因此旧 binary 被拒不声称整个目录字节不变；新版再次重开和全部结果核对证明其没有重建空库或破坏可恢复状态。

这是单宿主机、loopback、小库的一次升级与故障合同。SIGKILL 不等于断电；不证明三 AZ RPO、长期负载、GiB 库、生产 p99 或 SLO。`production_slo_passed` 必须为 false。脚本拒绝 `LLVM_PROFILE_FILE` / `NODE_V8_COVERAGE`，所有真实合同与单元覆盖率分离。
