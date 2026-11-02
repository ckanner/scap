# SQLite 服务、自动接管与冷生命周期

日期：2026-11-02（UTC）。本文记录当前正式源码中的有界服务实现，配套决策见 [ADR-0014](../adr/0014-sqlite-service-and-cold-lifecycle.md)。部署入口已经连接真实 SQLite、三副本 Raft、HTTP/Hrana、Node SDK 和 S3 兼容归档；容量、协议与恢复档位仍受本文列出的边界约束。性能验收采用[性能与恢复规范](performance-slo.md)，具体执行证据以[真实服务实验](../../experiments/service-network/README.md)和 [G0 执行记录](g0-evidence.md)为准。

## 1. 部署单元与技术栈

当前一个部署单元是一个固定三 voter 的 cell。三个 `scap-server` 进程分别拥有私有 RocksDB 目录、节点证书、peer 监听地址和 HTTP 地址。它们共享相同 cluster/cell 身份、数据库目录和配置策略；每个进程的 node ID、私钥与数据目录不同。多个小数据库共享这个 Raft 组，不为每个数据库再建立三节点集群。

| 模块 | 正式职责 | 已锁定的基础 |
| --- | --- | --- |
| `scap-server` | 配置、启动、监听、鉴权映射、SQL 调度、闲置休眠、后台归档与资源监督 | Rust 1.90.0、Tokio 1.50.0、Axum 0.8.9 |
| `scap-service` / `sdk/node` | 有界 Hrana HTTP v2 子集、稳定请求身份、显式结果查证、候选节点选择 | TypeScript、Node.js 24、`@libsql/client` 0.18.0 |
| `scap-sqlite` / `scap-engine` / `scap-sql` | SQLite 执行、提交前 gate、物理镜像校验、结果编码、强读 | libSQL 固定提交 `d8bc862d20bedc72945a1da27c8b7045414c0261` 的 SQLite C 内核 |
| `scap-sql-worker` / `scap-cell-client` | 独占 writer、Claim/Activate、当前权限、ReadIndex、逐请求 tracked 裁决 | 正式窄端口与 native adapter |
| `scap-cell` | owner/auth fencing、事务去重、结果与取消记录、冷生命周期 | 确定性状态机；apply 不执行 SQL 或 S3 I/O |
| `scap-raft-driver` / `scap-raft-runtime` | 串行 Ready、持久提交、自动 tick、等待票据、快照与有界队列 | TiKV `raft-rs` 固定提交 `ad13f3d90780f53aea2488c6a4b76c0d334bf136` |
| `scap-raft-store` / `scap-raft-rocks` | 校验的完整持久镜像、日志与应用位置、同步 WriteBatch | RocksDB Rust binding 0.24.0；完整解析依赖见 Cargo.lock |
| `scap-raft-wire` / `scap-raft-transport` | 身份绑定、证书 pin、有限消息、mTLS peer RPC | Tonic 0.14.6、Prost 0.14.3、rustls/ring |
| `scap-archive` | 不可变归档、签名 PUT/HEAD/GET、完整校验和有序发布/卸载/恢复 | object_store 0.14.2、reqwest 0.13.2、显式 S3 配置 |

具体依赖来自各 crate 的 Cargo.toml 和根 [Cargo.lock](../../Cargo.lock)。这里复用 TiKV 的共识内核，没有引入 TiKV 的完整存储服务器；SQLite 执行也没有切换为 Turso 的 Rust 重写引擎。

每个 daemon 的 SQL 线程独占全部本地 SQLite connection，另有独立 Raft owner 线程。Tokio 承担 HTTP 与 peer 网络；启用 S3 时再增加一个受监督的归档线程。SQLite connection 不跨线程迁移。数据复制传输的是一次执行后确定的物理变更和原结果，不在多个副本重新执行 SQL。

## 2. 请求、ACK 与强读

请求经过 `scap-service → Mailbox → SQL Worker → SQLite gate → Cell client → Raft runtime`。HTTP 凭据通过静态配置映射到固定数据库身份和 principal；外部用户不能提供 owner epoch、cell ID、归档 key 或文件路径。静态令牌表只做入口检查，最终权限与 auth epoch 仍由复制状态机确认。

写入成功需要完成同一条裁决链：

1. 生成或接受稳定 request ID，固定原始 SQL/参数及绝对 deadline。
2. 使用新的 ReadIndex 查询原请求；已经提交时返回原始结果，取消 fence 则拒绝新执行。Lookup 未找到只表示当次视图没有记录。
3. 当前 owner 执行一次有界 SQLite 事务，缓冲完整结果并产生物理变更。
4. 提交前 gate 将变更、request fingerprint、owner/auth 身份及前序 revision 交给 cell。
5. Raft 达到持久多数派，cell 有序接受，并且对应应用状态持久化；tracked proposal 返回该条命令的精确裁决。
6. native SQLite 按接受结果发布页面；完整结果在原 deadline 内交付，才形成客户端成功。

网络层 `Received`、本机 `Admitted`、一次 S3 PUT 或 `/readyz` 都不具备这个 ACK 含义。持久接受后本地发布失败或响应丢失时，业务可能已经提交；系统保留原 receipt/result，返回保守错误并退休 writer。服务不会把该情况解释为回滚，也不会自动重跑未知 SQL。

`query` 和 `batch(..., "read")` 使用独立强读路径：Safe ReadIndex 绑定当前数据库、权限、owner 和精确 head；本地引擎镜像核验通过后，在只读 SQLite 事务中执行。读不追加 accepted-write 历史，不增加数据库 revision。当前核验会重放保留的物理历史，其开销随历史增长，不能用“ReadIndex 已实现”推断低延迟目标已达成。

普通第三方 `@libsql/client.execute("SELECT ...")` 仍进入兼容写事务入口，可能登记一次结果。需要独立强读时使用 SCAP SDK 的 `query`，或显式选择受支持的 read 模式。[HTTP 协议说明](../../crates/scap-service/README.md)列出了精确子集。

## 3. 选举、owner 恢复与分区

正常超时选举启用 PreVote 和 check_quorum，读模式为 `ReadOnlyOption::Safe`，没有启用租约读。当前 tick 间隔为 100 ms，`election_tick=15`、`heartbeat_tick=2`。这些是协议调度参数；随机选举、持久化、队列和数据库恢复还会增加时间，因此它们不是故障恢复 SLA。

只有当前 Raft leader 负责恢复 SQL owner。leader/term 改变或领导状态无法取得时，worker 关闭本地 writers。接管依次完成：

`ClaimOwner → 新 ReadIndex → 校验完整物理历史 → 在全新目录构造 SQLite → ActivateOwner → 最终权限与 head 校验`。

Claim 绑定预期 owner epoch 并递增世代；Activate 必须提交精确恢复 revision/hash。任何步骤失败都不会交付可服务 writer。当前 leader 的周期维护会逐库恢复未休眠但缺少本地 writer 的数据库；已休眠的库保持休眠，直到一个获准业务请求需要它。

少数派不能获得新的强读屏障或持久提交。SDK 对 ready 的观察仅用于选择候选节点，直接访问旧 leader 也必须通过正式权限和共识检查。没有 quorum 时保留 CP 拒绝行为，不能切到旧 SQLite 文件、旧 S3 对象或本地成功模式。

并发归档新增了一个有界恢复竞态：请求刚读到非冷状态，后台可能在 Claim 前完成 Prune。只有 `Writer::recover` 明确返回 `Rejected(Cold)`，且 SQL 尚未执行时，服务才允许一次 fresh view → hydrate → 新 owner 恢复；递归刷新预算随即关闭，原 deadline 不变。Unknown 和其他恢复错误不进入这个重试。

## 4. S3 归档与休眠闭环

### 4.1 权威转换

| 阶段 | 必须满足的条件 | 完成后的权威状态 |
| --- | --- | --- |
| `SuspendDb` | 当前 owner token 与 expected revision 匹配 | 撤销 active；已有 owner 的 epoch 递增；suspended=true |
| 上传并校验 | 完整单库历史、固定作用域和内容摘要；条件创建后有界 HEAD/GET；长度与 SHA-256 精确相同 | 此时仍不能使用新对象恢复 |
| `PublishArchive` | 原 owner、当前 head、前序归档、源位置、完整对象/元数据摘要都匹配；库仍休眠 | cell 持久保存精确归档引用 |
| `PruneArchive` | 原 owner 未改变，已发布归档覆盖当前完整 head，库仍休眠且 inactive | 仅清除物理事务字节，cold=true |
| `HydrateArchive` | 新权威视图指定的对象；长度、摘要、每笔 receipt/result/fingerprint/hash/物理摘要全部匹配 | 装回物理字节，仍未授予执行权限 |
| Claim/Activate | 使用当前 owner 世代和已恢复精确 head | 新 writer 才可执行 SQL |

对象 key 绑定 cluster、cell/incarnation、database/incarnation、placement generation 和内容 SHA-256。归档包含完整物理历史、原始结果及源应用位置；ETag 不替代内容摘要。上传完成但 Publish 未被 cell 接受的对象是未发布对象，系统不会从 bucket 列表、文件名、最后修改时间或旧目录标签选择它。

Prune 保留全部已接受请求的身份、receipt、原结果、取消记录、权限、owner/auth fence 和归档引用。Hydrate 只恢复缺失物理字节，不能覆盖这些仍在 cell 中的元数据。Cold 状态下不能 Claim/Activate 或接受新的写入；结果查证与受 READ 授权的 status 不需要访问 S3。

### 4.2 后台任务与磁盘回收

后台归档有一个线程，任务与完成通知各最多 8 槽，每个 database ID 同时最多一个 pending。登记表最多容纳配置中的数据库数。任务只保存固定大小的元数据、原 RequestContext 与 operation IDs；对象正文由当前唯一归档任务有界构造，不放进任务队列。

失败后至少等到该次原 deadline 加 5 秒才接受该库新的归档任务。下一轮任务从新权威视图出发，不延长旧任务 deadline，也不把 UNKNOWN 当作未执行。排队时的 owner/head/auth epoch 通过 `publish_bound`、`prune_bound` 和最终状态机检查保留；I/O 期间即使同一个 head 经历唤醒再休眠，旧 owner 的任务也不能发布或裁剪。

SQL 维护线程只 enqueue/poll，不等待后台 S3 I/O。前景 cold hydrate 仍同步占用当前 SQL actor，并共享请求原 deadline；因此一个冷库唤醒仍可能推迟同进程其他库，后续需要按库分片执行器和恢复调度。

单库 Prune 不授权截断共享 Raft 日志。成功 prune 通知请求一次正式全 cell checkpoint；所有 voter 还在 applied 距 snapshot 达到 128 条时，以及每 30 次维护轮的强制检查中尝试 checkpoint。只有 applied 已前进才创建新快照。复制状态、membership 和 applied position 被完整持久化后，才能按 Store 的既有协议回收日志。旧快照或物理引擎文件释放时机与逻辑 Prune 不是同一个事件。

当前全部 S3 对象永久保留，没有安全 GC、删除 tombstone 或历史保留期协议。精确已发布引用构成恢复根，桶生命周期策略不能擅自删除它。该闭环降低冷状态的物理历史驻留，但仍保留请求结果与审计元数据，也会留下未发布对象，不能据此宣称冷库零成本或无限数据库密度。

## 5. 重启、故障与关闭

| 事件 | 当前行为与限制 |
| --- | --- |
| 单个 daemon / leader 退出 | 幸存多数派重新选举；新 leader 依据复制状态取得 owner、重建引擎；原已确认数据和请求结果仍属于共识历史 |
| 全部进程重启但持久目录完好 | 显式 OpenExisting 校验原身份和镜像后恢复；hot 库重建新 writer，suspended/cold 库维持其复制状态 |
| 本地 SQLite cache 缺失 | 从已确认物理历史重建新目录；旧 cache 不充当权威恢复来源 |
| cache 命名、目录或清理异常 | 停止相应服务准入并要求检查，不沿未知 symlink 删除外部路径，也不继续无界创建缓存 |
| RocksDB、WAL、快照损坏或身份不符 | 拒绝打开；不自动创建空 cell，不扫描 S3 伪装成零丢失恢复 |
| S3 不可用 | 热写仍通过原 durable quorum；后台任务有界失败/退避；未验证发布的数据不会裁剪；已冷库需要的唤醒失败 |
| 丢失多数派或不能持久化 | 不确认新写，不提供无屏障的强读；不隐式改为异步复制 |
| 原响应丢失 / deadline 到期 | 保留 UNKNOWN；可显式 Lookup，必要时 ResolveOrCancel；不会自动重执行原业务 SQL |
| HTTP、peer、Raft、SQL 或归档线程异常退出 | supervisor 结束节点服务，取消/关闭在途资源并回收线程；不留下独立继续写入的后台 owner |
| SIGTERM / Ctrl-C | 停止准入，通知网络与 owner 关闭，取消归档当前任务，按同一关闭预算 drain/join |

宿主取消 `run` future 时，资源守卫同步停止并回收 native owner，同时向下级 Tokio 任务发出 abort。被取消的 async 任务及其 listener 由执行器后续调度完成析构；父任务的 JoinHandle 结束不能单独证明所有 socket 已同步释放。正常关闭仍执行显式 drain/join，取消测试分别观察持久化锁与两个监听端口的实际释放，不以固定 sleep 作为完成证明。

正常关闭等待预算为 5 秒；同步磁盘调用无法被强制中断，超时不会被当成完成。CLI 对 runtime 的最后退出也使用有限等待，进程级 supervisor 仍需管理真正卡住的 native I/O。SIGKILL 实验不证明设备断电持久性。

## 6. 当前容量与兼容边界

这些数值来自 [server config](../../crates/scap-server/src/config.rs)、[node budgets](../../crates/scap-server/src/node.rs) 与 [mailbox](../../crates/scap-server/src/mailbox.rs)，属于首个部署 profile：

| 项目 | 当前上限或实现 |
| --- | --- |
| 拓扑 | 静态三个 voter，一个 cell，最多 32 个配置数据库 |
| 单库逻辑 SQLite 镜像 | 64 个 4096-byte page，即 256 KiB；不包含 WAL、快照、历史与缓存额外空间 |
| 每库请求记录 | 最多 128 个 accepted/cancel 记录；不自动淘汰 |
| cell 管理操作 | 最多 4096 条；owner/归档操作持续占用预算 |
| cell 状态 / command | 8 MiB / 4 MiB；归档正文加 192-byte hydrate 预算必须装进 command |
| 单事务物理变更 / SQL 原结果 | 300 KiB / 64 KiB |
| SQL 批次 / 参数 / 列 / 行 | 32 statements / 128 parameters / 64 columns / 1024 rows；其他值大小仍有独立限制 |
| SQL mailbox | 至多 32 个请求、合计 8 MiB 计量；单请求计量 1 MiB |
| HTTP | body 1 MiB、response 512 KiB、在途 32；服务端单请求最大预算 10 秒；当前 HTTP/1 每个请求结束关闭连接 |
| 后台维护 | 一个 SQL actor、一个归档线程；维护请求原预算 2 秒；任务有界排队 |
| 持久布局 | RocksDB 内保存并同步替换完整有界 Store 镜像；强读也核验完整保留历史 |

达到容量上限会拒绝继续增长，不能静默丢弃旧结果、取消 fence 或唯一恢复数据。Prune 后如果其他库占用了 cell 空间，Hydrate 也可能因总体容量不足拒绝；本版本没有恢复容量预留与跨 cell 自动搬迁。

未实现的规模化能力包括动态数据库目录、动态 Raft 成员、迁移、多 cell 路由、跨区灾难恢复入口、删除/GC 协议、对象分块 hydrate、增量本地持久布局、每库独立 actor、完整 ORM/SQLite 驱动兼容和 R1/R2 热备。etcd、Kubernetes 和生产观测平台不参与当前 daemon 的必要启动路径。

本 profile 的 256 KiB 逻辑镜像不能用于宣称 1 GiB 恢复目标达标。协议正确性、资源有界和小规模故障通过也不能替代生产负载、跨 AZ 与长期可用性验证。

## 7. 配置与实际启动

### 7.1 完整配置示例

下列是 node 1 的完整 JSON 结构。令牌摘要由公开的合成字符串 `SCAP-DOCUMENTATION-ONLY-REPLACE` 计算，只用于说明格式；实际部署必须替换为应用凭据的 SHA-256。S3 endpoint 为明确的占位地址，bucket 需要预先创建，凭据从指定环境变量取得。所有路径为绝对路径。

```json
{
  "version": 1,
  "cluster_id": "00000000000000000000000000000001",
  "cell_id": "00000000000000000000000000000002",
  "cell_incarnation": 1,
  "node_id": 1,
  "administrator_id": "00000000000000000000000000000064",
  "service_credential_id": "00000000000000000000000000000065",
  "data_dir": "/tmp/scap-demo/data-1",
  "http_listen": "127.0.0.1:8011",
  "peer_listen": "127.0.0.1:9011",
  "certificate_pem": "/tmp/scap-demo/certs/node-1.pem",
  "private_key_pem": "/tmp/scap-demo/certs/node-1.key",
  "ca_pem": "/tmp/scap-demo/certs/ca.pem",
  "idle_seconds": 60,
  "peers": [
    {"node_id": 1, "uri": "https://127.0.0.1:9011", "certificate_der": "/tmp/scap-demo/certs/node-1.der"},
    {"node_id": 2, "uri": "https://127.0.0.1:9012", "certificate_der": "/tmp/scap-demo/certs/node-2.der"},
    {"node_id": 3, "uri": "https://127.0.0.1:9013", "certificate_der": "/tmp/scap-demo/certs/node-3.der"}
  ],
  "databases": [
    {
      "name": "agents",
      "database_id": "00000000000000000000000000000003",
      "incarnation": 1,
      "placement_generation": 1,
      "tokens": [
        {"sha256": "f19f332f4d75c5ff4ec3e88bed7a7fd9bd2dc1c31b6fb163bd5dd7428ea32868", "principal_id": "000000000000000000000000000000c8", "credential_id": "000000000000000000000000000000c9", "auth_epoch": 1, "permissions": 3}
      ]
    }
  ],
  "archive": {
    "endpoint": "https://objects.example.invalid",
    "region": "us-east-1",
    "bucket": "scap-demo",
    "access_key_env": "SCAP_S3_ACCESS_KEY",
    "secret_key_env": "SCAP_S3_SECRET_KEY",
    "allow_http": false
  }
}
```

`permissions=1` 允许 READ，`3` 允许 READ+WRITE；公开令牌不能成为配置的 administrator。数据库名只使用 ASCII 字母、数字、下划线或连字符。每个 token digest 在整个配置中唯一，节点集合必须恰好三个互异非零 node ID，并包含本机。

node 2/3 复制相同 cluster/cell/database/peers 配置，只分别修改 node ID、data_dir、监听端口和本机 PEM/key 路径。所有节点都读取三个公开 leaf DER；不能把 node 1 私钥复制成另外两个节点的身份。当前配置不提供热更新；改变本地 token 表不能自动替代 cell 中的 AuthFence。

非 loopback HTTP 地址需要显式 `"proxy_terminates_tls": true`，表示部署者已配置外部 HTTPS 终止。此开关本身不会启动 TLS 代理。Peer 端始终使用 mTLS，S3 正常使用 HTTPS；`allow_http=true` 仅供显式本机兼容后端测试。

### 7.2 本机证书与配置准备

以下命令为隔离的本机演示生成两天有效的临时 CA/leaf。证书 SAN 必须精确绑定 `node-N.cluster-<32位cluster_id>.scap.internal`，EKU 包含 serverAuth 和 clientAuth。连接地址可以是 loopback IP，peer client 仍验证该作用域 DNS 身份和固定 leaf pin。[真实实验](../../experiments/service-network/run.mjs)使用同一身份规则。

```bash
umask 077
mkdir -p /tmp/scap-demo/certs
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
  -subj '/CN=SCAP local demo CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout /tmp/scap-demo/certs/ca.key -out /tmp/scap-demo/certs/ca.pem

for node in 1 2 3; do
  base="/tmp/scap-demo/certs/node-${node}"
  dns="node-${node}.cluster-00000000000000000000000000000001.scap.internal"
  openssl req -new -newkey rsa:2048 -nodes -sha256 -subj "/CN=${dns}" \
    -keyout "${base}.key" -out "${base}.csr"
  cat > "${base}.ext" <<CERT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:${dns}
CERT
  openssl x509 -req -in "${base}.csr" \
    -CA /tmp/scap-demo/certs/ca.pem -CAkey /tmp/scap-demo/certs/ca.key \
    -set_serial "$((node + 1))" -days 2 -sha256 -extfile "${base}.ext" -out "${base}.pem"
  openssl x509 -in "${base}.pem" -outform DER -out "${base}.der"
done
```

将上面的 JSON 保存为 `/tmp/scap-demo/node-1.json`。把真实应用 token 放入当前进程的 `SCAP_TOKEN` 环境变量后，以下脚本只把其摘要写入三个配置；不会打印 token。脚本按 node ID 生成不同的数据目录和证书引用。不测试 S3 时先从模板删除 `archive` 整段，不能把它写成 `null`。启用 S3 时，先替换 endpoint/bucket 并向每个服务进程提供所指定的凭据环境变量；不会回退到 ambient credential/IMDS。

```bash
python3 - <<'PY'
import copy, hashlib, json, os
from pathlib import Path
root = Path('/tmp/scap-demo')
base = json.loads((root / 'node-1.json').read_text())
token = os.environ['SCAP_TOKEN']
if not token:
    raise SystemExit('SCAP_TOKEN must be nonempty')
base['databases'][0]['tokens'][0]['sha256'] = hashlib.sha256(token.encode()).hexdigest()
for node in (1, 2, 3):
    config = copy.deepcopy(base)
    config.update(node_id=node, data_dir=str(root / f'data-{node}'),
                  http_listen=f'127.0.0.1:{8010 + node}', peer_listen=f'127.0.0.1:{9010 + node}',
                  certificate_pem=str(root / 'certs' / f'node-{node}.pem'),
                  private_key_pem=str(root / 'certs' / f'node-{node}.key'))
    (root / f'node-{node}.json').write_text(json.dumps(config, indent=2) + '\n')
PY
```

### 7.3 构建、初始化和再次打开

构建要求 Rust 1.90.0、C/C++17、make 与 libclang 18；Linux/native 条件见 [G0 构建说明](g0-evidence.md)。SDK 使用 Node.js 24。以下命令从仓库根目录执行：

```bash
cargo +1.90.0 build --release -p scap-server --locked
npm --prefix sdk/node ci --ignore-scripts
npm --prefix sdk/node run build
```

第一次启动必须明确使用 `--initialize`，并在三个终端或进程管理器中分别执行以下三行。`data-1/2/3` 事先不能存在；其父目录、配置与证书应已准备完成。

```bash
./target/release/scap-server --initialize /tmp/scap-demo/node-1.json
./target/release/scap-server --initialize /tmp/scap-demo/node-2.json
./target/release/scap-server --initialize /tmp/scap-demo/node-3.json
```

再次启动省略 flag，进入 OpenExisting；三个节点分别执行对应行：

```bash
./target/release/scap-server /tmp/scap-demo/node-1.json
./target/release/scap-server /tmp/scap-demo/node-2.json
./target/release/scap-server /tmp/scap-demo/node-3.json
```

不要用 `--initialize` 处理缺失、损坏或不兼容的原目录。OpenExisting 必须校验原 cluster/cell/node 身份、状态校验和与限额；失败时保留现场。启动先取得 RocksDB 独占锁，再检查并清理本进程专属的 disposable writer namespace。

### 7.4 Node.js 业务入口

从仓库根目录执行下例。连接地址必须属于同一个配置数据库身份；`SCAP_TOKEN` 与上述摘要一致。

```bash
node --input-type=module <<'JS'
import { createClient, ScapError } from './sdk/node/dist/client.js';
const db = createClient({
  endpoints: ['http://127.0.0.1:8011', 'http://127.0.0.1:8012', 'http://127.0.0.1:8013'],
  database: 'agents',
  authToken: process.env.SCAP_TOKEN,
  timeoutMs: 2000,
});
try {
  await db.execute('CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, body TEXT)');
  const id = crypto.randomUUID().replaceAll('-', '');
  await db.execute({ sql: 'INSERT INTO notes(body) VALUES (?) RETURNING id', args: ['hello'] }, { requestId: id });
  console.log((await db.query('SELECT id, body FROM notes')).rows);
  console.log(await db.status());
} catch (error) {
  if (!(error instanceof ScapError)) throw error;
  console.error(error.code, error.request.requestId);
  console.log(await db.lookup(error.request));
} finally {
  db.close();
}
JS
```

应用应在发起业务操作前保存稳定 ID 与原 SQL/参数，以便断连后查证。`lookup` 返回 unknown 不能触发自动重写；明确放弃时可对同一原请求调用 `resolveOrCancel`，它返回取消 fence 或已提交原结果。完整用法和受支持语法见 [Node SDK](../../sdk/node/README.md)。

现有 `@libsql/client/http` 应用可将 URL 指向 `/db/agents/` 后使用已验证的 execute/batch 子集；SCAP 薄封装增加多副本探测、稳定身份和强读入口。原 `better-sqlite3` 的同步本地文件接口不能直接把数据库路径换成 HTTP URL；迁移到远程调用需要异步调用及兼容性验证。

## 8. 格式升级与验证门禁

Cell state/command/outcome 写入 v2。新 reader 支持绑定相同身份和限额的合法 v1 热状态和旧命令/结果，不为旧数据伪造冷引用；从未 Claim 的旧库保持 `(epoch=0, worker=0)`，Suspend 不会创造虚假 owner。旧 Create/Claim/Activate/AuthFence intent hash 不包含 envelope version，原 operation ID 升级后仍解析为原 receipt。v1 envelope 中出现新生命周期命令或结果会被拒绝。

新归档对象使用 `SCAPARC!` v2；key 路径的 `scap/v1/` 是独立的路径布局版本。旧二进制不能直接读取新状态，不支持混合版本滚动协商或原地降级。升级需要停止写入、保留原版本备份并对完整副本集完成验证。限额也属于持久格式绑定；本实现没有把旧限额自动改写成新 profile 的离线迁移工具。

单元测试单独收集 Rust 行、函数、region 和分支的精确整数计数；Node SDK 独立检查行、函数、语句和分支。窄端口用于验证线程、时钟、网络、对象、权限与异常分支，生产状态转换不能转移到实验目录。具体命令与门禁见[覆盖率规范](testability-and-coverage.md)。

真实依赖实验分别验证 [SQLite/network](../../experiments/sqlite-network/README.md)、[S3 条件写与重启](../../experiments/archive-s3/README.md)和[三节点 daemon/SDK/生命周期](../../experiments/service-network/README.md)。复现完整自动临时部署可执行：

```bash
bash experiments/archive-s3/download-seaweedfs.sh /tmp/scap-seaweedfs
SCAP_SERVER_BIN="$PWD/target/release/scap-server" \
SCAP_SEAWEEDFS_BIN=/tmp/scap-seaweedfs/weed \
SCAP_SERVICE_NETWORK_EVIDENCE_DIR=/tmp/scap-service-network-new-run \
node experiments/service-network/run.mjs
```

每次使用新的 evidence 目录。完成清单、实际二进制摘要、原始请求结果、故障时刻和测量分母决定可以声称的结果；本文不预先填写测试通过数量或生产 SLO。生产验收还需要跨 AZ、设备故障、目标容量、目标吞吐、长期样本和独立安全评审。
