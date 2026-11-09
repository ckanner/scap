# Metadata-only HEAD 实际合同

本目录只装配正式 `scapd`、Node SDK 与真实 S3 兼容后端，验证 `takeover` 和 `policy` 的 metadata-only 网络合同。**当前状态：OBSERVER_CORRECTION_UNIT_PASS；原 `3ca5acd` actual01 完成固定 41 个请求后，被 observer 规则拒绝，保持 FAILED。本次窄修的 51 个单位（41 oracle、10 cleanup）已全部通过；新源码实际、独立实际 oracle、九负控及原样复制正控均 NOT_RUN。** 见[原始失败、窄修与新单位回执](../../docs/evidence/metadata-head-observer-correction-local-2026-11-09.json)；初始静态与 38-unit 记录见[原冻结回执](../../docs/evidence/metadata-head-acceptance-static-local-2026-11-09.json)。旧证据保持原状态，静态解释与单位不替代新源码实际验收。

产品起点是 [`778a4d25dc186b3afc7958cbd522e5e0316703c8`](https://github.com/ckanner/scap/commit/778a4d25dc186b3afc7958cbd522e5e0316703c8)。此实验不改既有 owner 合同的 70 个命令 / 144 个 POST，不增加公共产品接口。后续执行时，以 `daemon-build-evidence/` 中实际 source-bound release 和独立 fixture source archive 为准。

## 1. 为什么用独立的 worker 和代理

管理操作改为 metadata-only 后，成功发布的合同是：从原 exact HEAD GET 获得完整 body/ETag，在原 deadline 内验证原控制输入，使用同一个 ETag 条件提交允许的 HEAD 增量。它不再为 takeover/policy 读取 data manifest。

已有 owner 夹具记录完整真实网络，但并没有把服务内部 S3 请求与外层 HTTP 绑定为一个独立传播的 call ID。两个 RPC 的观察时间重叠，不能证明某个 GET 属于哪个 RPC。因此，本目录不增加按最近调用或时间区间猜测归属的 shared oracle 规则。

这里的 M daemon 从启动到退出只收到明确列出的 `status`、`takeover`、`policy` 请求。它的配置只指向专用 S3 listener。S daemon 先建立真实 SQLite 数据、执行 SQL，再承担独立新 status 和一个竞争 policy；S 使用另一个 S3 listener。维护 F 还有第三个 S3 listener，只有三次受控签名请求。完整 M listener 生命周期中的任何 immutable GET/PUT，都足以违反此合同；不存在可用来解释它的恢复或 SQL 操作。

外层 HTTP 中的 `X-SCAP-Fixture-Command` 只绑定实际入站 POST 与原 SDK 请求。它不会穿透产品成为 S3 因果标识。oracle 仍分别核对 HTTP 原输入和整个 M 网络投影，不声称能从日志反推出内部函数调用次数。

## 2. 固定的原输入

完整 Scope 的 `deployment=1`、`tenant=7`、`incarnation=1`、逻辑 `generation=1`。六个 database 依次为 2101–2106；名字只用于实验的固定映射。

| Scope 名 | database | 场景 |
| --- | --- | --- |
| `success` | 2101 | 新 status、成功 takeover、成功 policy、再次 status |
| `get_unknown` | 2102 | 真实 GET 200 后丢响应；原调用 UNKNOWN；S 新 status |
| `put_unknown` | 2103 | 真实条件 PUT 200 后丢响应；原调用 UNKNOWN；S 新 status |
| `stale_412` | 2104 | 暂停 M 原条件 PUT，S 先提交 policy，再放行原 M 候选得到 412 |
| `permission` | 2105 | reader takeover/policy 均 DENIED，S 新 status 确认原状态 |
| `known_quarantine` | 2106 | 同 resident control Engine 看见坏 HEAD；修复原字节后新 status 成功，但管理发布保持 CORRUPT |

S/O worker 为 8101，M worker 为 8202。writer principal 11 有 provision 权限；manager 12 和 reader 13 没有 provision。原 bearer 只存在 private runtime；公共证据保存 SHA，不保存 token/access secret。

每个 Scope 的四个种子调用严格按 `create → activate → execute → policy`。seed nonce 分别为 `10000 + 10*i`、`+1` 和 `+2`，activate 的 worker guard 为 8101。execute 使用保存到文件的原 `epoch=1/id=1/principal=11` 请求，只有两条 SQL：

```sql
CREATE TABLE witness(n INTEGER PRIMARY KEY);
INSERT INTO witness(n) VALUES(1) RETURNING n;
```

这六个 ACK 保留原 receipt、完整 `SCAPRES1`、typed result 和 SDK 保存请求。oracle 检查精确 affected rows / last insert rowid，包括第一条语句的两个 0，不能仅检查“返回了 1”。种子最终为 revision/head_serial 4、sequence 1、owner 8101/epoch 1/active true、auth_epoch 2；默认 quota 10 GiB、retention 4096 / 256 MiB 保持原值。

`BASE_POLICY` 是 11=READ+WRITE、12=READ+ADMIN、13=READ。`NEXT_POLICY` 只增加 13 的 WRITE。两者都保留完整三项，不能用字段缺失默认为权限撤销。

### M 的完整生命周期分母

| 命令 | 原输入 | 原 HTTP 结果 | M 的 S3 |
| --- | --- | --- | --- |
| `m_success_status_before` | manager status | 200 | GET |
| `m_success_takeover` | rev 4, nonce 20001, guard 8202 | 200 | GET + PUT 200 |
| `m_success_policy` | rev 5, nonce 20002, NEXT_POLICY | 200 | GET + PUT 200 |
| `m_success_status_after` | manager status | 200 | GET |
| `m_get_unknown_takeover` | rev 4, nonce 21001, guard 8202 | 503 UNKNOWN | GET 200，响应被丢弃 |
| `m_put_unknown_policy` | rev 4, nonce 22001, NEXT_POLICY | 503 UNKNOWN | GET + PUT 200，PUT 响应被丢弃 |
| `m_stale_takeover` | rev 4, nonce 23001, guard 8202 | 409 CONFLICT | GET + 原 PUT 412 |
| `m_permission_takeover` | reader, rev 4, nonce 24001, guard 8202 | 403 DENIED | GET |
| `m_permission_policy` | reader, rev 4, nonce 24002, NEXT_POLICY | 403 DENIED | GET |
| `m_quarantine_bad_status` | manager status | 409 CORRUPT | GET `{}` |
| `m_quarantine_repaired_status` | manager status | 200 | GET 完整原 HEAD |
| `m_quarantine_takeover` | rev 4, nonce 25001, guard 8202 | 409 CORRUPT | GET，无 PUT |
| `m_quarantine_policy` | rev 4, nonce 25002, NEXT_POLICY | 409 CORRUPT | GET，无 PUT |

总计 41 个原 SDK POST：S/O 28、M 13。M 有且只有 13 个 HEAD GET 和 4 个 HEAD PUT，其中 3 个真实 backend 200、1 个真实 backend 412。S 的不可变对象/恢复内部 GET 总数由真实记录给出，不为了适配遍历实现而规定一个虚假的固定值。

整个试验只有六个 SQL ACK、28 个普通业务 HEAD publication，加上两次明确声明的 F 故障 HEAD 写。任何重试、新 nonce 候选、额外 Scope、LIST、HEAD、DELETE 或未列明 method 都必须失败。

## 3. 三个故障以及已知隔离状态

`drop_get_unknown` 必须先观测到实际 backend GET 200 的原 bytes/ETag，才关闭响应传输。`drop_put_unknown` 必须先观测到实际条件 PUT 200，才丢弃该响应。oracle 既保留 caller UNKNOWN，也通过 S 的新 status 证明后者的原 nonce/ACL 已生效。后台成功不能补写原 ACK；GET 的丢响应也不能被解释为新的 takeover 已生效。

`hold_stale_put` 绑定 M 的原 request serial、Scope、nonce 23001、完整 body 和 If-Match。在该确切请求进入 gate 后，S 以同一个旧 revision/ETag 提交 nonce 23002/NEXT_POLICY。它的真实 200 返回后才释放 M 原请求。M 仍发送原 body/ETag，得到真实 412；oracle 不允许用 S 的新 ETag 重建它。

F 维护严格只有三个原签名请求：GET known_quarantine HEAD；以原 ETag PUT `{}`；M 原坏 status 返回后，以 bad ETag PUT 保存的完整原 HEAD 字节。不重新编码、不补一个额外 F verification GET。M 下一条新 status 是计划中明确的 readback。

F 的最后一次恢复可能让内容派生的 ETag 重复。oracle 只对这个确切 key、这三次 F 请求、相邻的四次 M read 单独证明；它不放宽其他 HEAD 的 serial/CAS 无 ABA 检查。正常种子 HEAD 历史仍按 HEAD5 版本链核对。

两 daemon 都只有一个 control worker。M 在全部种子完成后才启动；最后四条 M 请求连续同 Scope，中间只有 F 对 S3 的维护，没有任何新 M Scope、恢复、SQL、cache reset 或进程重启。当前 daemon 的 Engine database cache 上限仍为 1；这里通过冻结源码、配置、完整 offered 请求和同一进程生命周期共同约束 resident handle，不把“PID 相同”单独当作线程或 handle 同一性的证明。

新 status 能读取修复后的 HEAD，不表示 sticky quarantine 已清除。已知隔离状态仍阻止 takeover/policy publication。反过来，未检测到 data corruption 的管理 ACK 只证明 HEAD CAS；零 immutable I/O 不能证明 SQLite 图、Result 或 native image 健康。

## 4. 原始证据与独立核验

新 events、Node、HTTP/S3 proxy 日志用完整可逆的 `*_body_base64 / *_body_bytes / *_body_sha256` 三元组；stdin/stdout 原行用 `raw_base64 / raw_bytes / raw_sha256`。JSON 不接受重复 key、非有限值、非规范 base64 或布尔计数。

原 `object-service/client_ledger.mjs` 与 `client_transport.mjs` 原样复用。旧 ledger 的 `body/body_sha256` 字段不改写为新 schema。probe 的适配器只复制 Headers、加入固定 command ID、记录 bearer digest，然后把原 body/signal/redirect/deadline 交给原 recorder 一次。不存在第二个 Fetch 或 oracle 内部状态替代实际回复。

| 文件 | 独立检查 |
| --- | --- |
| `metadata-plan.json` | 与 oracle 自己的固定 41 输入、deadline、nonce、Scope、ACL 比较；不 import producer spec |
| `metadata-configuration.json`、`service-{S,M}.json` | 三种 caller digest、完整 Scope、两个原 worker、独立 native HTTP/S3 listener、单 control worker |
| `metadata-node.jsonl`、`events.jsonl` | Node fsync 原行与 parent 捕获 stdout 逐字节相同；原 stdin、one-shot offer、六份保存请求、最终 finished |
| `http-client-ledger.jsonl`、`http-proxy.jsonl` | 每个 command 一次原 Fetch；实际 inbound bytes/bearer 与完整 service reply，不仅信 SDK outcome |
| `http-client-transport.jsonl` | 原 request/socket 身份、完整 response body、RECORDED 结束；允许 recorder 关闭时仍有已观察 connection，不把它冒充完整 socket 寿命 |
| `s3.jsonl` | 全部 listener/handler 生命周期；原 request/forward/backend response/delivery 或两次明确 suppression |
| `request-*.json` | 保存的原 SDK 请求、SQL 指纹与六个 ACK/retained Result 逐字节对应 |
| `f_*.headers/.body/.stdout/.stderr` | 三个实际 curl、条件 header、原 status/ETag/body，与后端记录一致 |
| `daemon-build-evidence/` | 独立 `audit_build` 的原 Cargo、source、native archive、实际 executable 证明 |
| `metadata-source-before.json`、完整 source tar、after log | 完整 Git blob/tree、fixture/SDK/observer/oracle 原源码；daemon 编译输入与 fixture 内容相同，新增实验 commit 不冒充重新 C 编译 |

正常版本链复用独立 `audit_wire.object_versions`，**不传 HTTP call interval/bindings**。共享 HEAD5 schema 对每个普通 candidate 验证完整字段、1024 ACL 上界、storage 1/1、原 Scope、原 head_serial/revision 增量。外层另检查每个业务动作允许的 delta，保证管理动作不改数据根、sequence、请求窗口或配额。

六个固定种子图还检查原 empty manifest/index、完成后的少量 data manifest/node/chunk、单个 retained index/Result、保存请求身份、完整结果字节及出版前 readback。这是该小输入的依赖图证明，不是全部 SQLite 原生完整性、最大容量、所有 B+ tree 深度或新的 closure cursor 调用路径验收。

完整尾部不能以最后一个 HTTP response 代替。每个实际 handler 必须恰好对应一个 original request，且各自有正常 start/end；请求总数与 handler 总数相等不足以证明这一双射。新增反例让两个完整请求共用一个 handler，再保留另一个没有请求的 failed handler 抵消总数，要求精确拒绝。成功顺序必须是：Node 原 finished/wait4；S/M 正常 SIGINT/wait4；五个 proxy 停止 serve、全部已接受 handler 结束并 join；四个 backend 进程按实验计划 SIGKILL/wait4；无 cleanup error；最后删除 private runtime 并立即记录 absence。

共 10 个长期/维护 owned child：4 backend、2 daemon、1 Node、3 curl。版本探测与有限 backend readiness provisioning 单列为启动设施，不虚报为 10 个对象或 F 请求。后端计划 SIGKILL 与 daemon/Node 失败后的 forced cleanup 区分，任何后者都不能通过。归档复制不要求原路径再次存在；历史 absence 必须来自原始记录，不用现在的 `stat()` 改写过去事实。

### 固定 Node 的完成后 informational disposal

原 relay 明确发送 `Connection: close`。固定 Node22.16.0 的内置 `internal/deps/undici/undici` 源码为 601703 bytes、SHA256 `b6ba65bd17b764b8eaae71a81e358f82b3efcd5954f2bd0da6f6b6206f0250e7`。其 `onMessageComplete` 先校验响应长度并调用 `request.onComplete`，后者发布 trailers diagnostic，再在不保持连接的路径以 InformationalError 销毁 socket；该 error 的 code 是 `UND_ERR_INFO`。这是固定二进制内置源码的静态分析；[相同版本的官方源码位置](https://github.com/nodejs/node/blob/v22.16.0/deps/undici/undici.js)用于定位，不把未单独核对的远端文件冒充本次提取字节。

冻结 observer 将 trailers 记为 `request_body_complete`，保留 safe error code，而不记录任意 error message。因此只能把符合下列条件的原事件称为“与固定源码相容的完成后 informational disposal”，不能说日志实际记录了字面原因 `reset`：

- 每个 connection 恰绑定一个 original request/call；原 request body completion 已发生，之后该 connection 才出现唯一 `socket_error`，safe 字段精确为 `UND_ERR_INFO` / name `UNKNOWN` / cause `UNKNOWN`。
- 原 Fetch 完整 body、原 ledger 与 relay 的全部 bytes/status、同 call 的 `RECORDED` terminal 仍独立成立；request_error、Fetch failure、INCOMPLETE 或其他 socket error 仍拒绝。
- 可见的 end/error/close 各至多一次，且 sequence 必须严格晚于原 sendHeaders、monotonic_ns 不早于它；observer 的 socket identity 注册与 sendHeaders 记录在同一个同步调用栈中，不能在两者之间插入 socket 事件。close 后没有该连接的新事件。若 close 已观察到，必须晚于此 INFO，且 `had_error=true`。没有 INFO 的正常 close 仍要求 `had_error=false`。
- 允许 close 先于 Fetch 的 Promise continuation，也允许 recorder 停止时尚未观察 close。后一种只保留“未观察关闭”的事实；global RECORDED 与 `remaining_connections` 必须精确对应 observed-but-not-closed 的身份集合，不声称完整 socket 生命周期。

这个窄规则不更改 observer、Fetch、deadline、relay 或原日志，也不凭 code 白名单接受失败响应。新增单位包括两种 close/Fetch 调度、先 headers 后 body、部分 socket 生命周期，以及 pre-body INFO、跨连接借用、连接复用、重复错误/close、错误 code/cause、had_error 不匹配、缺失完整结果和 remaining 数量不符的定向拒绝。

## 5. 九个语义投影负控

`controls.py` 先对原完整目录执行 full audit，再把整个目录逐字节复制到独立临时路径，对复制目录重新 full audit。原样复制必须得到相同 verdict 和全部输入 SHA。summary 文件不参与原事实判定。

之后的九项修改明确作用于**完整审计通过后产生的语义投影**，不是完整 raw ledger 的伪造实验。每项保留原 file/sequence/request_serial/handler/call_id/byte SHA 引用、完整改变后的投影、before/after SHA、预期 rule 和实际拒绝。新增 immutable PUT 用语义相同但字节不同的合法 SCAPOBJ2，获得另一个内容 key，避免假造已占 key 的第二次成功 conditional create。

| 修改 | 必须命中的 rule |
| --- | --- |
| M 加入完整合法 immutable GET | `M_OBJECT_GET` |
| M 加入完整合法 immutable PUT | `M_OBJECT_PUT` |
| immutable GET 放在最后管理 HTTP 回复之后、原 daemon wait4 之前 | `M_TAIL_OBJECT_IO` |
| M offered operation 改成合法 `open` | `M_NON_METADATA` |
| 后端已接受 PUT 的原 caller UNKNOWN 改成成功 ACK | `M_UNKNOWN_OUTCOME` |
| UNKNOWN 后增加第二次原 HEAD 候选，即使再次合法得到 412 | `M_PUBLICATION_ATTEMPT_COUNT` |
| stale 候选改用竞争者的新 ETag 和形状合法的新 revision | `M_ORIGINAL_ETAG` |
| 修复后的 known-quarantine 管理调用改成成功 | `M_KNOWN_QUARANTINE` |
| DENIED 原 reader 的实际 credential digest 改成 manager | `M_PERMISSION` |

一个负控必须命中这一精确 rule 才计通过；KeyError、schema、body hash、普通分母失败或其他更早的拒绝会被原样保存为**控制失败**。额外单位检查还包含 permission HEAD PUT、UNKNOWN 被改成 NotApplied、完整尾部与原 bytes/Scope/guard 条件。它们是规则测试，不计入九个实际投影控制的分母。

## 6. 执行接口与状态边界

只有源码冻结、实际 build receipt 已绑定并获得实际窗口后才运行：

```bash
python3 -B experiments/object-metadata/run.py \
  --server /absolute/release/scapd \
  --weed /absolute/pinned/weed \
  --build-record /absolute/source-bound-service-build \
  --evidence /tmp/new-metadata-evidence

python3 -B experiments/object-metadata/oracle.py \
  --evidence /tmp/new-metadata-evidence \
  --output /tmp/new-metadata-oracle.json

python3 -B experiments/object-metadata/controls.py \
  --evidence /tmp/new-metadata-evidence \
  --output /tmp/new-metadata-controls.json

python3 -B -m unittest discover -s experiments/object-metadata -p 'test_*.py'
```

`--output` 是一个新 JSON 文件，不是目录；拒绝覆盖旧结果。runner 默认调用 `oracle.audit(evidence)`。独立 oracle 默认要求原 native archive/executable 与输入可重新取到。`--allow-missing-build-artifacts` 只允许明确标注的离线诊断，不能作为 formal acceptance；九负控不提供这一绕过参数。

该实际合同不证明 AWS Standard 云端保证、吞吐 SLO、自动 owner controller、全局 quarantine、GC/pins/多物理世代、删除或 PITR。此目录任何成功都必须与完整 workspace 单位/四维覆盖、原生与其他实际合同分开报告。原 UNKNOWN、原 412 和已知隔离不可因后续观察而被重新解释成原 ACK 或“可安全重放 SQL”。
