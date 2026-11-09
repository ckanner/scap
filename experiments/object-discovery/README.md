# 从部署根执行有界冷恢复

本合同装配正式 `scap_object::catalogue::RecoveryJob`，验证全部计算进程及本地缓存丢失后，仅凭部署身份、S3 连接和可信 tenant→READ 主体配置，从部署根发现并恢复数据库。目录协调、预算、权限和 native 恢复逻辑位于 `crates/scap-object/src/catalogue/recovery_{job,budget}.rs`；实验目录只负责真实进程、S3、故障门控、原始证据和独立审计。

**此源码提交仅完成 Python 行为用例和 Rust 格式检查。真实 Rust release 编译、原生 SQLite/S3 合同和完整原迹 controls 在冻结组合候选上运行之前均为 `NOT_RUN`。** Python 用例中的手写收据、对象和小子进程不是数据库真实验收。此合同严格读取 HEAD5 / SCAPOBJ2：`head_serial >= revision >= 1`，当前只接受 `storage={active_generation:1,allocated_through:1}`，ACL 上限为 1,024。每个实际接受的 HEAD 从原 body/ETag 前驱验证 serial 与业务 revision 各增一；所有闭包对象键由同一次捕获 HEAD 的 storage generation 推导为 `.../storage/1/objects/<hash>`。旧 HEAD4、缺失/未知字段和未实现的 storage 状态均拒绝。此前 HEAD4 的真实证据保留其原源码身份，不冒充本次格式升级的验收。

原始请求层同样验证 orphan、失败 GET 和故障门控尚未转发的对象键，不能只在最终恢复闭包中检查路径。完整 Scope、规范非零 u64、固定 storage generation 1 和 64 位小写十六进制摘要缺一不可；同一永久 HEAD 键的后继也不能更换逻辑身份。

## 验证范围与分母

恢复进程配置不接收 Scope、名称、对象键、游标、ACK 清单或预知 tenant 列表。允许的可信配置只有 endpoint、region、bucket、连接凭据、deployment、worker、tenant→principal READ 映射、本地路径和总作业时限；实际已加载配置的原字节 SHA 和去凭据投影由子进程自己回显。映射仅决定读取数据时使用哪个真实主体，不能限制目录发现的 tenant 分母。

种子阶段生成 35 个只存在 CreateDescriptor 的未知 tenant，另有直接创建、Maintenance、权限限制、请求窗口退休、删除后同名重建，以及 Reserved、Provisioning、Bound、ControlAdmitted、Aborting、Aborted 状态。旧物理 HEAD 永久保留；一个无 HEAD 的真实对象前缀必须显式分类为 OrphanPrefix。独立 oracle 从全部实际已接受 S3 对象推导目录分母，并检查每个 LIST 页的完整原始键、KeyCount、顺序和 More；不会拿恢复输出的 Scope 集合充当应恢复集合。

数据阶段固定 13 个原始 SQL 意图。每个随机 4096 字节 BLOB 都在准备/执行前完整保存，指纹由独立 SCAPSQL1 读者重算。SQL 同时产生随机 token，完整原始结果作为不可重放的输出证据。原始 `execute` / `session_execute` 成功响应与 ACK 账本必须一一对应：11 个 ACK、1 个明确取消的迟到候选、1 个 S3 已接受但 native publication 失败的 `CommittedButUnavailable`。取消、退休、删除和 UNKNOWN 不互相替代，也不从原始输入分母中消失。

| 恢复 profile | 实际条件 | 必须观察到的结果 |
| --- | --- | --- |
| `interrupted` | 根扫描进行至少 12 step 后杀死全部计算进程，移除缓存，并重启四个 S3 后端进程 | 未完成；下一个独立作业从部署根开始，不复用进程内 checkpoint |
| `missing_reader` | tenant 99 没有可信 READ 主体映射 | `PermissionBlocked`，保留 pending Scope，不读取该槽的数据对象 |
| `admin_without_read` | tenant 99 映射到只有 ADMIN 的主体 | 同样阻塞，ADMIN 不隐含 READ |
| `missing_retained_result` | 实际删除 native 数据库已关闭窗口中的一个原始 Result 对象 | `Corrupt`，实际 GET 404，保留 pending，不能称完整恢复 |
| `complete` | 恢复此前删除的同一份 Result 原字节；配置当前拥有 READ 的主体 | 完整分类并恢复所有 Ready/Maintenance 物理槽；完整 data/result/native 验证后才能为 true |

每个被恢复的永久槽必须在同一步真实 GET 中具备完整 Data tree、所有保留窗口的分段索引和全部 Result 闭包；父节点摘要不能代替孩子读取。恢复前和最后 exact HEAD 的 body/ETag 必须来自对应实际响应并保持相同，最后读必须位于完整依赖读取之后。实验逐字节保存实际 native 文件，与完整物理页重构相等，再通过独立 SQLite `integrity_check` 和全部原始行内容核对。生产返回的只读 handle 另做完整查询，并重新读取当前 HEAD / READ 权限。

目录 Name/Create/Control/AbortProof 输出必须有本次 exact GET 和稳定 `Name → Proof → HEAD → Name` 证据。Control 原条件及 nonce 只能投影已验证的 immutable ControlDescriptor；恢复能力不授权冒用 creator，也不自动执行控制动作。Ready 和 Maintenance 都验证数据；Provisioning/Deleted 等只做准确元数据分类。历史 ACK 若因退休或删除不再属于数据恢复 profile，必须由实际永久屏障单独解释。

两次 Name GET 都存在时，稳定证据要求相同 body/ETag；都返回经原始对象版本历史独立核对的 404 时，比较缺失状态。S3 错误 XML 的 RequestId 可以不同，不能把错误体摘要当作 NameBinding 的版本。404→200、200→404、同 key 已存在却声称 404，以及 200 body/ETag 变化仍必须拒绝。实验同目录模块按绝对文件位置加载到独立名称，服务端实验的同名 Python 模块、路径优先级或测试顺序不能替换恢复合同/代理/oracle。

## 原生失败、迟到请求与实际进程链

迟到 SQL 候选在 HEAD PUT 发送给后端之前被门控，原进程被 SIGKILL 并由 wait4 回收；新进程用相同原始请求身份发布取消屏障。随后释放旧 PUT，要求原条件实际收到 412，不更换 ETag、不重放 SQL。

native 故障发生在另一次 HEAD PUT 已被后端接受、响应尚被门控时。对实际存活的原生进程设置 `RLIMIT_FSIZE=0`，释放响应，要求真实调用返回 `CommittedButUnavailable`，随后恢复限制。未返回原生成功的调用不计 ACK，但它的已提交数据和原始 Result 必须在冷恢复中保留。

每次 Popen 都在握手前登记所有权，保存执行文件/配置身份、spawn 边界、子进程自报 PID 和内核 wait4 结果；同一 PID 的重叠独立生命周期会被拒绝。构造或日志写入失败也必须回收子进程。半行响应受完整读取截止时间约束。后端三次启动的四个角色同样逐个计入原始分母。

代理保存完整 request/response body、条件、同次 ETag、发送前 delivery marker 和发送后的日志。后者合法地可能晚于调用者观察到返回，oracle 不会把日志延迟误判为协议错误。独立审计用原始私有配置中的临时签名密钥重新计算 SigV4 MAC；公开证据只保存安全的 signed header 值与密钥/签名摘要，不保存凭据。完整审计需要原机保留私有配置，公开离线审计明确降为 partial。

这组夹具顺序执行实际后端请求，唯一迟到候选在发送前暂停。oracle 先用原始请求、release、后端响应区间证明后端操作不重叠，才按该合法顺序重算版本和条件。它不是通用并发历史线性化器；不满足该前提的证据会拒绝。中间态丢响应、迟到 412 和 post-send logger 延迟保留原始时间，不能通过改写时间消除冲突。

## 预算与完成语义

生产作业的总 pages/candidates/GET/list bytes/metadata bytes/data bytes 和绝对时限跨 step 累计，最多一个 pending Scope、一个 native image，不能通过分页重置。实验采用固定 15 分钟作业时限、每 step 30 秒、最多 2048 个 step；配置不能提高生产预算。每个 image 查询后释放 lease，最终再观察一次不含新 image 的作业状态，使累计用量包括最后查询的 exact GET。

`metadata_bytes` 和 `data_bytes` 是生产保守额度消耗。失败 GET 保留整个 reservation，不能当成实际 HTTP 传输或费用；原始 response body 字节独立统计，不包括 HTTP 头/TLS。同步 native I/O 不能硬实时抢占，截止时间前后检查只能保证超时不发布 healthy/complete。完成指各永久槽各自的验证时点已覆盖，**不是所有数据库在同一瞬间的健康快照**。进程内 checkpoint 不能持久 resume，进程丢失就从根重新开始。

## 构建和运行

使用固定环境、干净的完整组合候选和独占目标。所有证据目录必须不存在。以下变量由实际运行者设置为绝对路径，不能指向旧候选的已编译二进制：

```bash
python3 -m unittest discover -s experiments/object-discovery -p 'test_*.py' -v
cargo +1.90.0 fmt --manifest-path experiments/object-discovery/Cargo.toml --all -- --check
cargo +1.90.0 clippy --manifest-path experiments/object-discovery/Cargo.toml --all-targets --frozen -- -D warnings

python3 experiments/object-network/build.py \
  --target-dir "$SCAP_DISCOVERY_TARGET" --evidence "$SCAP_DISCOVERY_EVIDENCE/seed-build"
python3 experiments/object-discovery/discovery_build.py \
  --target-dir "$SCAP_DISCOVERY_TARGET" --evidence "$SCAP_DISCOVERY_EVIDENCE/recovery-build"

python3 experiments/object-discovery/discovery_contract.py \
  --seed-worker "$SCAP_DISCOVERY_TARGET/release/scap-object-network" \
  --seed-build "$SCAP_DISCOVERY_EVIDENCE/seed-build/build.json" \
  --worker "$SCAP_DISCOVERY_TARGET/release/scap-object-discovery" \
  --build "$SCAP_DISCOVERY_EVIDENCE/recovery-build/build.json" \
  --weed "$SCAP_WEED" --evidence "$SCAP_DISCOVERY_EVIDENCE/run-01"

python3 experiments/object-discovery/discovery_oracle.py \
  --evidence "$SCAP_DISCOVERY_EVIDENCE/run-01" > "$SCAP_DISCOVERY_EVIDENCE/independent-oracle.json"
python3 experiments/object-discovery/discovery_controls.py \
  --evidence "$SCAP_DISCOVERY_EVIDENCE/run-01" > "$SCAP_DISCOVERY_EVIDENCE/independent-controls.json"
```

设置 `CARGO_TARGET_DIR` 为同一独占目标后再运行 clippy；它是开发检查，不能代替随后单独捕获的 release 构建。实验不能设置 `LLVM_PROFILE_FILE` 或 coverage Rust flags，不贡献生产单元覆盖。

`discovery_build.py` 保存实际 Cargo 原始 stdout/stderr、唯一 release executable、实际 static libSQL link path/native `.a` 字节、Rust/Cargo executable 身份、原始源码清单及 source archive。独立 `discovery_build_audit.py` 自己枚举完整源码、解析 raw Cargo、检查真实路径/字节/链接归属；`status=passed`、非零 Cargo 退出码或另一个二进制不构成证明。seed worker 也独立捕获并完整审计自身构建。源码前后、binary/native 发生变化必须重建新证据，不能覆盖旧失败。

公开目录包括原始 plan/facts/calls/inputs/acks/history、按 SHA 存储的完整 input/S3 body、实际 native image 和两组构建证据。凭据、后端内部数据库、原进程日志和 disposable cache 位于同名 `.private` 目录，不能复制到公开证据包。实际随机输入只用于本实验，不包含用户数据。

`--offline` 仅对已归档原始字节做受限重审：缺失的原机 binary/native/compiler/runtime secret 无法重新验证，明确输出 partial 并退出 2，不能当作合入门禁。普通 oracle 默认 full。`discovery_controls.py` 首先要求真实基线 full 通过，再对内存副本执行 23 个负控与 1 个合法迟写日志正控；删整次 HTTP exchange 时重绑序号，修改 body 时重算摘要，使深层检查得到实际考验。原始输入、对象、native 和构建文件的字节前后必须完全不变。

本地 SeaweedFS 4.51 的签名 HTTP 合同不证明 AWS S3 Standard 云端一致性、真实跨 AZ 延迟/吞吐、生产成本或 SLO；这些仍单列 `NOT_RUN`。GC 未开启，保留原始对象、旧结果和 orphan 的增长也不能由此宣称已解决。
