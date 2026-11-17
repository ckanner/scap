# S2 实际恢复专项

`run.py` 复用既有 pinned SeaweedFS 4.51 进程夹具；`probe.mjs` 使用正式 Node SDK、
实际 `scapd` HTTP、native SQLite 和签名 S3。产品逻辑只在 Rust crates 中。

```bash
python experiments/object-restore-runtime/run.py \
  --server /absolute/path/to/scapd \
  --weed /absolute/path/to/weed \
  --node /absolute/path/to/node \
  --evidence /absolute/path/to/new-empty-evidence-directory
```

七项合同覆盖原随机值/多块 BLOB、Empty/Restore first-winner 槽、复制被挂起时的取消、
源权限撤销、HTTP 成功响应丢失后 SIGKILL/新 ID/空缓存继续，以及源 payload 实际 DELETE
并逐个 GET=404 后目标全冷恢复。第七项使用独立的原恢复操作 `1004`：复制完成并持久化
completion 后，按返回 Scope 和实际成功 HEAD PUT 确定目标永久 HEAD，执行真实 DELETE、
GET=404，验证 inspect/resume 均为 `CORRUPT` 且无任何该槽的新 PUT。这个故障插在最终
源 payload 删除之前，不改变前六项的源点与预算。每次推进一个明确 resume；有限阶段
循环是实验安排，不是客户端的自动重试策略。

透明代理只暂停已经签名的 payload GET，不修改正文、ETag、条件头或返回状态。
`capture.mjs` 把 SDK 实际发送/接收的完整正文以 canonical base64、长度、SHA-256 写入
连续序号的 `audit.jsonl`，同时记录 S3 请求/响应配对、条件头、HEAD 正文及摘要、明确
阶段边界、原始 typed rows/receipt、保存在提交前的原 restore 意图。只记录必要的非秘密
字段，不记录 Authorization、Cookie、token、签名或配置内容。源对象删除来自本次实际
成功 GET/PUT 的完整已观察键集合，每个键都有独立的签名 DELETE 与 GET=404 结果。

`audit.mjs` 不导入 SDK、生产 codec 或观察器辅助代码，不读取 `cases.json`/`result.json`
作为判据。它独立解码 `SCAPRES1`，保留整数、浮点位和 BLOB；独立计算 SQL fingerprint
及 `SCAPOBJ2` 原 Result 哈希；检查完整七项 HTTP 意图/响应、恢复原身份、完成后不再取
源 payload、目标 sequence=0/inactive/空请求窗口、原随机 SQL lookup、实际缺失对象和
SIGKILL → wait/close → 缓存目录 ENOENT → 新进程 → 独立目标冷查询的顺序。ChildProcess
拥有关系与 wait 事件构成进程记录，不跨容器 PID namespace 猜测 `/proc/<pid>`。

`negative-controls.mjs` 基于本次真实完整记录执行定向反例：改变原身份、SQL/receipt、
64 位整数、原随机结果、权限撤销、取消、源读取、删除 404、目标请求窗口、进程/缓存
生命周期及目标 HEAD 重建等。语义变体同步修复正文/frame hash、序号等外围 bookkeeping，
要求独立审计仍然拒绝；缺记录、序号洞、坏摘要另有结构反例。保留原记录，不写变体日志。
每一个有 Scope 的实际 SDK 调用都分别加入 scope 篡改反例，每个行查询都分别加入 SQL
篡改反例；所有 source 控制/快照请求、查询 SQL/参数、状态返回 Scope、原 UNKNOWN 的
完整 caller/intent envelope 均绑定固定实验身份。目标 authority-loss 还校验 copied HEAD
的 completion_hash 与实际 completion PUT/GET 摘要一致，并看到每次失败调用中的
HEAD404 → 原 completion GET200 → HEAD404，不能把 unrelated completion 当作证明。

runner 在运行前后冻结 fixture、共享 backend helper、实际 SDK/codec 输入与三个二进制
的 SHA-256；记录 harness Git commit/tree，二进制源码仍需与独立构建清单配对。先执行
审计器单元测试，再跑进程实验、独立审计、定向反例，确认后端回收和输入未变后才写
`run.json.status=PASS`。`LLVM_PROFILE_FILE` 存在时拒绝运行。单独重查保留证据：

```bash
node --test experiments/object-restore-runtime/audit.test.mjs
node experiments/object-restore-runtime/audit.mjs /absolute/path/to/evidence
node experiments/object-restore-runtime/negative-controls.mjs /absolute/path/to/evidence
```

原始请求历史、进程错误与每项结果只写独立 evidence 目录；后端凭据只在临时私有配置
与子进程环境中。禁止提交配置、日志、数据库、原始随机结果和 credential。证据审计是
对捕获记录的独立交叉核验，并不提供对恶意篡改全部原始观测的密码学来源证明。

这是固定小库的实际故障专项，不替代 Rust/Node 单元覆盖、完整容量、长期过载、AWS
Standard/IAM、S3 Express 故障域或生产 SLO。原始失败与新的完整通过必须分别保留。
