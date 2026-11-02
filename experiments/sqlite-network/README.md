# 真实 SQLite writer / mTLS cell 故障合同

本独立 workspace 将正式 `scap-sql-worker::Writer`、`scap-cell-client`、`scap-sqlite`、cell 状态机、Raft driver、RocksDB 和 mTLS runtime 放在同一条实际执行路径中。它扩展原有 [网络实验](../raft-network/README.md) 与 [SQLite adapter 实验](../sqlite-engine/README.md) 的组合证据，不替代第一方生产代码的独立单元覆盖率。

## 实际边界

每个 voter 是一个独立 OS 子进程，拥有独立 RocksDB 目录、正式串行 runtime 线程、Tokio 网络执行器和一个专用 SQL 线程。原生 SQLite writer 只在 SQL 线程构建和使用；它通过正式 `RuntimePort` 调用独立运行的 cell，不负责驱动 Raft。

六条定向 TCP proxy 只转发或黑洞 TLS 字节，不解密、不解析 Raft、不生成共识响应。CA 和叶证书在每项测试的临时目录中现场生成。数据库创建、测试用 owner/auth fence 与 ResolveOrCancel 均通过正式 `CellClient` 和逐提案的持久应用结果执行。

新 writer 使用正式 owner 恢复入口，依次完成 owner claim、fresh Safe ReadIndex、权威物理镜像恢复、新目录构造、owner activate 和最终新鲜读屏障。实验不自行编写这套策略，不复用前任 SQLite/WAL 目录，不重放 SQL 生成恢复数据。

测试控制通道只传入固定合成请求、调度指令和观察结果，不传送 Raft 消息。控制协议有长度、数量和等待上限；原生 SQL 请求只使用固定、无参数的测试批次，不构成面向客户的 SQL RPC 或 SDK。

## 七项合同

| 场景 | 必须观察到的结果 |
| --- | --- |
| SQL、RETURNING 与重复 DDL | 真正执行 `CREATE TABLE`、唯一键 INSERT 和 `randomblob`；成功对应持久接受；重复请求原样返回完整结果和原回执，不重复执行 DDL，随后退役该 writer |
| owner fence | 取得真实 Safe ReadIndex view 后暂停；在同一 leader 有序 claim 新 owner；旧请求最终被 fence，独立只读 SQLite 连接仍见原 payload，cell revision 不变 |
| auth fence | 在同样的前置读取边界推进 auth epoch；旧调用最终 Unauthorized，未发布原生页面，也未建立成功请求记录 |
| 无 quorum 与有序取消 | 黑洞旧 leader 的全部 peer 路径；SQL 返回 UNKNOWN 且本地页面不变；新多数派通过 ResolveOrCancel 写入取消记录；恢复网络后同 ID 请求仍被拒绝 |
| Accepted 回复超时 | 真正持久 Accepted 的回复在端口返回前越过原调用 deadline；请求保持 UNKNOWN 且未发布本地页；有序解析确认原提交，新目录恢复并返回原随机结果 |
| Accepted 后 SIGKILL | 在正式逐提案结果已为 Accepted、尚未进入原生发布时真实 SIGKILL writer/voter 进程；无 SQL ACK；其他 voter 选主后在新目录恢复精确页面和结果 |
| snapshot 与全组重启 | 停掉一个落后 voter，积累真实 SQLite 物理历史与取消记录，checkpoint 后通过 mTLS 安装实际 snapshot；再次杀掉接收者直接检查其持久 snapshot；全组三进程 SIGKILL/reopen 后由新 owner 重建 SQLite |

`PausingPort` 只包装正式 `CellPort` 的效果边界。读取暂停点是正式 Safe ReadIndex view 已返回、即将交给 client 校验和 gate 授权的边界；恢复后仍使用这个已线性化的 view，最终 owner/auth 冲突由有序 Commit 裁决。Accepted 暂停点先以正式 codec 校验该提案的 `term/index` 与 `Outcome::Accepted`。夹具不将 transport Received、本地 Admitted 或“读不到请求”伪装成持久接受/取消。

所有“未发布”结论使用另一个真实只读 SQLite 连接检查原生可见数据，并同时检查权威 cell 状态。收到历史结果的 writer 停止继续执行，恢复必须重新走正式 owner 入口。

## 运行

依赖版本由本目录 `Cargo.lock` 固定：Rust 1.90.0、指定 commit 的 TiKV raft-rs 和 libSQL、RocksDB 10.4.2、Tonic 0.14.6、Tokio 1.50.0。构建需要 C/C++17、make、libclang 18；测试需要 Linux loopback socket 和启动/杀死本测试子进程的权限。

```bash
CARGO_BUILD_JOBS=2 CXXFLAGS=-g0 \
cargo +1.90.0 test \
  --manifest-path experiments/sqlite-network/Cargo.toml \
  --locked -- --test-threads=1
```

CI 从锁定源码构建 native 依赖。开发环境可复用由相同源码、features 和工具链构建且有 SHA-256 记录的本地静态库以减少重复编译；不得把未核验的预编译库提交到仓库或替代 CI 的源码构建。

每项通过的合同写出独立 evidence 日志，默认路径为本 workspace 的 `target/evidence/sqlite-network/`。可用 `SCAP_SQL_NETWORK_EVIDENCE_DIR` 指向隔离目录。日志包含事件顺序、状态和实际进程/TCP 故障观察；证书私钥、数据库文件和运行日志均不提交。

## 不能据此宣称的能力

这七项测试验证固定三 voter、单 cell、有界合成数据库的正确性与恢复合同。它们不测生产 p99 延迟、跨 AZ RTO、SLO、长期可用性、大库恢复吞吐或容量。夹具等待上限只是防止测试卡死，不能作为性能结果。

它也不包含对外鉴权服务、SQL/Hrana 网络 API、Node.js SDK、自动发现/调度新 owner、动态成员、多 cell、公平队列、S3 归档/休眠/唤醒，以及永久丢失多数副本后的恢复承诺。测试中的 trusted `Admission` 是固定合成身份，不是面向真实用户的认证实现。

正式源码的 100% 单元行、函数、region、分支门禁另外执行；本实验的进程、网络、native 和故障 profile 必须与单元 profile 隔离。运行结果统一同步至 [G0 执行证据](../../docs/engineering/g0-evidence.md)，不能仅凭本 README 的测试定义认定已通过。
