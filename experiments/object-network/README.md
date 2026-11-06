# 对象原生单库的独立真实故障合同

本实验启动固定 SeaweedFS 4.51 的 master、volume、filer、S3 四个独立进程，和多个实际 Rust worker 子进程。worker 直接调用正式 `scap-object`、`scap-object-store`、`scap-object-sqlite`；SQLite 执行、HEAD 发布、物理恢复、权限、请求结果和 fencing 算法没有在实验里重写。

`run.py` 只负责进程与 TCP 故障编排及观察断言。worker 的标准输入 JSON 是实验驱动接口，不是产品 HTTP API 或已发布 SDK。单元覆盖率与本实验分开执行；设置 `LLVM_PROFILE_FILE` 时实验拒绝启动。

这里的小型故障库显式使用 256 KiB 数据配额、每世代 16 个结果条目和 128 MiB 结果保留预算，不依赖或改变生产 `Options::default()` 的 10 GiB 配额。新的 [容量实验](../object-capacity/README.md) 复用同一正式库薄 worker、S3 进程和代理，分别验证真实 1 GiB 数据与默认 10 GiB 边界；两类结果分开报告。

## 运行

需要 Linux amd64、Python 3 标准库、curl、loopback TCP、Rust 1.90.0 及正式 libSQL 构建环境。后端版本固定为官方 [SeaweedFS 4.51](https://github.com/seaweedfs/seaweedfs/releases/tag/4.51)，源提交 `153ab668c99731a6d29492bf6c61d0b4fa701101`。官方 `linux_amd64.tar.gz` 的 SHA-256 为 `c03be37416a8ee672c77766e20b22a4e1430744c3af2668599a4b6eeaec14cee`；须先校验再解压。运行器再次校验实际版本，并记录后端与 worker 的二进制摘要。

```bash
cargo +1.90.0 fmt --manifest-path experiments/object-network/Cargo.toml --all -- --check
cargo +1.90.0 clippy --manifest-path experiments/object-network/Cargo.toml --all-targets --locked -- -D warnings
python3 experiments/object-network/build.py \
  --target-dir "$PWD/target/object-network-build" \
  --evidence /absolute/path/to/new-build-evidence
python3 experiments/object-network/run.py \
  --worker "$PWD/target/object-network-build/release/scap-object-network" \
  --weed /absolute/path/to/weed \
  --build-record /absolute/path/to/new-build-evidence/build.json \
  --evidence /absolute/path/to/new-object-evidence
```

`build.py` 实际执行固定 Rust 的 `cargo build --release --locked`，保存原始构建日志、compiler artifact、native libSQL archive、输入文件清单和二进制摘要；构建前后输入必须相同。运行器再次检查构建收据、输入与二进制。两个证据目录均必须尚不存在，不能覆盖失败尝试。维护者的完整候选源码清单仍需在整轮门禁前后核对；这个最小生产/实验输入收据不能代替整仓库身份审计。

仅作开发诊断时，可以显式用 `--diagnostic` 替代 `--build-record`；摘要会标记诊断执行和未核验构建记录。此类运行不能替代最终 release 门禁。

## 必须完成的十项合同

| 合同 | 实际观察 |
| --- | --- |
| 签名与条件对象 | 错误签名拒绝、不可变 Create 不覆盖、错误 ETag 拒绝；单独注入 409 和 412，分别保留 UNKNOWN 与确定条件失败 |
| 同 ETag 竞争 | 两个独立 worker 的 PUT 在 TCP 代理处同步放行；固定八轮中每轮恰有一个成功，精确 GET 与胜者内容一致 |
| 原结果与全计算丢失 | 原随机 `RETURNING` 成功后，SIGKILL 所有计算进程并删除全部 SQLite 缓存；新 worker 仅凭对象及部署身份恢复原结果和 receipt |
| HEAD 响应丢失 | 代理观察真实后端返回 200 后才丢弃响应；调用保持 UNKNOWN，原身份查证及后续查询证明没有重复执行 SQL |
| 在途旧 writer | 暂停旧提交的 HEAD PUT，新 worker 完成接管和激活后再放行；旧条件失败且不能继续写入 |
| 提交／取消竞争 | 分别阻塞提交或取消的 HEAD PUT，验证两种胜序及同身份后续查证 |
| 取消响应丢失 | 取消 HEAD 实际返回 200 后丢弃响应；原调用 UNKNOWN，独立查证仍为 Cancelled，旧业务身份不能执行 |
| 恢复依赖损坏 | 仅在合成测试库中，以受信测试身份条件替换数据对象为坏字节；强读和新执行拒绝，HEAD 不变；精确恢复原对象后重新查询 |
| S3 黑洞 | 实际接收 TCP 请求后停止响应，强读和新写在原 deadline 内失败，不以缓存返回成功 |
| 后端重启与完整 ACK 审计 | SIGKILL 四个 S3 后端进程，原目录重开后逐条核对独立持久客户端账本中的全部业务 ACK、receipt、原结果，以及对应的实际行值 |

每次 `execute` 成功后，客户端在继续故障注入前，将事先已知的 scope／主体／请求世代／请求 ID、原 SQL、返回的 receipt、完整编码结果与 `RETURNING` 行写入 `ack-ledger.jsonl` 并 `fsync`。返回身份必须先与调用身份相符。最终读取该独立账本，逐条查证并精确比较全部四个 ACK（包括 DDL、随机值写入和最后一条常量写入），缺失或不一致使验收失败。最终行集合由已观察的随机 `RETURNING` 和已知常量 700 组成，再与恢复后的完整查询逐值比较；不能由最终数据库反推期望值，也不能用行数代替值校验。

公共产物为 `history.jsonl`、`ack-ledger.jsonl`、`summary.json` 和最终运行复制的 `build-receipt.json`。构建目录另有 `build.json`、`cargo.stdout.jsonl`、`cargo.stderr.log`。摘要中的 ACK 总数与 mismatch 数由实际账本审计计算，没有硬编码“零丢失”。原始历史记录调用／响应、worker 的容器与实际 procfs PID、进程启动身份和 SIGKILL 等待状态、后端前后 PID 与相同目录身份、CAS 的 `If-Match`／ETag、GET/PUT body 字节；不记录 Authorization 或凭据。

临时身份、配置、数据库和后端日志在另一个私有临时目录；成功或失败均保留供诊断，不应上传其中的身份文件。运行器仅终止自己创建的进程，失败也执行清理。故障代理的工作线程异常单独记录并阻断完成标记。

## 证明范围

这是**单机 S3 兼容后端、正式 SQLite 引擎及真实进程/TCP 故障实验**。它没有访问 AWS S3，摘要始终保留 `aws_endpoint_gate=NOT_RUN`、`production_slo_passed=false`；没有验证生产云配置、实际跨 AZ 持久性、设备断电、GC/PITR、多库公平性、长期容量或生产延迟。

十项通过只能证明本次准确构建在这些场景中的行为；它们没有被等同为方案 OT-01–OT-15 全部验收，不能代替真实 AWS 对象合同，也不表示 N0–N4 整体完成。当前实验保留全部对象，不能由此声称存储成本收敛。
