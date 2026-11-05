# 有界控制回执的真实故障实验

本目录验证 v5 行政控制序列与“每库一个最新回执”合同。它是独立 experiment workspace，不进入第一方生产单元覆盖率。测试命令、故障调度和断言留在实验目录；共识、持久应用、权限检查、SQLite 恢复和 S3 归档均调用生产库。

源代码存在、编译成功或检查器单元测试通过，都不等于真实故障实验已经通过。运行结论只来自一个完整、封闭、由 `check_evidence.py` 校验的证据目录。

## 验证范围

| 合同 | 实际执行与判定 |
| --- | --- |
| 旧表容量 | 将本实验的旧兼容探针编译到精确固定的 v4 生产源码上。三个独立 voter 真实接受 Create、ClaimOwner、ActivateOwner 和 4093 次 AuthFence；第 4097 个新的旧式操作返回 Capacity。 |
| 满表升级 | 关闭旧进程后复制其真实 RocksDB 目录，候选 runtime 以 OpenExisting 打开并有序激活 v5。4096 个旧回执保留；已知旧操作重试仍匹配；未知旧 ID 返回 ControlRetired；新的控制序列继续接受 AuthFence、ClaimOwner、ActivateOwner。 |
| 超过4096次新控制 | 另一个真实三 voter cell 连续接受 4097 次带原始预期序列的 AuthFence。逐条记录成功位置、控制序列、操作 ID 和 auth epoch。压力段每128次观察实际编码状态大小并 checkpoint，大小必须恒定。 |
| 精确重试与永久边界 | 最新操作返回 ControlAlreadyApplied 和原始 ControlResult，包括原始 term/index；更旧序列及未知旧 ID 关闭。每次重试仍使用当前有权 principal。 |
| 真实冷循环 | 正式 Controller 经固定版本 SeaweedFS 上传、读回校验、发布、Prune、Hydrate；原 SQLite 内容与原请求结果逐字节保留。Hydrate 后延迟到达的旧 Prune 返回 ControlRetired。 |
| 丢失 Publish 返回 | 在正式 runtime 已给出持久提案结果后，可信端口丢弃返回。实验解码并核对确切 Publish 命令、ControlApplied、下一序列、原始位置和 archive digest；随后插入其他控制操作，旧 Prune 关闭。已确认但过时的 PublishedArchive 也不能用于 Prune。 |
| 丢失 Hydrate 返回 | 同一故障边界丢弃真实持久结果。重发捕获的原始命令字节得到原始回执；另一控制操作后，旧 Hydrate 返回 ControlRetired。不会自动改用新序列重发旧意图。 |
| Claim / Activate 崩溃 | Native Writer::recover 在正式 OwnerClaimed 或 OwnerActivated 持久结果之后暂停；父进程真实 SIGKILL。新 owner 在新缓存目录恢复，旧 activation 被序列和 owner token 双重边界拒绝。 |
| 快照与重启 | 三个来源 voter 均 checkpoint 到指定权威观察之后，再正式加入第四个 learner。关闭 learner 后直接检查其实际 RocksDB 快照：新控制仅保留一个回执、控制序列和原 SQL 结果完整。对真实快照字节进行纯内存正式状态机重试检查，验证最新槽的原始位置；这项检查不计作新 durable commit。全部 voter 重启后，再经真实 quorum 重试同一最新控制命令，核对同一原始回执。 |
| 真实服务升级 | 独立冻结的 v4 `scap-server` 创建热数据、请求结果及真实冷 archive；候选服务在同一目录升级，完成冷恢复、leader SIGKILL、全部进程重启。 |
| 混合代际与回退 | 两个旧 peer 和一个新 peer 之间不注入网络隔离；旧 quorum 的新进展不能被单个新 peer 应用，其读写探针拒绝。三个升级目录逐个由旧 daemon 打开，必须因 STORE_APPLICATION 失败；端口、配置或文件锁错误不能充当版本拒绝。 |

`successful_new_controls: 4097` 指压力段的4097个 AuthFence 成功提交。冷生命周期、owner 恢复、升级以及精确重试另有原始记录，不混入该压力段计数。

## 进程与边界

Rust `contracts` 与 `legacy` 各自启动三个 voter OS 进程、独立 RocksDB、真实 mTLS/TCP 和正式有界 network workers；第四个进程起初只是预信任但未加入的 genesis 节点。stdin/stdout 仅用于本机受信任的测试指令与观察，Raft payload 不走该管道。没有生产调试 HTTP 入口。

Publish/Hydrate 返回丢失发生在 runtime → Controller 的同步受信任端口边界。S3 上传和读取、Raft 复制和 durable quorum 仍是真实的。端口保留被丢弃命令与结果的原始编码、term/index 和 proposal ticket；它不会合成一个“成功”结果。该实验验证丢失已持久返回后的控制语义，不把这个边界故障说成互联网数据包测量。

Rust cell 使用有限的小型 SQL fixture：8 MiB cell 状态、4096 旧行政回执上限、128 请求、256 KiB SQLite 图像、300 KiB transaction；数据库数、policy、command/result 等界限比完整服务更窄，详见 `src/common.rs`。Node 阶段使用实际服务部署与其原有 profile。没有放宽生产容量以通过实验。

所有 SQL 写只执行一次既定调用；UNKNOWN 不触发 SQL 重放。异步冷恢复期间只有新的只读观察可以再试，每次失败都会留在 `requests.jsonl` 和 `http-attempts.jsonl` 中。实验中的有限超时和吞吐不属于生产 SLO 验证。

## 旧源码和二进制身份

冻结 daemon 与旧 fixture probe 是两个不同的可执行文件，不共用 SHA 或构建证明：

- 本地默认 v4 daemon SHA256 为 `52e81c031af6202ef4a41b2b8fab59d3cf202f56af51161951e7eb85f115b68b`，对应已验证的运行时源码提交 `fa34c955ab8bcb1895e1348184bd0687d07833f8`。
- CI 的旧源码默认固定到 `f14b03d03d9216ea56b78aef9d71c5d78fd83645`，tree 为 `43131a1599d2e20b4865025e2040a0796ee9cd80`。本地文档收尾提交 `99e1e31cab1fd23fa25a64211671f9ceb56d8058` 的 tree 与它相同；构建脚本允许显式选这个本地对象。
- `build_legacy.py` 只从允许的精确 git commit 导出独立源树，再放入本实验的旧兼容驱动。它不修改原仓库或任何序列化状态。它锁定依赖和工具链，保存实际构建命令、封闭 stdout/stderr、所有生产和实际编译 fixture 输入的前后 SHA 校验，以及输出 probe 的独立 SHA。编译时把所选 commit/tree 绑定进旧测试可执行文件。
- CI 可通过 `SCAP_CONTROL_OLD_SERVER_SHA256` 和 `SCAP_CONTROL_OLD_SERVER_SOURCE_COMMIT` 指定其重建旧 daemon 的实际 receipt；不能假定跨环境重建得到与本地冻结 release 相同的 SHA。源码仍必须属于上述固定 v4 身份。

## 构建

先提供 Rust 1.90.0、锁定依赖缓存和工具配置。两个密集控制探针均使用 release profile；普通 `assert!` 仍执行，4096/4097 次操作、压力段每条控制命令的5秒预算和600秒场景预算保持原样。不要与完整单元 coverage 构建共用 profile 输出。

CI 由 Cargo 从锁定的 `librocksdb-sys 0.17.3+10.4.2` 源码构建静态 RocksDB。若本地通过 `ROCKSDB_LIB_DIR` 使用已有库，须根据该库原有构建证明选择 release 产物，设置 `ROCKSDB_STATIC=1`、`SCAP_CONTROL_NATIVE_PROFILE=release` 和 `SCAP_CONTROL_NATIVE_SHA256`。后者必须是已选择的 release 库 SHA256；旧 probe 构建脚本在编译前后核对，下面单独调用的候选收据生成器在编译后核对，外层构建流程另行保存候选编译前的 native 校验。目录名称本身不证明编译 profile。收据明确区分 Cargo 源码构建和外部固定库，不声称从二进制反推出原始编译器参数。

构建候选测试可执行文件：

```bash
probe_build_dir=$(mktemp -d /tmp/scap-control-current-build-XXXXXX)
cargo +1.90.0 test --release --offline --locked \
  --manifest-path experiments/control-network/Cargo.toml \
  --test contracts --no-run --message-format=json \
  > "$probe_build_dir/cargo.jsonl" 2> "$probe_build_dir/cargo.stderr.log"
```

从 Cargo 的 `compiler-artifact` 记录选择 `target.name == "contracts"` 的 `executable`，保存为候选独立二进制，并设置 `SCAP_CONTROL_TEST_BIN`。不要把某个同名旧测试程序误作本次构建产物。记录原始构建输出、实际编译 profile、复制后的二进制和真正链接的静态 native 输入：

```bash
python3 experiments/control-network/record_probe_build.py \
  --cargo-json "$probe_build_dir/cargo.jsonl" \
  --cargo-stderr "$probe_build_dir/cargo.stderr.log" \
  --executable "$SCAP_CONTROL_TEST_BIN" --target contracts \
  --output "$probe_build_dir/probe-build.json" -- \
  cargo +1.90.0 test --release --offline --locked \
  --manifest-path experiments/control-network/Cargo.toml \
  --test contracts --no-run --message-format=json
export SCAP_CONTROL_PROBE_BUILD_RECEIPT="$probe_build_dir/probe-build.json"
```

构建真实旧源码 probe：

```bash
python3 experiments/control-network/build_legacy.py \
  --repository /absolute/path/to/repository-containing-pinned-commit \
  --output /tmp/scap-control-legacy-build-unique
```

本地若只有相同 tree 的 `99e1e31...` 对象，可增加：

```text
--commit 99e1e31cab1fd23fa25a64211671f9ceb56d8058
```

脚本使用相同的 release 构建要求，最后返回 JSON：`executable` 是旧 probe，`receipt` 是完整来源收据，其中 `probe_build` 包含实际 Cargo 与 native 记录。分别赋给 `SCAP_CONTROL_LEGACY_TEST_BIN` 和 `SCAP_CONTROL_LEGACY_SOURCE_RECEIPT`；若显式改了 commit，同时将 `SCAP_CONTROL_LEGACY_SOURCE_COMMIT` 设置成相同值。旧 probe 不需要修改根 workspace member；本包自带 `[workspace]`。

## 完整运行

必须显式提供绝对路径：

| 环境变量 | 内容 |
| --- | --- |
| `SCAP_SERVER_BIN` | 本次候选服务二进制 |
| `SCAP_OLD_SERVER_BIN` | 固定 v4 服务二进制 |
| `SCAP_CONTROL_TEST_BIN` | 本次候选 Rust `contracts` 可执行文件 |
| `SCAP_CONTROL_PROBE_BUILD_RECEIPT` | `record_probe_build.py` 的候选 release 构建收据 |
| `SCAP_CONTROL_LEGACY_TEST_BIN` | 来源收据绑定的旧 Rust `legacy` 可执行文件 |
| `SCAP_CONTROL_LEGACY_SOURCE_RECEIPT` | `build_legacy.py` 的完整构建收据 |
| `SCAP_SEAWEEDFS_BIN` | SeaweedFS 4.51，commit `153ab668c99731a6d29492bf6c61d0b4fa701101` |
| `SCAP_CONTROL_EVIDENCE_DIR` | 独占、初始为空的 `/tmp` 子目录 |

`SCAP_SEAWEEDFS_MODE=separate` 使用真实 master、volume、filer 和 S3 进程；`mini` 也必须是同一固定真实后端。runner 自动注入临时 S3 凭据到私有子进程环境。

```bash
node experiments/control-network/run.mjs
python3 experiments/control-network/check_evidence.py /tmp/scap-control-evidence-unique
```

Node SDK 须先按仓库原有流程构建。不要设置 `LLVM_PROFILE_FILE` 或 `NODE_V8_COVERAGE`。正常完整运行含 4096 个旧控制和至少4097个新控制，且进行实际网络与冷恢复，不是快速单元检查。

外层 console 日志应写在证据目录之外。runner 要求目录最初为空，而且 `closed-manifest.json` 必须只覆盖已经关闭的文件；不能把仍由外层 shell 写入的日志提前算作封闭证据。候选、旧 probe、helper 和 SDK 的源身份必须在执行期间保持不变。

## 证据检查与保存

成功路径先关闭客户端、daemon、probe 和 S3，再生成完整 `closed-manifest.json`。检查器逐项核对文件 SHA 和长度，拒绝缺少、额外、链接、重名或被改写的文件；重复 JSON 键、非有限时间及有歧义的整数类型也会拒绝。

runner 原样保留两个探针的 Cargo JSONL 和 stderr。检查器将收据中的 profile 与原始 `compiler-artifact` 逐项比对，要求测试和 native Rust binding 均为 release 优化构建，并核对 native build-script 的静态链接输入。构建完成不代表任何真实故障合同已通过；此前失败的 debug 运行仍保留其原始失败结论。

检查器还直接读取三个实际状态编码：`legacy-full-state.bin`、`legacy-upgraded-state.bin`、`learner-state.bin`。它核对版本和 SHA256 envelope，独立计数4096个保留旧回执和一个最新控制槽，检查原始回执位置，并比对原请求结果哈希。它不会修复、重写或再次提交任何命令。

```bash
python3 -m unittest discover -s experiments/control-network -p 'test_*.py' -v
```

检查器单元测试中的人工 byte fixture 只用于验证审计器拒绝损坏与矛盾证据；它们不是旧状态生产器，也不能进入真实故障证据目录。

发生失败时保留原始 `failure.json`、各测试日志及已完成请求记录，另建新目录进行下一次完整运行。禁止截去失败尾部、复用成功片段或覆盖丢失的原始记录。进程全部关闭并通过检查器后，才将整个目录复制到持久工作区，并再次逐字节或按 SHA 验证复制结果。原始 private RocksDB、证书和 S3 目录保持在单独的 `/tmp` fixture 下，不提交到仓库。
