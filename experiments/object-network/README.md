# 对象原生单库的独立真实故障合同

本实验启动固定 SeaweedFS 4.51 的 master、volume、filer、S3 四个独立进程，和多个实际 Rust worker 子进程。worker 直接调用正式 `scap-object`、`scap-object-store`、`scap-object-sqlite`；SQLite 执行、HEAD 发布、物理恢复、权限、请求结果和 fencing 算法没有在实验里重写。

`run.py` 只负责进程与 TCP 故障编排及观察断言。worker 的标准输入 JSON 是实验驱动接口，不是产品 HTTP API 或已发布 SDK。单元覆盖率与本实验分开执行；设置 `LLVM_PROFILE_FILE` 时实验拒绝启动。

基础合同的小型故障库显式使用 256 KiB 数据配额、每世代 16 个结果条目和 128 MiB 结果保留预算。提交／恢复扩展合同使用独立的 2 MiB 库、每世代 2 条及 128 MiB 原结果预算，便于在关闭旧请求世代后逐项注入故障。这些是测试输入；生产 `Options::default()` 的配额为 10 GiB，管理员可以调整或取消业务配额。[容量实验](../object-capacity/README.md)复用同一正式库薄 worker、S3 进程和代理，分别验证真实 1 GiB 数据与默认 10 GiB 边界；两类结果分开报告。

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

## 基础十项合同

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

## 提交与恢复边界

扩展合同使用独立 scope 和真实正式库调用，保留基础十项。下面的边界分别记录，不能由一次进程退出推断所有切点都已验证。

| 场景 | 必须保留的事实与判定 |
| --- | --- |
| 不可变依赖上传切点 | 先观察一个固定形态事务的实际 PUT 顺序，再对各序号在转发前、后端成功后分别暂停并 SIGKILL；未转发请求显式丢弃，核对 HEAD 未变化、旧数据仍可恢复、未 ACK 的原身份仍为 Unknown |
| 全部依赖完成、HEAD 尚未发布 | 暂停 HEAD PUT 并终止调用进程；依赖已上传的 orphan 不构成提交，旧 HEAD 与原数据不变 |
| HEAD 已接受、调用进程丢失 | 必须先观察真实后端的成功响应，再抑制回包并 SIGKILL；原身份查回 Committed 和原结果，新计算进程恢复对应数据 |
| HEAD 已接受、native 发布失败 | 专用子进程在 HEAD 成功响应屏障处受到 Linux 文件限长故障；观察 `CommittedButUnavailable` 和 receipt、原 Session 拒绝后续新读写、独立查证与全新恢复，不能把普通 UNKNOWN 回包算成此场景 |
| native 已发布、检查点受阻 | 独立只读进程持有旧事务，使正式连接的 TRUNCATE 检查点受阻；同时观察 HEAD 成功、`CommittedButUnavailable`、新本地连接看到新值而旧读者仍看到旧值，再丢弃全部计算状态并核对 S3 原结果 |
| 冷恢复依赖缺失／损坏 | 对当前 Chunk、Node、Manifest 以及保留 Index、Result 分别进行受控删除或条件替换；新 handle 恢复拒绝，HEAD 不变，不自动补空页、空库或退回旧根 |
| 恢复期间 HEAD 改变 | 暂停所选依赖 GET，由另一进程改变 HEAD；旧激活必须拒绝且不能发布新 HEAD，记录变更前后 body／ETag |

文件限长只施加到实验自行创建的专用计算进程，不改变正式配置或生产代码。控制器保留原硬限，只调整软限，并在观察结果后恢复；该进程明确忽略 `SIGXFSZ`，让本地写失败作为错误返回。代理屏障、限长状态、原始错误和后续查证共同定义该场景。没有 syscall trace 时，不宣称直接观察到了特定 errno 或覆盖了每一种 checkpoint 故障。相关操作语义见 Python 官方 [subprocess](https://docs.python.org/3/library/subprocess.html#subprocess.Popen) 与 [resource](https://docs.python.org/3/library/resource.html#resource.prlimit) 文档。

HEAD 已接受但没有 execute ACK 的场景，在计算丢失前由独立 observer 查证并同步完整 receipt 和 encoded result；之后终止包括 observer 在内的全部场景计算进程、删除完整缓存目录，由新进程恢复并逐字节比较。读到 S3 原结果不被改记成 execute ACK。原 Session 的 `StaleSnapshot` 证明它拒绝后续新工作，不单凭这个错误推断内部 stopped 位的独立原因。

这些提交切点对应实际探测到的一种事务依赖序列；它们不穷举任意 SQL、不同树高、分页布局、DDL、截断和所有请求生命周期的组合。闭包冷恢复与已暖 handle 的隔离也须分别报告，不能用冷恢复失败替代暖 handle 的验证。

## ALTER 与原始结果恢复

同一 `run.py` 还执行 `schema_contract.py` 的两个独立 scope：分别通过 `Database.execute` 和暖 `Session.execute` 创建带索引、视图、触发器与外键的表，写入带 `random()` 的原始 `RETURNING`，然后依次重命名表、重命名列、删除列并再次写入。每个场景六笔成功调用的完整 receipt、编码结果和返回行在故障前同步到独立客户端账本，并由另一个实际 worker 查证。

随后 SIGKILL 场景全部计算进程并删除整个本地缓存目录。全新逻辑 worker 通过 takeover 和 activate_session 从 S3 恢复，逐笔核对全部原始 ACK；以原身份再次发送已经提交的六个事务，必须返回原 receipt、编码结果和行，且 HEAD body/ETag 不变、没有任何 PUT。非幂等 ALTER 也参与重发，因此不能靠重新执行迁移来重造结果。

恢复后的全部随机业务值、确切列形状、视图值、触发器写入、索引归属和外键关系均与故障前的独立输入／返回值核对；外键无效写入必须准确产生 FK ConstraintViolation、没有发布且原请求仍 Unknown。该场景不证明所有 DDL 故障切点已覆盖；它与前面的逐发布边界故障和正式 native 单元验证分别报告。

原生 writer 在 SQL 执行失败后停止，现有单元测试明确要求丢弃它。复用 Session 模式先验证原 Session 的下一次查询准确返回 `StaleSnapshot`，再显式 `session_open`，从当前授权的 HEAD 和数据根恢复新缓存并核对全部已提交数据。重新打开同样不能写 HEAD 或任何对象；失败 SQL 不重放。一次性执行模式的失败发生在另一个短期 writer 中，不影响观察用 Session。此前诊断错误地要求失败的 Session 直接继续查询；该失败记录应保留，不能将其描述为 SQL 数据丢失或为实验改变产品语义。

也可使用同一正式 release 的收据单独执行：

```bash
python3 experiments/object-network/schema_contract.py \
  --worker "$PWD/target/object-network-build/release/scap-object-network" \
  --weed /absolute/path/to/weed \
  --build-record /absolute/path/to/new-build-evidence/build.json \
  --evidence /absolute/path/to/new-schema-evidence
```

独立入口在开始与结束时核对构建收据和源输入，缺少二进制或受插桩污染时返回非零的 `blocked`；场景失败、输入漂移、代理或清理失败均不能写入成功结论。

证据为 `schema-input-ledger.jsonl`、`schema-ack-ledger.jsonl`、`schema-audit.jsonl`，以及独立 `summary.json` 或完整运行中的 `schema_contracts`。两种执行路径共十二笔 ACK，故障后查证、重发和 mismatch 计数来自实际账本；`test_schema_contract.py` 是控制器和独立预期值自测，不算作数据库运行通过，也不计入产品单元覆盖率。

## 正确哈希对象中的损坏原结果

`retained_result_contract.py` 覆盖当前与关闭的请求世代，各注入六种内部结果损坏：错误版本头、截断尾部、多余尾字节、未知值类型、非有限浮点数和非法 UTF-8。它重新计算 Result、Index 和 HEAD 引用，并调整结果字节计数，使外层对象格式和哈希仍合法；正式对象解码器必须接受外层，正式 SQL 结果解码器必须拒绝内部内容。

每个场景分别用五个全新 worker 检查 `lookup_identity`、`cancel_identity`、`activate`、`activate_session` 和 `session_open`：准确返回 `Corrupt`，观察到实际 S3 对损坏 Result 的 200 响应，HEAD body/ETag 不变、没有 HEAD PUT、没有遗留恢复目录。之后由私有测试身份恢复原 HEAD 引用，再用新进程核对原始 receipt、结果和数据。十二个场景、六十次入口检查、三十条原始 ACK 必须全部通过；未启动的场景不能计为通过。

```bash
python3 experiments/object-network/retained_result_contract.py \
  --worker "$PWD/target/object-network-build/release/scap-object-network" \
  --weed /absolute/path/to/weed \
  --build-record /absolute/path/to/new-build-evidence/build.json \
  --evidence /absolute/path/to/new-result-evidence
```

该脚本的自测使用明确的控制器替身；构造并检查损坏载荷不等于执行生产 Rust。两套真实合同都需要同一准确 release 的构建收据，并继续将 AWS Standard 与生产 SLO 标记为未验收。

## 生命周期、取消、退休与 owner 交替

`lifecycle_contract.py` 实现[冻结计划](../../docs/engineering/n1-lifecycle-validation-plan.md)的 LC-01–LC-12。 首轮候选 `135ef89` 的真实控制器运行到末尾，但离线审计拒绝 Deleted 恢复的重复调用标签，该轮保留为 FAILED；修复后必须重跑，不能重新标记旧证据为通过。当前实现已经完成夹具自测，**新候选的 Rust 构建与真实生命周期运行仍为 NOT_RUN**；自测结果不能替代下面的独立真实入口。

| 场景 | 必查顺序 |
| --- | --- |
| LC-01–LC-03 | 撤权、Maintenance、Deleted 先成功发布，再放行原 SQL 候选；要求后端真实 412 |
| LC-04–LC-06 | SQL HEAD 后端先返回 200，但响应仍被代理扣住；控制 CAS 随后发布，最后交付原 SQL 的正确 ACK |
| LC-07–LC-09 | cancel 先胜、commit 先胜及取消响应丢失；精确区分 Cancelled、Committed 与 Store(Unknown) |
| LC-10 | 同身份原结果重复返回、变 SQL／参数／主体／未来 epoch 拒绝，以及读型 execute 和零变化 UPDATE |
| LC-11 | 在途候选遇到满窗关闭、原结果保留、完整窗口退休，以及保存的原候选 bytes／ETag 在退休后的条件重发 |
| LC-12 | A→B→新 A2 实例接管、旧 owner 拒绝、旧 expected revision／ETag 拒绝，以及 Ready→Maintenance→Ready 的 revision 推进 |

每场独立 scope，固定 4 MiB 逻辑配额、当前窗口 4 个终态、128 MiB 原结果预算；窗口关闭仍采用正式协议的 current 加两个 closed epochs。这些小输入用于完成有界竞争，不能外推生产默认 4096 条窗口的容量或保留时长。每个实例使用不同 worker identity，原主体 17 和独立管理员 18 由可信 worker 配置进入 API。

维护状态仍允许已授权的强读。撤权场景先验证原主体的新 query／lookup 返回 Denied，再由独立管理员以新的正式控制意图恢复权限；此后才用原主体和原 Request 审计原结果。Deleted 永不恢复 Ready，删除后的 ACK 单列为访问拒绝检查。LC-11 的退休 ACK 单列为 Retired，已提交业务行仍须恢复；不能把这两类计为原结果逐字节恢复成功。填窗取消的 epoch 2／3 用原主体 18 查回同一 cancellation transition，epoch 1 则明确检查 Retired。

每场先 SIGKILL 所有属于该场的计算进程、核对 wait4、删除整个场景计算目录，再用新实例 takeover／activate_session 恢复。随后再次终止所有计算，SIGKILL 并重启四个后端进程，再逐场用新的计算实例复核。Deleted 场景只读取墓碑和验证访问／管理操作拒绝，不反向激活数据库。LC-11 在 worker 原有 8 秒 S3 timeout 内完成关闭竞争；多轮退休后的重发是保存候选的原始条件 PUT，不是重跑 SQL，也不是声称一个 SQL 调用跨越整个退休过程。

```bash
python3 -m unittest discover -s experiments/object-network -p 'test_lifecycle*.py' -v
python3 experiments/object-network/lifecycle_contract.py \
  --worker "$PWD/target/object-network-build/release/scap-object-network" \
  --weed /absolute/path/to/weed \
  --build-record /absolute/path/to/new-build-evidence/build.json \
  --evidence /absolute/path/to/new-lifecycle-evidence
python3 experiments/object-network/lifecycle_oracle.py \
  --evidence /absolute/path/to/new-lifecycle-evidence
```

这个入口必须使用包含 `set_lifecycle` 的新 worker 和完整冻结输入的 release 收据。它不提供 diagnostic 绕过，不继承 unit 插桩，证据目录必须尚不存在。`run.py` 的原有场景不能替代这一独立入口。

控制器同步保存 `lifecycle-plan.json`、`lifecycle-input-ledger.jsonl`、`lifecycle-client-ledger.jsonl`、`lifecycle-ack-ledger.jsonl` 和 `lifecycle-facts.jsonl`，并复用代理的 `history.jsonl`。每次完整调用和响应都有唯一 call ID；成功重复 execute 也逐条进入 ACK 账本。`lifecycle-oracle.py` 不导入控制器或产品转换算法，只读这些文件和 `build-receipt.json`，重新计算全部十二场景、ACK 分类、取消证明、旧候选拒绝、Retired／Closed、撤权和删除访问检查分母。它的输出保存在 `lifecycle-oracle.json`；再次独立执行只向 stdout 输出，不改写原始证据。

oracle 独立核对 SCAPSQL1 fingerprint，严格解码完整 SCAPRES1 字节，并重算包含全部 receipt 字段的 SCAPOBJ2 Result frame 哈希。它还将实际 GET／PUT 绑定 call 时间区间、scope 的物理键和 request serial，检查首次 ACK 对应真实 HEAD 发布、Result 的发布前回读、连续 HEAD revision／ETag、原条件不刷新以及所有进程的实际存活区间。同步修改所有结果摘要、遗漏首次发布、丢失 ACK、把注入错误当后端 412、错误复活 Deleted、虚构后端重启或把 Retired 改成 Cancelled，均有独立负对照。

控制器在关闭代理、终止自有进程并重新检查冻结源码／二进制之后才运行最终 oracle。任何源码漂移、缺失证据、代理错误或清理失败都会使最终 summary 失败。私有后端目录、worker 配置及诊断日志继续保留供审计；`summary.json` 的 `private_diagnostics` 和 `remaining_case_compute_directories` 分别记录保留与计算目录删除状态。私有目录包含夹具凭据，不应作为公开产物上传。

## 原始证据与清理

基础公共产物为 `history.jsonl`、`ack-ledger.jsonl`、`summary.json` 和最终运行复制的 `build-receipt.json`。构建目录另有 `build.json`、`cargo.stdout.jsonl`、`cargo.stderr.log`。摘要中的 ACK 总数与 mismatch 数由实际账本审计计算，没有硬编码“零丢失”。原始历史记录调用／响应、worker 的容器与实际 procfs PID、进程启动身份和 SIGKILL 等待状态、后端前后 PID 与相同目录身份、CAS 的 `If-Match`／ETag、GET/PUT body 字节；不记录 Authorization 或凭据。

扩展合同另保留 `fault-plan.json` 的实际探测序列与逐切点计划、`fault-input-ledger.jsonl` 的调用前身份／输入、`fault-ack-ledger.jsonl` 的实际成功调用、`fault-outcome-ledger.jsonl` 的故障后查证原结果，以及 `fault-cases.jsonl` 的逐场景事实与判定。输入和 ACK 在继续注入前同步到独立客户端文件；HEAD 已持久却没有收到成功响应的请求记入 outcome，不计为 execute ACK。基础四条 ACK 与扩展 ACK 分别全量审计。

临时身份、配置、数据库和后端日志在另一个私有临时目录；成功或失败均保留供诊断，不应上传其中的身份文件。运行器仅终止自己创建的进程，失败也执行清理。故障代理的工作线程异常单独记录并阻断完成标记。

## 证明范围

这是**单机 S3 兼容后端、正式 SQLite 引擎及真实进程/TCP 故障实验**。它没有访问 AWS S3，摘要始终保留 `aws_endpoint_gate=NOT_RUN`、`production_slo_passed=false`；没有验证生产云配置、实际跨 AZ 持久性、设备断电、GC/PITR、多库公平性、长期容量或生产延迟。

基础及扩展合同通过只能证明本次准确构建在实际记录场景中的行为；它们没有被等同为方案 OT-01–OT-08 或 OT-01–OT-15 全部验收，不能代替真实 AWS 对象合同，也不表示 N0–N4 整体完成。同 ETag 的基础竞争仍是原始条件对象 PUT，不构成两个完整 SQL writer 的线性化历史。生命周期、退休与 ABA 的具体十二场景由上述独立入口验收，其实现或夹具自测本身不构成真实运行通过；更完整的组合、GC/PITR 和多库调度仍需后续验证。生产物理 GC 保持关闭；实验中的受控删除只用于故障注入并随后恢复原字节，不能由此声称长期存储成本收敛。
