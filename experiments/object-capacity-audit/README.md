# 固定 1 GiB 合同的独立原始证据与 SQLite 镜像审计

本目录为 `experiments/object-capacity/run.py --profile gib1` 提供独立复审。实际运行仍使用原控制器、正式 release worker、原场景和原预算。这里不实现数据库提交或恢复，也不把小型工具自测计入生产单元覆盖率。

`audit_capacity_gib1_v2.py` 是新的审计工具身份。历史验收摘要曾引用的外部脚本未恢复；新工具及其结果不能冒用旧脚本的哈希或旧验收身份。必须分别记录实际运行的完整源码身份、构建收据和二进制，以及本目录审计/捕获工具的 SHA-256。

## 文件职责

| 文件 | 职责 |
| --- | --- |
| `audit_capacity_gib1_v2.py` | 检查全部原调用、原结果、退出/恢复和 HTTP 见证，并用独立 SQLite 读取完整闭合镜像，核对每个最终 BLOB |
| `capture_closed_image.py` | 在原控制器完成、全部自有子进程退出后，将唯一恢复镜像及已闭合 sidecar 复制到新的目录；保存源/副本全文件哈希与退出时序 |
| `test_audit_capacity_gib1_v2.py` | 审计器的小型拒绝边界测试，不运行实际 1 GiB 场景 |
| `test_capture_closed_image.py` | 捕获工具的危险路径、源变化、非空 WAL、退出见证边界测试，不伪造实际容量验收 |

审计器只从给定源码树加载既有独立只读解析器 `experiments/object-network/{lifecycle_oracle.py,head5_audit.py,audit_build.py}`；不导入容量控制器或产品实现。工具要求 Python 3 标准库以及带 SQLite 支持的 `sqlite3` 模块，禁止 `-O` 和 `PYTHONOPTIMIZE`。

## 运行顺序

先按 [原容量合同](../object-capacity/README.md) 冻结源码、固定环境并生成新的正式 release 构建收据。`SCAP_SOURCE` 是原运行的冻结源码树；`SCAP_AUDIT_TOOLS` 是本目录的绝对路径，可以来自另一个明确记录的工具提交。`SCAP_WORKER`、`SCAP_WEED`、`SCAP_BUILD_RECORD` 和 `SCAP_ACTUAL` 也均使用本次明确选择的绝对路径；不得借用另一源码版本的结果。每次尝试使用全新证据目录，保留失败，不覆盖或续写失败尝试。

```bash
python3 -B -m unittest discover \
  -s "$SCAP_AUDIT_TOOLS" -p 'test_*.py' -v

python3 -B "$SCAP_SOURCE/experiments/object-capacity/run.py" \
  --worker "$SCAP_WORKER" \
  --weed "$SCAP_WEED" \
  --build-record "$SCAP_BUILD_RECORD" \
  --profile gib1 \
  --evidence "$SCAP_ACTUAL"
```

只在原命令返回零、原 `summary.json` 为非诊断 `gib1` 成功后执行捕获。根据原摘要中的 `private_fixture`，确定 `compute` 子树中唯一的 `database.sqlite`，将这个完整原路径显式传给 `SCAP_NATIVE_IMAGE`。不要任选第一个匹配文件。`SCAP_CLOSED_IMAGE_DIR` 必须尚不存在，其父目录须已经存在，并位于原公共证据与原私有状态树之外。

```bash
python3 -B "$SCAP_AUDIT_TOOLS/capture_closed_image.py" \
  --actual "$SCAP_ACTUAL" \
  --source "$SCAP_NATIVE_IMAGE" \
  --destination "$SCAP_CLOSED_IMAGE_DIR" \
  --capture "$SCAP_CLOSED_IMAGE_DIR/capture.json"
```

捕获工具核对三个计算进程、两轮共八个后端进程的原始 owned `Popen`/内核 `wait4` 退出凭据，原缓存删除和后端重启顺序，以及捕获开始时间晚于全部退出。它不从宿主 `/proc/<pid>` 推测另一个 PID 命名空间的进程身份。它拒绝 symlink、原证据目录内的输出、已有目标、非空 WAL/journal 和复制中发生变化的源文件；失败产生的部分新输出保留以便排查。副本必须拥有独立 inode，不能以原数据库的 hardlink 冒充独立复制。

捕获记录包含数据库及 `-wal`、`-shm`、`-journal` 的源前/源后/副本完整字节哈希，原公共证据完整文件清单和前后不变检查。原 SQLite 至少为固定 1 GiB 数据的实际文件大小。这里只复制已经关闭的文件；这一步没有再次从 S3 恢复，也不复制 S3 后端、凭据或整个缓存树。

创建单独、全新的 `SCAP_AUDIT_DIR` 后，执行独立审计。`SCAP_EXPECTED_COMMIT` 是原运行冻结的完整提交 SHA；审计工具可以来自另一个明确记录的源码身份，不能因此改写原构建收据。

```bash
python3 -B "$SCAP_AUDIT_TOOLS/audit_capacity_gib1_v2.py" \
  --repo "$SCAP_SOURCE" \
  --evidence "$SCAP_ACTUAL" \
  --image "$SCAP_CLOSED_IMAGE_DIR/database.sqlite" \
  --capture "$SCAP_CLOSED_IMAGE_DIR/capture.json" \
  --expected-commit "$SCAP_EXPECTED_COMMIT" \
  --manifest-out "$SCAP_AUDIT_DIR/final-blob-manifest.jsonl" \
  --controls
```

用外部记录器分别保存每条原命令的 argv、cwd、开始/结束时间、退出码、原始 stdout/stderr 与哈希。单独保留审计器实际进程的内核 `wait4` `ru_maxrss`；Linux 的该字段单位为 KiB。它是审计器进程高水位，不能当成数据库 worker 的内存指标。实际运行前后还要验证完整源码清单，而非仅核对本目录工具。

## 完整分母与拒绝控制

固定 `gib1` 审计要求原 39 次准备和执行恰好存在、请求身份唯一；38 次原执行 ACK 和一次原 UNKNOWN 保持不同，后者必须由原 warm worker 的真实 committed lookup 得到结果。全部原 39 个结果在丢失后重新查证，receipt 和完整编码字节均与原件一致。额外调用、重复执行、未计划操作以及错绑进程身份都不能通过。

恢复后的 256 个非空 BLOB 查询批次、一个实际空终止查询和相关边界均从原事件中核对。最终期望集合只由执行前输入哈希和真实已观察的原结果推导。独立镜像以 `mode=ro&immutable=1` 和 `query_only` 打开，完整 `PRAGMA integrity_check` 必须通过；逐行读取并重新计算全部 16,384 个实际 64 KiB BLOB 的哈希，即 1,073,741,824 字节，不以行数、摘要账本或抽样代替真实字节校验。

`--controls` 在内存中只复制并改变相应原始记录，不修改证据文件；以下五项必须分别被指定规则拒绝，随后不变正例须再次通过。镜像和全部原证据还需在最后保持相同完整哈希。

| 控制 | 指定拒绝规则 |
| --- | --- |
| `missing_result` | `all-39-original-results` |
| `recovered_result` | `recovered-original-result` |
| `blob_hash` | `every-original-blob-hash` |
| `missing_exit` | `all-owned-compute-exits` |
| `unknown_relabelled` | `original-unknown-preserved` |

## 必须保留的限制

原代理保留请求/响应长度和哈希，不保存所有对象 body。因此本工具检查原 native 恢复执行的完整闭包访问见证和完整恢复镜像，**不宣称独立重建了所有 S3 对象图**。它不读取私有凭据，也不重新计算 SigV4 MAC。原控制器已删除的 bulk 输入文件不能用于重新计算完整历史 typed-SQL 指纹；最终镜像也无法重新计算六个已被覆盖的旧 BLOB 版本。

`object_response` 是后端响应的时间下界；`object_response_delivered` 在写回客户端后记录，可能晚于客户端 ACK 或下一请求的日志。这些事件必须正确配对且保持转发、后端响应、写回记录的内部顺序，不能把这个事后记录伪装成客户端收到最后字节的精确时间。

本工具不证明 AWS Standard、跨 AZ 持久性、生产 SLO 或默认 10 GiB 边界通过，也不补充生产单元覆盖率。未运行项目保留 `NOT_RUN`。小型工具自测成功只允许进入实际验收，不构成 1 GiB 通过。

公共复审包可保存原公共证据、已闭合的随机 fixture 镜像、捕获记录、工具源码、完整源码身份和准确构建工件；不要上传私有凭据、后端卷或重复缓存。原构建收据引用的二进制/native archive 绝对路径应通过恢复原路径或等价只读挂载提供，不能编辑原收据适配新位置。没有原私有镜像时不能重新执行捕获；已保存闭合副本和原捕获记录仍可用于上述独立只读审计。
