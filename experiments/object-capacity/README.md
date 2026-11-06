# 真实 S3 与 SQLite 的容量验收

本实验复用 `experiments/object-network` 的正式库薄 worker、四进程 SeaweedFS 后端、真实 HTTP 代理和进程管理。实验不实现事务、数据树、恢复或请求指纹算法。worker 使用 `Database::with_options(..., Options::default())`、`activate_session` 和持久 `Session`：默认配额仍为 **10 GiB**，SQL、结果、输入、脏页、缓存和 deadline 预算也保持默认值。

## 两个独立执行档位

| `--profile` | 必须实际完成的工作 |
| --- | --- |
| `gib1` | 提交 1,073,741,824 字节独立随机 BLOB；在 64 MiB 和 1 GiB 数据量处测量 64 KiB 点更新；撤权、旧根、真实 HEAD 200 回包丢失；杀死全部计算进程并删除缓存，杀死并重启全部后端进程，再从 S3 恢复并审计全部原结果和每个 BLOB |
| `default-quota` | 用超过 9 GiB 独立随机 BLOB 实际增长数据库，以至多 64 张真实小表补齐最后少量元数据页，触达 2,621,440 个 4096 字节页，即默认 10 GiB 物理文件配额；同尺寸 UPDATE 仍成功，额外分配页失败且 HEAD 不变；随后完整故障恢复、原结果及全部 BLOB 审计 |

10 GiB 档位的配额口径是 SQLite 主文件的逻辑大小，包含 B-tree、overflow 和 schema 页；不能把 10 GiB 配额误写成 10 GiB 用户 BLOB 容量。实际用户数据字节、文件逻辑大小、文件系统分配字节和后端总分配字节分别记录。最后少量元数据页只用于精确触达边界，主体数据必须是逐个生成、逐个校验的高熵 BLOB，不能使用稀疏文件、全零、重复内容或仅报 `page_count` 冒充大库。

每行 BLOB 为 64 KiB；最多 512 行合为一条多 VALUES INSERT，再附一条 `SELECT random()`，每事务最多 32 MiB 用户数据和两条 SQL。这保留默认 256 条语句上限并给 64 MiB 脏页预算留出 SQLite 元数据余量。若真实运行触发 spill、预算、deadline 或磁盘余量保护，保留失败证据并报告失败，不能放宽默认值后继续声称默认配置通过。

## 运行

前置环境、固定 SeaweedFS 版本与官方压缩包 SHA-256 见 [网络实验说明](../object-network/README.md)。容量后端显式使用 1024 MiB volume 大小、32 个 volume 槽位、关闭 volume 预分配，避免继承小故障实验的 64 MiB × 2 容量瓶颈。运行器只终止自己启动的进程。

先冻结候选源码并保存完整清单，再用同一个 release 构建分别执行两个档位。每次使用全新证据目录：

```bash
python3 experiments/object-network/build.py \
  --target-dir "$PWD/target/object-network-build" \
  --evidence /absolute/path/to/new-build-evidence

python3 experiments/object-capacity/run.py \
  --worker "$PWD/target/object-network-build/release/scap-object-network" \
  --weed /absolute/path/to/weed \
  --build-record /absolute/path/to/new-build-evidence/build.json \
  --profile gib1 \
  --evidence /absolute/path/to/new-gib1-evidence

python3 experiments/object-capacity/run.py \
  --worker "$PWD/target/object-network-build/release/scap-object-network" \
  --weed /absolute/path/to/weed \
  --build-record /absolute/path/to/new-build-evidence/build.json \
  --profile default-quota \
  --evidence /absolute/path/to/new-quota-evidence
```

`build.py` 的输入清单包含两个实验目录下的 Rust/Python 源码、正式 crate 源码、依赖锁和工具链文件。运行前再次检查实际二进制与全部输入摘要。开发诊断可显式以 `--diagnostic` 替代 `--build-record`；这种运行不属于冻结 release 门禁。实验拒绝 `LLVM_PROFILE_FILE`，不向单元覆盖率提供任何计数。

运行会保留私有后端数据以供诊断。单个 10 GiB 档位需要同时容纳 S3 对象、一个 SQLite 缓存、旧不可变对象和测量日志；应预留明显大于 20 GiB 的实际可用空间。每个事务前检查至少还有 4 GiB 空闲空间，触发保护即失败。不要并行运行多个大容量档位。

## 独立证据与完整性判据

控制器使用 `os.urandom` 生成每行独立字节，将至多一个 32 MiB 批次文件写入私有目录并 `fsync`。它独立计算每行 SHA-256 和批次 SHA-256，先将行 ID、长度、哈希、SQL 与调用身份写入公共 `input-ledger.jsonl` 并 `fsync`，再请求正式库生成 canonical Request。完整 Request 也在执行前持久记录。薄 worker 接收文件路径、偏移、长度和哈希，验证实际读入字节后作为 typed BLOB 绑定；它不接收巨型 JSON 字节数组。

每次成功执行的完整 receipt、原始编码结果和已知调用身份立即写入 `ack-ledger.jsonl` 并 `fsync`。receipt 必须与调用方事先准备的整个 Request 和 scope 精确一致。HEAD 响应丢失时，仅通过正式 `lookup` 查证；首次查证为 committed 后保存该原始结果，不重放 SQL。已完成输入文件随后删除，因此最终校验不能依赖本地 BLOB 备份。

恢复后，逐条读取独立 ACK 账本，用执行前保存的 Request 查证，精确比较 **每个** receipt 和完整编码结果，包括 DDL、所有 bulk、点更新及已查证的 UNKNOWN。期望业务行集合仅由独立输入账本和这些已观察 ACK 推导。恢复后的同一个持久 Session 每次强读最多 64 行，薄 worker 对正式查询实际返回的每个 BLOB 计算长度与 SHA-256；控制器逐行比较完整集合，不能以计数、几个样本或恢复后的数据反推期望值替代。

每个成功写入附带的 `SELECT random()` 使原结果核对覆盖非确定性结果保留。失败的超配额请求不会加入 ACK 集合。10 GiB 档位还逐项检查已 ACK 的尾部表确实存在。任何缺行、错值、重复身份、receipt/result 不同或未完成审计都会失败；摘要中的 mismatch 数来自实际比较。

公共产物：

- `history.jsonl`：实际客户端调用与响应、S3 条件请求/响应、阶段、SIGKILL、恢复及全部哈希审计事件；不包含 Authorization 或凭据。
- `input-ledger.jsonl`：独立输入 SHA-256、原 SQL、scope/Request；执行前持久记录。
- `ack-ledger.jsonl`：完整原结果和 receipt；观察成功后持久记录。
- `worker-resources-*.jsonl`：每个 worker 从自己的 `/proc/self` 每 100 ms 记录实际 RSS/VmHWM；身份和采样有效性必须通过检查。
- `resource-samples.jsonl`：每 100 ms 记录共享 cgroup、磁盘余量和已启动的进程身份。
- `summary.json`：真实完成范围、失败信息、完整审计计数、阶段流量、内存、磁盘测量。
- `build-receipt.json`：最终 release 执行复制的构建收据；诊断执行没有该证明。

生成数据、SQLite、后端日志和临时凭据在私有临时目录，不应作为公共 artifact 上传。成功或失败的证据目录都不能覆盖。

## 测量口径与范围

HTTP 代理对每个实际请求记录方法、条件字段、请求 body 字节、返回 body 字节、状态码及耗时，再按阶段汇总 GET/PUT 数与字节。点更新阶段包含 fresh HEAD、变更 chunk、树路径、请求结果索引及正式不可变对象回读，不选择性只统计 payload 上传。1 GiB 点更新的验收上界是每次总 GET 和 PUT body 分别小于 8 MiB、GET 少于 512 次、PUT 少于 64 次；这是证明没有重新传输整库的实验上界，不是生产延迟或费用承诺。摘要同时记录每字节实际写入放大，完整装载和冷恢复各自独立计量。

worker 从自己的 `/proc/self/status` 读取 VmRSS/VmHWM，并持续写入独立资源日志；调用响应也带上即时读数。控制器将自报容器 PID 与自己创建的 Popen 子进程对齐，并核对自报 procfs PID 和启动时间保持一致。每个活过的 worker 都必须有非零且身份一致的有效采样，不能把缺测写成零。当前执行环境的外部 `/proc/<pid>` 视图与子进程命名空间不一致，因此不从外部路径推测 RSS；后端进程的高水位由对自己真实子进程的内核 `wait4` 收集，明确没有后端实时 RSS 轨迹。VmHWM 是内核记录的进程高水位；共享 cgroup `memory.current` 包含别的工作进程和页缓存，不能冒充该 worker RSS。默认 64 MiB SQLite cache 是缓存目标，不是进程硬内存上限。

冷恢复先从 S3 完整、流式重建本地数据库，并做完整 SQLite 校验；此后 Session 持续复用本地文件，每次仍读取最新 HEAD 授权。该实现**不是 lazy VFS**。故障杀死全部计算进程并删除所有计算文件，也重启后端进程，但没有清空内核页缓存，因此是计算进程与文件缓存丢失，不是设备冷启动、断电或跨 AZ 测试。热缓存 HEAD 黑洞必须真实收到 GET、等待 deadline 后失败，不能以缓存返回成功。

本实验仅使用单机 SeaweedFS S3 兼容端点。`aws_endpoint_gate=NOT_RUN`、`production_slo_passed=false` 始终保留；没有验证 AWS Standard、生产部署、跨 AZ 持久性、长期负载、多库公平性或存储回收。GC 仍关闭，所有历史不可变对象保留，后端总分配量不等于当前数据库配额。
