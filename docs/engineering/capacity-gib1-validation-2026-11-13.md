# 固定 1 GiB：原实际与独立全量审计

2026-11-13 本轮结果为通过。实际使用冻结
`b15bc455349ea36162b8004c2c73fc7d812d4c10` 的原
`experiments/object-capacity/run.py --profile gib1` 和正式 native release；没有改变
工作量、预算、故障点或数据库容量。接续审计／捕获工具的提交为 `642383c`，它们是
独立观察器，不把实际生产来源改成该 commit 或之后的文档提交。

精确源码清单、正式构建 receipt、原命令、原始报告与哈希汇总于
[机器记录](../evidence/capacity-gib1-local-2026-11-13.json)。早先
[工具单元记录](../evidence/capacity-audit-tools-2026-11-13.json)保留其提交时
ACTUAL_NOT_RUN 的历史含义；28 项工具测试不替代这里的实际。

## 原实际的结果

| 观察 | 完整结果 |
| --- | --- |
| 原固定 actual | 370.425 秒，退出 0；394 次 client 调用、34,862 个 S3 HTTP 请求 |
| 原事务身份 | 38 个 execute ACK、1 个 UNKNOWN；UNKNOWN 通过原身份 lookup 查证，未重标成原 ACK |
| 冷恢复后原结果 | 39 份原 lookup 逐一一致，结果失配为 0 |
| 数据 | 256 批、16,384 个 BLOB，共 1,073,741,824 字节；全部重新读取并逐项核验哈希，失配为 0 |
| 关闭镜像 | 1,082,163,200 字节，包括 SQLite 页面及结构开销；完整 integrity_check 为 `["ok"]` |
| 原进程终态 | 3 个 compute、8 个 backend，共 11 个 owned wait4；无 cleanup 或 proxy errors |
| 独立审计 | 捕获 12.753 秒；审计及全部控制 42.655 秒，分别退出 0；原文件和源码核验不变 |

原 30 秒 operation、30 分钟 recovery 预算、8 秒 S3 超时和 4 GiB 启动磁盘检查未扩大。
热缓存 HEAD blackhole 观察为 0.205 秒，在原 2 秒拒绝门内。它只证明该固定故障下
及时失败关闭，不是正常提交延迟或生产 SLO。

## 关闭镜像与审计边界

捕获只在全部 11 个实际子进程退出后开始，拒绝符号链接和不合法的文件状态，逐块
复制完整镜像并 fsync，核对源前后与副本 SHA。原镜像及其侧文件保持不变；最终 WAL
长度为 0，SHM 为 32,768 字节，journal 不存在。镜像 SHA-256 为
`bd5d9e2906d172c4bbacf2a5ff9274c8361714ceacfcea03e214b0ae544e6998`。

新审计器检查原命令与回收记录、全部原事务结果、冷恢复查证和最终每个 BLOB；以
外部 SQLite 3.53.1 的 `ro&immutable=1` 打开关闭副本执行完整 integrity_check。这个
只读审计版本不是运行时固定的 libSQL/SQLite 版本，也没有替换生产 native 引擎。
审计器由单独父进程 wait4 回收，其 max RSS 为 471,140 KiB；这不是产品进程的
内存上限，也不是已实现硬隔离的证据。

原 driver 的 `ACTUAL_AND_IMAGE_CAPTURE_COMPLETE_INDEPENDENT_AUDIT_REQUIRED`
摘要原样保留，最终通过来自另一份独立审计结果，未覆写原摘要来制造成功。
718 个跟踪源码文件前后及最终清单相同，正式二进制与构建输入单独核验。

## 全部控制

| 反例 | 必须触发且实际触发的拒绝条件 |
| --- | --- |
| missing_result | all-39-original-results |
| recovered_result | recovered-original-result |
| blob_hash | every-original-blob-hash |
| missing_exit | all-owned-compute-exits |
| unknown_relabelled | original-unknown-preserved |

5 个反例均被对应 guard 拒绝，未修改原历史的正对照通过。控制是同一实际证据的
变异审计，不是另外 5 次容量运行。原报告字段 `ack_audited_count=39` 表示审计的
原结果身份数；原执行 ACK 仍是 38，另一个原执行结果仍是 UNKNOWN。

## 未认证的范围

这次完整审计没有重新从 S3 独立构造第二个数据库：原 native activation 已遍历并
验证对象闭包，审计器检查其原网络见证和全部最终镜像；原代理只保留部分对象的
哈希与长度，不能凭此宣称独立重建每个 S3 对象。独立审计不读取私有密钥，也不
宣称重新计算全部 SigV4 MAC。

原控制器已删除的批量随机 SQL 输入和被覆盖的 6 个历史 BLOB 版本无法从最终镜像
重新逐字节构造，此限制保留；不把最终全 BLOB 审计扩大成所有历史中间版本审计。
本次 GC 关闭，冷恢复仍完整加载，非 lazy VFS。默认 10 GiB、fd508 候选的容量实际、
真实 AWS Standard、跨 AZ 故障、长期多库公平性及生产 SLO 均为 NOT_RUN。
容量通过不补足 Rust 的分支测量缺口，也不签发整体 merge-ready。
