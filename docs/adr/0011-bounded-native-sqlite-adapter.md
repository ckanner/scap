# ADR-0011：正式 SQLite 提交适配与完整镜像恢复

- 日期：2026-10-31。
- 状态：有界正式模块；完整 SQL 服务、生产 RPC、SDK 和自动接管仍未完成。
- 延续：[ADR-0010](0010-cell-acceptance-and-raft-safety.md) 的业务接受与故障合同。

## 背景

上一阶段的 SQLite/cell 实验证明了真实提交前 gate 与物理页恢复，但引擎装配依赖夹具 SQL、测试专用版本表和非正式页格式。它不具备通用参数/结果、前置幂等查询、独占恢复目录或正式源码覆盖率，不能直接成为运行时依赖。

本阶段把边界迁入正式模块，同时保持所有第一方源码的精确 100% 单元行、函数、region 和分支门禁。单元覆盖与真实共识/故障证据分别采集。

## 决策

1. `scap-sql` 负责有界 SQL 请求类型、精确请求 fingerprint 和完整结果 codec。fingerprint 绑定版本、原始 SQL 与有序的类型化参数，区别于物理事务摘要；不推断两个 SQL 文本的语义等价。
2. `scap-engine` 负责 `SCAPIMG!` v1 页事务、完整逻辑镜像及恢复。每笔事务绑定完整数据库身份、前序 revision、前序镜像摘要与结果镜像摘要；4096 字节页按严格递增顺序编码。空页事务只允许镜像大小不变，仍推进 revision。
3. `scap-sqlite` 复用固定 libSQL commit 的 C 内核与 virtual WAL。连接私有，线程受限，输入为完整 statement batch；不公开 raw connection 或任意执行 closure。显式 `BEGIN IMMEDIATE`，缓冲全部结果，最终 `COMMIT` 的 WAL 回调在 native 发布前提议不可变物理事务。
4. 成功仍要求 durable quorum、cell 业务 Accepted、native 发布和完整 SQLite COMMIT 成功。`Prepared::accepted` 仅校验回执，不自行证明 quorum，也不代表 native 已发布。
5. SQL 执行前先做当前授权与线性化请求查询，解决重复 DDL/唯一键 INSERT 在 gate 之前报错的问题；gate 再裁决一次并发竞争。历史提交返回原 ticket 与原结果，新 staged pages 必须丢弃。未找到不等于取消，也不授予自动重试 UNKNOWN 的许可。
6. 无 dirty pages 的成功事务没有 WAL 回调。此时在 SQLite COMMIT 返回成功后，提交同镜像的空页记录与完整结果，cell 接受后才 ACK。当前接口中的 SELECT 也采用该路径；它不是独立的 ReadIndex-only SQL 读接口。
7. worker 每次启动都从经过 Safe ReadIndex、`decode_bound` 和精确 tip 绑定的完整 cell 历史重建。只新建专用目录和数据库文件，拒绝复用旧目录、旧 SQLite/WAL 或 sidecar。同步文件、目录和父目录，在资源与安全限额生效后做结构 `integrity_check`；检查期间临时忽略可能依赖旧连接状态的 CHECK，随后必恢复强制约束，任何失败均不发布连接。通过后才使用。运行期 head 只保存在受控内存中，并在整个 COMMIT 完成后推进。
8. SQL authorizer 默认拒绝未声明动作和函数，禁止用户事务控制、ATTACH、PRAGMA、临时库、虚表、扩展加载和外部文件访问。SQL 长度、参数、结果、页变化与 VM 指令预算均有界。任何异常停止当前 writer；panic 在返回 C ABI 前捕获。

## 取舍

完整逻辑镜像避免了“本地版本 sidecar 已前进、SQLite 尚未发布”的恢复窗口，也不要求在业务 schema 插入版本表。镜像 hash 表示合并 WAL 后的逻辑页，不是尚未 checkpoint 的 main file hash。cell commit hash 则保护另一层的接受历史，二者不混用。

代价是每笔写入复制和摘要计算与数据库大小相关，重启需要完整历史重放。当前模块不能据此宣称达到 1 GiB 恢复、长期运行内存预算或 p99 延迟目标。cell 仍保留全部已接受事务，没有归档/GC；存储布局改进与增量恢复必须另立验证。

`SCAPIMG!` 是首次正式引擎格式，不兼容旧实验 `SCAPPG01`。旧实验继续作为独立证据保存，不提供把实验磁盘数据直接升级成正式数据库的承诺。

不在本阶段引入完整 sqld 服务依赖树；先直接集成 `libsql-sys`。Hrana/Node.js 兼容、interactive transaction、savepoint API、独立强读、生产身份与网络 transport 仍需后续实现。这些边界不能通过放宽提交或覆盖率合同来规避。

## 验证与后续条件

正式模块使用窄端口注入共识与文件系统效果；所有错误路径计入单元分母。独立 [SQLite adapter 实验](../../experiments/sqlite-engine/README.md)使用真实 RawNode/RocksDB、正式引擎和 writer 子进程，验证物理提交、幂等、无变化事务、分区、fence、快照与接受后退出恢复。具体已完成计数统一记录在 [执行证据](../engineering/g0-evidence.md)，不以本文代替测试日志。

完整 HA 服务仍需生产 peer transport/mTLS、受控任务调度、端到端客户端、owner 故障检测及恢复编排、长期容量与性能验证。S3 归档继续位于同步提交之后，不能替代实时多数派。
