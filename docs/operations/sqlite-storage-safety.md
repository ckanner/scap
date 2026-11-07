# SQLite on S3 的执行存储边界

## 结论

SCAP 通过对象 API 保存不可变物理数据及原请求结果，以每库 HEAD 的条件更新发布事务。它不把数据库文件挂载到 S3，也不让多个节点打开同一份网络文件系统上的 `.db`、`-wal` 或 `-shm`。

SQLite 仍在计算节点上执行，私有镜像必须具备可靠的本地文件 I/O 语义。“本地文件不是持久权威”不等于“本地文件可以放在任意文件系统”：错误的本地读取仍可能影响 SQL 结果及后续上传的物理页。S3 CAS 只能决定哪个候选成为权威，不能修正错误的候选内容。

[PR #28](https://github.com/ckanner/scap/pull/28) 新增目录防护候选。初始保存时工作环境中断，构建、单元测试及覆盖率均为 **NOT_RUN**；后续恢复环境并不自动改变该历史结果。本文定义候选行为及支持边界，实际执行状态见[审查记录](../engineering/status-2026-11-07.md)，不得仅凭文档声称已完成存储安全验收。

## SQLite 官方警告的适用范围

SQLite 官方说明，部分网络文件系统的锁或同步实现不满足其假设，多个进程并发访问可能损坏数据库；默认 WAL 还要求所有访问进程处于同一主机，以共享 wal-index 内存。风险不能只归因于缓存或 `fcntl`，也不能概括为所有 NFS 一定损坏。[S1][S2][S3]

AWS EFS 支持 NFSv4 advisory 字节范围锁，但这种支持不是 SQLite 跨主机共享 WAL 的保证。AWS Mountpoint for S3 明确不提供文件锁；它也不能充当这里的执行文件系统。[S4][S5]

## SCAP 的现有隔离与提交顺序

1. 服务在配置的父目录下为 worker 创建独立临时目录，SQLite 执行器独占创建新的 session 目录和数据库文件。目录权限 `0700`，数据库权限 `0600`；存在的目录及旧 WAL 不复用。
2. 从一次精确 GET 得到 HEAD body 与 ETag，校验当前 scope、权限、请求身份和 owner。对象依赖按哈希校验后物化为私有镜像。
3. SQLite 的提交前 gate 捕获变化页面及完整原结果；先条件创建不可变依赖并回读校验，再使用原 ETag 条件更新 HEAD。
4. HEAD 发布成功后才允许 native SQLite publication；两者完成后才能 ACK。接管、撤权、取消和提交在同一 HEAD 上排序，旧 owner 或旧候选不能换新 ETag 继续提交。
5. 本地执行失败即丢弃私有状态，从对象权威恢复。S3 不可用时失败关闭；不以本地 WAL 或缓存替代远端权威。

代码对应：[服务目录](../../crates/scap-service/src/engine.rs)、[私有镜像](../../crates/scap-object-sqlite/src/file.rs)、[提交 gate](../../crates/scap-object-sqlite/src/gate.rs)、[HEAD 发布与接管](../../crates/scap-object/src/lib.rs)、[条件对象访问](../../crates/scap-object-store/src/lib.rs)。

AWS S3 提供强一致对象访问、单 key 原子更新及条件写，但没有跨 key 原子事务。SCAP 必须自行保证依赖先于 HEAD 发布、身份 fencing、UNKNOWN 查证以及未来 GC 的保护关系。[S6][S7] 本地兼容端点的结果不能代替 AWS Standard 合同验收。

## 新增目录准入

公开函数 `scap_object_sqlite::validate_cache_directory` 用只读目录描述符查询实际文件系统，而不是根据路径名字、前缀或文件扩展名判断。符号链接跟随到实际目标；打开目录或文件系统查询失败均直接返回错误。

服务启动调用同一检查；独立使用 Rust API 时，`ImageBuilder` 在创建前校验父目录，创建后再校验实际私有目录。第二次检查失败时只清理已经独占创建的目录，不删除已有目录或既有数据库。

当前支持范围是 Linux。其他 Unix 平台在文件系统准入时返回 `Unsupported`，没有默认放行或编译期禁止。未经独立实现及验收，不宣称 macOS 等平台能够运行服务；Node SDK 使用者不受服务执行平台的这个限制。

| Linux 文件系统类型 | 准入策略 |
| --- | --- |
| ext2/ext3/ext4 | 允许；仍要求运维保证实际存储栈满足本地 I/O 语义 |
| XFS、Btrfs | 允许；同样需要可靠的底层存储 |
| tmpfs | 允许；容量和内存预算由部署配置控制，丢失后从 S3 恢复 |
| overlayfs | 允许；运维必须确认其 upper/work/backing storage 是支持的本地存储 |
| NFS/EFS、CIFS/SMB、CephFS、AFS、9p | 拒绝 |
| FUSE，包括对象存储挂载 | 拒绝 |
| 其他未知类型 | 拒绝，须评估和测试后才能加入允许列表 |

文件系统编号取自 Linux UAPI 的 `magic.h`；检测通过固定版本 rustix 的安全 API 实现，没有第一方 unsafe 代码。[S8][S9]

## 这项检查不提供的保证

`fstatfs` 只识别当前描述符所属的文件系统类型。它无法完整检查 overlay 的下层挂载、管理员之后的 mount 变更、磁盘固件或所有云块设备故障。允许列表是防误配置措施，不是任意底层存储正确性的证明。执行目录及其挂载命名空间必须由可信运维控制，不能由租户替换。

`PRAGMA temp_store=FILE` 使用的排序等临时文件可能位于 SQLite 选择的另一个 OS 临时目录；`SQLITE_TMPDIR`、`TMPDIR` 等部署设置同样必须指向可信本地存储。本次检查覆盖主数据库及相邻 WAL/SHM，未声称已经约束全部 SQLite 临时路径。

对象数据前缀禁止外部覆盖、删除可达对象及任意 bucket TTL。GC/pin/PITR 尚未完整实现，不能用“缓存可丢弃”替代它们的正确性合同。主文件逻辑配额也不限制对象存储总量。

## 需要执行的验证

新增单元用例覆盖允许类型、已知网络/FUSE/未知类型拒绝、目录打开失败、文件系统查询失败、父目录与新建目录的拒绝顺序及清理。原生用例使用真实本地临时目录，并用指向 Linux procfs 的符号链接验证实际目标检测；这不冒充真实 NFS 挂载测试。

原有私有目录权限、独占创建、旧 sidecar 不复用、HEAD 竞争、迟到 owner、UNKNOWN 与全计算丢失测试继续作为独立门禁。候选源码修改后须重新执行完整 unit 覆盖，行、函数、region、branch 均精确 100%；不能沿用旧提交的绿色结果。

初始候选的编译、fmt/clippy、unit、精确覆盖率、真实 NFS/EFS 挂载、真实 AWS S3 合同均为 **NOT_RUN**。后续按新冻结候选记录实际结果；真实本地目录及兼容 S3 验证、真实网络挂载验证、AWS 合同分别统计，不能相互冒充。缺少所需合入验证时保持草稿，生产发布仍有独立门禁。

## 官方来源

- [S1：SQLite — How To Corrupt An SQLite Database File](https://www.sqlite.org/howtocorrupt.html)
- [S2：SQLite — SQLite Over a Network](https://www.sqlite.org/useovernet.html)
- [S3：SQLite — Write-Ahead Logging](https://www.sqlite.org/wal.html)
- [S4：AWS — EFS data consistency and file locking](https://docs.aws.amazon.com/efs/latest/ug/features.html)
- [S5：AWS — Mountpoint for Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/mountpoint.html)
- [S6：AWS — Amazon S3 data consistency model](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html#ConsistencyModel)
- [S7：AWS — Conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)
- [S8：Linux UAPI — magic.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/magic.h)
- [S9：rustix 0.38.44 — filesystem descriptor operations](https://github.com/bytecodealliance/rustix/blob/v0.38.44/src/fs/fd.rs)
