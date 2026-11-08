# SQLite on S3 的执行存储边界

## 结论

SCAP 通过对象 API 保存不可变物理数据及原请求结果，以每库 HEAD 的条件更新发布事务。它不把数据库文件挂载到 S3，也不让多个节点打开同一份网络文件系统上的 `.db`、`-wal` 或 `-shm`。

SQLite 仍在计算节点上执行，私有镜像必须具备可靠的本地文件 I/O 语义。“本地文件不是持久权威”不等于“本地文件可以放在任意文件系统”：错误的本地读取仍可能影响 SQL 结果及后续上传的物理页。S3 CAS 只能决定哪个候选成为权威，不能修正错误的候选内容。

[PR #28](https://github.com/ckanner/scap/pull/28) 已合入目录防护，并完成冻结候选 `a11e61e` 的编译、204 项 Rust 单元、24 个生产文件四维精确覆盖及真实本地回归，见[验收记录](../engineering/local-storage-validation.md)。初始环境中断时的 NOT_RUN、随后格式与构建失败仍保留；成功只绑定实际验证的源码，不改写旧记录。真实网络挂载、AWS 和生产故障域仍是独立验证。

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

## 固定内核与单库并发边界

截至 2026-11-08，本仓库固定 libSQL revision `d8bc862d20bedc72945a1da27c8b7045414c0261`，其 bundled SQLite 标记为 `3.47.0`。[锁定依赖](../../crates/scap-object-sqlite/Cargo.toml)与[上游固定源码](https://github.com/tursodatabase/libsql/blob/d8bc862d20bedc72945a1da27c8b7045414c0261/libsql-ffi/bundled/src/sqlite3.c)可以直接核对；不能把上游最新发布的修复视为本仓库已经包含。

SQLite 官方在 2026 年公开 WAL-reset 缺陷：同一文件上的多个连接同时写入／checkpoint 时，特定竞态可能破坏页面；官方修复版本包括 3.51.3 及以后，以及 3.44.6、3.50.7 回补版本。[S3] SCAP 当前每份私有镜像只有一个连接，由所属线程串行使用，关闭自动 checkpoint，并在该连接完成权威与 native publication 后显式 TRUNCATE；独立 reader 另建私有文件，不共享 writer 的 WAL。这一拓扑排除了官方描述的触发前提，S3 本身没有修复 SQLite 内核缺陷。

因此，未来增加同一执行文件的读连接池、独立后台 checkpoint 或替换内核前，必须重新审查固定 revision 的修复、原生提交前 gate 与并发故障合同。跨数据库并行可继续使用不同私有镜像；它不要求把多个线程放进同一份 WAL。单库提交仍按 HEAD 串行发布，其吞吐取决于 SQL、变化页、依赖回读和对象往返，不能以数据库数量的横向扩展推导单库写入能力。

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

## 独立临时文件目录准入

本候选在每次正式 native 连接打开之前，对固定 Unix VFS 的全部候选目录执行同一目录描述符 `fstatfs` allowlist：`SQLITE_TMPDIR`、`TMPDIR`、`/var/tmp`、`/usr/tmp`、`/tmp`、当前工作目录。空环境变量忽略；打开时明确不存在的候选跳过且不创建，权限错误、非目录和其他打开失败直接拒绝；已打开目录的查询错误即使是 `NotFound` 也不能当成候选不存在。任意已存在候选是 NFS/FUSE/未知类型即拒绝，即使排在它之前的本地目录当前可用。这是刻意保守的准入，不复制 SQLite 当前一次的可写性选择后忽略其他回退路径。[S10][S11]

固定 VFS 还会优先使用进程全局 `sqlite3_temp_directory`。正式文件连接打开前先建立一个私有内存连接，通过安全 rusqlite API 读取 `PRAGMA temp_store_directory`，任何返回值都拒绝；不接受宿主事先设置的全局覆盖，即使它指向本地目录。该查询在固定 pragma 表中不要求读取文件 schema。拒绝早于 libSQL 文件连接打开时的内部 `journal_mode=WAL` SQL；后者会要求 schema 初始化，不能把 libSQL 的打开过程误称为尚未执行内部 SQL。正式连接配置时再次验证覆盖仍不存在，然后才执行配置、结构扫描和业务语句。SCAP 不写这个全局变量，不执行全局目录切换，也不修改进程环境。[S11][S12]

这些检查要求默认的固定 Unix VFS，不支持宿主注册的 auto-extension。`SQLITE_TMPDIR` / `TMPDIR` 的指针在首次 SQLite 初始化时缓存，所以环境和工作目录必须从**首次 SQLite 初始化之前**到整个进程退出都保持不变；不能在初始化后换环境值再依赖一次新检查。宿主不得并发改变全局临时目录或注册替代 VFS，运维不得在准入后新建、替换或重新挂载候选目录。以上属于与主执行目录相同的受信任进程和命名空间边界，不是对恶意宿主的沙箱。

`PRAGMA temp_store=FILE` 保持不变，排序等工作仍可溢出到通过准入的本地文件系统。没有将所有临时数据搬入内存，也没有把页面缓存配置当成硬 RSS 或磁盘预留。临时文件类型和位置取决于固定 SQLite 实现；更换内核、VFS 或打开路径时必须重新审查。主文件、相邻 journal/WAL/SHM 与独立临时目录分别检查，公开 SQL 仍不能使用 ATTACH、任意 PRAGMA 或扩展来另开存储路径。[S10]

本候选的新增单元与真实回归状态单独记录；此处描述实现和适用前提，不把 PR #28 的旧验收自动归给它。测试包含默认/空/缺失/非 Unicode 环境、低优先级不安全目录、打开和查询失败，以及独立子进程的真实目录、procfs、symlink、工作目录和宿主全局覆盖。子进程只改变自己的启动环境，全局覆盖注入也只发生在单线程的新进程，父测试进程不变更共享 SQLite 全局状态。

## 这项检查不提供的保证

`fstatfs` 只识别当前描述符所属的文件系统类型。它无法完整检查 overlay 的下层挂载、管理员之后的 mount 变更、磁盘固件或所有云块设备故障。允许列表是防误配置措施，不是任意底层存储正确性的证明。执行目录及其挂载命名空间必须由可信运维控制，不能由租户替换。

目录准入不是每次 VFS 文件打开时的沙箱拦截，不能阻止有权改变进程、全局配置或挂载命名空间的代码绕过部署前提。并发内存／磁盘预算、实际网络挂载故障与压力验证仍须分别验收；真实 procfs 拒绝不能冒充 EFS/NFS 实验。

对象数据前缀禁止外部覆盖、删除可达对象及任意 bucket TTL。GC/pin/PITR 尚未完整实现，不能用“缓存可丢弃”替代它们的正确性合同。主文件逻辑配额也不限制对象存储总量。

## 验证合同与实际范围

新增单元用例覆盖允许类型、已知网络/FUSE/未知类型拒绝、目录打开失败、文件系统查询失败、父目录与新建目录的拒绝顺序及清理。原生用例使用真实本地临时目录，并用指向 Linux procfs 的符号链接验证实际目标检测；这不冒充真实 NFS 挂载测试。

原有私有目录权限、独占创建、旧 sidecar 不复用、HEAD 竞争、迟到 owner、UNKNOWN 与全计算丢失测试继续作为独立门禁。候选源码修改后须重新执行完整 unit 覆盖，行、函数、region、branch 均精确 100%；不能沿用旧提交的绿色结果。

冻结候选 `a11e61e` 已完成 fmt/clippy、unit、精确覆盖率、实际本地目录与兼容 S3/原生/服务/1 GiB 回归。真实 NFS/EFS/FUSE 挂载和真实 AWS S3 合同仍为 **NOT_RUN**，不能用类型分类或本地端点代替。后续代码修改按新的冻结候选重新记录，缺少所需合入验证时保持草稿，生产发布另有门禁。

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
- [S10：SQLite — Temporary Files Used By SQLite](https://www.sqlite.org/tempfiles.html)
- [S11：固定 libSQL Unix VFS 临时目录选择和初始化](https://github.com/tursodatabase/libsql/blob/d8bc862d20bedc72945a1da27c8b7045414c0261/libsql-sqlite3/src/os_unix.c)
- [S12：SQLite — Name Of The Folder Holding Temporary Files](https://www.sqlite.org/c3ref/temp_directory.html)
