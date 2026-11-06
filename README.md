# SCAP：S3 原生 SQLite

按 [PR #16](https://github.com/ckanner/scap/pull/16) 重建的对象存储权威数据库。数据库页面、原请求结果、权限和写者身份由 S3 中的单库 HEAD 引用；本地 SQLite 文件仅用于执行和缓存，可全部丢弃后重建。

当前构建已经移除旧 Raft、RocksDB、cell 服务和旧 SDK，没有双后端、旧盘迁移或格式兼容路径。旧代码保留在 Git 历史。选择性复用纯 SQL 编解码和 SQLite 原生提交前 WAL gate，不复用旧 cell 回执或提交协议。

**当前是单库原生实现候选，不是生产发布。** 新对象协议的单元覆盖率、真实本地 S3 合同与 AWS Standard 验收分别记录。没有真实 AWS 配置时不宣称 N1 整体通过；HTTP/Node SDK、多库调度、GC/PITR、真实 AWS 和生产 SLO 仍有独立退出门禁。单库已改为默认 10 GiB、可调整或取消业务配额的 v2 实现，实际容量验收与配置分开记录。

[PR #19 的历史本地验证记录](docs/evidence/object-native-local-2026-11-06.json)：87 项 Rust 单元测试通过，11 个生产文件四维覆盖率精确 100%；release 构建的 10 项真实本地 S3/进程故障合同通过。4 条成功写入均由独立持久账本逐条核对原回执与原结果；AWS Standard 保持 `NOT_RUN`。

## 实现入口

| 模块 | 职责 |
| --- | --- |
| [scap-object](crates/scap-object/src/lib.rs) | HEAD/对象格式、权限、精确请求身份、提交/取消/关闭窗口、接管/激活、独立强读 |
| [scap-object-store](crates/scap-object-store/src/lib.rs) | 真实签名 S3 exact GET、同响应 ETag、条件创建/替换、截止时间和错误分类 |
| [scap-object-sqlite](crates/scap-object-sqlite/src/lib.rs) | 固定 libSQL SQLite 内核、私有连接、提交前物理页拦截、结果缓冲和只读快照 |
| [scap-sql](crates/scap-sql/src/lib.rs) | 有界 SQL 参数、精确指纹和完整类型化结果编码 |

成功写必须依次完成：暂存 SQL 与原结果 → 上传并回读校验不可变依赖 → 用原 ETag 条件发布 HEAD → 本地 native publication → 返回成功。HEAD 响应丢失时保留 UNKNOWN；查证和取消始终使用原请求身份，不重新执行随机 SQL。

每个新强读先读取新的 HEAD，并校验当前 READ 权限和固定数据根。S3 不可用时新强读和写入都失败关闭，没有热缓存成功降级。接管以 HEAD CAS 推进 owner epoch，恢复数据与保留结果后重新核对 HEAD，再激活。

## 容量与运行配置

**默认单库为 10 GiB，管理员可调大，也可设置 `quota.max_bytes = None` 取消 SCAP 业务容量配额。** 配额随 HEAD 持久化并以原 revision 的 CAS 修改；禁止缩到已有文件以下。SQLite 的 4 KiB 页号边界仍存在，约 16 TiB 理论文件空间不等于实测服务容量。

| 项目 | 默认或实现 |
| --- | --- |
| 单库逻辑文件 | 10 GiB；既有库遵守 HEAD 配额 |
| 持久数据布局 | 128 KiB 原始字节块，256 分支内容寻址树，仅更新变化块及路径 |
| 冷恢复与热执行 | 流式恢复到新私有文件；Session 复用连接，每次读写重新验证远端 HEAD |
| 事务变化页 / page cache | 各 64 MiB；cache 是软目标，不是进程 RSS 隔离 |
| SQL 结果 / 参数和返回值 | 每事务 50 MiB / 每个 Text-BLOB 2 MiB，可独立配置 |
| 聚合输入 / SQL 文本 | 64 MiB / 1 MiB，包含编码开销 |
| 操作 / 恢复预算 | 30 秒 / 30 分钟，受调用方更早 deadline 约束 |
| 请求留存 | 默认每世代 4,096 条、256 MiB 原结果，保留 current 与两代 closed |

这些执行和留存预算不随数据库大小增长。对象帧与原结果采用原始二进制字节，去掉整库内存复制与 JSON 字节数组膨胀。完整冷恢复仍需下载并检查整个数据库；没有实现 lazy VFS。

[真实容量实验](experiments/object-capacity/README.md)分别装载 1 GiB 独立随机数据及默认 10 GiB 实际 SQLite 文件边界，检查增量 I/O、全部计算丢失后的恢复、全部 ACK 原结果和每个 BLOB。不能仅凭配置或稀疏文件宣称实测通过；具体完成范围以候选绑定的验证记录为准。官方产品对照、配置 API 和证明边界见 [ADR-0022](docs/adr/0022-production-capacity.md)与[对象运行时](docs/engineering/object-runtime.md)。

关闭窗口只变更引用，**当前不删除 S3 对象**。旧块、索引和 orphan 仍会增长；当前文件配额不限制 bucket 总量。内部 Rust API 的 principal 是可信准入输入，对外鉴权、自动协调和新 SDK 尚未交付。

## 构建与验证

Rust 固定 1.90.0。native 编译需要 C/C++ 编译器、make 和 libclang。依赖与引擎 Git revision 均由 Cargo.lock 锁定。

```bash
cargo build --workspace --locked
cargo test --workspace --lib --locked -- --test-threads=1
cargo clippy --workspace --all-targets --locked -- -D warnings
python3 scripts/check_repo.py
```

四维精确单元覆盖率、真实对象故障合同和执行身份按 [验证规范](docs/engineering/validation.md)独立执行。独立 [N0 模型](experiments/object-authority-model/README.md)保留自己的可执行历史判定器，不能替代真实 S3/SQLite 验证。

## 设计与后续阶段

- [已接受的完整方案](docs/architecture/object-storage-native-proposal.md)、[ADR-0020](docs/adr/0020-object-storage-native-authority.md)。
- [首个原生实现与格式选择](docs/adr/0021-object-native-runtime.md)、[可配置容量与 v2 恢复布局](docs/adr/0022-production-capacity.md)。
- [路线图](docs/engineering/roadmap.md)、[故障矩阵](docs/operations/failure-matrix.md)、[运行说明](docs/operations/runbooks.md)。
- [协作要求](AGENTS.md)、[本地验证身份](docs/engineering/local-validation.md)。

本仓库不承诺生产 SLA、跨 AZ 或长期低成本结论；GiB 恢复只按实际候选实验报告范围描述。SDK 和对外服务将在新的权限、目录与准入边界上实现。许可证仍由维护者决定，第三方组件保留各自许可证。
