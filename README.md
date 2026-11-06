# SCAP：S3 原生 SQLite

按 [PR #16](https://github.com/ckanner/scap/pull/16) 重建的对象存储权威数据库。数据库页面、原请求结果、权限和写者身份由 S3 中的单库 HEAD 引用；本地 SQLite 文件仅用于执行和缓存，可全部丢弃后重建。

当前构建已经移除旧 Raft、RocksDB、cell 服务和旧 SDK，没有双后端、旧盘迁移或格式兼容路径。旧代码保留在 Git 历史。选择性复用纯 SQL 编解码和 SQLite 原生提交前 WAL gate，不复用旧 cell 回执或提交协议。

**当前是单库原生实现候选，不是生产发布。** 新对象协议的单元覆盖率、真实本地 S3 合同与 AWS Standard 验收分别记录。没有真实 AWS 配置时不宣称 N1 整体通过；HTTP/Node SDK、多库调度、GC/PITR 和生产容量仍属于后续阶段。

[本轮本地验证记录](docs/evidence/object-native-local-2026-11-06.json)：87 项 Rust 单元测试通过，11 个生产文件四维覆盖率精确 100%；release 构建的 10 项真实本地 S3/进程故障合同通过。4 条成功写入均由独立持久账本逐条核对原回执与原结果；AWS Standard 保持 `NOT_RUN`。

## 实现入口

| 模块 | 职责 |
| --- | --- |
| [scap-object](crates/scap-object/src/lib.rs) | HEAD/对象格式、权限、精确请求身份、提交/取消/关闭窗口、接管/激活、独立强读 |
| [scap-object-store](crates/scap-object-store/src/lib.rs) | 真实签名 S3 exact GET、同响应 ETag、条件创建/替换、截止时间和错误分类 |
| [scap-object-sqlite](crates/scap-object-sqlite/src/lib.rs) | 固定 libSQL SQLite 内核、私有连接、提交前物理页拦截、结果缓冲和只读快照 |
| [scap-sql](crates/scap-sql/src/lib.rs) | 有界 SQL 参数、精确指纹和完整类型化结果编码 |

成功写必须依次完成：暂存 SQL 与原结果 → 上传并回读校验不可变依赖 → 用原 ETag 条件发布 HEAD → 本地 native publication → 返回成功。HEAD 响应丢失时保留 UNKNOWN；查证和取消始终使用原请求身份，不重新执行随机 SQL。

每个新强读先读取新的 HEAD，并校验当前 READ 权限和固定数据根。S3 不可用时新强读和写入都失败关闭，没有热缓存成功降级。接管以 HEAD CAS 推进 owner epoch，恢复数据与保留结果后重新核对 HEAD，再激活。

## 当前小规模 profile

- 4096 字节页，单库最多 64 页（256 KiB）。事务只上传变化的页面，未变化页复用不可变引用。
- HEAD 最多 16 KiB；单对象编码最多 512 KiB；SQL 原结果最多 64 KiB。
- 每个请求世代最多 128 条终态，保留 current 与最近两个完整 closed epochs；只允许满窗口关闭。没有任何正的墙钟留存承诺。
- 关闭窗口只释放当前索引引用，**不删除 S3 对象**。失败上传可能留下 orphan；每次操作预算不等于 bucket 总量或长期成本有界。
- 数据库通过不可变 ID 显式创建；名称目录和外部用户认证入口尚未提供。Rust API 的 principal 是可信准入输入，不能直接接受客户端自报身份。
- 控制请求绑定原 expected revision；无法查证的控制结果保守返回错误，不以 nonce 匹配伪造 Applied。

精确格式、限制和故障边界见 [对象运行时](docs/engineering/object-runtime.md)。

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
- [首个原生实现与格式选择](docs/adr/0021-object-native-runtime.md)。
- [路线图](docs/engineering/roadmap.md)、[故障矩阵](docs/operations/failure-matrix.md)、[运行说明](docs/operations/runbooks.md)。
- [协作要求](AGENTS.md)、[本地验证身份](docs/engineering/local-validation.md)。

本仓库不承诺生产 SLA、GiB 恢复、三 AZ 或低成本结论。SDK 和对外服务将在新的权限、目录与准入边界上实现。许可证仍由维护者决定，第三方组件保留各自许可证。
