# 参与开发

## 当前阶段

仓库目前交付架构方案与工程规范。开发前阅读 [文档地图](docs/README.md) 和 [实施路线](docs/engineering/roadmap.md)。尚无可部署数据库或稳定公共 API。

## 分支与提交

- 默认分支：`main`。
- 功能分支示例：`docs/consistency-review`、`feat/wal-adapter-poc`、`fix/snapshot-recovery`。
- 提交采用 Conventional Commits 风格，例如 `docs: define quorum commit contract`。
- 初始空仓库可直接初始化；后续通过 PR 保留评审和验证记录。
- 不 force-push 覆盖未确认的并发变更；更新远端引用时使用期望 head 检查。

## 设计改动

说明要解决的问题、行为变化、兼容性影响、验证证据及剩余风险。改变提交、身份、日志、恢复或权限语义时新增 / 更新 ADR，联动 API、运维和验证文档。

保持“已有能力 / 设计目标 / 测量结果”三者清晰。不要因使用了 Raft、S3、Kubernetes 或 SQLite 就推导未验证的可靠性。

## 文档检查

```bash
python3 scripts/check_repo.py
git diff --check
```

CI 只运行仓库结构与文档契约检查，不代表数据库正确性验证。外部链接检查采用人工核实官方来源，不在每次 CI 中依赖外网抓取。

## 实现阶段

第一批代码加入时固定 Rust / Node 工具链、锁文件、构建选项和依赖许可。Rust 运行时不得由 SQLite 或 RocksDB 阻塞 I/O 拖住 Raft 心跳；存储错误必须正确传播。

验证以 [validation.md](docs/engineering/validation.md) 为准。保持日志 / 磁盘 / 对象格式前后兼容说明和实际回滚路径，不能仅以编译成功作为升级依据。

## 数据与安全

使用合成测试数据；不要在 issue、PR、trace 或测试夹具中放真实客户数据。漏洞按 [SECURITY.md](SECURITY.md) 处理。

项目许可证尚未选定。引入外部源码前记录来源、版本、许可证和必要 notices，不因本仓库使用某个开源依赖就推定本仓库已有相同许可。
