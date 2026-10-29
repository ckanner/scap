# 参与开发

## 当前阶段

仓库目前进入 G0 可行性原型。开发前阅读 [文档地图](docs/README.md)、[实施路线](docs/engineering/roadmap.md)、[性能目标](docs/engineering/performance-slo.md) 与 [100% 单元覆盖率规范](docs/engineering/testability-and-coverage.md)。尚无可部署数据库或稳定公共 API。

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

文档检查不代表数据库正确性验证。CI 另行运行正式模块单元覆盖率、工具脚本覆盖率以及真实引擎、RPC、存储恢复和三进程故障探针；各层证据独立。外部链接检查采用人工核实官方来源，不在每次 CI 中依赖外网抓取。

## 代码与覆盖率门禁

Rust 第一方生产代码要求单元行、函数、分支覆盖率均为 100%，同时要求 LLVM region 全覆盖。门禁使用原始整数计数，99.999% 不四舍五入为通过。每个生产源码都必须进入覆盖率映射，新增 binary、feature、适配器及错误路径都需要扩展测量和测试。

Python 仓库工具要求语句和分支全覆盖。所有计数均只取独立单元测试运行，集成和故障测试另报；测试资产、第三方依赖和研究探针的分类见机器可读清单，不能把产品代码移出分母。当前固定命令与工具版本见 [执行证据](docs/engineering/g0-evidence.md)。

先写行为与失败路径测试，再实现和重构；代码难以单测时优先调整依赖边界。以高内聚、窄接口、依赖反转和可替换 adapter 支持开闭原则。相同 port 的 fake 与真实实现必须遵守同一契约，不能用过度 mock 掩盖存储或网络事实。

## 实现阶段

第一批代码加入时固定 Rust / Node 工具链、锁文件、构建选项和依赖许可。Rust 运行时不得由 SQLite 或 RocksDB 阻塞 I/O 拖住 Raft 心跳；存储错误必须正确传播。

验证以 [validation.md](docs/engineering/validation.md) 为准。保持日志 / 磁盘 / 对象格式前后兼容说明和实际回滚路径，不能仅以编译成功作为升级依据。

## 数据与安全

使用合成测试数据；不要在 issue、PR、trace 或测试夹具中放真实客户数据。漏洞按 [SECURITY.md](SECURITY.md) 处理。

项目许可证尚未选定。引入外部源码前记录来源、版本、许可证和必要 notices，不因本仓库使用某个开源依赖就推定本仓库已有相同许可。
