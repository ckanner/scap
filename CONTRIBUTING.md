# 开发与审查

先阅读 [AGENTS](AGENTS.md)、[新架构方案](docs/architecture/object-storage-native-proposal.md)和[运行时格式](docs/engineering/object-runtime.md)。当前工作区只保留对象原生实现，不修复旧运行时兼容链路。

在独立分支/工作区开发；公开接口变更与文档、机器合同、单位及实际故障验收一起交付。第一方源文件逐文件要求 100% 单元行、函数、region、分支覆盖，不使用 coverage exclusion。

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --lib --locked -- --test-threads=1
python3 -m unittest discover -s tests/tooling -v
python3 scripts/check_repo.py
git diff --check
```

完整覆盖命令见 [覆盖率规范](docs/engineering/testability-and-coverage.md)。数据库一致性变更必须执行对应真实对象/SQLite 故障合同。没有云端凭据时如实保留 AWS NOT_RUN，不把模拟服务或模型结果当作云端认证。

维护者已允许以精确候选的完整本地验证作为合入依据。不得修改分支保护、虚构 CI 通过或把历史验证套给新代码；具体流程见 [本地验证](docs/engineering/local-validation.md)。
