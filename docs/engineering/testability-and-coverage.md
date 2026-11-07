# 精确单元覆盖率

第一方新生产源码采用100%行、函数、region、branch四项门禁，测试代码只按 `contracts/coverage-policy.json` 明确列出的文件排除。所有生产文件自动从仓库发现；遗漏、旧测试路径或非法coverage属性均失败。

```bash
cargo +nightly-2025-09-18 llvm-cov clean --workspace
cargo +nightly-2025-09-18 llvm-cov --branch --workspace --lib --bins --all-features --locked \
  --no-cfg-coverage --no-cfg-coverage-nightly \
  --json --output-path /tmp/scap-object-unit.json -- --test-threads=1
python3 scripts/check_unit_coverage.py /tmp/scap-object-unit.json
```

固定cargo-llvm-cov 0.6.21，nightly安装llvm-tools-preview。并行开发的局部报告使用独立target目录；最终验收从干净profile采集完整workspace，不能混入真实故障实验。源码与实际构建/执行身份均需核对。

`scapd` 的实际 `main.rs` 也进入生产分母；单元目标调用同一源文件的薄入口，不排除二进制或以真实进程 profile 补覆盖。Node SDK 使用独立 fresh V8 目录，逐生产文件核对行／函数／分支与所有原始 range 计数；真实 Fetch 和服务恢复不设置 `NODE_V8_COVERAGE`。

存储、时钟及native失败通过实际需要的ports和小型纯函数验证；不得使用coverage(off)、降低阈值、删除有意义分支或把产品代码藏进实验目录。覆盖率只证明被执行的代码，不单独证明协议安全、云端合同或生产SLO。
