# 保留结果语义损坏：独立对象／进程合同

状态：**实现候选，真实 Rust/S3 执行为 NOT_RUN，不能合并**。本轮在 PR #23 上补齐专用实验入口，不更改生产 crates、固定依赖、v2 格式、10 GiB 默认配额或 S3 唯一持久权威，也不覆盖 PR #22 的 ALTER 候选。

## 为什么需要独立场景

损坏 Result 外层对象字节会被已有 SHA-256 校验拒绝，不能验证内部 SCAPRES1 检查。仅截断内部结果、却不修正窗口 result_bytes，也会被原有聚合计数检查拒绝，同样容易误判为修复有效。

新夹具读取真实已提交对象，改变内部结果，重新编码合法 v2 Result、Index 及 HEAD 引用；所有新对象使用自己的内容哈希，结果长度变化同步更新对应窗口的精确 result_bytes。SQL request、sequence、transition、data_root、数据文件和原始客户端账本不变。修改前后均调用正式 worker 的对象 codec；原结果能由正式 SQL decoder 解码，变体不能解码。原不可变对象不覆盖、不删除。

这由临时私有 S3 后端的可信测试身份条件发布，属于故障注入，不是产品恢复接口，也不声称恶意字节可绕过 SHA-256。

## 12 个场景、60 次独立入口检查

当前请求世代和已关闭但仍保留的世代，分别执行六类语义损坏：错误魔数、尾字段截断、多余尾字节、未知类型、非有限实数、非法 UTF-8。每个场景先使 owner 进入 Recovering，注入损坏并杀掉全部场景计算进程、删除其本地缓存。

随后五个入口分别启动全新 worker：`lookup_identity`、`cancel_identity`、`activate`、`activate_session`、`session_open`。不能让一次 lookup 的共享隔离状态替另一个入口触发拒绝。

每次必须同时满足：

- 收到准确的 `Corrupt`，不能把 `Format(Corrupt)`、Missing、timeout 或 worker 退出当成目标成功。
- HTTP 历史含实际 Result GET 的后端 200 和新对象准确摘要，说明读到了目标字节。
- HEAD body 和 ETag 都不变，没有尝试 HEAD PUT；失败恢复目录不存在。

完成拒绝检查后，测试身份以原条件 ETag 恢复未损坏 HEAD，再关闭该进程、用新进程完整冷激活。已有 FaultSuite 独立比对提交前输入、实际 execute ACK 的完整 receipt/encoded result，以及恢复后的每个 witness BLOB 哈希和 nonce。12 个场景预期共 30 条 execute ACK，全部必须核对，不能只检查行数或当前值存在。

## 可执行入口

在完整干净候选检出、固定工具链和本地 S3 后端可用时，先完成原有 Rust 单元／四维覆盖率、格式和 Clippy，再执行：

```bash
python3 -m unittest discover -s experiments/object-network -p 'test_*.py' -v
python3 experiments/object-network/build.py \
  --target-dir /tmp/scap-result-build \
  --evidence /tmp/scap-result-build-record
python3 experiments/object-network/retained_result_contract.py \
  --worker /tmp/scap-result-build/release/scap-object-network \
  --weed /path/to/pinned/weed \
  --build-record /tmp/scap-result-build-record/build.json \
  --evidence /tmp/scap-result-contract
```

`weed` 必须是既有 quality workflow 锁定的 SeaweedFS 4.51 二进制；这里不下载或更换它。`build.py` 已将该目录全部 Python/Rust 源与锁文件纳入构建输入，运行前后重新校验。单元插桩、关闭 Python assert、无 release build record、缺少 worker、覆盖旧证据目录都被拒绝。工作流已把此合同作为已有真实网络 job 的独立步骤，并保留其公开历史和账本；既有故障、1 GiB 容量步骤和覆盖率门槛保持不变。

唯一可报告 `passed` 的情况是：完整场景和入口清单匹配、所有 ACK/原始结果一致、没有代理或资源清理错误、运行后构建输入仍匹配。未准备环境返回非零和 `blocked`，不能记为跳过后成功。错误期间保留已有证据，不用失败重试覆盖输出。私有后端、凭据及 native 数据库只放在独立临时目录，artifact 清单不上传它们。

## 本轮实际验证与限制

新增的 **18 个 Python 夹具自测已执行通过**，包含对象重新定址和计数、变体精确字节、入口拒绝判据、完整 ACK 清单、源码构建绑定、错误清理和 blocked CLI。测试替身可模拟“旧实现返回成功”、错误外层分类、未读取损坏对象、错误改写 HEAD 和泄漏恢复目录，均不能通过场景判据。

本环境 coverage.py 为 **7.13.3**，该单一实验脚本的诊断自测达到 243/243 语句、42/42 分支，0 排除。它不同于项目固定的 coverage.py 7.10.6 工具门禁，不能作为项目工具总覆盖率或 Rust 覆盖率。替身不运行 SQLite/S3，只检验夹具控制和证据判据。

本环境 cargo/rustc 不存在，外部 Rust 下载站点 DNS 解析失败；真实 worker 和 SeaweedFS 也不存在。脚本实际前置检查已返回 `blocked`、非零退出码和 `real_worker_started=false`。因此 **12 个真实场景、60 次真实入口、30 条真实 ACK 审计均未运行**，不是通过结果。固定 Rust 编译、完整单元、四维100%、真实 S3、1 GiB及受影响范围内容量回归仍阻塞合并。机器状态见[本轮记录](../evidence/retained-result-harness-2026-11-06.json)。

整体 N1、AWS Standard、多库/SDK、GC/PITR 和生产 SLO 状态不因夹具自测通过而改变。
