# 恢复提交前 Manifest GET 后的实际验收（2026-11-17，纽约）

将 GET-elision 优化从功能候选拆出后，新正式 release 完成 **S2 7/7 + 126/126 定向反例、显式身份 10/10、自动身份 18/18**，各一轮通过。旧 `1cbe6b3` 的运行独立保留；当前结论绑定 `aab8a22` 的新二进制，不能用旧二进制结果替代。

## 当前源码与构建

生产改动原提交 `971401ea62cc2910d60ecaf8e7da3b6059d05893` 只恢复常规 SQL publication：`data_tree::update` 返回根 String，SQL commit 回到 `publish_in`，在原 HEAD 条件发布前保留独立 exact Manifest GET。专用 `VerifiedManifest`/`publish_updated`/`publication_matches` 被删除。完整 HEAD 摘要、常规 ObjectContext 隔离/退休诊断、原 deadline/ETag、不可变条件创建和回读、native ACK 顺序、S2/身份保护与 pool8 均保留。

该修改独立 core 单元 **487/487** 通过，包含真实 native changed/no-op × Unknown/Missing/Corrupt 最终 GET 故障。故障发生在 Result 和请求 Index 已持久化之后，必须无 ACK、原 HEAD 字节和 ETag 不变、writer 停止、原请求 lookup=Unknown、全冷查询不含未提交写。独立只读审查未发现阻断项。完整 workspace 单位覆盖由整合运行单独报告。

- 本次冻结组合：`aab8a223f3cb4f4cf981990b4f5de80288b0dadc`，tree `81f39821d3ed74735903f27675b96f885e75b4ad`。
- `source_manifest.py` 固定全部 **815** 文件，源码指纹 `813f8af13ce6b8c2f34d01a8a721a6601ec475920f717d4c65c3f560c35862f6`；每个实际 suite 前后均 verify。
- 既有 `experiments/object-service/build.py` 在全新 target 构建 Rust1.90 正式 release；无覆盖率或性能插桩、没有覆盖旧 release。
- `scapd` SHA-256：`24797df0d6b9ab3aca9fa3157c4f3094b24724b7b415b5d0ee351586c57ba1ce`。
- 原 build receipt SHA-256：`849019b6fdbb7225434f17326cfaef8a5d49670a6a47cfee97824fc28e9e780e`；构建完成事件、native archive、实际 executable 和输入均由现有 `build.verify` 核对。
- 实际运行 UTC 区间：`2026-11-18T01:46:29.707752+00:00` → `2026-11-18T01:47:53.583094+00:00`；客户端 America/New_York 日期为 2026-11-17。

## 三组实际结果

| 验收 | 结果 | 见证 |
|---|---:|---|
| S2 HTTP/SDK/native/签名 S3 | 7/7 | 原随机值和多块 BLOB、Empty/Restore first-winner、暂停时取消、源撤权、丢成功响应后 SIGKILL/新进程恢复、源 payload 删除后的目标全冷查询、completion 存在但永久 HEAD 缺失时拒绝重建 |
| 独立 auditor 反例 | 126/126 拒绝 | 122 个语义反例修复外围 frame/body hash 与序号后仍拒绝；另4个结构反例 |
| 显式 worker ID | 10/10 | live/clean/crash 重用拒绝、竞争、PUT ACK 丢失后的永久消耗、坏回读、不可达后端 |
| 自动 worker ID | 18/18 | 一次初始化、同配置正常/崩溃重启、native SQL/worker guard、并发、显式抢占、counter/marker丢ACK空洞、claimed与ready、listener失败、独立bucket最后u64/耗尽无回绕/坏counter |

S2 独立审计 **2,966 条记录、59 次 SDK 调用、913 次 S3 调用、30 次管理员调用、3 个 daemon**。本次观察到的 **14 个源 payload 对象**全部实际 DELETE 并逐个 GET=404，目标仍恢复原始 typed rows。永久目标 HEAD 丢失案例验证原 completion 摘要绑定和 HEAD404 → completion GET200 → HEAD404，无该槽的新 HEAD PUT。所有独立审计、反例、输入冻结和 backend 清理 gate 通过。

逐条统计的 S3 method：旧 `1cbe6b3` 为 825 GET / 86 PUT，本次为 **827 GET / 86 PUT**。这与恢复两个 SQL 提交的最后 Manifest GET 一致，作为功能路径见证；两轮使用独立后端及随机值，不据此宣称吞吐或延迟改善。GET-elision 的性能结论仍属于独立 Draft 的后续工作。

同配置启动获得新 ID，不代表自动重写既有数据库 owner 或外部 route。原 owner/target mismatch 边界继续保留。

## 证据与适用范围

[机器可读证据](../evidence/manifest-get-runtime-2026-11-17.json)包含全部 case 名称、source/build/二进制摘要和原始 artifact 哈希。每个 suite 都复制了现有 `capture_receipt` 的原 Cargo 日志、source archive、receipt 及完整815文件 source manifest；原始记录仅保留在外置 evidence，没有提交凭据、配置、随机结果、日志或数据库。

复现使用 [S2 既有 runner](../../experiments/object-restore-runtime/README.md)和[身份既有 runner](../../experiments/worker-instance/README.md)，以及各项前后的 `build.verify`/完整 `source_manifest.py verify`。本次固定 SeaweedFS4.51、Node22.16.0。AWS Standard/IAM、云端故障域、跨区域恢复、容量与生产 SLO 为 `NOT_RUN`。单位覆盖、TCP/segmented/isolation、metadata/output/response 合同各有独立结果；本报告不宣称远端 CI 完成。
