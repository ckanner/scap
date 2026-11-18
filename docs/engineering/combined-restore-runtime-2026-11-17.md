# 新组合恢复与 worker 身份实际验收（2026-11-17，纽约）

同一个新建、未插桩的正式 service release 完成全部三组实际验收：S2 **7/7 + 126/126 反例**、显式 worker identity **10/10**、自动 identity **18/18**，各一轮通过。运行时间为 UTC `2026-11-18T01:27:04.856713+00:00` 至 `2026-11-18T01:28:19.368879+00:00`，客户端 America/New_York 日期为 2026-11-17。

[机器可读证据](../evidence/combined-restore-runtime-2026-11-17.json)记录完整来源、各项名称和计数、原始结果/receipt/source archive 的 SHA-256。原始请求历史、随机结果、日志、配置与数据库均留在外置 evidence，未提交到仓库。

## 构建与输入对应

- 冻结组合：`1cbe6b39fdfff72610956a18bb6fe1d523bab8eb`，tree `de2317e25fb840fb1338090088c1b1b434bf0277`。
- 正式 `scripts/source_manifest.py capture` 固定全部 802 个 tracked 文件，源码指纹 `104f8cd80feb910c5ff8f91a0b1b2c0ba132efb55cf4da27dfdbe41c6feac670`。三项运行前后分别执行完整 source verify。
- 在独立 detached worktree、全新 target 中运行既有 `experiments/object-service/build.py`；Rust 1.90.0、`--release --locked -p scap-service --bin scapd`，jobs=2，native `CXXFLAGS=-g0`。无覆盖率或性能插桩，不覆盖任何旧 release。
- 新 `scapd` SHA-256：`a941b366cf5c9ccba5e27cb64c26f172fce5fd16dc9f2085c9f088e52982ced5`。
- 原始 build receipt SHA-256：`b3faf4fb88e4a15539c8ba2e9cb49ba8272a98d7843411b2f27d76605ccf076f`。既有 `build.verify` 在各项运行前后校验源码输入、Cargo JSONL 的最终成功事件、实际 executable 和 native SQLite archive。
- 每项 evidence 另用既有 `capture_receipt` 保存原始 Cargo 输出、source manifest/source archive、build receipt，并复制完整 802 文件 manifest。构建原件和旧运行证据没有重写。

## 实际结果

| 验收 | 结果 | 实际观察 |
|---|---:|---|
| S2 daemon / HTTP / Node SDK / native SQLite / 签名 S3 | 7/7 | 原随机值与多块 BLOB、Empty/Restore first winner、暂停复制时取消、源撤权、成功响应丢失后进程崩溃与新进程继续、删除源 payload 后独立目标全冷恢复、完成记录存在时永久目标 HEAD 丢失拒绝重建 |
| 独立 S2 auditor 的定向反例 | 126/126 拒绝 | 122 个语义见证反例、4 个结构反例；语义变体修复外围 body/frame hash 和序号，不能仅因 bookkeeping 不符而通过测试 |
| 显式 worker identity | 10/10 | 存活/正常退出/崩溃后拒绝重复 ID、两个进程竞争、PUT ACK 丢失、UNKNOWN ID 不再复用、损坏回读及不可达后端 |
| 自动 worker identity | 18/18 | 一次初始化、拒绝缺失/重置、同配置正常/崩溃重启、实际 native SQL 与 worker guard、并发分配、显式 claim 抢占、counter/marker ACK 丢失后的空洞、claimed/ready 区分、listener 失败、独立 bucket 的最后一个 u64 与无回绕耗尽、坏 counter |

S2 的独立审计解析 **2,960 条记录**，核对 **59 次 SDK 调用、911 次 S3 调用、30 次管理员调用和 3 个真实 daemon 进程**。本次观察到的 **14 个源 payload 对象**逐个实际 DELETE 后 GET=404；目标恢复仍返回原始 typed rows。目标 HEAD 丢失案例另外检查原 completion 绑定、HEAD404 → completion GET200 → HEAD404，以及没有新 HEAD PUT。输入冻结、独立审计、反例和四个 backend owned process 的回收 gate 均通过。

自动 ID 验收只证明相同配置的重启可以安全获得新的永久身份，并保留 owner/target mismatch 边界；它不自动重写既有数据库 owner，也不更新外部静态路由注册。完整身份协议见[永久 claim](../architecture/worker-instance-claim.md)和[自动分配](../architecture/worker-instance-allocation.md)。

## 复现入口与边界

使用新 evidence 目录与同一个正式 build receipt，运行既有入口：

```bash
python3 experiments/object-service/build.py --target-dir /absolute/new/release-target --evidence /absolute/new/build-evidence
python3 experiments/object-restore-runtime/run.py --server /absolute/new/release-target/release/scapd --weed /absolute/pinned/weed --node /absolute/pinned/node --evidence /absolute/new/s2-evidence
python3 experiments/worker-instance/run.py --binary /absolute/new/release-target/release/scapd --weed /absolute/pinned/weed --evidence /absolute/new/explicit-evidence
python3 experiments/worker-instance/auto.py --binary /absolute/new/release-target/release/scapd --weed /absolute/pinned/weed --evidence /absolute/new/auto-evidence
```

此次使用固定 SeaweedFS 4.51 和 Node 22.16.0。它是本地 S3 兼容端点上的真实协议、I/O 与进程故障验收，AWS Standard/IAM、跨区域恢复、容量与生产 SLO 为 `NOT_RUN`。单位覆盖率、TCP 8 项以及 metadata/output pool 检查使用各自的独立报告；本报告不合并它们的 profile，也不宣称远端 CI 已完成。
