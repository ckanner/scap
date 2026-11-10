# HEAD6：完整复制、退休世代回收与组合验收

状态：**生产候选已冻结，整栈验收进行中；PR #54 仍为草稿。** 本记录只把实际已经完成的门禁列为通过，不继承 HEAD5 的 unit profile 或真实运行结果。历史 HEAD5 的完整记录和后续发现见[上一批验收](runtime-completion-validation.md)。

## 1. 源码与构建身份

| 项目 | 固定身份 |
| --- | --- |
| 生产候选 | `66f452ec73111f8c9dc7509883717828ba883e8a` |
| 生产候选 tree | `0d3dfee179ecb22df8cc62da3d14e0f7907e2bfd` |
| 整树源码清单 | 506 个文件；运行前后核对 |
| 正式 HTTP 服务 SHA256 | `d744c47fd4f60bcd9dfd738d6639039f7680daa21972843a75b479213100bbb4` |
| 正式 native worker SHA256 | `9d4c7d095f5f3ab1bacc3e7f790aa9b641a7973e4a00a929e099e938a9fc4c81` |
| 后续实际回收夹具 | `8fd8a3d24cbb99603a0d138e05ffc6865b51545d`；与生产身份分开记录 |
| 后续负载夹具 | `f8a40d7defb67bb858930b022a83ba0e74e3d6a0`；与生产身份分开记录 |

后续夹具检查全部 237 个 service 构建输入和 164 个 native 构建输入，与生产候选逐字节相同，另核对 release 二进制、原构建收据、native archive 和工具身份。后续文档或实验提交不是新的生产构建，不修改冻结源码。

## 2. 已完成的单元与静态门禁

stable 与独立 nightly coverage 分别完成 **632 项 Rust 单元测试**。59 个第一方生产文件逐文件满足四维精确 100%；没有排除未命中文件，没有使用真实网络或集成 profile 填单位覆盖。

| 维度 | 命中 / 分母 |
| --- | ---: |
| 行 | 11,896 / 11,896 |
| 函数 | 1,076 / 1,076 |
| region | 18,091 / 18,091 |
| 分支 | 2,240 / 2,240 |

逐文件源码摘要与计数见[机器记录](../evidence/head6-unit-local-2026-11-10.json)。workspace fmt、严格 Clippy、SDK 原始 V8 精确覆盖、真实 Fetch、严格 TypeScript 声明、codec V8、Python 工具覆盖、文档检查和 actionlint 均通过。standalone native/discovery/resource/GC transport harness 的 fmt 与严格 Clippy 另跑通过。

这批修复了核心 retained Result/cancelled 条目缺少 `transition.nonce == request.id` 的语义验证。旧 d60 合法实际负载通过，不代表它能拒绝这种 hash-valid 语义损坏；新共享 verifier 与本批新单位证据才覆盖该缺口。

## 3. 已完成的真实 native 合同

使用同一冻结候选的正式 release，以下全部通过，源码后验清单不变：

- 原生提交、依赖故障、schema、UNKNOWN、原结果及 native publication 合同。
- 保留结果：12 场景、72 个入口核对、30 条已确认请求。
- 生命周期与退休合同。
- 名称目录：116 场景、1,000 次 ACK。
- 新的 1 GiB 全计算/后端进程丢失与 S3 恢复：39 条已确认请求、16,384 个 BLOB、1,073,741,824 字节完整核对，零差异。

容量合同保持默认 10 GiB 配额、原操作/恢复预算、独立随机输入和完整原结果核对。这里报告实际重新运行的 1 GiB，**没有重新认证旧候选的 10 GiB 边界实测**。该轮未启用物理 GC；回收协议由另外的实际合同验证。

1 GiB 冷恢复实际发出 8,337 个 GET、2 个 PUT，GET 响应共 1,084,291,477 字节。它证明全量恢复路径，不能据此宣称已有按需页加载或 AWS 恢复时延。

## 4. HTTP、部署与资源组合状态

已完成新实际运行及独立判定的项目包括：租户输出池竞争、响应与连接关闭期限、bounded transport、正式 HTTP/SDK、owner、metadata、名称目录、跨库隔离、分段请求索引。各自负对照按原判定边界运行，原输入、HTTP/S3 字节与进程账本保留。

部署恢复、bounded S3 listing/response、资源生命周期和专用 conditional DELETE transport 的新实际、独立判定及各自负对照也已全部通过。HTTP discovery 的实际与内置 29 负/1 正对照已通过；单独进程中的复核与 guarded status 仍在推进。最终汇总必须逐项引用本候选的命令/退出记录，不能预先将整个组合标为通过。

## 5. HEAD6 回收的真实故障合同

场景与独立原始判定器见[回收实验](../../experiments/object-reclamation-runtime/README.md)。固定工作包括三代保留窗口、全部原结果、COPY 期间 ACL 更新、旧 GET/PUT/HEAD CAS/DELETE 暂停、持久 checkpoint 与重启、DELETE 响应丢失、同字节不同真实 ETag、原条件 412、重复从起点清扫和全部缓存丢失后的恢复。

原失败保持各自身份：

| 运行 | 实际边界与处理 |
| --- | --- |
| actual01，夹具 `8d0ff6a` | 在 SDK prepare 时把 native 的 `params` 输入直接交给要求 `parameters` 的公开 SDK；未发出 `/v1` POST 或 S3 请求。健康检查 GET 单列。补了公开 SDK prepare/save/restore、独立指纹与零 fetch 单位测试。 |
| actual02，夹具 `f8a40d7` | 264 ACK、完整复制、多轮 sweep、旧读过期、迟到 PUT、旧 CAS 412 和迟到 DELETE 已实际发生，但 operator GET 的嵌套响应 body 适配失败，最后场景与冷恢复未完成。**无完整通过判定**。原 18,866 个 S3 请求的最终分母及 owned 进程回收已经核对。 |
| actual03，夹具 `8fd8a3d` | 从干净夹具重新执行完整 raw 合同，208.784 秒完成，264 个 cold original lookup 全部执行，全部 owned 进程和代理回收；runner 原状态保留为 `OBSERVED_NOT_AUDITED`。后续独立 oracle 已通过，23 个负对照仍在运行。 |

第二次修复仅修改实验 adapter，全部五处解码使用原 `response.body`；新增真实 loopback HTTP 单位覆盖签名、NoSuchKey、非 UTF-8/零字节、multipart 请求及 readback/ETag，共 31 个实验单位通过。它不是实际 S3 multipart 的替代证明。生产二进制、工作量、180 秒 hold 和原业务 deadline 不变。

actual03 独立原始审计核对 457 个 HTTP POST、20,296 个 S3 请求、264 个 native ACK 与全部 264 个冷恢复原结果。完整主 COPY 闭包含 270 个真实依赖，其中 260 个为原 Result；另外三次闭包各有六个依赖。46 个持久 prepare/progress/clear 周期中，共观察 1,340 个 DELETE 请求、1,338 次实际接受、两次真实条件冲突；19 个 owned 进程的 wait4 均与账本匹配。六个故障与五个原 UNKNOWN 单独保留。该审计不证明永久 prefix 为空、Deleted 最后一代已回收或 AWS/SLO。

旧读可在严格证明原物理世代已永久退休后返回 `SnapshotExpired`。已知提交的 receipt 不能被此结果抹掉；UNKNOWN 不重放 SQL，GC checkpoint 不刷新原 ETag。完整协议见[HEAD6 设计](../architecture/head6-compaction-gc.md)。

## 6. 吞吐与冷恢复基线

[固定负载计划](../../experiments/object-load/PLAN.md)与夹具已冻结。八库、两租户、185 个原 execute 身份、871 个 POST 的完整工作分母，以及 288 个测量调用，在运行前确定。报告将区分同库/多库、读/写、计划排队/端到端延迟、全部失败状态、S3 请求/字节和进程/缓存资源。

当前为 **NOT_RUN**。其 preflight 已核对真实 SDK 输入、服务构建输入与全部 HTTP body 上限；实际测量安排在独立窗口。没有 AWS 数字或预先通过的生产 SLO；小样本 closed-loop 基线与完整容量、持续过载、硬资源隔离不同。

## 7. 原失败与未运行边界

release 批次第一次使用了错误的 discovery 构建脚本路径，之后 resource/GC builder 又因共享 target 而拒绝。两次原命令和退出保留；使用正确脚本及各自全新 isolated target 后构建通过，没有放宽构建身份检查。

GitHub 当前返回失败 check，已检查的 job 没有执行步骤或可用失败摘要。不能据此宣称远端 CI 通过，也不能无证据归因于额度。按仓库已有维护者授权，合入依赖完整本地门禁；缺少本地 required gate 时继续保持草稿，不修改分支保护。

真实 AWS Standard/Express、目标 IAM/KMS、跨 AZ、真实网络挂载、生产长运行及成本/SLO 均为 **NOT_RUN**。HEAD6 保护 Deleted 的最后 active generation；永久终态退休、显式快照/PITR、自动 owner controller 与完整资源总账仍需各自生产实现和验收。
