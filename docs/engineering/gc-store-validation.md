# 有界 S3 删除接口：2026-11-09 本地验收

本批只验收独立 `GcS3` 传输能力。**产品物理 GC 仍关闭**；本文件不证明
storage generation 已退休、读者 pin 已排空、PITR 引用已解除或总存储收敛。
完整 workspace、owner/pins/intake 组合、AWS Standard 和生产 SLO 仍为 NOT_RUN。

## 冻结来源

实际单元、release 构建及真实合同的本地源码提交为
`985c5180ec6bb29acd12f2769de52d659f557acc`，完整 tree 为
`8d590967bc301ece8df0bbce7b2ff4a87c5f7915`，341 个跟踪文件。
验收记录保存完整源码清单、工具身份、原始 Cargo 输出、实际单元可执行文件、
native archives、unit-only profiles 以及源码/工具/二进制运行前后核验。
本次交付只更新本说明、[机器可读摘要](../evidence/gc-store-local-2026-11-09.json)
及[重现入口](../../experiments/object-gc-store/README.md)，不改变实际运行输入中的代码。
没有宣称这些文档更新之后又重编了同一个二进制。

## 已通过的范围

| 门禁 | 实际结果 |
| --- | --- |
| `scap-object-store` stable 单元 | 固定 Rust 1.90.0，40/40，0 ignored；实际 binary 的 `--list` 与 Cargo 运行记录核对 |
| 同 crate nightly 单元 | 固定 nightly-2025-09-18，40/40，0 ignored；独立目标和新 unit-only LLVM profiles |
| 精确覆盖 | 6 个生产文件逐文件行、函数、region、分支均精确 100%，无排除、无集成 profile 补足 |
| 格式与 Clippy | workspace fmt；本 crate all-targets/all-features strict Clippy |
| 新 release | 未插桩的 `scap-object-gc-store`，SHA256 `4b2fc4a8df43ba739d651171d5e53487ebffe4add5b260ead746d22fad5ae006`；3 个 native archive 身份另存 |
| 真实兼容 S3 合同 | 固定 SeaweedFS 4.51，42 场景，115 次签名产品请求，136 次独立对象 GET |
| 子进程与独立重读 | 4 个 worker 与 4 个后端进程均由 owned wait4 回收；独立 CLI 重读完整 history 与输入/输出，与原审计结果相同 |
| 历史反例 | 13 个负控全部拒绝，1 个正控通过；原始 history SHA256 `aec4954d1c6d94482bb6a4185734a914b9641bcd64f6b44a37320fe5651604e7` |

新增单元覆盖的是实际错误边界：原始 deadline、截断响应、凭据失败、签名失败、
非法 UTF-8/XML 字符和 BOM。凭据或签名失败不能触发 DELETE，传输不确定会关闭当前批次。
严格 XML reader 现在逐组件验证字节，拒绝原始 `]]>` 等非法文本；合法实体编码仍通过。
这些结论不能代替对整个工作区其余生产文件的组合验收。

## 保留的原始失败

- 首次 quick-xml API 使用错误保留为编译失败。
- `05603dd` 的 35 个 nightly 单元虽全部执行通过，但 `gc.rs`、`gc_xml.rs`
  的 region/branch 有缺口；它不是精确覆盖通过。
- `23ea274` 首轮 stable 编译因新凭据单测需要 `Arc<AmazonS3>` 而失败，未运行单元。
  新候选只修正该单测的共享所有权，之后使用全新 stable/nightly 目标完成上述 40/40。
- 旧 `7a8b443` 真实合同虽执行 42 场景，原 oracle 可接受错误事件时序和重复进程身份，
  因此旧运行不计为完整验收。修正夹具后重新实际执行，未给旧 history 补造观察。

本轮使用真实 `backend_forward_started` 和 `delivery_attempt`，区分请求到达代理、
发往后端、后端完成与响应交付。负控包括遗漏调用/DELETE、改写原 ETag/签名、
UNKNOWN 冒充 Applied、迟到冒充及时、遗漏原输入、未回收或重复进程、配置晚于交付、
结果早于交付以及声称故障但未交付对应字节。原失败与本次新运行的原始字节分别保留。

## 仍然阻塞的出口

本地兼容后端不能认证 AWS 条件删除和故障域。桶版本化/Object Lock 预检查也不是
配置锁；部署必须固定设置。Applied 不意味着历史版本、delete marker 或整个前缀
永远为空，迟到 PUT 仍需要上层持久计划与公平重复 sweep。

自动删除开启前仍需完成：同一权威上的 generation/pin/Seal/drain 证明、不可复用
身份、持久退休计划、崩溃恢复、多轮清扫及显式快照/PITR 的闭包保护。完整组合门禁
没有通过之前，本 PR 保持草稿，不以这份传输验收宣布 N3 或整个项目完成。
