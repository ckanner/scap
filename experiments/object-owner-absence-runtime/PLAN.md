# HEAD8：真实 Missing 与并发 owner 发布验收

状态：**actual01 原始观察已完成，原 oracle 因 query 返回形状假设错误失败；本修订待冻结后执行 actual02**。详见 [原始审计失败及修正](../../docs/evidence/owner-absence-actual01-query-oracle-diagnosis-2026-11-11.json)，未冻结诊断不计正式验收。本合同补充 owner-plan 主合同，不替代其 native 三窗口、进程退出、删除及冷恢复验收。生产修复源为 `e3bdf7b6a3e5ee2bf9114e8e571f0b8a64e53492`；新夹具提交身份必须另外固定。

## 为什么增加这个合同

对象不存在是一次 GET 的观察，不是覆盖随后时间的事实。原 `owner_prepare` 可能先读到 Descriptor Missing，随后另一调用已创建 Descriptor、Claim 并替换 HEAD；如果把旧 Missing 与新 HEAD/Proof 拼在一起判 Corrupt，就会把合法竞争误判为永久损坏。核心单位已覆盖该交错，本合同要求真实 HTTP、正式 native SQLite 服务与带 SigV4 的实际 S3 响应重现。

共享组件只提供进程装配、公共 SDK 驱动、原 HTTP/S3 字节观察和独立格式解码。`absence_audit.py` 不导入本 runner、输入生成器或产品 verifier；固定输入和结果分母在审计侧另行定义。共享 audit 函数的新参数由本 oracle 的固定常量提供，旧 owner-plan 合同的默认分母不变。

## 固定输入、进程和期限

Scope 为 `(deployment=1, tenant=7, database=7301/7302/7303, incarnation=1, generation=1)`，分别命名 current / superseded / proof。正式服务 A9401、B9402、C9403 各自有独立 HTTP endpoint、S3 observer 和私有本地目录；SDK A/B/C 使用真实公开 Node SDK。所有 owner 原意图由 C 的公开 saveInput/restoreInput 在任何 RPC 前持久保存；竞争者使用相同原输入，只有 bootstrap endpoint 指向 B。

| 固定分母 | 数量 |
| --- | ---: |
| Scope / 服务 / SDK incarnation | 3 / 3 / 3 |
| 保存的 SQL / 原成功 ACK | 6 / 6 |
| 原结果逐字节 lookup / 最终业务查询 | 6 / 3 |
| 保存 owner 输入 / Descriptor / 永久 Proof | 7 / 7 / 4 |
| owner POST：prepare / claim / resume / abort / inspect | 10 / 5 / 3 / 6 / 3 = 27 |
| HEAD phase：Claimed / Cancelling / Active / Aborted | 5 / 2 / 3 / 4 |
| 真实 404 hold / 真实 HEAD2 hold | 3 / 1 |
| owned wait4 | 12：3 服务、3 SDK、2 版本进程、4 后端 |
| 全历史负控 / 原样正控 | 13 / 1 |

每 Scope 先经 create / activate / 两次 SQL 建表并写入非确定性 `randomblob(64)`、`random()` 返回值，再通过公开 policy 赋予当前 ADMIN11/12。后续恢复绝不重放 SQL；逐字节 lookup 原 receipt/result，最终查询验证 `counter=2` 和原最后一次 blob。

固定 Node v22.16.0、SeaweedFS 4.51、正式 release build receipt。scapd 的 SQLite native archive 必须在 receipt 中实际存在且 SHA 匹配；本合同的 SQL 经正式服务内 native SQLite 执行。native seed worker 的同源 receipt 同时核验，**本合同不启动 seed worker**，其独立原生进程和三 retained 窗口工作量由主 owner-plan 合同负责。

SDK control 90s / recovery 300s，服务 HTTP/S3 120s，owner_prepare 保持 core 原 30s，proxy hold 180s，整体 1200s。三个原 prepare 的原 HTTP 调用均须在 30s 内结束；不续期、不重试、不重建输入。HTTP/S3 observer 的资源与关闭上界沿用主合同。两个 daemon 处理竞争，避免同 Scope 同 control lane 的人为依赖环。

## 三个真实交错

### current：Missing 之后同输入已 Claim

1. C 发原 prepare，S3 实际返回 Descriptor 404，observer 在 `after_response` 持有该原响应。
2. B 用保存的同一原输入 prepare，实际条件创建 Descriptor 并 exact readback；原 target9402 Claim 成功。
3. 放行 C 的原 404。C 必须按 `Missing → HEAD1 → Descriptor200 → HEAD2` 重新观察，HEAD1/2 均是 B 已 Claim 的同一真实 HEAD/ETag。
4. C 返回与 B 相同的 Prepared，且原调用全程只有 GET、没有重建 Descriptor 或发布 HEAD。当前记录保持 Claim。C inspect/status 健康，B 原计划 resume 在真实 native SQLite 恢复，C lookup/query 验证原数据。

### superseded：Missing 之后原计划已转为永久历史

1. 同样持有 C 已由实际 S3 返回的 Descriptor404。
2. B prepare+Claim P1，然后 Abort P1。保存独立 P2（activate 同一 owner9402），prepare 后 Abort 两次，完成 Cancelling→Aborted；替换 P1 marker 前必须持久保存 P1 terminal Proof 并 exact readback。
3. 放行原 404。C 的 Descriptor 重读取回真实 P1；其前后 HEAD 都是 P2 Aborted。C 必须返回原 P1 Prepared，不可 Corrupt 或 Fenced。
4. C inspect P1 读取真实永久 Proof，status 健康。独立新意图 P3 在 B 恢复 native SQLite，所有原 SQL 数据保持。

### proof：两次真实 Missing 后，迟到的新 Proof 不能证明损坏

1. C 的第一份真实 Descriptor404 先被 after_response 持有。预先安装第二个 gate，仅匹配该原 prepare 的第二次 HEAD GET，然后放行第一份 404。
2. C 实际按 `Descriptor404 → HEAD1 → Descriptor404 → HEAD2` 读取；HEAD1/2 的后端原文和 ETag 相同，第二次 HEAD 的完整真实200响应在交付前被 hold。两份 Descriptor404 都来自后端，不注入 Missing。
3. B 按 superseded 的路径完成 P1 prepare/Claim/Abort、P2 prepare/Cancelling/Aborted，留下真实永久 P1 Proof。
4. 放行旧的 HEAD2。C 随后真实 GET 到新 Proof；必须再发 HEAD3，读到已变化的 HEAD/ETag，并返回 Conflict。原调用不得写入、不得 Corrupt/Unknown。
5. 原 C daemon 的 inspect/status 必须继续成功，证明没有被错误隔离；B 的 P3 恢复及 C 原结果 lookup/query 成功。

所有正例只延迟原后端响应，**不修改 HEAD、不伪造404/200、不删除对象**。oracle 从闭合交换核对真实 backend 与 delivery 原文完全一致，并重建每个 accepted HEAD CAS、原 ETag、Descriptor input digest、永久 Proof 发布先后和全部数据/结果依赖；不能靠 runner 标签或最终状态替代交错证据。

## 独立反例与运行规则

13 个完整副本分别移除 S3/HTTP 交换、移除 hold、改成 before_forward、错误报告 Fenced/Corrupt、移除当前第二次 Descriptor、移除 proof 场景第二次404/后续 Proof/HEAD3、将永久 Proof 改为 pending、改变 accepted HEAD 的原 If-Match、替换跨 Scope 的完整一致 receipt/result。每例必须被指定语义 guard 拒绝；完整副本保留，最后重新核对原证据所有文件 SHA。正控完整复用原证据必须通过。

轻量单位使用显式 synthetic signed loopback 后端测试“404 已观测、条件创建后原404仍交付、重读200”，并独立测试各 oracle 缺边反例；这些单位不是产品 actual。

源码先提交冻结、核验正式二进制和全输入等价，再运行 actual；runner 仅报告 `OBSERVED_NOT_AUDITED`。oracle 与 controls 均通过才允许记录本合同通过。任何失败保存原目录、原日志、原输入和期限，修复后新 commit、新 attempt。不能将本地兼容 S3 结果推广为 AWS Standard 或通用吞吐 SLO，也不能声称本合同覆盖进程重启、全部故障组合或自动接管 controller。
