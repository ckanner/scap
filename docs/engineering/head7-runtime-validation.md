# HEAD7：永久退休 Deleted 最后一代的本地验收

## 状态与源码归属

HEAD7 的新单位、精确覆盖、终态退休合同、负载合同和原生兼容合同已经通过。
其余 HTTP 组合及多代 GC 的最终离线负对照仍在执行，**本页尚不宣布整批完成或可上线**。
[PR #55](https://github.com/ckanner/scap/pull/55) 保持草稿；HEAD8 的 accepted owner plan
在 [PR #56](https://github.com/ckanner/scap/pull/56) 单独推进，不继承本页的产品验收结论。

| 身份 | 冻结提交及用途 |
| --- | --- |
| 产品、SDK、普通实际夹具 | `7b757f7ec184af96d81ca5cd700bf3bc65d0f741`；tree `684d8b97e46acc4b61ed8f213cfd8923bf018b9f`，545 个跟踪文件 |
| 终态合同 actual02 夹具 | `4601297a0949fd505ad855928db1bcff5b18bf89`；实际运行与原始历史 |
| 最终终态负对照夹具 | `4512e318af7ef8e0872c4712048af238a0a4d731`；只改 README、对照构造和对照单位，产品、正向判定器和原实际历史不变 |

终态合同的源码、原始命令、构建产物和逐项分母见
[机器记录](../evidence/head7-terminal-local-2026-11-10.json)。
新的 ordinary native/HTTP/GC/load 均使用同一份 7b757 release；不能把后续 fixture 提交
描述成重新编译或重新执行了生产代码。

## 实现解决的缺口

HEAD6 把 active generation 作为永久保护对象，即使数据库已经 Deleted 也不删除最后
一代。HEAD7 增加显式、不可撤销的 terminal storage seal，使管理员能退休 Deleted
数据库的全部已分配 payload generations，同时保留 HEAD、名称和创建/删除控制证明。

seal 只推进技术 serial、格式和终态标记，不改原业务 revision、transition、A/M 或
原创建/删除身份；后续 GC checkpoint 也不能解除 seal。旧 SQL HEAD CAS、旧初始
Absent PUT 和旧 Name Release 仍受各自原条件约束。终态状态读取不加载已删除 payload，
正常的 query/lookup 在 Deleted 后继续按原 Lifecycle 合同拒绝。

这条协议延续 S3 上的条件发布与不可变对象设计。它不依靠网络文件锁，也不把 S3
挂载成 SQLite 的 `.db`、WAL 或 SHM 目录。详细格式、删除权限与知识边界见
[终态退休设计](../architecture/terminal-storage-retirement.md)。

## 新单位与逐文件覆盖

stable 和独立 nightly 均通过 **652 项 Rust 单元**。新鲜 unit-only LLVM profile 覆盖
60 个生产文件，所有有测量分母的文件分别满足以下四项精确计数：

| 指标 | 已覆盖 / 全部分母 |
| --- | --- |
| Lines | 12,083 / 12,083 |
| Functions | 1,091 / 1,091 |
| Regions | 18,418 / 18,418 |
| Branches | 2,288 / 2,288 |

0/0 的文件分支图按零分母记录，不能解释为独立测得的 100% 分支率。SDK 原始 V8
单位 profile、真实 Fetch、严格 TypeScript、codec、工具分支覆盖、夹具单位、fmt、
Clippy、文档检查和 actionlint 分别通过。真实进程或集成 profile 没有并入单位分母。
完整逐文件源码哈希与报告见[单位机器记录](../evidence/head7-unit-local-2026-11-10.json)。

## 终态实际合同

actual02 在原冻结时限内完成真实 SQLite、认证 HTTP 和 signed S3 历史；随后独立
判定器及 **25 个负对照、1 个正对照** 全部通过。夹具自身有 43 项单位，原始历史
在修正对照构造前后逐字节不变。

| 分母 | 实测 |
| --- | --- |
| 原始 HTTP POST | 235 |
| 实际 S3 请求 | 2,627 |
| 原始 SQL 输入 / 原始 ACK | 23 / 21 |
| terminal seals | 10 |
| 实际条件 DELETE | 103，全部接受 |
| 显式故障切点 | 19 |
| 原始 UNKNOWN | 13 |
| 缓存丢失 / 存活库冷 lookup | 10 / 6 |
| 受控进程 wait4 | 21 |

直接库验证了最后 A 代 seal、原 seal 响应丢失、两候选竞争、迟到 PUT 后重新扫除、
旧 GET 的严格 SnapshotExpired 诊断，以及删除完成后才交付的原提交回执。
命名库验证了 seal 位于 Release 前、Name 复用后、OwnDeleted proof 前后，以及
FenceAbsent 与迟到原始创建之间的排序。ForeignOccupied 不获得外国 Scope 的删除
权，名称后继库和外国库的原始结果在全缓存丢失后仍一致。

仅因旧 GET 失败不能报告 SnapshotExpired：必须有原合同要求的新鲜退休证明。
已知原提交不能被降级为未提交。READ 被撤销但 ADMIN 保留时可以退休；不能通过
夹具偷偷重新授予 READ 来令普通 status 成功。

原 actual 耗时约 59.805 秒，最长原始 hold 约 5.524 秒；旧读过期观察约 2.339 秒，
原提交迟交付约 1.267 秒。原整体 1,200 秒、hold 180 秒和观察 30,000 ms 的上限没有
在运行之后改变。所有受控进程已回收，private fixture 已移除，cleanup errors 为空。

## 保留的失败

actual01 的夹具在撤销 READ 后又调用普通 status，产品正确返回 Denied，因此该次
没有完成整个合同。修正版使用已经返回的权限变更 revision，保留 READ 撤销，不新增
权限。另一个运行前修正移除了原始 SQL 保存输入中不存在的 version 字段。

actual02 的真实执行和独立判定通过后，首轮 `unstable_name_view_accepted` 负对照没有
命中声明的 Name 双读稳定性规则。4512 只把对照切到真实可用的 after-seal-unknown
观察：第一次 Name GET 使用原真实 Tombstone 字节和响应头，第二次仍是原 successor；
原请求、时点、判定器与正向数据保持不变。修正后的 25/1 对照通过，原失败目录保留，
没有把实际历史重跑后覆盖成成功。

## 兼容、容量与负载

新原生网络故障、retained result、生命周期、目录和 1 GiB 全量恢复全部通过。
1 GiB 恢复逐条核对 **39 个 ACK、16,384 个 BLOB、1,073,741,824 字节业务数据**，
回执、原结果和数据哈希均零差异。该次冷恢复实际用了 8,337 GET、2 PUT 和
1,084,291,477 字节 GET 响应；仍为完整冷加载，没有声称 lazy VFS。

固定本地负载的完整原始输入、请求时间、S3 计数与资源采样见
[负载机器记录](../evidence/head7-load-local-2026-11-10.json)。独立判定与 14 个负对照、
3 个正对照全部通过；871 个 POST 中 870 个成功，另一个是预期 RecoveryBusy。
没有业务 SQL 重试。测量阶段是以下小样本 closed loop：

| 负载 | 样本 / 并发 | 吞吐 / 秒 | p50 / p95 / p99（ms） |
| --- | --- | --- | --- |
| 单库顺序写 | 32 / 1 | 10.823 | 89.159 / 119.850 / 137.289 |
| 单库并发写 | 64 / 4 | 10.083 | 390.155 / 517.274 / 579.567 |
| 四库并发写 | 64 / 4 | 14.707 | 259.076 / 343.298 / 366.518 |
| 单库读 | 64 / 4 | 150.957 | 20.859 / 69.669 / 88.797 |
| 四库读 | 64 / 4 | 153.357 | 20.785 / 67.145 / 89.791 |

同库增加并发主要增加排队；四库写吞吐本轮约为同库并发的 1.459 倍。不能把它推算
为线性扩容，也不能把小样本 p99 当成稳定长尾预测（该样本量的 nearest-rank p99
就是最大值）。32 MiB 冷恢复约 1,498.697 ms，其中含 225.374 ms 人为 gate；11 个
热库/控制探针均在解除 gate 前结束，最长请求 87.575 ms。

负载运行前团队停止了已知重编译和其他实际负载；这不是对整个宿主独占的证明。
采样 RSS 与 wait4 maxrss 分别保留，采样中的 VmHWM 非单调现象尚无解释。有限采样
不能证明进程 RSS、全局临时盘或租户资源的硬上限。

## 尚未由本批认证

HTTP 组合的最终汇总和多代 GC 的完整负对照结果仍待完成后单列。本页不以一项
终态合同替代多代 GC 的原始 264 请求保留窗口、复制、checkpoint 和延迟 DELETE 合同。

真实 AWS Standard/Express、实际 EFS/NFS/FUSE 挂载、跨 AZ 故障域、开放环流量、
长运行成本及数字 SLO 均未在本批运行。自动 owner controller、显式 snapshots/PITR、
完整内存和磁盘预算是后续产品工作；HEAD8 的新格式和 owner 接口须独立验收。
一次扫空不能证明迟到 PUT 永远不再出现，后台重扫与成本收敛仍有独立要求。
