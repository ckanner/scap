# HEAD9 S1 保留点真实验收（固定合同）

运行前冻结本文件、全部夹具源码、正式 `scapd` 与 native worker release receipt。
运行器只产生 `OBSERVED_NOT_AUDITED`；独立 oracle 与指定 guard 负控另行判定。
对象存储为真实本地 SeaweedFS 4.51，实际 SigV4 请求逐条验签；不宣称 AWS Standard、跨 AZ 或生产 SLO 已验收。

## 固定分母与次序

唯一直接 Scope 为 `(1,7,8201,1,1)`。native worker 9300 执行原始 SQL 1、2，
正式 HTTP/Node SDK 执行 SQL 3–6；每笔事务修改 `counter`、`randomblob` 并返回原始 BLOB 与 `random()`。
先由 SDK 保存全部六个输入，独立保留每笔原 ACK 的完整结果 bytes 与 receipt。
`retention.max_entries=2`，两次 `close_full` 后保留三个完整窗口，每窗两笔。
点一严格捕获事务 2 后当前 Manifest；点二严格捕获事务 4 后当前 Manifest；
点一 BLOB 为 64 bytes，点二与最终当前 BLOB 为 196608 bytes，必须有不同根和不同 Manifest page_count。
期望业务数据来自原 ACK，不从恢复库反读构造。

| 项目 | 固定数量 |
|---|---:|
| Scope / SQL 原输入及 ACK / 冷恢复 lookup | 1 / 6 / 6 |
| native SQL / public Node SQL / retained windows | 2 / 4 / 3 |
| owner 原输入、descriptor、prepare/claim/resume | 2 / 2 / 各 2 |
| snapshot 原输入、descriptor、capture、release、永久 proof | 各 2 |
| snapshot limits 设置 / COPY→sealed→promote | 1 / 1 |
| retired-generation GC 轮 / terminal payload GC 轮 | 1 / 1 |
| 有保留点的 seal 拒绝 / 成功 terminal seal | 1 / 1 |
| capture/release HTTP ACK 丢失 | 各 1 |
| daemon / SDK incarnations | 各 3 |
| owned wait4（9 个直接子进程及 4 个 Seaweed 进程） | 13 |
| 全 warm daemon cache 删除 / native cache 删除 | 2 / 1 |

每轮 GC 从 `after=null` 开始，只按正式响应的严格递增 frontier 继续，最多 32 页。
其运行页数不作为可缩减场景分母：oracle 重新构造全部实际 S3 交换、每一 checkpoint、
原 ETag DELETE 与完整已退休代对象集合，要求穷尽后无剩余 payload。
所有 SDK command、HTTP listener/connection/request、S3 listener/request、进程 start/stop
必须有封闭原始分母；遗漏任意交换不能通过。
原输入先跨所有 SDK 原件校验 fsync，再按原请求时间核对使用；不能按控制器启动顺序
推定保存顺序。全部旧 daemon/SDK 的 owned wait4 必须先于新 daemon spawn，
每个旧 daemon 的 cache removal 必须晚于其 owned exit，且三个 daemon cache 路径不复用。
GC 每页原 `after` 必须精确来自上页真实报告，首个为 null、非终页严格递增、末页
真实 `exhausted=true`；报告必须绑定真实 LIST、typed exact GET、checkpoint、resume。
代 1 的完整清除必须在全部 warm 计算丢失之前已完成。
第一轮 Scope 仍 Ready，用普通 `status` 读取；第二轮为 Deleted terminal，用专门的
`storage_status` 元数据入口。该入口本身不接受 Ready，不得把 LIFECYCLE 失败当成 GC 成功。

## 固定历史

1. native 创建与激活唯一库，执行 SQL 1、2，关闭 native 并删除缓存。
2. C(9403) 从原始输入 prepare owner；A(9401) claim/resume。显式设置两个点、4 MiB gross 限额。
3. C 保存点一输入、prepare、capture。代理在真实服务成功响应后丢弃 ACK；
   原 SDK 调用必须 UNKNOWN。A 从保存输入 inspect，确认 `retained`；不得把原 UNKNOWN 改成 ACK。
4. A 关闭第一窗口、执行 SQL 3、4；C 保存点二输入并 prepare/capture。
   A 关闭第二窗口并执行 SQL 5、6。点一、点二的原根、page_count、sequence/source_revision 不得漂移。
5. C 执行一次完整 COPY→sealed→promote，basis 必须保存两点与其限额。
   oracle 按每棵 Manifest 自身几何遍历当前根、两个 held root、三个窗口/result；
   逐一核实新代相同 bytes，不能以 list 长度或当前根代替完整闭包。清理退休代 1。
6. 停止全部 A/C daemon 和 SDK，删除两个缓存。仅启动 C(9503) 与全新 SDK；
   从新 owner 原输入 prepare/claim/resume，实际恢复 GET 必须涵盖代 2 的完整保留闭包。
   六个 cold lookup 必须保持原 receipt/result bytes；当前 SQL query 必须匹配事务 6 原 ACK。
7. C inspect 两个保存点；release 点一同样真实服务成功后丢弃 HTTP ACK，
   原调用 UNKNOWN，随后 inspect 为 `released_observed`。点二仍保留。
8. 正式 lifecycle 删除；带点二调用 seal 必须拒绝；Deleted 下 release 点二、inspect，
   seal 成功，再完整清理代 2 payload。两个 descriptor 与两个 proof 的 bytes/ETag 不变，
   两个 inspect 仍为 `released_observed`；所有 payload 已移除。

## 独立审计与负控

oracle 不导入产品或 SDK 验证器，不执行产品算法；只复用早期独立审计的纯 frame/SQL/result
decoder 与原始证据封闭检查，并独立实现 HEAD9/S1 point/descriptor/proof/COPY basis 规则。
它读取原 HTTP、S3、进程、输入与原 ACK；不得信任运行器 `status` 或事后结果摘要。
必需负控分别命中指定 guard：漏一个 held root、替换 COPY basis、错误 SnapshotRef、错误 Scope、
缺 release proof、把 UNKNOWN 改成 ACK、省略 HTTP 交换、省略 S3 交换、修改原结果、删除永久 metadata。
负控为复制证据后有意改动，不向实际产品偷偷注入伪造正向 HEAD。

S2 restore/fork、定时备份、snapshot RESTORE、自动控制器、AWS 云端和吞吐 SLO 不在 S1 此固定合同中。
