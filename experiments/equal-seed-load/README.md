# equal-seed-v1

新夹具接续 [生命周期设计](../../docs/architecture/admission-lifecycle-diagnostics.md)。
旧 `short-v1`、`admission-curve-v1` 的文件和输入未修改。这个目录不实现数据库算法，
只装配正式 release 服务、正式 Node SDK、真实本地 S3 兼容 backend 和独立原字节审计。

实现与真实验证状态以[验证台账](../../docs/engineering/admission-lifecycle-validation-2026-11-22.md)
为准。单元中的合成 snapshot仅用于检查 parser/不变量，绝不写入 actual 原始证据或冒充
产品导出。夹具源码在首次证据前冻结，后续结果写入独立台账，不修改本合同解释结果。

## 固定输入

每个 `12/s`、`32/s` 速率分别按 off/on/on/off 启动四个全新后端、服务、库和本地 cache。
每 cell 原 DDL 后以 `4/s` 发 256 个独立 INSERT，64 秒、全部原始 ACK、drain；测量
32 秒，8 个 4 秒窗口。seed 四次 status，load 八次 status。总测量 5632 INSERT，
seed 2048 INSERT；最大每库 1280 行、1281 execute 身份。random witness 分别核验，
不要求对象 hash 相同；schema、页数、request/data 树层级和原结果保留规模必须相同。

所有生产 intake/queue/output/cache/transport/group 限制与原业务期限保持不变。
唯一处理变量是 group 开关。两边均启用同版 lifecycle profile 和独立随机诊断凭证。
每身份最多一次 original SQL POST；核验仅 lookup/UNKNOWN cancel/lookup，绝不重放 SQL。

## 有界观察

全部数字由 `spec.py` 固定：每 cell raw 2 GiB、S3 60000 attempts/240000 rows/384 MiB、
SDK 22000 rows/32 MiB、原诊断最多16 GET/1 MiB、采样15000 ticks/合计64 MiB。
采样投影 `resources.jsonl` 与角色原文 `envelope.jsonl` 共用64 MiB预算。
SDK、raw、S3 trace 和样本在写前检查额度；不截断后声称完整。阶段/全矩阵时限触顶失败，
不改计划重跑。独立审计每 cell90秒，全矩阵额外120秒；不能完成就不报告 PASSED。

服务、Node、四个 backend 进程均通过原 launcher 传入拥有的 `/proc/self` 目录 fd，
不通过宿主 PID 猜测进程。observer 读取自己的 proc fd。角色接受上限按设计固定，
**backend 四个进程合计**。100 ms目标间隔、实际扫描时间/间隔、FD/task原数组、原始
stat/status、wait4终态RSS与CPU都保留。采样可能遗漏间隔内 overshoot，不宣称内核硬限。

每 cell 开始对已封存 evidence 前缀记录完整统计；100 ms只扫描当前cell与private目录，
将封存前缀计入24 GiB/200000 inode总额度。cell边界与末尾重新扫描整个矩阵。
这样避免随着已完成cell文件增长而反复扫描旧目录；实际scan span仍完整记录。
运行始终保留2 GiB空闲；启动要求26 GiB和220000可用inode。全矩阵同时只有一个backend。

baseline在seed完全drain之后；end在load全部原响应drain之后、settlement之前。
每边界最多8次原诊断GET；不reset，也不因观测改变原SDK结果。只有valid=true且所有lane/
group active=0才能做完整差分。原acquire拒绝不算lease；成功acquire后发生的后续gate拒绝
仍计入。无法从原HTTP证明acquire的transport-only结果使精确cohort不可用。

parser核对计数、桶、组尺寸、时间范围和单调差分；所有释放的total_hold必须完成。
原SDK和HTTP成功的execute/status还要求八个interval都有完整样本，不能把缺hook变成
not_reached并仅凭守恒通过。真正错误路径的不完整样本保留，不平均、相加或用p99相减。

## 来源与执行

**先提交冻结的spec和fixture，再执行真实矩阵**；runner拒绝未跟踪或相对HEAD有修改的
fixture文件。它在启动/结束核对fixture、release build/source archive、正式SDK和工具
摘要，保留原始失败。不提交raw日志、数据库、cache、服务token或S3凭据。

```bash
python -m unittest discover -s experiments/equal-seed-load -p 'test_*.py' -v
python experiments/equal-seed-load/run.py \
  --binary /absolute/release/scapd --build-record /absolute/build/build-receipt.json \
  --node /absolute/node-v22.16.0/bin/node --weed /absolute/weed \
  --evidence /absolute/new-exclusive-evidence-directory
python experiments/equal-seed-load/controls.py /absolute/evidence-directory
```

`shared.py`只在初始化时解析旧实验工具的sibling imports，不改旧文件或运行中的算法。
`oracle.py`不导入runner或生产模块。它保留旧原始HTTP/S3、原HEAD ETag、不可变闭包、
原结果/witness、最终SQLite integrity证明，并另查seed几何、resource envelope与cohort。
定向controls只修改内存中的审计投影，不再次启动SQL或覆盖原始记录。
`controls.py`执行一次完整8cell正审计，然后在额外120秒总期限内验证局部投影反例，输出
`audit`与`controls`两个部分；每例必须命中指定拒绝规则，timeout或任意其他异常不能
充当反例通过。`oracle.py`亦可单独运行。派生报告放在矩阵根或外部，不追加到已封存cell。

## 报告与限制

首要指标是原ACK数/成功率和固定32秒内ACK数，同时给完整drain分母；成功、拒绝、其他
结果的latency分开。成本按seed/load+drain/settlement分账，包括所有S3失败尝试、双向
body bytes、CPU/资源、全部不可变对象、最终live closure及orphan；按offered与原ACK
分别归一。GC关闭，不能宣称无限运行或只用HEAD PUT数代表成本。

证据通过不要求group获胜。若讨论改善，两个固定配对均须保持ACK与窗口内ACK不降，
成功p99/control p99/S3 requests per ACK/双向body bytes per ACK均不增加超过5%，
且原ACK或S3 requests per ACK至少改善5%。不满足就明确未达到预登记改善条件。

128pages/4chunks是更严格的本机接受额度，超出失败；不是所有SQLite输入的数学上界。
本轮是相同起点的有限增长对照，不是steady state、AWS Standard、跨AZ或生产SLO证明。
原字节capture/fsync、proxy、诊断和采样会增加观察开销；两边采用相同规则不等于零开销。
