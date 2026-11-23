# 有界 intake 生命周期诊断与相同 seed 对照

状态：**设计已先提交到 PR #71，生产实现已进入同一草稿；完整验收尚未完成**。
当前候选、精确验证与限制见[验证台账](../engineering/admission-lifecycle-validation-2026-11-22.md)。
本合同接续已合并的 PR #70；其依据与后续优化出口见
[接纳容量设计](../engineering/admission-capacity-next.md)。先提交本设计的 Draft PR，
再在同一 PR 实现、冻结源码并收集新证据。不得把已有 c6a40f41 的验证算作本实现通过。

## 1. 目标与边界

现有原始 HTTP 拒绝全部首先命中单租户 data intake 40，但这没有解释名额花在哪里。
本次交付固定低基数的驻留时间观测，以及消除累计阶段起点差异的对照夹具。
**保留 intake 40、全部原 quota、SQL、身份、deadline、原 ownership 和 ACK 屏障。**
本阶段不预先选择吞吐优化，不提前释放 lease，不提高队列或连接预算，不启用默认组批。

诊断解释服务资源驻留，不能替代外部 HTTP/S3 原字节、原 ETag 条件 HEAD、完整不可变
闭包和最终 native publication 证明。SQLite 仍只在私有本地执行目录工作，不共享活跃
`.db`、WAL、SHM 到 NFS/EFS；S3 仍是唯一持久权威。

## 2. 配置与独立导出权限

新增可选配置，缺省为关闭：

```json
{
  "lifecycle_diagnostics": {
    "version": 1,
    "token_sha256": "<64 个小写十六进制字符>"
  }
}
```

配置严格拒绝未知字段、未知版本和非法摘要，且必须在永久 worker identity claim 前
完成本地验证。摘要匹配采用现有 SHA-256/恒定时间比较；Bearer token 的语法沿用
32–1024 字节 ASCII graphic。此凭证只授权全进程的匿名诊断，不能执行数据库请求；
普通租户或 deployment inventory 凭证也不因此获得全进程诊断权限。操作人员应使用
独立随机凭证，配置和原始证据中不得提交明文 token。

`GET /diagnostics/lifecycle` 使用上述凭证，保留现有仅 loopback 监听与 transport
约束。关闭时返回 404，缺失/非法凭证返回 403；同时最多一个导出响应，额度不足
立即返回 429，不排队。成功 JSON 最大 **65536 字节**，超过上限返回有限错误而不
输出截断 JSON。单个导出 permit 从生成 snapshot 前持有，经过 response body、
frame、`Bytes` clone 和非空 slice，最后真实字节 owner 释放后才归还。

导出在短临界区复制固定聚合状态，解锁后序列化；不持有业务 quota/queue 锁，不访问
S3，不创建按请求队列，不 reset 计数，也不把导出本身计入 intake cohort。
关闭路径仍有固定 optional 字段和分支开销，不能宣称零成本。慢客户端可能占住唯一
诊断额度；既有 transport deadline 继续生效，不能用释放仍存活字节的 permit 解决。

## 3. 覆盖与固定 schema

每 daemon 一个聚合器，固定五个 lane：`data`、`control`、`recovery`、`catalogue`、
`restore`。它们对应原 intake pool；catalogue 与 restore 虽共用 worker 类型仍分账。
discovery 使用另一种 reservation，本版**不覆盖 discovery**，不能输出其零耗时来
表示已观测。schema 明确 version、覆盖 lane、有效性和固定单位，不含 tenant、
deployment、database、request、SQL、对象 key 或路径标签。

每个原 `Lease` 只携带一个固定大小 trace。聚合器和 group attempt guard 都不能持有
`Arc<Lease>`、输入、输出或 native 对象，不能延长原工作和字节所有权。

每 lane 记录 acquired、released、active；每个 interval 记录 completed、censored、
not_reached、总微秒和固定桶频数。所有 u64 数量以规范十进制字符串导出，避免 JavaScript
精度丢失。活动请求只计 active，未释放请求不伪造成完成的直方图样本。

### 3.1 八种 interval

| 名称 | 起止 | 语义限制 |
| --- | --- | --- |
| `body` | acquire → 完整 body 并成功 shrink | body 读失败没有完成边界 |
| `pre_enqueue` | body ready → 成功 enqueue | claim、授权、output claim 不等于 enqueue |
| `queue` | 成功 enqueue → worker invocation 开始 | 选入 group 不等于 consumed 或开始 SQL |
| `invocation` | worker invocation 开始 → 可信返回 | 包含生产 worker 的整体工作，不称为纯 SQL/native 时间 |
| `encoding` | worker 预编码开始 → 预编码返回 | 包含 fallback、CBU、无 Reply；catalogue 在 HTTP 编码，本项未到达 |
| `post_work_hold` | 最后 worker 返回/预编码完成边界 → 退款 | 是工作边界后的资源持有，非纯网络耗时 |
| `post_http_hold` | HTTP response ready → 退款 | HTTP 可能先超时，后续仍在执行，不表示后台工作已结束 |
| `total_hold` | acquire → 最后 lease owner 退款 | 包含 queue/native cleanup/body/frame/clone/slice 的原生命周期 |

`http_response_ready` 与 worker 编码完成是两个字段，不能互相覆盖。多个 interval
可以重叠，不相加解释为串行 wall time，也不通过两个 p99 相减计算第三个 p99。

有起点但没有终点的 interval 记 censored；无起点记 not_reached。正常早拒绝、排队
过期、receiver 消失、HTTP deadline、panic 没有可信返回等，允许出现可解释的 censored
或 not_reached，不自动把业务失败判作诊断内部损坏。逆序的依赖时间、重复阶段标记、
计数或时间溢出、诊断锁中毒则留下 sticky invalid，使该 snapshot 不可用于完整归因。
诊断错误不能改变原结果、引发 Drop panic、自动重放 SQL 或把 UNKNOWN 改写为 ACK。

采用单调 `Instant`，完成时转换成微秒并检查 u128→u64。固定 **19 个含上界桶**：

```text
100, 500, 1000, 5000, 10000, 50000, 100000, 500000,
1000000, 2500000, 5000000, 10000000, 30000000, 60000000,
300000000, 1800000000, 86400000000, 604800000000, 18446744073709551615
```

桶是分布范围，不能从它们声称获得精确样本分位数。固定数组内存、trace 内存和导出
JSON 最大尺寸须由实现单元测试给出实际大小与最坏序列化检查，不建立历史 vector/map。

### 3.2 正确的 hook 与 group 语义

成功 enqueue 在原队列锁内、实际 push 前标记固定 trace 字段，不能等返回后与 worker
竞争，也不能在后缀 requeue 时重写原 enqueue。这里只写固定 trace，不聚合或导出。
`perform` 在 receiver/deadline 早退之后、实际调用 worker 之前才记录 invocation。
Lease Drop 先完成原 quota 退款并释放原锁，再进行诊断收尾；结束时间对应退款边界。
worker 先销毁、active job 后销毁的字段顺序保持不变。
关闭或拒绝路径若原本在 queue 锁内销毁 Job，改为锁内移出有界待处理队列并完成原
queue usage 记账，解锁后才发送失败及销毁 Job；intake/output 仍由原 owner 最后释放。
这样诊断聚合不进入原业务资源临界区，且没有新增无界历史或清理队列。

每次 group attempt 另有固定聚合：attempt 次数、selected/consumed 计数、declined、
completed、incomplete 与时长桶，以及固定 1–64 成员大小分布。attempt guard 不持有
lease。`Declined` 后只为实际 fallback 首成员记录普通调用；未消费后缀保留原 enqueue。
可信 `Completed` 只给 consumed 前缀追记这次 group 调用的共同开始/返回范围。
这表示每成员参与的 worker 调用范围，不表示每成员实际 SQL 开始时间；即使前缀错误
也可能没有运行 SQL。panic 无可信 consumed 边界，attempt 记 incomplete，不能猜测。
group 共享调用时间不按成员平均后称为实测，也不与成员 interval 相加。

## 4. equal-seed-v1：第一份固定合同

这是新目录 `experiments/equal-seed-load` 的独立合同。旧 short-v1、admission-curve-v1
的输入、profile 和证据不变。旧 96 秒 × 五档 × 两个 ABBA block 仍是后续提案，
尚未运行；本次在第一条证据前固定较小矩阵，以排除已有起点混杂并观察更长窗口。

| 参数 | 冻结值 |
| --- | --- |
| 到达率 | 12/s、32/s |
| 顺序 | 每档 off-1、on-1、on-2、off-2；共 8 个独立 cell |
| seed | 新后端/服务/数据库/私有 cache；原 schema + 256 INSERT，4/s、64 秒；全部原 ACK 后 drain |
| load | 每 cell 32 秒；384 或 1024 原事务；8 个 4 秒窗口 |
| control | seed 4 次，load 每 4 秒一次共 8 次 status |
| 原事务 | 全矩阵 5632 measured INSERT、2048 seed INSERT，另每 cell 一次 schema |
| 最大单库 | 1280 INSERT 行，1281 个原 execute 身份（含 schema） |
| SQL/payload | 原 INTEGER PRIMARY KEY rowid 表，256 字节 payload，random() witness 与 RETURNING 原结果 |
| 唯一处理变量 | group off/on；最多 8 成员及原 input/page/result profile |
| 资源 | 保留原 intake 80/40、queue 96/80/72/control reserve 8、全部 output/cache/transport/retention 配置 |
| 客户端 | inflight 192、原 offer-lag 1000 ms、client 65000/recovery 70000 ms、S3 15000 ms |
| 诊断 | 两边同时启用同版 profile 与独立导出凭证；不改变数据库授权 |

不能用本地复制 `.db` 做 seed；必须走产品提交路径。每 cell 比较 seed schema、256
个相同 id/payload、257 个 retained 身份、page_count、request/data 树层级、epoch、
原结果总字节与同一冷/热规则。random witness、HEAD ETag 和内容摘要可以不同，分别
记录并独立验证。起点几何不匹配或 seed 原 ACK 缺失则合同失败，不能悄悄补发。

seed drain 后、load 前获取 valid=true/active=0 的基线；load 原响应完全 drain 后、
任何 lookup/cancel/final query 之前获取 valid=true/active=0 结束 snapshot。
差分覆盖 load 的全部成功 acquire（含 body/后续 gate 拒绝）及 8 个 control，原 acquire
拒绝没有 lease，须从原 HTTP 拒绝账本扣除，不能要求所有 offered 都形成 trace。
不能 reset 活动 trace；无法按时取得完整终点则保留不完整事实、归因 NOT_RUN。

## 5. 几何、证据与运行预算

下列区分**输入可推导范围**、**实验停止额度**与**观测接受上限**。有限身份数不保证
所有冷恢复/故障/settlement 路径能在本机预算内完成；触顶保留失败，不提升上限或
覆盖重跑。此首版是有限增长归因合同，不是无限运行/最坏路径完成定理。

### 5.1 输入几何

最大 N=1280 INSERT，K=N+1=1281 execute 身份，低于 retention 4096。每 INSERT
原 SCAPRES1 结果 343 字节，schema 36 字节；最大保留原结果 439076 字节，低于
原 256 MiB。最终全行查询 64+279N=357184 字节。结果字节和随机 witness 由独立
oracle 逐条核对，不用产品 encoder 生成预期答案。

只有固定 rowid 表和 SQLite schema、无删除、无 overflow/freelist 的约束下，保守按
每行一个叶页、内部页不超过叶页数、另两个元数据页，完整 image 不超过 2N+2=2562
个 4096 字节页，最多 81 个 32-page chunk。该推导前提必须由重建 image 独立检查。
本机首版额外采用更严格的 **128 pages /4 chunks /data level 0 接受上限**；超出即
失败而非截断或用旧样本峰值证明上界。K≤1281 的 request tree 最多 20 个 64-entry
非根叶加根，层级≤1；每个实际节点计数和闭包均独立核对。

每个 execute 身份至多 original POST + lookup +（UNKNOWN 时 cancel + lookup），
再加 create/activate 2、status 12、final query 1，单 cell POST 机械上限 **4K+15=5139**。
诊断 GET 单独最多 16 次、每次≤65536 字节；不重发 SQL。SDK 每 POST 至多四条
call/http 记录，加1280+12个 offer和固定阶段事件，账本最多22000行。

### 5.2 执行前冻结的停止/接受额度

| 域 | 每 cell 或全矩阵额度 | 触顶与核查 |
| --- | --- | --- |
| S3 attempts | 每 cell 60000；每 attempt 原 trace 四条，≤240000 行 | 在观察器接纳处检查；失败尝试也计数 |
| S3 trace | 每 cell 384 MiB | 原始记录写入前检查字节额度，不截断后声称完整 |
| raw request/response bodies | 每 cell 2 GiB，单 body 64 MiB | 原捕获额度；存储全部原字节，拒绝后保留失败 |
| HTTP ledger | 每 cell 22000行/32 MiB | 所有 POST、offer、失败和阶段记录计入 |
| 诊断原文 | 每 cell 16 GET/1 MiB | 单响应最多64 KiB；全部导出含时间与来源 |
| samples | 每 cell 15000条/64 MiB、100 ms间隔 | 实测≤900秒理论9001采样，加启动/收尾裕量 |
| 并发 | client192、transport192、proxy32 | 固定既有 admission；导出额外单响应额度 |
| backend | 全矩阵同一时刻只有一个 backend；data接受上限2 GiB | 定期核对并在 cell 结束审计；含 orphan，不声称 GC |
| 证据磁盘 | 全矩阵24 GiB；启动至少26 GiB空闲，运行保留2 GiB | 含8×2 GiB raw、trace/账本/sample、backend与重建裕量；不在该预算内复制归档 |
| inode | 全矩阵接受上限200000，启动至少220000可用 | 定期采样和结束核验，保留失败证据 |
| RSS/fd/tasks | 分角色固定在新 spec，实施前按下述规则核对 | 采样接受上限，不冒充内核强制上界 |
| startup | 每 cell60秒 | 期限失败保留 |
| seed/load | seed100秒/load90秒（含各自drain） | 保留原单请求 deadline，不因测量而延长 |
| settlement | 每 cell600秒 | 预算耗尽则失败，不能假称所有故障路径能在此完成 |
| 独立审计 | 每 cell90秒；全矩阵另120秒 | 未完整审计不通过 |
| shutdown | 原graceful30秒；随后强制终止及有界清理 | 清理不改变原结果 |
| 总时间 | 每 cell900秒；全矩阵7200秒 | 总期限优先，不将分阶段上限相加后自动扩容 |

观察器/runner 必须明示采样延迟与两次采样间可能超过接受上限的事实。RSS/fd/task
采样不能被描述为 hard cap；若环境提供可验证的 kernel envelope，另记其真实限制。
默认以服务 RSS 2 GiB/2048 fd/256 tasks、Node 1 GiB/1024 fd/64 tasks、backend
四个进程合计2 GiB/2048 fd/512 tasks、observer+runner 1 GiB/1024 fd/128 tasks 作本地接受上限；
每100ms采样，超限停止并判失败。独立 oracle 检查账本完整、采样跨度与终态峰值，
不能用没采到峰值证明从未越界。首轮启动前须验证当前环境能执行这些监测规则。

## 6. 判定与验证

证据通过与性能改善是两个判定。完整保留每个原 offered 身份、原 ACK/BP/UNKNOWN/CBU、
generator reject、迟到响应、全部 control、成本和失败。独立核对原返回字节、lookup /
cancel 屏障、原 HEAD ETag、S3 闭包及重建 SQLite integrity_check。原 SDK 截止后观察
到 HTTP ACK 不能重写原 SDK UNKNOWN。原成本按 seed/load+drain/settlement/audit 分账，
同时列 S3 各操作、请求/响应字节、retained/orphan 增长，不以 HEAD PUT 数代表全部费用。

本合同不要求 group 获胜。若讨论“改善”，同一到达率的两个固定 off/on 配对中，原 ACK
与到达窗内 ACK 均不得减少；成功 p99、control p99、S3 请求/ACK、双向 body 字节/ACK
均不得比配对 baseline 增加超过5%，并且至少一项预登记目标（原 ACK或S3请求/ACK）
改善≥5%。没有满足则明确未通过，不事后选取有利分母。32秒有限增长仍不构成生产SLO
或长期稳态容量，AWS Standard/跨AZ/账单保持 NOT_RUN。

生产验证覆盖：默认关闭和专用授权、enqueue前失败、排队过期/receiver消失、超时先于
worker完成、panic cleanup、编码fallback/CBU/无Reply、group declined/短前缀/后缀
requeue、body/frame/clone/slice最后释放、导出慢客户端额度、溢出/逆序/中毒。
每个生产 Rust 文件四维精确100% unit-only；真实HTTP/native/S3/进程合同独立运行，
不得互相补覆盖。新夹具独立正对照与篡改反例必须拒绝缺失seed、计数不守恒、无效
snapshot、错误cohort、超额、来源不符及被删除失败记录。

## 7. 交付顺序

1. 提交本设计与版本化预算到 Draft PR，所有新实现和新证据标为 NOT_RUN。
2. 实现固定 trace/聚合器、原生命周期 hook、独立有界导出和单元验证；提交代码。
3. 实现 equal-seed-v1 夹具、原字节审计与反例；冻结源码、工具和 release 身份。
4. 完成精确单元覆盖、真实生命周期回归与8cell对照；保留全部失败，提交派生报告和摘要。
5. 用实际主要驻留阶段选择下一项单机制优化。剩余门槛未通过时 PR 保持 Draft，
   不把“已提交设计”写成“已解决吞吐”或“可替代 Postgres 的通用生产服务”。
