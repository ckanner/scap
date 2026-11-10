# HEAD7 终态存储退休实际验收

本目录验证 Deleted 数据库显式 seal 后，最后 active generation 也能进入有原 ETag 的
GC checkpoint，同时永久 HEAD、名称和来源记录不会被删除。它装配正式 `scapd`、公开
Node SDK、服务内链接的 native SQLite 和要求 SigV4 的 SeaweedFS S3，不新增产品接口，
不实现替代数据库或替代 GC。

**当前状态：actual01 未完成；夹具权限前置已修正，等待新冻结源的完整重验。** 产品
`7b757f7` / 夹具 `430f7a3` 的原失败保留：撤回 READ/WRITE 后普通 status 正确返回
DENIED，旧 runner 错误要求成功。现保留该拒绝，并使用原 policy 成功响应的 revision
执行管理删除；没有恢复读写权限。原 actual01 不作为完整合同通过。现有 HEAD6
三保留窗口、COPY 完整闭包和晚到请求合同仍由相邻 `object-reclamation-runtime` 独立
承担；本目录不使用缩小的终态场景代替那份合同。

## 固定范围

完整前置和交错见 [PLAN.md](PLAN.md)。输入固定在 `spec.py`：

| 项目 | 固定范围 |
| --- | --- |
| 场景 | 8 个主场景族，另有原已提交回复子场景和 2 个明确损坏 authority 的专用 scope |
| 业务请求 | 20 次 seed SQL，1 次原已提交但回复延迟的 SQL，2 次原 Unknown SQL；23 个身份各执行一次 |
| 原件 | 21 份实际完整结果与 receipt，6 次 survivor 冷 lookup，以及 3 次完整业务行查询 |
| 名称 | 8 个 Creation，包含 2 次同名 successor；6 个原 Control、4 个 AbortProof |
| 终态 | 10 个真实 seal；当前 A 和全部已分配 g 都须在各自完整 Scope 中判断 |
| 进程 | 11 个 service incarnation、4 个 SDK、2 个工具版本 child、4 个后端 child；21 次原 wait4 |
| 交错 | 19 个明确一次传输切点；每个真实 hold 最长 180 秒 |
| 期限 | 整个场景 1200 秒；HTTP/S3 120 秒；SDK 普通 90 秒、recovery 300 秒；刻意 Unknown 1.5 秒 |
| 额外验收界限 | 两个旧 reader 与已提交延迟回复各小于 30 秒，原请求预算不续期 |
| 反例 | 25 个完整历史反例和 1 个原样正控，复制目录持久保留 |

`lookup` 的 30 秒是本场景主动选择的观察界限。它不是对产品强制 clamp 的推断。
HEAD6 direct Deleted 允许保留历史 active bit；只有 HEAD7 seal 保证 inactive。
公开 status 的 `terminal:null` 和持久 HEAD6 必须省略 terminal 字段，也分开核验。

数据来自正式 SQLite 的 `randomblob(64)`、`random()` 与真实行修改。Oracle 用原始
Result 对象、retained index、原 HEAD 发布与实际 ACK 逐字节核对；不能先算一个预期
随机输出再把它当成数据库结果。原已提交回复子场景在后端已经接受 HEAD PUT 后暂停
成功响应，经过 Delete→Seal→GC 再放行，要求原 native COMMIT/receipt 正常返回。
它不冒充 native COMMIT 失败的 CommittedButUnavailable；后者继续由核心精确单位与
已有真实 output/response 合同覆盖。

## 文件分工

`client.mjs` 只调用公开 SDK，保存原 SQL 和目录意图，完整记录每一次 Fetch 输入和
响应。`harness.py`/`run.py` 只编排正式进程、公开控制调用与显式传输暂停。
`support.py` 复用相邻实验的 owned child、raw archive、签名 TCP proxy；共享源随
完整源码清单一起归档，未复用相邻实验的 controller 或判定器。

`audit_model.py` 独立解析 HEAD6/HEAD7、完整 Scope 和目录记录，区分业务 revision 与
物理 serial，验证 terminal 与 checkpoint 的顺序。它只复用已独立实现的纯 SQL wire
解码、指纹和图遍历，以新的完整 Scope loader 加载对象，不调用产品 verifier。
`audit_evidence.py` 核对源码/正式 release receipt、原 wait4、HTTP 原件和每个 role
完整 S3 serial 分母。`oracle.py` 再核对实际 authority、元数据来源、原 ACK、GC 与
全部固定交错。

两个 operator 写入仅允许固定的 `stale` / `bad_sweep` scope：原 exact GET ETag 条件下
分别只改 `terminal.serial` 或 `sweep.serial`。没有 operator DELETE，没有对任何
正例补造状态。所有 operator 请求也经过同一个要求真实 SigV4、记录完整分母的 proxy。
旧 terminal serial 用真实 COPY→Abort→Activate 先拉开 serial/revision 差距，确保
损坏状态仍可静态解码；旧 reader 必须保留 MISSING，不能获得 SnapshotExpired。
非法 sweep serial 则必须直接 CORRUPT，且不发 DELETE 或 HEAD 技术更新。

## 运行

先冻结产品与本目录，保留真实 release build receipt、候选 source manifest 与工具
身份。从 clean checkout 运行；release 的所有 build inputs 必须和该 checkout 逐字节
相同。工具要求沿用仓库正式环境：Node 22.16.0、SeaweedFS 4.51 和固定 Rust/native
构建。验证没有 coverage instrumentation 环境变量。

```bash
python3 -B -m unittest discover \
  -s experiments/object-terminal-retirement-runtime -p 'test_*.py' -v
node --check experiments/object-terminal-retirement-runtime/client.mjs

python3 -B experiments/object-terminal-retirement-runtime/run.py \
  --server /absolute/head7-release/scapd \
  --build-record /absolute/head7-build/build.json \
  --weed /absolute/weed --node /absolute/node \
  --evidence /absolute/new-terminal-actual-directory

python3 -B experiments/object-terminal-retirement-runtime/oracle.py \
  /absolute/new-terminal-actual-directory

python3 -B experiments/object-terminal-retirement-runtime/controls.py \
  /absolute/new-terminal-actual-directory \
  /absolute/new-terminal-controls-directory
```

43 个边界单位包含严格字段、terminal/revision/checkpoint 边界、完整 Scope、原 ETag、永久元数据
格式、闭合观察分母、硬链接副本隔离，以及真实 SDK 的全部 23 次离线 prepare/restore
指纹，以及 8 个 Creation 的全部 48 种目录 action prepare/save/restore。另有 owned
loopback HTTP 验证真实签名 helper 的嵌套 body、原 ETag 条件和两个
限定 operator 字段；它不算 S3 或数据库实际验收。原始 S3 观察按 path、role、serial 和
请求时间一次建立索引；每个反例仍从自己的完整原始历史重建索引，不复用任何 PASS
缓存，也不减少原始分母或判定步骤。权限回归核对原 policy 响应版本与仅 ADMIN 的
完整历史；名称变化回归要求读取发生在原调用内、变更前，并过滤原方法和路径。

`run.py` 成功只输出 `OBSERVED_NOT_AUDITED`。只有独立 oracle、所有命名反例、原样
正控和最终 source verify 都完成，才报告该次实际合同通过。反例必须命中指定语义
边界；一个更早的无关解析失败不能替代所测试的安全性质。

每次 evidence 和 controls 都使用全新目录，失败保留 public/private 原始记录。
成功的 raw 执行会回收所有 owned child、join proxy 并清理临时凭据/cache；独立审计
使用保留的公开原始证据。不要把 runner summary、可读 status 或空 LIST 单独当成
提交、永久 prefix 为空、全局健康或原 Unknown 已经解决的证明。

本地结果不声明 `aws_standard` 或 `production_slo`。HEAD/目录元数据永久保留；
ForeignOccupied losing Scope 的 bootstrap orphan、PITR/holds 和自动 GC 调度也没有
由本合同顺带宣称完成。
