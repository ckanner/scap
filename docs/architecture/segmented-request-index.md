# 分段请求索引（HEAD 4）

本批实现 HEAD 4 的不可变请求 B+ 树，替换 HEAD 3 每次复制整个窗口的 `Index(Vec<Entry>)`。GC 仍然关闭；物理世代、pin/freeze、DELETE、保留快照及 PITR 均未实现。正式验收状态以冻结源码和独立原始记录为准，开发检查不代表正式门禁。

## 格式与不变量

永久 HEAD key、完整逻辑 Scope、请求身份、原始 Result 字节和 Result hash 不变。不可变 framing 仍是 `SCAPOBJ2`、envelope format 2；只有 HEAD 显式升级为 4，请求索引 payload 改为有类型的节点。HEAD 3 和旧 flat Index 严格拒绝，按仓库 greenfield 约束不提供静默迁移或双格式 fallback。

`Payload::Index` 包含以下两种结构：

| 节点 | 字段 | 硬边界 |
| --- | --- | --- |
| Leaf | `kind=leaf, epoch, entries` | 每叶最多 128 项；非根至少 64 项 |
| Branch | `kind=branch, epoch, level, children` | 每节点最多 32 个孩子；根至少 2 个，非根至少 16 个 |
| Entry | 完整 `request`、原 `outcome`、`result_bytes` | ID 严格递增；取消字节数为零；结果长度至多 64 MiB |
| IndexChild | `hash, summary` | summary 为 `first,last,count,result_bytes`，范围有序、不重叠且能容纳声明条目数 |

Leaf 是 level 0，父节点必须比孩子恰好多一级。最大 level 为 3：假如产生 level 4 根，至少需要 `2 × 16³ × 64 = 524,288` 项，已经超过合法窗口的 65,536 项硬上限。节点半满规则和按 ID 分裂保证任意合法 ID 排列都能使用窗口容量；不存在哈希桶碰撞导致的提前 WindowFull。

每个节点自身先严格验证，随后沿边核对孩子的实际 level、最小占用率和完整 summary。严格下降的 level 和不重叠的范围使循环引用和重复子树无法通过完整遍历，不需要无界 visited 集合。每个 Entry 保留完整 Request；按 ID 找到以后仍比较 epoch、principal、fingerprint 等全部字段。

所有索引元数据沿用小对象的 `64 KiB - 20-byte frame` 上界，移除旧 flat index 的约 32 MiB 元数据例外。单元测试用 `u64::MAX`、最长固定哈希和最大结果长度构造完整合法叶/内部节点，验证编码预算。Result 与 Chunk 的 raw bytes 仍在 JSON metadata 之外。

## 插入、查找与完整恢复

插入先验证 HEAD Window 对根的 count/result_bytes 声明，只加载一条路径。Leaf 超过 128 项后分为 64/65；Branch 超过 32 个孩子后分为 16/17。Gap 中的 ID 放入右邻子树，超出最后范围则扩展最后子树。每个新对象仍通过生产 Objects 的条件创建和精确回读后才能被引用。

一次树查找最多四次索引 GET；这不是整次 SQL 或取消的总 S3 请求数。Committed lookup 还要 fresh HEAD 和原 Result GET。当前取消/提交先查重复，再在 append 时加载插入路径，且仍有数据树、Result、manifest 回读和原 ETag HEAD CAS。单库发布点仍是一个 HEAD，不把索引优化解释为单库多写者能力。

父 summary 只支持路径验证。完整恢复遍历所有保留窗口的所有孩子、所有 Entry 及每一个原 Result；验证原结果实际字节数等于叶声明，再验证原结果格式、身份、sequence 和 transition。不能用一次点查成功或父聚合正确，跳过另一条坏枝。

在 GC 关闭的当前协议下，COW 发布继续继承既有 HEAD 对未修改子树的不可变闭包保证。启动/恢复和发现损坏后的 quarantine 不变；没有隐式退回旧根、空库或重新执行原 SQL。

## 本批明确增加的冷查询检查

此前 `Database::session`、`activate_session` 与 `activate` 校验完整保留历史，但低层一次性 `Database::query` 只恢复当前数据镜像。本批给后者也加入完整结果/索引校验，避免直接冷查询绕过不在目标查询路径上的损坏保留枝。

这增加一次性冷查询的 S3 读取与结果验证成本，仍受该入口已有的普通操作 deadline 约束；它没有被偷偷升级为 30 分钟恢复预算。准备长期 Session 应调用独立恢复预算的 Open。暖 `Session::query` 仍是一次 fresh HEAD GET 加本地 SQLite 查询，不登记 pin、不额外下载数据或索引。

原 N3 设计快照固定于旧源码，该文档的“完整冷恢复”不能倒推成旧的 `Database::query` 已做历史验证；本节明确记录旧边界和本批实际增量。

## 业务语义保持

当前加前两个已满窗口、原 count/result_bytes 满窗口判定以及 close_full 退休次序不变。Unknown、Closed、Retired、Cancelled、RequestConflict、Committed 原结果保持独立含义。HEAD 发布仍使用封存候选的原 ETag；冲突不重绑，不重放 SQL。原 Result 的 data_root 仍是回执信息，不产生 PITR 历史数据保留边。

物理发现所需的 `DatabaseSlot` 仅表示 deployment/tenant/database 永久槽。`decode_head_at_slot` 验证完整 HEAD 格式、完整存储 Scope 自身有效性以及物理槽一致性；它不会伪造 incarnation/generation。常规 `decode_head` 继续比较完整预期 Scope。

## 验收范围

- 独立 BTreeMap 参考模型覆盖递增、逆序、交错极端和稀疏 ID，COW 后旧根保持可读；另构造多层级联分裂与完整 65,536 项窗口容量。
- 严格 codec 和边验证覆盖范围、重复 ID/子树、level、epoch、占用率、结果字节伪造、缺子节点及非目标坏枝；直接冷 query 和 Open 均有拒绝回归。
- 每个生产文件要求 line/function/region/branch 精确 100% 单元覆盖；缺 map、旧 worktree 的 map、零分母或混入集成 profile 一律失败。
- 既有真实 native/network/HTTP 合同升级为严格 HEAD 4；原 retained-result 合同增加直接冷 query，固定为 12 个场景 × 6 个入口。
- 新真实 HTTP + signed S3 合同必须实际跨越叶分裂和根增长，保存所有输入、原始结果、调用及对象字节，重启全部计算后完整恢复，并实际破坏非目标叶证明点查成功不能代替全恢复。其结果不得冒充 AWS Standard 或生产吞吐。

无永久物理回收或成本收敛声明；仍须持续披露 orphan 与总存储增长。

### 新真实合同的固定输入与原始证据

`experiments/object-service/segmented_contract.py` 使用正式 `scapd`、原生 libSQL、官方 Node SDK 和真正的 SeaweedFS 签名 S3。`segmented_spec.py` 在进程启动前冻结 2,114 项保留身份：两次原始 SQL 提交，2,112 次取消；另外保存 Unknown 与 identity conflict 两个探针输入。七个 SDK 阶段一共 2,145 次 HTTP 调用，不重试或删除失败分母。分裂观测点固定为第 129 项和第 2,113 项。

六次全新 daemon 进程使用同一既有 owner identity，前一进程被 kill 并由 kernel wait4 证实退出，其本地目录删除后才启动下一进程；这验证缓存全失后的恢复，不声称自动 owner 接管。冷 Open 以及修复后的 Open 必须读取当前全部索引、原结果与页树。三类损坏都实际施加在最后一片、与第一个 ID 无关的叶：替换 magic、实际 DELETE 后返回 404，以及重新哈希后的虚假结果长度。每类都要求原第一个 ID 点查成功、Open 与 HTTP 冷 Query 拒绝、Status 可用。HTTP 冷 Query 走 `Engine::session` 的完整恢复路径；低层 `Database::query` 新增校验的真实证据另由 native retained-result 合同的 12 场景 × 6 入口（含 query）提供。损坏修复后再检查原 SQL 随机值和 BLOB 字节。DELETE 是私有故障 fixture 的操作；产品 Objects API 与物理 GC 没有因此新增 DELETE。

代理保存每个原请求、原后端响应、ETag、条件、SigV4 身份及完整对象字节；重复字节按 SHA-256 单独存档。`segmented_oracle.py` 和 `segmented_tree_audit.py` 不导入 controller 或 Rust codec，独立核对每次真实 HEAD 发布前的完整有类型闭包、全部原输入与原结果、同一 GET 的字节/ETag 版本关系、每个调用与 S3 操作的时序归属、原进程命令和 wait4、实际 release 二进制及静态 native archive 收据。日志写入时点可以晚于网络返回；审计使用后端 response 与实际调用窗口，不把 logger 时点冒充子进程出生时点。

运行方式（必须使用当前冻结源码新生成的 build receipt 和全新 evidence 目录）：

```sh
python3 experiments/object-service/build.py --target-dir "$RELEASE_TARGET" --evidence "$BUILD_EVIDENCE"
python3 experiments/object-service/segmented_contract.py --server "$RELEASE_TARGET/release/scapd" --weed "$SCAP_WEED" --build-record "$BUILD_EVIDENCE/build.json" --evidence "$CONTRACT_EVIDENCE"
python3 experiments/object-service/segmented_oracle.py "$CONTRACT_EVIDENCE"
python3 experiments/object-service/segmented_controls.py --evidence "$CONTRACT_EVIDENCE" --output "$CONTROL_EVIDENCE"
```

证据损坏 controls 固定为 19 个负例和 1 个正例；正例证明 controller summary 不决定验收。原失败日志与未完成分母保留，不改写旧 source manifest 或旧 build receipt。合成 Python 测试只验证审计器的拒绝能力，不是 native/S3 已运行的证据。当前运行状态由对应独立审计输出记录，不在文档里预写“通过”。
