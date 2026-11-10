# Deleted 终态退休：独立有界模型

状态：设计验证，**不含产品实现**。协议见 [terminal-storage-retirement.md](../../docs/architecture/terminal-storage-retirement.md)。冻结产品基线为 `66f452ec73111f8c9dc7509883717828ba883e8a`；本目录不会改变 HEAD6 对 Deleted 最后 A 的保护。

本实验回答一个有限问题：在既有 HEAD6 代际与目录协议条件下，新增一次永久 terminal seal，并沿用原条件 checkpoint GC，能否在列出的调度中保留业务删除屏障、阻止 authority 复活、正确投影旧读失败和 UNKNOWN，同时完成原具名删除/取消恢复？它没有模拟真实 S3 响应格式、hash/JSON/native SQLite validator，也没有重做全部 HEAD6 COPY 或 Catalogue 创建协议。

## 文件与独立性

| 文件 | 职责 |
| --- | --- |
| `model.py` | 有限对象存储、固定候选、网络四阶段、原 ETag、目录来源、旧读与知识谱系；不导入生产代码。 |
| `oracle.py` | 仅消费 JSON history，从原始 GET/request/condition/effect/response 重放存储与客户端知识；不导入 model、scheduler、candidate 构造器或产品。 |
| `counterexamples.py` | 生成 14 个故意违反协议的可执行变体、6 个独立 observer 观测变异；保留导致拒绝的具体请求/证据。 |
| `explore.py` | 穷举列出的两条有序 action chain 的全部交织，另加确定的重启次序；每条完整 history 交给独立 oracle。 |
| `test_model.py`、`test_oracle.py`、`test_explore.py` | 定向协议正例、反例敏感性、observer 隔离和有限调度器自测；不进入生产单位覆盖分母/分子。 |

`oracle.py` 只使用 Python 标准库，可与一份 history 单独复制到空目录，用 `python3 -I oracle.py history.json` 执行。测试会实际验证这种隔离，不能借 model 的 `retired()` 或返回的 “ok” 标签证明自己。

## 有限域与继承条件

完整 Scope 是五元组；测试旧 Scope 为 `(1,7,11,1,1)`，foreign Scope 占用同一永久 HEAD slot，但完整 Scope 不同；同名 successor 使用新的 database ID 和永久 HEAD slot。payload key 包含完整 Scope、物理 g 与内容 hash 符号。

边界固定为：最多 48 个不同 call identity、1,024 个 trace events、技术序号不超过 31、逻辑时钟不超过 32；每个运行最多一次 compute crash。一个 checkpoint 只含一项，代表 HEAD6 最多 32 项前缀中的单项条件与持久化顺序，不证明多项遍历、LIST 分页或字节预算实现。完整扫描结束也不意味着永久为空。

模型区分 `prepare`、`invoke`、存储 `effect`、客户端 `response`。Unknown 可以先于 effect；crash 之后已经 invoke 的操作仍可落地。旧进程未发送的候选不能被新进程调用；原 caller 的 Unknown 不因新进程看到 terminal 或 absence 而被改写。新的独立句柄重新取得权威，不能承接旧可执行读取前缀。

必须继承的基础条件：

- HEAD6 `A/M/serial` 单调、分配只用 M+1、被放弃的 target 永不复用；本目录有退休谓词边界例，但没有重证全部 COPY/Seal/Promote/Abort。
- payload immutable Absent PUT、exact GET、HEAD 原 ETag CAS 与 conditional DELETE 符合存储合同；HEAD 的 authority ETag/serial 不能 ABA。payload ETag 既有每次新值模式，也有同 bytes 重建重复值模式。
- ordinary 读可中止、没有 durable read pins；当前没有 retained roots/holds。原 context 的 backend、Scope/g、HEAD body/ETag 与 deadline 固定。
- hash-valid 语义坏、物理坏、Budget 是不同符号化输入类别；这里没有实际计算这些 fault 的 frame hash，也不验证真实 wire response。
- Catalogue 原 descriptor/control/proof 永久存在，Name revision 单调。模型记录 Proof→HEAD 与 Name 双读顺序，但同步 view 内每个 GET 的交织没有穷举。初始状态已经完成旧 control admission 与必要的 Name 接受；不重建整个 admission 状态机。
- successor 创建是已验证完成的抽象原子步骤。ForeignOccupied 原取消可以独立完成元数据 Release/Done，但始终没有 own terminal 权限；losing Scope bootstrap orphan 不在清扫范围内。

模型把格式 6/7 归一为一个内存结构，`terminal=None` 的字段会出现在模拟 JSON 中。这不是提议给真实 HEAD6 wire 添加字段；产品仍要求两个严格版本 schema 的字段存在性合同。终态格式还要求 `M < terminal.serial`、`revision < terminal.serial` 以及有 checkpoint 时的 `terminal.serial < checkpoint.serial`；模型与独立 observer 分别检查这些关系。

当前树里的旧 [`object-authority-model`](../object-authority-model/README.md) 是另一个实验。PR43/49 的 GC/handle 模型没有在本目录取回或验证，因此此处不声称沿用了它们的完整模型证明，也不把新模型与冻结 HEAD6 的 unit 结果解释为实现等价性证明。

## 穷举配置

每个 profile 仅在下表明确命名的 action 边界交织。GC pipeline 是 `seal → checkpoint → DELETE → settle → clear` 五个同步宏步骤；这些宏内的所有 raw events 都进入 oracle，但 scheduler 没有把宏内部每次 I/O 作为可插入另一个 actor 的位置。单独的 terminal-race profile 则拆开两个候选的 invoke/effect/response。

| Profile | 参数与调度边界 | 完整运行正向 histories |
| --- | --- | ---: |
| terminal-race | 4 个 own 来源 × 4 个响应丢失组合 × 两条三阶段 chain 的 20 种交织 | 320 |
| late-put | 2 种 payload ETag × 2 种原回复结局 × 旧 PUT 三阶段与 GC 五步骤的 56 种交织；若重建 orphan，再跑新一轮 | 224 |
| late-get | Ready direct / Ready named delete × 旧 GET invoke/effect/response/materialize 与 GC 五步骤的 126 种交织 | 252 |
| late-head | 4 个来源的旧 Absent HEAD，加 3 个已有 HEAD 的旧 If-Match，总 7 组 × 56 次序 | 392 |
| restart-terminal | 4 个来源 × prepared / invoked / effected / responded 后 crash | 16 |
| restart-gc | 2 种 ETag × 原 Unknown DELETE 在新进程重入之前/clear 之后生效 | 4 |
| foreign-abort | 已有 ForeignOccupied proof，Name Release 四个阶段后 crash，原取消恢复且 foreign HEAD 不变 | 4 |
| 合计 | 有限参数域的全部上述次序 | 1,212 |

此外保存 20 条预期被拒绝的 counterexamples。`--smoke` 只取每组参数的第一种交织，得到 53 条正例；它明确不是完整探索。1,212 是计划矩阵的基数，必须以一次实际完整运行 manifest 验证后才能声称已经穷举。

`distinct_macro_states/edges` 是每次明确宏步骤前后完整 `snapshot()` 的 JSON 摘要去重计数，包含 call/observation provenance；不是逐条 raw event 的状态数，更不是生产程序状态空间大小。调度器不使用这个去重集合跳过未探索分支。

## 反例合同

| 反例 | Oracle 必须拒绝的规则 | 说明 |
| --- | --- | --- |
| bare-deleted-authorizes-last-a | explicit_retirement_before_gc | 缺显式解除 A 保护的格式/authority 转移；不冒称已证明当前所有 Deleted mutator 可复活。 |
| seal-rewrites-own-deleted-transition | business_barrier | 原 OwnDeleted proof 与原操作恢复被技术转移破坏。 |
| inspect-refreshes-checkpoint-condition | original_delete_etag | 新 inspect 偷换原 checkpoint ETag。 |
| unknown-delete-recorded-applied | unknown_not_disposition | 客户端尚无确定结果却持久化 Applied。 |
| delete-permanent-head-reopens-absent-create | permanent_metadata | 删除永久 HEAD 后，真正的旧 Absent 请求重新成功。 |
| seal-accepts-missing-actual-control | catalogue_authority | 只信内嵌 mark，忽略真实原 control 丢失。 |
| fresh-cas-unseals-terminal | terminal_monotonicity | 新鲜条件仍不能授权把 terminal 恢复为 live。 |
| terminal-allocates-new-generation | terminal_monotonicity | seal 后增加 M，破坏永久终态。 |
| restart-reuses-old-unsent-candidate | fresh_process_invocation | 新进程继承旧 candidate / observation 能力。 |
| seal-without-current-admin | current_admin | 没有当前 ADMIN 也尝试终态发布。 |
| foreign-proof-treated-as-owned-authority | scope_binding | 把取消来源的 ForeignOccupied proof 当作 foreign 数据退休权。 |
| terminal-clears-semantic-latch | lineage_publication_gate | 因全部 namespace 已退休而清除内容语义知识。 |
| diagnostic-extends-original-deadline | original_deadline | 失败前缀延长期限后补做 authority 调查。 |
| terminal-seal-predates-original-live-context | strict_expiry_proof | HEAD7 serial 虽然更新，但 seal serial 早于已见 HEAD6 context，属于不可能的 authority 历史。 |
| candidate-omits-stable-name-observation | stable_catalogue_view | 候选丢失稳定 Name 双读证据。 |
| semantic-error-labelled-snapshot-expired | failure_provenance | hash-valid 语义坏被显示成正常过期。 |
| unknown-head-labelled-retirement-proof | strict_expiry_proof | 不可得的 HEAD 被显示成退休证明。 |
| known-commit-converted-to-expired | known_receipt_preserved | 已知原提交回执被终态错误覆盖。 |
| unknown-inspect-forged-as-key-absence | exact_get | 原 inspect Unknown 被伪造为与实际对象状态矛盾的 Missing。 |
| terminal-seal-not-after-business-revision | strict_expiry_proof | 实际 GET 的 malformed HEAD 满足 M < seal、seal <= HEAD，却声称 revision == seal；错误 observer 仍把它显示成退休证明。 |

前 14 条改变具体协议执行，后 6 条是 observer 输入变异。最后一条明确包含故障元数据输入，再改变诊断 outcome，不声称合法产品 API 能产生该 HEAD。只有每条都被自身预期规则拒绝，才通过负控；单纯 JSON 解析失败或任意其他错误不算命中。某些反例暴露的是请求合同或证据错误，不一定导致退休 payload 的实际损坏，二者不混称。

## 运行与证据

只依赖 Python 3 标准库。模型自测命令：

```sh
python3 -m unittest discover -s experiments/object-terminal-retirement-model -p 'test_*.py' -v
```

完整探索将原始 history 与 counterexample 写到**仓库外全新目录**，已有目录拒绝覆盖；失败也保留已写 history 和失败 manifest。不要把运行日志或生成轨迹提交进源码。

```sh
python3 experiments/object-terminal-retirement-model/explore.py \
  --out /absolute/path/outside-repository/terminal-model-attempt-01
```

每次 manifest 记录产品基线、当前 source HEAD、全部 Python 源 SHA256、Python 版本、参数、每份原始 history 的 SHA256/字节数、observer 计数、反例具体拒绝事件、宏状态/边、运行状态与时间。结束时再次核对所有 Python 源，运行中修改源码直接失败。

2026-11-10 已发布 `1219d35700c0a634f5876ae033bbeb9e0a6b79f8` 的历史有限域验证如下；它没有覆盖后来新增的 `revision < terminal.serial`，以下数字与指纹不能替代 HEAD7 修正后的新门禁：

- **43 个模型/observer/scheduler 自测通过**，0.621 秒，包含 53 个 smoke 参数例、19 条预期反例、严格终态 serial/ checkpoint 时序以及独立 observer 隔离。
- **完整 1,212 条正向 histories 通过**，共 51,571 个记录事件；19 条 counterexamples 均由自身预期规则拒绝。有限矩阵全部完成，不是只跑 smoke。
- 记录 3,697 个不同宏状态、3,778 条不同宏边；全部原始 histories 总计 29,395,746 bytes。本次探索约 10.71 秒；这个运行时间仅作复现记录，不是产品性能测量。
- 最终证据目录：`terminal-model-validation-20261110-02`。`exploration/manifest.json` SHA256：`1ec3266f1e4c0113655aa24fbc7e71a6f694ac1d7e2cb42e9634ca04cd718cfa`；`unit-manifest.json` SHA256：`ef74948a1d068da2a47b7630b011f8a72d68611d283c19850fefa4ef3ae72ed6`。
- 七个 Python 源文件的排序 path→SHA256 映射经紧凑 JSON 编码后的聚合指纹：`01590a8a532f25ecd85adfff33ec1e08c1f0c24ced42d3a2a62fb37704f2deb2`。单位与完整探索的源映射相同，详细逐文件值在两个 manifest。

原诊断没有覆盖或删除：`terminal-model-pre-ready-diagnostic-01` 保存先前源码和一条错误允许 Provisioning ordinary read 的实际模拟 trace，明确标为不可达产品前缀；旧 38-test 交互输出不是最终证明。修正后，只有 Ready direct/delete 可创建 ordinary read，取消来源也不再预置不可能的 SQL 已知回执。`terminal-model-validation-20261110-01` 保存首次 42-test 与完整矩阵结果；增加 `sweep.serial > terminal.serial` 校验后，另开 02 重新验证最终源码。

HEAD7 工作树新增 `revision < terminal.serial` 后，2026-11-10 在新证据目录 `terminal-model-validation-20261110-03` 重新运行：

- **44 个自测通过**，0.704 秒；model 与独立 observer 分别拒绝单份自相矛盾的权威 HEAD，包含第 20 条 metadata/observer 变异。
- **完整 1,212 条正向 histories 与 20 条预期反例通过**，51,571 个正向事件、3,697 个宏状态、3,778 条宏边；原始 histories 共 29,416,044 bytes，运行约 16.85 秒。
- `exploration/manifest.json` SHA256：`5bedcd44de4ef6e3b1d1b15147e65c98576772b9beae7e944b2d82774b416ef8`；`unit-manifest.json` SHA256：`aaec4a1eb3979b4e28b6829c0fb17bf55884e7c997f00c59e43ffed32346fbda`。
- 七个 Python 源的同口径聚合指纹：`b2983de5c95241bacb6e5bbae1b97c1a8619390615f4c17340bd3d8d8b1f52ea`。单位与完整探索的逐文件 source map 相同；原 43/1,212/19 结果与源码不变，保留为旧有限域证据。

产品实现仍须另过完整门禁：严格 HEAD7 解码、完整 core/service/SDK 消费者、每个受影响生产文件精确单位覆盖，以及真实 native/HTTP/S3/目录恢复/进程退出的独立验收。这个实验不提前打开任何生产 DELETE 路径。
