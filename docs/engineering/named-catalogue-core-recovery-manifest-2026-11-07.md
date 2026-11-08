# 名称目录核心恢复候选清单（2026-11-07）

## 状态与基线

**NOT_COMPILED / NOT_RUN；不是验收候选，不得合入生产主线。** 本清单用于保全执行环境中断期间可恢复的源码和具体后续工作，不代表已完成 N2。

可重建基线为 commit `f16a4f6d12c0b8275e0563f56fa9d5017c3293ac`，tree `16186b3085723ce3e71aec53209a6596ef0a43a9`，parent `d63f41ee274f84cc98b0480f5e348a53f4527f4b`。PR #31 后续仅文档提交没有把下列恢复代码混入 f16 运行时。所有本清单新 blob 均通过 GitHub create_blob 保存，再 fetch_blob 回读，与提供给 create_blob 的完整 UTF-8 内容逐字相等。该核验只证明保存完整性，不证明编译或行为正确。

最后试图同时写最终 control、改变 tombstone_view 返回值、格式化和编译的 exec 命令在派发前失败。不能推断该命令产生了任何磁盘文件、格式化结果、编译日志或成功状态。本次未创建 tree、commit、ref 或 PR；由协调者按独立恢复分支接收。

## 源码与文档清单

以下路径均相对于仓库根目录。

| 路径 | 最终候选 blob SHA | 恢复性质 |
| --- | --- | --- |
| crates/scap-object/src/catalogue/records.rs | e2a488b002360e92d96fe9a5911dba4f5044062e | 将保留的 Canonical 补丁准确重放到 f16；无丢失磁盘最终哈希可比 |
| crates/scap-object/src/catalogue/mod.rs | 6b617f34d47ce18eb460cde7c9d5f85ba0315099 | 基于 f16 与已记录类型/函数结构重建；包含未执行的 tombstone_view 返回 &Head 调整及恢复时新加的 Proof→HEAD 读序修正 |
| crates/scap-object/src/catalogue/inspect.rs | 9e23e21801203152e94115878e0fc258d464fb3c | 根据保留的完整实现结构重建；不能证明逐字等于失联前文件 |
| crates/scap-object/src/catalogue/create.rs | 337c33e019074d67703d8f40296987d180866af4 | 根据保留的实现结构重建；不能证明逐字等于失联前文件 |
| crates/scap-object/src/catalogue/control.rs | 4204aedfeeadaf93f0dfe5dc985c4293927a4d0b | 保存最后未执行命令中的完整控制候选；未编译，不能称为曾经成功落盘的文件 |
| crates/scap-object/src/catalogue/fault_tests.rs | 8ee9dde327dee9dd906bd2c45198c2129df55367 | 两个保留的旧接口测试补丁重放到 f16；仍须适配 Canonical，不能与新生产文件直接宣称已可测试 |
| docs/architecture/name-catalogue-plan.md | 9795da53c99437f927ac17b30a7d5d7cce191ec6 | 新恢复说明与合同补充：控制意图比较先后、精确分类、类型边界、读取顺序及必跑并发门槛 |

较早重建的 mod blob `48ed0f8a6fb2987c2613e3984101187aa0828f4a` 保留作为历史；它仍先读 HEAD 再读 Proof，已被最终 `6b617f3` 替代。不要误用这个中间 blob。

目录有六个生产文件；types.rs 继续明确采用下表的 f16 公共 DTO 基线，五个其他生产文件采用上表。类型重构没有新增公共裸 complete、abort、proof 或任意 S3 key 接口。

### 未另行恢复的基线文件与不确定性

下列文件未记录需要重放的 post-f16 功能补丁；原有公开格式/入口变更已在 f16。**最终失联磁盘字节没有重新读取、散列或核对，均标 UNKNOWN。** 采用下列 f16 blob 是显式恢复基线选择，不能表述成已证明它就是最后磁盘快照。格式化执行先后也不据记忆补造。

| 路径 | 显式保留的 f16 blob SHA | 已知后续工作 |
| --- | --- | --- |
| crates/scap-object/src/format.rs | 8551b380ac59c049651af3a8e3952a21f2fb6873 | 未记录后续功能补丁；旧覆盖还差 1 个 region，新冻结须重新运行 |
| crates/scap-object/src/lib.rs | 210828596fcb8d7f13fa151ec1e5347ad48c5c57 | 未记录后续功能补丁；新 catalogue 私有构造 Database 依赖此结构，仍须编译验证 |
| crates/scap-object/src/format_tests.rs | 0231eb7c08ca10e401e65229b8fd6786194b46b9 | 未记录后续功能补丁；HEAD v3 / SCAPOBJ2 v2 合同不得混改 |
| crates/scap-object/src/catalogue/types.rs | 33d344348efa5531df066be5198e3da7303e55d6 | 公共 DTO 保持 f16；无已完成的新接口变更 |
| crates/scap-object/src/catalogue/protocol_tests.rs | cd31e84ac0e9047ac9e6e8d261f265977524e87d | Canonical / infallible helper 适配尚未执行 |
| crates/scap-object/src/catalogue/records_tests.rs | ee43ef9c320401836e17a2e0050c40892a850f33 | Record::Shape、新 trait bounds、Canonical decode 等适配尚未执行 |
| crates/scap-object/src/catalogue/tests.rs | 0e32a5184cffad35d9b4d5a62107e74f6768e632 | helper 返回 Source 尚未执行；f16 本身已有 Fault::Run 与第二 worker 支持 |

若恢复后发现与真实保留磁盘不同的文件，必须保存差异、审阅后纳入新的冻结候选；不能从本清单推断未知差异不存在。

## 本候选保留的协议修正

- ControlDescriptor 按当前可信 caller/kind/operation 寻址。先检查已存在操作的完整公开意图，再访问用户改投的目标 descriptor/HEAD。有效新目标尚未创建也不能遮盖已有操作变参应返回的 Conflict。新 delete 准入及原意图重入依旧要求 fresh ADMIN；abort 仍要求原 creator 与当前 provision。
- Source/Admitted 使用私有不可变 Canonical 包装，完整记录、规范字节、摘要和形状见证保持一致；不提供可变 inner 或 DerefMut。实际 Binding/HEAD 的可变观察、新鲜度、权限和 CAS 条件不缓存。
- HEAD 的命名来源 exact GET 真实 CreateDescriptor 并核对完整 Scope 与来源摘要。ForeignOccupied 只证明不可变身份元数据与永久物理槽，不遍历外来 Binding 或业务页，不宣称外来数据库业务闭包健康。
- Bound + HEAD 缺失或错误来源，在 resolve、abort 和 delete 的权威分类中为 Corrupt；descriptor-only 尚无 HEAD 的 delete 可为 NotFound；合法 Reserved 物理身份碰撞可为 IdentityConflict。
- resolve 的 Tombstone 先核对引用的 AbortProof / 删除来源；Bound + Deleted 先 exact GET 对应 ControlDescriptor。来源验证独立于原 creator READ，避免 READ 调用者被错误绑定原 creator 权限；需要当前权限的公开入口各自检查。
- 旧 abort 面对后继名称和本创建的正常 Deleted HEAD，必须检查当前名称 revision 严格大于旧轮次 terminal revision。低 revision 回滚不能当作正常 CannotAbortBound。
- create 最多推进四个明确阶段，abort 最多推进四个阶段，delete 最多推进两个阶段。每次条件写失败或 UNKNOWN 直接返回；显式下一次调用按原固定意图恢复，不给失败候选更换 ETag。
- HEAD v3 及 direct create 保留 f16 合同；SCAPOBJ2 / retained result envelope 仍为 v2。

## 恢复时发现的新静态反例

此前 View 顺序是 Binding → HEAD → Proof → Binding。即使两次名称相同，以下仍是合法历史：

1. A 读到名称 Aborting，再读到 HEAD 404；另一种初始情况为同意图 Provisioning。
2. B 按同一原 abort 意图发布 Deleted HEAD，再发布永久 AbortProof，并在最后名称 Tombstone CAS 之前暂停。
3. A 读到新 Proof，末次名称仍为相同 Aborting。把旧 HEAD 与新 Proof 合并校验会误报 Corrupt。

最终 mod 改为 Binding → Proof → HEAD → Binding。Proof 永久且只能在 HEAD 屏障之后发布，因此先读证明再读它的依赖可避免上述混合观察。名字末次 exact GET 的 body/ETag 核对仍保留。

这是独立静态审查发现并经协议分析认可的反例，**没有运行复现，没有运行修正后的反例测试**。恢复后必须通过实际 Objects/并发工作者的有序行为测试覆盖以下两个切点，不能用检查源码字符串或调用顺序字面量代替：

- HEAD 404 → B 的 Deleted + AbortProof，名称一直 Aborting；
- HEAD Provisioning → B 的 Deleted + AbortProof，名称一直 Aborting。

还需保留 A 在旧请求已经 invoke 后进程失联、写入迟到生效的原故障范围。永久证明和读序修正不构成超时调度或活性的完整证明。

## 必须完成的内部测试适配

以下任务尚未执行，当前测试文件预计不能直接与新类型编译：

1. tests.rs 的 descriptor helper 返回 Source（Canonical<Descriptor>），不再返回裸 Descriptor。
2. `catalogue.database(&source)` 改为直接 Database，移除旧 Result unwrap；`source.origin()` 和 admitted.mark() 改为不可变已校验值的直接读取。
3. 需要篡改记录做负向测试时，显式取 `raw().clone()` 得到裸记录，再送 encode / Canonical::new / 对象存储；不能给 Canonical 增加可变访问来适配测试。
4. decode 现在返回 Canonical<R>。roundtrip 比较规范 bytes 和 `raw()`；源摘要必须与完整规范编码绑定，错误记录仍由严格 decode 拒绝。
5. Record 的测试替身补 Clone、Debug、PartialEq、Eq 及 `type Shape = ()`；FailedSerialize / LargeRecord 保留真正编码失败和尺寸边界。
6. Binding body 的可变候选从 `body.raw().clone()` 构造。read_binding 返回 Name，read_proof 返回 Proof；仅有持久 source/control 经核对后才建立 NameStage/Proof。
7. own/revisions/progress 变为不可失败的只读投影；所有原单元依其实际新签名适配。仍须保留 mutable Binding/HEAD 的重新校验与故障注入。
8. 重新执行仓库固定 edition 的 rustfmt、stable 单元、严格 Clippy、nightly 精确四维覆盖；不引入 coverage 排除、不以构造不真实状态来掩盖生产不可达错误分支。

尚未编写的明确回归测试：

- 同 control ID 改投合法但不存在 descriptor 的新目标，abort/delete 均 Conflict，且不访问改投目标；未授权新 delete 不持久准入。
- resolve 的 Tombstone 引用 Proof 缺失、Bound + Deleted 引用 ControlDescriptor 缺失均 Corrupt；普通 READ 主体不依赖 creator READ。
- 旧 abort + 后继名称回滚到低 revision + 本创建正常 Deleted HEAD 时 Corrupt。
- 新 Canonical 的不可变字节/摘要/Shape 绑定、非法控制/证明形状、实际 source 核验仍保留。
- 上述两个保持 Aborting 的多键读取并发反例。

## 已有验证与本候选的证据边界

旧开发代码曾记录 stable 100/100 单元以及一轮 nightly 104/104 单元通过。它们来自旧接口/开发工作区，不绑定这里重建出的新源码；这里没有 rustfmt、cargo check、单元、Clippy、覆盖、release 或真实目录合同的通过结果。断线前未完成的编译命令不记作已运行。

旧首次 coverage 诊断明确没有达到精确门禁：

| 文件 | 行 | 函数 | region | 分支 |
| --- | --- | --- | --- | --- |
| catalogue/control.rs | 361/372 | 13/13 | 692/761 | 77/82 |
| catalogue/create.rs | 117/118 | 5/5 | 268/285 | 16/18 |
| catalogue/inspect.rs | 191/196 | 7/7 | 317/358 | 28/32 |
| catalogue/mod.rs | 309/315 | 31/31 | 474/506 | 38/52 |
| catalogue/records.rs | 190/191 | 18/18 | 305/311 | 50/52 |
| catalogue/types.rs | 8/8 | 1/1 | 8/8 | 0/0 |
| format.rs | 324/324 | 35/35 | 623/624 | 46/46 |
| lib.rs | 861/861 | 77/77 | 1353/1353 | 116/116 |

这些计数只用于说明为何需要后续工作，不是新版本覆盖数据。必须重新冻结全量集成源码并运行正式门禁，不能将不同源码/profile 的数据拼接成 100%。

PR #30 已合入的独立有界模型、原始 885 条正向历史及 25 条负对照不随本恢复改写。模型有明确交错范围，不能替代本轮每个 GET 内部交错、真实 S3、SQLite/native 或 HTTP/SDK 的验收。特别是此处新发现的多键读取误报反例必须单独实测。

恢复后的下一步是测试适配、编译与有限明确缺陷修复，再冻结新候选统一验收。名称全枚举、完整冷启动发现、自动 owner 路由、冷热隔离、GC、PITR 和 lazy VFS 等目标仍按路线图独立推进；本次保全工作没有扩大已完成范围。
