# 不可变对象操作上下文：N3 的前置边界

## 1. 本批范围

本批把不可变对象的地址选择从 `Database` 移到一次操作捕获的 `ObjectContext`。
它是后续存储世代设计的前置改动；当前仍使用 HEAD format 4、`SCAPOBJ2` frame
和既有 Scope 对象路径。没有引入 `storage_generation`、`head_serial`、pin、退休判定、
LIST、DELETE 或 PITR，也不代表总存储成本已经收敛。

实现基线为 `838ff0e638e3b0b9ec534407696f89f5218983cd`。完整存储回收目标仍见
[存储回收设计](storage-reclamation-plan.md)；该文第 1 节记录的是更早设计输入，
其中 HEAD 3 和完整 Vec 请求索引的描述不能用于判断本批基线。
当前 [format](../../crates/scap-object/src/format.rs) 已使用 HEAD 4 和不可变请求树，
本批不修改其算法、字段或编码。

## 2. 为什么单独捕获

一次写入可以在下载、原生 SQLite 执行、上传、回读或 HEAD CAS 前暂停。
如果未来把可变的“当前物理世代”放到 `Database`，旧操作恢复后再次查询该字段，
同一候选的对象就可能被发送到不同物理命名空间。即使最终 HEAD CAS 失败，
这种改绑也会破坏后续关于退休命名空间和迟到上传的证明。

[ObjectContext](../../crates/scap-object/src/object_context.rs) 现在保存逻辑 Scope 的独立
副本、对象后端的 Arc 及共享 quarantine 标志。字段是模块私有的，生产代码不能在
操作中修改它们。数据树与请求树只接受它实现的 `DataObjects`；`Database` 不再
实现该 trait，也没有绕过上下文的不可变 `load/upload` 方法。

当前格式没有单独物理世代，因而这个上下文只冻结当前已经存在的地址选择。
后续新增世代或 pin 时，仍须先完成独立状态模型与严格格式升级，不能把此处的
Scope.generation 解释成 GC 计数器。

## 3. 捕获和传递边界

| 路径 | 捕获点 | 保持同一个上下文的阶段 |
| --- | --- | --- |
| Fresh execute | exact HEAD GET、权限校验之后 | 请求状态查找、冷恢复（如需要）、保留历史验证、SQL publication gate、树和结果上传、原 ETag 发布前的 manifest 校验 |
| lookup / cancel | exact HEAD GET、权限校验之后 | 请求树查找、原 Result 验证；cancel 的新索引和发布 |
| session / 冷 query | exact HEAD GET、权限校验之后 | 物理页树恢复和全部保留结果校验 |
| activate / activate_session | 原控制 Snapshot 校验之后 | 完整闭包验证、必要的本地恢复、对 HEAD body/ETag 的重查和原候选发布 |
| set_quota / close_full | 原控制 Snapshot 校验之后 | 旧根检查或新窗口对象构造，以及发布前校验 |
| 纯控制元数据发布 | 根据原 Snapshot 在发布入口捕获 | 发布前 manifest 校验；没有刷新候选或 ETag |
| Catalogue named completion | 已校验 Provisioning Snapshot | 完整闭包、HEAD 重查和原 Provisioning 候选的 Ready 发布 |
| 部署恢复作业 | 已分类、已鉴权 Snapshot 和计量后端建立之后 | 本地恢复和全部 retained Result 校验；仍使用原作业期限及计量后端 |
| 明确创建 / named Provisioning / FenceAbsent | `initial_head` 的 bootstrap 入口 | 空数据树和初始请求树；HEAD 仍通过 Absent 条件创建 |

`Admission::Fresh` 保存完整的 `Box<AttemptContext>`：原 Snapshot（body 与 ETag）、
原 Request、原有效 deadline，以及已经捕获的 ObjectContext。这个值移动到
`Publication`，再由 `PublishGate` 取出一次并交给 commit；gate 不重新构造上下文、
查询 HEAD、替换 ETag 或重放 SQL。调用者的 deadline 仍只在原入口受 Options 截断，
上下文本身没有计时器或延期行为。

HEAD 始终由数据库控制面使用原槽位和条件写入；ObjectContext 只提供不可变对象
GET 和 Absent PUT。发布前的 manifest 检查使用候选的同一个上下文。所有对象
写入仍须 exact read-back；已存在对象只在回读字节完全一致后接受。错误分类和共享
quarantine 不变：缺失、损坏、超格式上限等完整性问题阻断该 Database 及其克隆
后续发布，暂时性 UNKNOWN 和 CAS Conflict 不被改成损坏。

暖 `Session::query` 继续只做 fresh HEAD GET 和本地 SQLite 查询，没有不可变对象
下载或额外 CAS。它不因这次重构获得授权租约或未来的 pin。

## 4. 格式和命名创建保持不变

逻辑身份仍为 `(deployment, tenant, database, incarnation, generation)`。
HEAD key 仍是 `scap-object/v1/{deployment}/{tenant}/{database}/head`；
不可变对象 key 仍是 `.../inc/{incarnation}/gen/{generation}/objects/{sha256}`。
对象 frame 不新增上下文字段，Receipt、请求身份和原始结果字节不变。

创建前没有 HEAD，因此 bootstrap 必须明确出现在创建实现中，不能把任意缺失 HEAD
当成新建授权。两个逻辑 Scope 争用同一个 HEAD 槽位时，迟到的创建只能留下自己
命名空间中的 orphan；它不能覆盖另一个已经成功创建的 HEAD。Named Provisioning
仍保留原创建描述符、Scope、revision 1 到 2、权限和所有权约束。本批对 Catalogue
只做上下文参数传递，没有增加技术 CAS，也没有改变其状态机。

## 5. 验证要求与剩余工作

新增 [对象上下文测试](../../crates/scap-object/src/object_context_tests.rs) 通过对象端口验证：

- 捕获之后修改或丢弃源句柄仍保留原 Scope、后端、原 deadline 及共享 quarantine；
  使用固定字节和 SHA-256 golden 验证现有 frame 与 key。
- bootstrap 的 PUT 暂停期间另一 Scope 赢得 HEAD，恢复后所有旧对象仍留在旧
  命名空间，原 Absent HEAD 写入失败，不能返回成功。
- admission 到 publication 的上下文不被重新捕获；HEAD-only 测试端口会拒绝任何
  经 Database 重新选择后端的不可变 I/O。
- 控制修改抢先发布后，旧 gate 只做一次原 ETag CAS，不重读 HEAD、不换候选，
  返回 Conflict，原请求仍未提交。
- 暖查询保留一次 HEAD GET，没有新的对象读写或 pin CAS。

原有 unit 回归继续覆盖 immutable collision、回读失败、格式错误、原结果绑定、
取消、请求窗口退休、完整恢复、quarantine、命名创建及恢复计量。新生产模块进入
逐文件 line/function/region/branch 的正常分母，单独测试文件仅按现有规则登记。
冻结候选的实际门禁结果应以对应源码清单和原始验证日志为准，不能由本设计文档
推定通过。

后续仍需设计和证明：每次 HEAD CAS 的单调 head_serial、防止 ETag ABA、单调
物理世代分配、退休命名空间不可复活、远程对象读取前的 pin admission、暂停读者和
上传者的实际 quiescence、Provisioning 的准入规则，以及独立删除能力验证。
当前 `publish` 会先读取 manifest，因此未来 PinAdd 不能直接复用它来实现“先 pin
后读”；需要另一个只处理严格元数据的条件发布边界。GcS3 继续不接入本批核心路径。
