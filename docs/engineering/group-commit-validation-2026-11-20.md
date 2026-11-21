# 独立事务 group commit：2026-11-20 验证记录

日期按 America/New_York。基准主线为已合入 #67 的
[`68246fd639d0331d5c90a31d8b3134e96532b3b5`](https://github.com/ckanner/scap/commit/68246fd639d0331d5c90a31d8b3134e96532b3b5)。
本轮新增实现与证明见[设计](../architecture/independent-group-commit.md)和
[实际合同](../../experiments/group-commit/README.md)。

## 范围和验收状态

新增 native 私有 staging、逐请求逻辑版本和原结果、一次原 HEAD 条件发布、默认关闭
的 writer actor 组批、持续计费的队列资源以及逐成员输出。普通单请求、协议字段、
Node SDK 业务调用和默认部署路径继续回归；新增生产文件进入原精确覆盖分母。

这是候选开发中的来源记录。最终冻结提交、workspace 覆盖、正式 release 的实际合同
和 PR checks 尚待本轮记录补齐时，不能把各 crate 局部绿色或 #67 的旧结果当作当前
候选整体通过。AWS、生产 SLO、长期 GC/成本与性能配对保持 NOT_RUN。

## 开发期已发现并修正的问题

- Native scoped 首轮 101 项单位通过，但新 staging 文件存在阶段中断和重复单态实例
  的覆盖缺口；原 `unit.json` 保留。补真实 native COMMIT 后、远端发布前中断，并将
  内部 gate/effects 使用同一动态边界后，新鲜采集的 102 项单位与 native 9 个生产
  文件四维精确 100% 通过；不合并前后 profiles，不降低任何门槛。
- 实际观察器初稿在 ENGINE/CONFLICT/BACKPRESSURE 失败分支过早退出，未核对固定
  SQL/指纹。审查发现后把所有 execute 原输入校验前置，并绑定 lookup/cancel 原身份；
  不允许用另一条更容易失败的 SQL 冒充 deferred foreign key 边界。
- 独立 SQLite 观察器实测发现内存 `deserialize` 不能读取保留 WAL header 的 checkpoint
  镜像。改为写入完整原字节，使用 readonly immutable 文件连接检查，再验证观察期间
  原字节未变化；没有修补权威页头或调用产品恢复来替代独立校验。
- Service scoped 首轮有 shutdown 后缀交付循环的 LLVM 计数缺口，已有测试确实观察
  后缀 UNAVAILABLE 与 Usage 清零。将可信 worker 边界与消费/交付方法分开后 fresh
  profile 全绿；随后独立审查发现直接 Rust Engine API 在聚合预算检查前会复制输入，
  增加分配前整组预检，再重新采集最终 280 lib + 1 bin 单位和 28 个生产文件精确四维
  100%。三轮日志、原始 profile 和严格检查器结果分别保留，没有合并 profiles。
- Core scoped 最终 503 项单位、36 个生产文件的 8,939 行、705 函数、13,817 region、
  1,834 branch 全命中；首轮未命中与修正保留。新增 native/core/service 交叉审查核对
  private COMMIT、受检 rollback、ObjectContext、窗口预留、取消竞争和 panic 清理顺序。
- Node 22.16.0 的 184 项单位及 22 个生产模块精确 V8 门禁通过；新增两项兼容回归
  保留每成员旧 receipt 和 UNKNOWN/已提交输出失败，不自动派发第二次 SQL。
- 模型与观察器 28 项单位通过，有限模型覆盖 2,940 个调度。发现并修正模型允许重复
  rejected CAS 的观察缺口，新增明确反例；35 项实际证据负控等待正式运行，未提前
  标记通过。

开发期局部测试和失败不等于最终冻结验收。后续结果必须写明来源、工具、原始退出码
和实际范围；代码修正后重新采集受影响 gate。
