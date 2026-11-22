# 资源拒绝诊断与固定到达曲线：候选验证

更新：2026-11-22（纽约）。基准为主线 `d066354`，即已合并的
[PR #69](https://github.com/ckanner/scap/pull/69)。#69 最终 head `1c8bce1` 的 6 个
PR 工作流、26 个 job 均首次运行成功；该次结论对应其自己的源码，不能作为本轮新增
生产代码的覆盖或真实运行证明。

## 本轮改变与边界

[设计](../architecture/resource-rejection-diagnostics.md)规定可选、默认关闭的拒绝
预算诊断，41 个计数型与 5 个来源型原因，原锁内首触发快照、固定 256 ASCII 字节
wire 上限，完整错误编码链与 SDK 无损只读投影。保留原状态码、请求结果、UNKNOWN、
已提交回执与不自动重试 SQL 的合同。没有修改配额、调度优先级、持久化和 ACK 边界。

原短配对的租户 intake 上限实际为 40，单库数据队列上限为 64。没有原拒绝原因时，
不能把原成功数变化直接归因于组提交保留队列额度。本次保留原 `short-v1` 到达预算，
增加 `admission-curve-v1` 的固定 3,072 个到达与分窗观察；两者采用相同容量和 ABBA 顺序。
每档的数据库及保留结果增长单独记录，不能宣称相同工作集下的无限稳态吞吐。

## 验证台账

| 范围 | 状态 | 说明 |
| --- | --- | --- |
| Node SDK 单位 | 开发检查通过 | 192 项；23 个生产模块精确 V8 单元覆盖；正式冻结后绑定完整源码 |
| Node HTTP／controller 进程 | 开发检查通过 | 21 项，独立于 unit profile |
| 固定 TypeScript／codec | 开发检查通过 | TypeScript 5.9.3 严格声明；codec 13 项及精确覆盖 |
| Rust service stable／全仓 Clippy | 开发检查通过 | service 294 项；workspace/all-targets/all-features `-D warnings` |
| Rust 全仓 stable/nightly 与逐文件四维覆盖 | 运行中 | 不继承 #69 的 971／82 计数；未完成前不作为通过 |
| 实验观察器 selftests | 开发检查通过 | 34 项，含保留的原 23 项；不能代替 actual |
| 工具／文档／workflow | 开发检查通过 | 76 项工具单位、精确分支覆盖；固定 actionlint 1.7.12、文档与 whitespace |
| 正式 release 与真实 HTTP/S3 | NOT_RUN | 等待冻结新源码和二进制 |
| `short-v1` 实际／独立 oracle／负控 | NOT_RUN | 不把 #69 原 640 到达结果转给新候选 |
| `admission-curve-v1` 实际／独立 oracle／负控 | NOT_RUN | 不用 self-test 或修改证据替代 actual |
| 目标 AWS、生产 SLO、长期成本 | NOT_RUN | 需要目标环境和独立出口 |

## 原始失败

首次新增 SDK 单元的成功响应夹具使用空 SQL 数组，被既有 codec 合同以
`Expected a nonempty bounded statement array` 拒绝。只将测试输入改为合法的
`SELECT 1` 与空参数列表，生产代码未为此放宽；新的完整 192 项及严格覆盖通过。
该首轮失败与后续通过分别保留，不将覆盖率输出中的 100% 当作失败测试通过。

首次增强 scheduler concurrent-starting 单元时，将既有场景误写成 actor draining；
原 gate 顺序先检查队列，实际准确返回 `queue_database_data` 的 8/8。只修正测试期待，
没有改变生产判断顺序；完整 service 重跑 294 项通过。首次 codec 校验误用了该目录
不存在的 `test/run.mjs` 入口，测试没有启动；随后按原 `npm test` 正确执行 13 项与覆盖。

## 接续出口

冻结完整候选后，必须完成精确单位、正式构建、实际原字节审计、负控、复核与最终
head CI。尚缺门禁时保持 Draft。真实结果回来后按原到达分母报告拒绝原因、成功数、
控制进展、尾延迟、对象请求与字节；保持所有负面样本，不通过中途扩大容量改善数字。
