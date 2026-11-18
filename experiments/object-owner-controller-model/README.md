# Owner controller 独立有限策略模型

本目录验证固定有限 policy 与 HEAD8 原权威事件的组合。
[PLAN.md](PLAN.md) 冻结 402 个正向调度（360 个真正两 PUT 交错和 42 个具名边界）、
40 个具名语义负控、3 个正控；旧记录未定义的 354/48/3 门禁没有被替换或宣布通过。

`model.py` 是有界策略投影，不是生产实现；它加载已存在的 HEAD8 模型。
`oracle.py` 只加载已存在的独立 HEAD8 checker，逐个观察绑定原始 GET、ETag、HTTP
调用和 caller outcome，重建自己的 policy/window/预算知识。它不导入本模型、cases、
controls 或生产模块。正向名称有独立固定清单，关键场景必须有实际原始事件见证，
单纯把一条 healthy trace 改名不能通过。完整双 ledger 必须逐条唯一。

在仓库根目录运行（`RUN` 必须是全新目录）：

```sh
python -m unittest discover -s experiments/object-owner-controller-model -p 'test_*.py' -v
python experiments/object-owner-controller-model/explore.py "$RUN"
python experiments/object-owner-controller-model/oracle.py "$RUN"
python experiments/object-owner-controller-model/oracle.py "$RUN" --controls
```

正式运行前必须提交全部声明源码。部分恢复或工作中可在 explore 后加 `--diagnostic`；
这样的运行会明确标注开发诊断，不具备冻结候选的正式证据资格。三个有界命令共享从
explore 开始的 180 秒总期限、512 MiB 原始证据预算。所有输出只追加、不可覆盖；
失败会保存 traceback 和当时已写入的 trace。不能在同一目录重跑覆盖原失败。

输出 `inputs.json`、`inventory.json`、`traces.json`、`exploration.json`、
`oracle.json`、`controls.json` 及各条完整 trace。记录源码前后 SHA256、仓库 HEAD、
Python 版本/二进制、实际 HTTP/S3/UNKNOWN 分母及各场景的判断；这些是有限模型的
原始事件计数，不能当成真实 HTTP/S3 的请求量。raw trace 不提交仓库。

明确未认证：生产 controller 进程、真实多实例/native SQLite/HTTP/S3、AWS Standard、
吞吐和恢复 SLO；fleet 公平性、DNS/TLS/代理、SIGINT、后台资源清理；不同 rank 表的
任意迁移、动态登记、任意 worker 数和无限历史。终态 proof 在旧 core 模型中是独立
operator 动作，本组合不把它说成已实现的自动 controller HTTP 流程。
