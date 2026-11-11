# HEAD8：可恢复 owner plan 验收

状态：正式单位与静态组合检查通过；普通真实合同大部分通过，专项和剩余审计继续执行，PR #56保持草稿。没有把未执行项算入已完成范围。

## 冻结身份

产品为 `3e850357478133ae2b76007c3e0e9609d3d8ac02`，tree `a4e5860de2ce091f1b0631dcfac77b43ec985498`，完整源码清单582文件。owner descriptor、accepted HEAD8 marker、Claimed/Cancelling/Active/Aborted、稳定终态proof、严格wire与SDK均在该候选中。

发现夹具的两个健康Python子进程测试原来误用了100ms故障注入启动预算。原命令失败完整保留；测试修正 `2da24432080a20b3a379416fb78bc85bb7465117` 改为原Worker的12秒启动合同，刻意不完整ready行的100ms测试不变。产品、实际Worker和实际操作期限均未变；该clean fixture的23个单位重新通过。

## 正式单位与静态组合

[完整机器记录](../evidence/head8-unit-local-2026-11-10.json)保存源码hash、逐文件指标、原始命令身份以及失败/续跑组合。

| 门禁 | 结果与范围 |
| --- | --- |
| Rust stable / nightly | 各700个单位；各binary分母352/81/44/186/0/37 |
| 生产Rust覆盖 | 63文件；13092行、1184函数、20127 region、2554分支，正分母逐项精确通过 |
| 零分母 | 已测0/0不称为独立测得100% |
| Node SDK | 92单位、15个生产JS模块全部raw V8 function/range为正，严格类型检查通过 |
| Codec / tooling / lint | 独立unit-only、文档和actionlint通过；Rust fmt/clippy完整组合通过 |
| owner有限模型 | 19单位、989正向、48指定负对照、3正对照；模型不认证真实产品 |

三个构建/lint长进程曾失去exec session，原因未确定。没有完整exit/receipt的原命令保持interrupted。已完成的network/discovery lint记录与新完整resource/GC lint记录分别核对后组合；新native/resource/GC release构建有各自完整收据，不伪造原进程成功退出。SDK与Rust真实集成profile均未用于补单元覆盖。

## 真实产品状态

当前记录只讨论本地真实native SQLite、HTTP、进程及signed S3兼容端点。正式产品二进制及其依赖源码分别有build receipt。

- 已通过新的native网络、保留结果、生命周期、目录、1 GiB全量恢复；普通HTTP的输出池、响应边界、传输、SDK、旧式owner、metadata、catalogue、隔离、segmented和guarded status通过。
- 发现接口第一次实际合同中，一条自然分页从客户端请求记录到响应为5.165509491秒，超过原5秒验收上界；其中1.147238780秒出现在记录到发出HTTP headers之间。原失败保留，不能仅由该外部间隔推断服务端续期。使用同一产品/fixture、相同工作负载/期限/断言在团队无其他重任务时重跑，原始阶段已完成，独立审计和控制继续执行。
- listing、部署恢复、resource lifetimes和GC transport通过；terminal退休实际合同及全部25负/1正对照通过；LOAD原始、独立oracle和14负/3正对照通过。
- 多代GC原始场景已通过；完整oracle及23负/1正对照尚未汇总。
- HEAD8可恢复owner plan的专用真实合同已在独立fixture中固定17个Scope、200个owner POST、295条原SQL ACK及40负/1正对照；69个夹具单位通过，产品实际执行尚未进行，不能由旧owner接口合同替代。

普通调用或实际运行的失败不因后继通过被抹除。最终源码、全部原件、修正和通过结果须在专项完成后一起汇总；当前不满足合入门禁。

## 尚未由本轮认证的目标

自动controller由独立PR #57推进。HEAD9保留快照、新Scope恢复、完整资源隔离、实际NFS/EFS/FUSE挂载、AWS Standard/Express故障域、生产吞吐和RTO均不能从本轮单位或本地兼容端点结果推出。显式owner plan不等于自动调度；历史Active也不等于当前native Session或过去HTTP调用ACK。
