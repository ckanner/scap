# 历史 manifest proof 回退：限定 2×2 诊断计划

本实验解释服务和观察器的实际成本，不替代 `object-load` 的 871 次请求、
冷恢复、资源证据或负控合同。历史两组四库样本约 24% 的下降仍是有效的
未归因观察；新样本未重现该下降，也不能将其改记为「已修复」。

## 冻结的两个实现

- baseline：原 `b15bc455349ea36162b8004c2c73fc7d812d4c10` 的生产输入。
  本地 `9674bb1` 的 Rust、Cargo、SDK 和 object-load 输入与其相同；
  两个提交之间的改动是文档、其他实验和覆盖工具。
- initial proof：原 `fd508cc052c21dba0e3c54b8e8e82d11c167777a` 的生产输入。
  远端 `b25b7855eaa478636c8763be0a23caf8d03b0c5b` 与其生产输入相同。
  在 9674bb1 上恢复 b25 的全部 11 个差异文件，逐文件核对 Git blob。
  生产差异只有 `data_tree.rs`、`object_context.rs`、`lib.rs`；其余是测试、
  coverage 分类和设计文档。

这组对照包含最初的 String 指纹和 root clone。后来的二进制指纹、
borrow/Cow 优化、连接池 8、worker 永久身份和 S2 都没有混入。

两个实现应用相同的 `historical-instrumentation.patch`、同一 metrics crate、
同一 SDK probe。这个 patch 只把已有 `instrumentation.patch` 中的
`head_fingerprint` 上下文适配回历史 String 实现，其他挂点相同。
每个源码副本有独立的 Cargo target，记录完整源码清单、实际构建日志、
Rust/native 输入、最终二进制散列；即使非同时构建，也不跨副本复用 target。

## 固定顺序与工作量

只执行以下四个样本。每个样本使用新的有签名 SeaweedFS 4.51 后端、
私有 SQLite cache 和相同服务配置；先等待本样本进程全部退出，再开始下一个。

| 顺序 | 实现 | S3 路径 |
|---|---|---|
| 1 | baseline | 直接连接签名本地 S3 |
| 2 | initial proof | 原始完整证据代理 |
| 3 | initial proof | 直接连接签名本地 S3 |
| 4 | baseline | 原始完整证据代理 |

每个样本使用同一 `probe.mjs`：18 次设置、144 次计时请求、112 次原始结果
lookup、6 次最终行检查，共 280 次 SDK POST。四个计时阶段依次是
16 次单库串行写、64 次四库并行写、32 次同库并行写、32 次四库读。
4 KiB payload 按固定公式生成；原始 `RETURNING random()` 结果在计时后逐一
用原身份查回并比较原始字节。一次 execute 只发一次，没有 SQL 重放。

`/__profile` GET 和 Python/Node 的阶段握手均在计时区间外。握手通过子进程
标准输入输出，既不增加产品路由，也不增加对象操作。采集过渡期仍可能带入
少量计数开销，所以对阶段 CPU 的解释保留这个限制。

正式比较前需要其他 agent 明确停止编译、native 测试、coverage 和后端。
保留所有失败、重叠和原始计数；不选择性删除不利样本。本计划不包含反复短跑
直到出现理想方向，也不为跨机器或 AWS 生产吞吐给出置信区间。

## 观察器成本及预先声明的假设

1. **实现开销**：初始 proof 增加一次完整 HEAD 指纹计算与绑定校验，但每次
   正常业务发布应少一次 manifest GET。用实际 fingerprint CPU/分配、S3
   调用数和字节核对，不能只依据函数级纳秒基准作吞吐结论。
2. **传输与证据成本**：原始代理每个响应都关闭连接，保留请求/响应原始 body。
   RawStore 每次取得原来的锁；新 body 同步预算文件和 body 文件。
   Trace 每行 flush，关闭时 fsync。它没有在每一行 emit 时 fsync。
   因此旧 TPS 包含这些成本；它不是纯 S3 延迟。
3. **并发交互**：四库请求可能在 RawStore 锁、文件同步、HTTP 连接和服务调度
   上产生不同的等待比例。必须由记录的等待和 CPU 支持，不能把未解释的差异
   命名为「噪声」或直接归因到本地存储。

`causal.py` 复用原始 Backend、Proxy、RawStore 和 Trace，不重写协议。
额外包装器测量 raw-save、其锁等待、trace emit/锁等待、fsync，以及上游发送、
响应头和 body 等待。包装器保留返回对象和原始异常；三个辅助测试验证这一点
以及阶段快照不被后续计数修改。代理源文件本身保持逐字相同。

Rust 的 inclusive stage wall、调用线程 CPU、分配次数和请求容量与已有探针
含义相同。并行和嵌套 stage 不能相加当作总耗时；请求分配容量不是 RSS/峰值，
Python fsync wall 也不是内核写盘时间。新增计时器、全局分配计数和观察器包装
本身有开销；两种实现使用相同探针，这仍只是有仪器干扰的局部诊断。

## 如何解释与保留结果

先核对 280 POST 全部结果、112 个随机原始结果、最终所有行、S3 请求/字节
差异、源码和二进制，再讨论时间。完整代理样本还保留原始签名字段摘要、
GET/PUT 条件、body 和 ETag 记录；直连样本只有产品 Objects 计数，没有
独立完整网络证明。二者都不冒充正式 871 请求验收。

若历史 24% 差异没有被这四个样本直接解释，就明确保留未归因状态。可报告
当前精确输入下的实现成本、观察器成本和不同符号的阶段结果，但不能把新诊断
的一次正向 TPS 当作历史回退修复。没有实测依据的存储或 checkpoint 改造不实施。
FULL 同步、立即检查的 TRUNCATE、原 ACK/UNKNOWN、不可变回读和原 HEAD CAS
保持历史实现；任何产品优化必须另有正确性审查与验证。

所有原始记录保存在仓库外，提交只包括诊断源码、聚合结果、文件清单及散列。
