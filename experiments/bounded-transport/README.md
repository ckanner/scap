# 实际 daemon TCP 合同

这个实验只装配正式 `scapd`，通过原始 loopback TCP 调用 `/healthz`。
它独立于 Rust unit/LLVM profile，不使用内存 router 替代实际 listener，也不需要 S3 后端。
配置使用一个不会被健康接口调用的 dummy S3 endpoint；这不构成任何 S3 或数据库验收。

## 固定合同

[oracle.py](oracle.py)冻结小容量 profile：2 connections、4 headers、512 header bytes、
8192 字节 Hyper buffer 配置、3000 ms header 窗口，以及 30000 ms 响应发送和关闭窗口。
完整默认值另由产品 unit 验证。

| 合同 | 观察方式 |
| --- | --- |
| accept 前的连接上限 | 两条连接各收到完整健康响应，再各保留一个 partial header；第三条请求在释放一条前没有响应，释放后完成 |
| 首次 header deadline | 保留半个 header，两秒后补几个字节；连接仍按原三秒窗口关闭 |
| keep-alive header deadline | 第一条请求完整成功后，下一条 partial header 受到同一绝对窗口限制 |
| header 字节边界 | 完整请求头恰为 512 字节时成功，513 字节返回 431 |
| header 数量边界 | 4 个 header 成功，5 个返回 431 |
| HTTP/2 拒绝 | 原始 h2 preface 没有进入 HTTP/2 会话，连接关闭 |
| graceful 清理 | keep-alive 闲置连接随 SIGINT 关闭，owned child 经 wait4 回收且退出码为 0 |

connect 成功不是 accept 证据；前两条已收到的健康响应才证明服务已处理它们。
容量案例还要求释放发生在两个占用连接记录 partial header 后一秒内，早于三秒 header 期限；
不能把 deadline 自然释放的名额误认为显式释放的效果。
真实网络时间测试保留原 monotonic 时间及宽松调度窗口；窗口内失败必须保留，不能改写为成功。
不对慢响应、S3 工作或整个 daemon 的 RSS 推导额外保证。慢响应最后 Bytes 和 active drain
及不续期的发送/关闭上界由正式单元中的实际 Hyper + DuplexStream 路径另行验证；
本 healthz 实验不把小响应成功计作真实大响应或 SQL 的发送期限验收。
实际 SQLite/S3 大响应、逐字节慢读、已提交响应截断后的原身份 lookup，以及活跃响应关闭
由独立的 [response 夹具](response/README.md) 验收；它有自己的冻结 PLAN、raw oracle 和负控。

## 执行

使用同一冻结源码编译的未插桩二进制，在仓库外创建新的 target 与 evidence 目录。
源码 manifest、Cargo 构建日志及二进制/native 身份沿用仓库的正式验证流程。
runner 记录所提供二进制的 SHA-256，但仅凭二进制 hash 不声称源码与编译产物已经对应。

```bash
CARGO_TARGET_DIR=/tmp/scap-tcp-target cargo build --release -p scap-service --bin scapd --locked
python3 experiments/bounded-transport/run.py \
  --binary /tmp/scap-tcp-target/release/scapd \
  --evidence /tmp/scap-tcp-evidence
python3 experiments/bounded-transport/oracle.py /tmp/scap-tcp-evidence/observations.json
python3 -m unittest discover -s experiments/bounded-transport -p 'test_*.py' -v
```

evidence 目录必须不存在。`plan.json` 在启动前保存，`events.jsonl` 逐条 fsync 保存原始
请求/响应的 Base64、monotonic 时序、子进程身份及回收结果；`observations.json` 保留
完整或失败时已取得的观察。失败也会回收 owned child，强制回收不能被 oracle 当作成功。
不要设置 `LLVM_PROFILE_FILE`；不要把此运行产生的任何 profile 合并进单元覆盖。

oracle 从原始字节与时间重新计算八项合同和进程清理，不接受 runner 的 passed 字段。
夹具自测包括缺失/重复案例、连接超额立即响应、deadline 被 drip 重置、431 消失、h2
进入二进制会话，以及强制/未完成进程回收的负控。夹具自测不替代实际 TCP 执行。
