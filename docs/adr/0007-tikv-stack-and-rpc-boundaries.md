# ADR-0007：参考 TiKV 技术栈，明确运行与 RPC 边界

- 日期：2026-10-29
- 状态：技术方向已确定；具体生产依赖与集成仍按 G0/G1 验证
- 关联：[ADR-0004](0004-engine-and-implementation-boundary.md)、[ADR-0006](0006-raft-rs-consensus-library.md)

## 背景

用户要求参考 TiKV 长期使用的 Rust 框架和组件。必须同时核查正式发布的 manifest、锁文件和实际调用路径，区分主服务、状态接口、云 SDK、历史兼容与测试依赖。仅在 Cargo.lock 中看到某个包，不能证明它承担主 RPC。

固定参考 TiKV v8.5.8 的源码后，确认主 RPC 为 grpcio、状态/管理 HTTP 为 Hyper，另有 Tokio、yatp、slog、Prometheus、Serde/TOML 与 fail-rs。其云 SDK 另引入 Tonic/Prost；TiKV 的 native 库、fork、nightly 与历史运行时组合并不适合整体复制。事实来源见 [技术栈审计](../research/tikv-rust-stack.md)。

## 决策

1. 保持 SCAP 平台的 Tokio、Axum/Tower、Tonic、tracing 与 Prometheus 方向，继续优先验证 raft-rs。HTTP 路由层与底层 Hyper 并非互斥选择。
2. 借鉴 TiKV 的专用执行池、有界队列、按字节批处理、资源准入、管理面隔离、配置生效记录和故障注入。第一版不因参考项目采用，就同时引入 grpcio、yatp、其全套 allocator 或历史 Tokio 兼容层。
3. Raft 消息使用明确的 codec 边界。初始契约实验采用 raft-rs 的 `protobuf-codec`，外层以 SCAP 自有 Tonic/Prost envelope 携带原始 bytes。外层版本、cell/节点身份和大小先验证，内层再用对应 decoder 处理；不把不同 Prost 版本的 Rust 类型当成兼容类型。
4. gRPC 收到/解码/入队响应不能代替 durable quorum、状态机接受或 SQL 发布。Raft 消息重传与业务 SQL 重试分开处理；未知 SQL 提交不得因 transport 错误自动重执行。
5. 生产内部 mTLS 保持必须条件。字段自报身份不是认证，证书身份还要映射到节点与 cell 权限；单机明文实验不作为该能力的证明。
6. RocksDB binding、Raft Engine、S3 SDK、TLS crypto provider 和 allocator 逐项验证后锁定。参考 TiKV 的 fork 与 native 子模块不等于采用 crates.io 同名包；不直接复制其版本、默认参数或整个工具链。
7. 固定 libSQL 的 sqld 仍使用另一代 Axum/Hyper/Tonic/Prost 和精确 Tokio 依赖。G0 必须明确协议复用、fork/抽取或独立构建/进程边界；不能声称整个上游 server 已和现代平台依赖树合编通过。

## 工程合同

[运行与 RPC 契约](../engineering/runtime-and-rpc.md)定义资源、消息、超时、身份、健康检查与测量边界；[技术决策清单](../../contracts/technology-decisions.json)记录候选与实际证据，不作为部署配置或依赖锁文件。

`experiments/raft-rpc` 仅为独立 codec/transport 契约测试，无产品 library target，不参与生产单元覆盖率分母。任何代码进入 runtime 前必须移入正式模块，满足 100% 单元覆盖率、真实依赖契约与故障门禁。实验锁定版本不自动成为产品版本。

## 取舍与重新评审

保留一套主服务运行时减少集成组合，但这不构成比 grpcio 更快或更可靠的结论。真实持久化、mTLS、长连接、拥塞和多 cell 压力尚需证明。如果实测显示 Tonic 的性能、取消或流控不能满足合同，可在相同负载和持久模式下比较 grpcio；更换需要记录构建、运维和测试成本。

性能目标、CP 行为、共享 cell、同步 ACK 和原有覆盖率门禁不因框架选择改变。依赖名称和上游测试结果不能代替本项目证据。
