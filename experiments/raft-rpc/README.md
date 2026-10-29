# raft-rs 与 Tonic 的编码及传输契约实验

记录日期：2026-10-29。状态：**研究/集成测试，8 项测试实际通过；不是产品 transport，也不是 Raft 持久化或 HA 实现。**

## 目的

固定的 raft-rs 候选同时提供 `protobuf-codec` 和 `prost-codec`，其中后者的 [raft-proto 依赖](https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/proto/Cargo.toml) 是 Prost 0.11。Tonic 0.14 的常规 codec 使用 Prost 0.14；两套生成类型不能因为都叫 Protobuf 就假设具有相同 Rust trait。

此实验选择另一条明确边界：内层使用 raft-rs `protobuf-codec` 序列化真实 `eraftpb::Message`，外层用自己的 Prost schema 携带原始 `bytes`。真实 Tonic 客户端通过本机 TCP/HTTP2/gRPC 调用 fixture，fixture 解码内层消息并返回观察结果和未经重新编码的原始 payload。

这证明所测组合在该协议边界可工作，不证明与 TiKV 的 `kvproto` RPC 协议互通，也没有将 TiKV 的 gRPC C-core / `grpcio` 服务替换成 Tonic。

## 已锁定组合

| 组件 | 本实验选择 |
| --- | --- |
| Rust | `1.90.0`，Linux x86_64 实际编译运行 |
| raft / raft-proto | git `ad13f3d90780f53aea2488c6a4b76c0d334bf136`，仅启用 `protobuf-codec` |
| 内层 rust-protobuf | crates.io `protobuf 2.28.0`，并非 TiKV 使用的 PingCAP fork |
| gRPC | `tonic 0.14.6`、`tonic-prost 0.14.6` |
| 外层消息 | `prost 0.14.3` |
| 代码生成 | `tonic-build 0.14.6`、`tonic-prost-build 0.14.6` |
| 外层 protoc | `protoc-bin-vendored 3.2.0`；显式传给生成器，不依赖系统 PATH 的 protoc |
| runtime | `tokio 1.50.0`、`tokio-stream 0.1.17` |
| 全部传递依赖 | 实际生成的 [Cargo.lock](Cargo.lock)；不手写锁文件 |

Tonic / tonic-prost / tonic-prost-build 0.14.6 的发布包声明 MSRV 1.88，Prost 0.14.3 声明 1.82，Tokio 1.50.0 声明 1.71；本次实际使用 Rust 1.90.0 验证组合，而非仅比较最低版本数字。来源是对应发布包的 Cargo.toml 和实际构建。

`protobuf-build` 在构建 raft-proto 时另行使用 `protobuf-src`，首次构建仍需要 C/C++ 编译器和 `make`。外层 vendored protoc 不会消除这个上游构建依赖。TiKV 使用的 fork、feature 与本实验不同，不能将本实验组合描述成与 TiKV 完全同构。

## 测试内容与结果

实际结果：**8 passed，0 failed，0 ignored**。每项使用绑定到 `127.0.0.1:0` 的真实 TCP listener、生成的客户端和服务端，并验证服务能够退出。客户端连接/请求和服务退出都有有限超时；没有睡眠等待端口就绪。

本次还验证了执行环境限制：默认沙箱禁止创建 TCP listener，8 项均在 bind 阶段报 `PermissionDenied`；在允许本机 loopback 的执行模式下，以同一锁文件重新运行后全部通过。没有跳过测试或改用 mock。Rustfmt 与 Clippy（`-D warnings`）也已通过。

| 测试 | 验证结果 |
| --- | --- |
| Append entries | 消息 term/index/log_term/commit、context 和 entry 的二进制 data/context 保持 |
| Snapshot | snapshot 字节、term/index 与完整 joint ConfState 字段跨传输保持；没有执行 snapshot 安装 |
| ReadIndex / reject response | ReadIndex 的 `entries[0].data` 请求 context、拒绝标记与 hint 保持；没有执行线性读 |
| 未知字段与非规范编码 | 注入合法未知字段和非规范 varint；证明内层 parse + re-encode 会改变 bytes，而外层透传原样保留 |
| 版本 / codec 不匹配 | 明确返回 FailedPrecondition，未作为正常消息观察 |
| 路由身份不匹配 | cluster/cell/incarnation/from/to 不符在内层 decode 前拒绝 |
| 畸形内层或身份冲突 | 无法解析的 protobuf、payload from/to 与 envelope 不一致明确拒绝 |
| 两层消息限制 | 超过 2048 字节 payload 返回 ResourceExhausted；超过 4096 字节 gRPC 消息返回 OutOfRange；随后正常请求仍成功 |

观察响应 `Observed` 仅表示 fixture 成功解码。它没有“持久成功”“quorum 成功”或 SQL COMMIT 的含义，不允许当作 SCAP 提交协调器的 Accepted 回执。

## 复现

在仓库根目录执行：

```bash
cargo +1.90.0 fmt --manifest-path experiments/raft-rpc/Cargo.toml --all -- --check
cargo +1.90.0 clippy --manifest-path experiments/raft-rpc/Cargo.toml --all-targets --locked -- -D warnings
cargo +1.90.0 test --manifest-path experiments/raft-rpc/Cargo.toml --locked -- --test-threads=1
```

依赖下载后可加 `--offline`。测试需要本机 loopback socket；若执行环境禁止创建 socket，应在允许本地测试网络的执行环境运行，不能改为 mock 后继续声称真实 gRPC 已验证。

此目录独立 workspace、`publish = false`，只有 test target 和构建脚本，**没有 library 或服务 binary target**。schema 生成到 Cargo `OUT_DIR`，不提交生成产物。所有手写逻辑均为实验 fixture；其路径应在仓库策略中显式归类为测试资产。本实验不参与产品单元覆盖率计数。未来任何代码若进入产品，必须迁移到生产源码清单并通过第一方 100% 单元覆盖率及真实契约门禁，不能把本目录当作复用生产逻辑的后门。

## 未验证的范围

- 没有 RawNode 运行循环、日志、fsync、quorum、状态机应用、成员变更或故障恢复。
- 使用 loopback 明文，未验证 mTLS、证书轮换、节点授权和安全信任。字段匹配只是 fixture 路由断言，不是来源认证；请求者填写正确字段就能满足 fixture 条件。
- 没有生产消息类型白名单、优先级队列、全局背压、批处理、断线重连、deadline/取消后的提交判定或快照分块协议。
- 原始内层字节被保留，不代表兼容未知消息语义或支持所有未来协议版本；当前 envelope 只接受指定 fixture 版本和 codec。
- 没有证明 JSON/Prost/Rust 类型可互换，没有证明与 TiKV RPC 或其 Protobuf fork 完全兼容。
- 测试耗时不作为生产延迟、RTO、吞吐或容量指标。

## 官方参考

- [固定 raft-proto Cargo.toml](https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/proto/Cargo.toml)
- [固定 RawNode 源码与 read_index](https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/raw_node.rs)
- [Tonic 0.14.6](https://docs.rs/tonic/0.14.6/tonic/)
- [tonic-prost-build 0.14.6](https://docs.rs/tonic-prost-build/0.14.6/tonic_prost_build/)
- [protoc-bin-vendored 3.2.0](https://docs.rs/protoc-bin-vendored/3.2.0/protoc_bin_vendored/)
