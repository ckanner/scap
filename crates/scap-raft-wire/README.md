# 有界 peer wire 与证书授权策略

本 crate 是正式第一方模块，提供固定网络 envelope、证书属性提取、peer
准入和队列消费前复核。它没有 listener、队列、时钟或持久化效果，也不把网络
准入表示成 Raft commit、cell Accepted 或 SQL 成功。

## 格式与依赖

`SCAPRPC1` envelope 使用固定 80 字节头，依次为 magic（8）、version（4）、
codec（4）、cluster ID（16）、cell ID（16）、cell incarnation（8）、from node（8）、
to node（8）、payload 长度（8），随后为 opaque Raft bytes。整数采用 little endian。
version 与 codec 初始均为 1。解码拒绝错误 magic、截断、尾随字节和超限长度。

codec 1 固定到 [raft-rs ad13f3d9][raft] 的 `protobuf-codec` 与 rust-protobuf 2.28.0。
内层未知普通字段和可解析的非规范 varint 保留原始 bytes；未知消息/entry enum、
非法 tag、group、截断与溢出拒绝。解析前先以零分配扫描已知嵌套消息，限制 Entry
数量和字段/配置成员数量，避免大量空 Entry 在生成式 decoder 中放大分配。
SQL data、context 和 snapshot application bytes 保持 opaque。

证书属性使用固定 [x509-parser 0.18.0][x509]，关闭默认 features，许可证
`MIT OR Apache-2.0`。仅提取完整 DER 的 SHA-256、notBefore、notAfter；**签名、链、
用途和 DNS 校验由上层 mTLS 完成**。原始 peer 证书必须来自已认证 TLS 连接，不能
来自请求 header 或用户可构造的身份字段。证书日期采用显式传入的 Unix 秒数，
不在策略中读取墙钟；有效期两端均包含。

## 授权与固定成员

`Policy::new` 固定完整 cell 身份、本节点和 bootstrap 成员集合。transport 证书
allowlist 与 Raft ConfState 分开：仅用落后副本的旧 ConfState 鉴权，会导致其拒绝
后来加入并当选的合法 leader，无法追赶。本阶段运行时采用固定成员配置，动态
Raft 成员管理不属于本 crate。

持续网络准入同样拒绝两种 ConfChange entry。非空 snapshot 的配置必须精确等于
固定 voters，不能带重复/未知成员、learner、joint configuration 或 auto-leave。
已授权消息同时绑定固定成员集摘要，不能在相同 revision、不同成员配置的另一个
policy 中复用。

每次请求先检查版本、路由、证书日期和当前 leaf fingerprint 到 node 的绑定，再
解码 Raft。外层 from/to 必须与内层一致，from 必须等于证书绑定节点。允许普通
复制、投票/预投票、快照、心跳及直接 TimeoutNow；拒绝五种 local-only 消息以及
Propose、ReadIndex、ReadIndexResp 和 TransferLeader。最后一种在上游可保留原
from 转发，与逐跳 TLS 源绑定不兼容；本阶段不提供该转发或领导权转移 API。

`replace_bindings` 完整校验候选后原子替换，仅允许固定 bootstrap 节点。
同节点可临时使用多个 pin 完成重叠轮换，空 allowlist 表示全部撤销。成功替换
推进 revision，排队中的旧 revision 消息必须丢弃，让 Raft 自身重传。
`AuthorizedMessage` 不允许修改字段；`revalidate` 在消费前复核 revision、
限制、日期及当前映射。运行时必须用同一锁协调 admission、policy replacement
和 dequeue 后的 driver step，避免复核后再被撤销的竞争窗口。

完整 envelope 与已解析对象会同时占用内存。上层预算必须计入两份 payload、
有界 Entry/field 对象、队列和正在处理的请求；单消息 wire 上限不等于进程内存上限。

[raft]: https://github.com/tikv/raft-rs/blob/ad13f3d90780f53aea2488c6a4b76c0d334bf136/src/raw_node.rs
[x509]: https://docs.rs/x509-parser/0.18.0/x509_parser/
