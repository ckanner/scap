# ADR-0021：对象原生运行时和第一版格式

- 状态：实现候选；验证结果单独记录，不表示 N1 全部退出。
- 范围：遵照 ADR-0020，删除旧 Raft/RocksDB/cell/SDK 构建，重新组织权威、对象适配和引擎。

## 选择

1. 四个生产 crate：object、object-store、object-sqlite、纯 SQL codec。只有对象存储接口是持久化 port；没有备用权威或本地权威文件。
2. 保留固定 libSQL C 内核的 xFrames 提交前 gate，改为真实对象发布判决；移除旧 CommitTicket、cell/term/index 等类型。结果仍缓冲，CAS 成功后才允许 native publish。
3. 有界 JSON v1 HEAD 和 envelope；严格拒绝未知字段、错误 scope、摘要、版本、超限和非法状态。具体预算见[运行时](../engineering/object-runtime.md)。固定引擎 revision 与4096页语义属于format v1，不跨引擎版本隐式重开。
4. 每页不可变对象与完整小型页映射 manifest。上传只写变化页面；恢复直接读取当前页引用，不沿无限历史链重放。小型页映射本身会整体编码，扩容时需要独立分段索引设计。
5. 每个世代有有界 COW 结果索引，原结果单独保存。取消、业务结果和新数据根经同一 HEAD CAS 生效；保留 current 与两个完整 closed epochs。
6. 控制 API 需要原 expected revision 与 nonce。没有精确控制意图结果索引，因此 UNKNOWN 后不以 nonce 命中声明原控制成功；旧 expected revision 永不刷新成重试。

## 当前限制

单库256KiB，尚无名称目录、网络用户认证、HTTP/Node SDK、自动公平调度或自动轮转服务。公开Rust API属于可信服务内部接口；Close只允许内部可信协调器或管理员编排，不能对租户开放任意轮转。

没有对象物理删除。每次操作预算不提供跨崩溃的bucket总量上界，失败CAS和上传会留下未引用对象；不能把逻辑索引有界解释为存储成本收敛。N3仍必须实现安全GC、pin、compaction、PITR和长期成本证据。

真实S3兼容服务测试只证明该端点及本项目接线。目标AWS Standard的真实条件写、IAM/region及恢复合同需单独运行，不从本地服务或厂商宣传推导。
