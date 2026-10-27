# ADR-0004：语言、开源基础与自研边界

- 日期：2026-10-27
- 状态：候选；G0 后锁定准确依赖版本

## 背景

用户希望复用开源基础并控制维护成本。SQLite 的 SQL 执行已经成熟，平台的主要新工作在持久化、一致性、生命周期和运维。

## 决策

服务端使用 Rust / Tokio；HTTP 使用 Axum，内部 RPC 使用 Tonic / Protobuf。SQL 内核首选 libSQL 的 SQLite C fork，以 Rust FFI / virtual WAL 接入。客户端使用 TypeScript 和现有 libSQL SDK。当前 Python 只用于仓库检查。

OpenRaft 复用共识算法，RocksDB 候选承担 cell 本地持久化，etcd 承担目录与控制意图。监控采用 Prometheus 与 OpenTelemetry。

自行实现：SQL 提交可见性适配、Raft 持久 store、cell 状态机、请求幂等、owner fencing、归档发布/GC、冷库调度、权限与配额、恢复和升级。

## 代价

libSQL 内部接口、OpenRaft API 和磁盘格式需要锁定和维护；Rust 服务仍包含 C / C++ 依赖。选择 Rust 不能消除 FFI、内存损坏、设备持久化或逻辑协议风险。

`sqld` 不是稳定的万能平台库，可能需要维护集中、可追踪的 fork patch。必须记录 upstream revision 与修改范围，避免将长期分叉成本隐藏。

## 暂不采用的方向

不从零重写 SQL 引擎，不为了所有代码都写 Rust 而直接换成 Turso Rust rewrite，不同时维护 PostgreSQL 数据面，也不引入独立 Go 服务仅为连接相邻模块。若 dqlite 等替代底座的验证结果更优，可以重新决定语言边界。

## 验证与许可

上游能力、许可证和来源记录见 [组件调查](../research/components.md)。引入源码、依赖、生成代码和镜像前核验确切版本与传递许可证；项目自身许可证由维护者另行选择，不由本 ADR 自动决定。

参考：[技术栈](../architecture/technology-stack.md)、[实施路线](../engineering/roadmap.md)。
