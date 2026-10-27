# ADR-0001：SQLite 优先与客户端接入

- 日期：2026-10-27
- 状态：设计基线

## 背景

用户决定先落地 SQLite，PostgreSQL 延后；期望 Node.js 现有 SQLite SDK / ORM 少改动，并希望多租户数据库能独立恢复、休眠和迁移。

## 决策

首期构建服务化的 SQLite 数据面，复用 libSQL 远程协议和客户端，异步 `@libsql/client` 为默认入口，`libsql` 同步兼容驱动为存量应用候选。管理 API 可以使用薄 TypeScript 封装。

底层 SQL 内核采用 libSQL 的 SQLite C 分支作为首选验证对象。SQLite 兼容范围必须明确，原生 driver 完全不改二进制的 VFS 方案后置。当前不实现 PostgreSQL 兼容层，也不自动迁移现有 PG 业务 SQL。

## 代价

远程 SDK 引入网络延迟和故障语义；同步兼容调用可能阻塞 Node 主线程。SDK 相似不代表扩展、事务回调、UDF、文件和错误行为完全相同。

服务化让应用不直接持有数据库文件，但需要独立网关、执行池和控制面。单个 worker 内多库仍共享进程故障边界。

## 替代方案

原生 SQLite + Litestream 适合应用和数据共同部署、先做备份恢复的场景。它可用于对照，但没有提供本项目要求的完整同步提交和安全接管。

## 重新评审条件

如果目标应用必须依赖未覆盖的 native API、远程 SDK 的事务限制不可接受，或兼容层改动大于收益，则重新评估 VFS / 本地执行路线，并保留相同持久化与 fencing 门禁。

参考：[客户端契约](../architecture/api-contracts.md)、[libSQL JS](https://github.com/tursodatabase/libsql-js)。
