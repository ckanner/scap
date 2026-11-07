# ADR-0023：S3 运行时的认证 HTTP 服务与 Node SDK

状态：已实现；2026-11-07 的冻结候选通过精确单元、真实 HTTP/S3、全计算恢复及 1 GiB 回归的独立本地审计，见[验收说明](../engineering/http-service-validation.md)及[机器记录](../evidence/http-service-local-2026-11-07.json)。AWS 与生产阶段分别验收。

## 问题

对象权威和 native SQLite 已能提交、强读、取消与恢复，但内部 Rust API 的 `principal` 是可信输入。业务客户端不能直接调用这个边界，也不能拿到 bucket 凭据。已有 Node codec 仅能计算指纹、解析结果，尚不能证明网络请求的身份、原结果或未知结局。

## 决定

增加正式 `scap-service` crate 与 `scapd`，用 Axum/Tokio 接收 HTTP，并将所有 S3 和 SQLite 操作交给普通 OS worker 线程。数据库身份先使用已有不可变五元组：deployment、tenant、database、incarnation、generation。名称 reservation、目录重建和自动 owner 调度继续单独实施；本接口不以本地目录保存唯一身份，也不从缺失 HEAD 建空库。

服务监听 loopback，由部署方的 TLS 反向代理提供外部 HTTPS。配置将 bearer token 的 SHA-256 映射到 deployment、tenant、principal 和创建权限；客户提交的 scope 必须匹配该租户，request 中 principal 必须匹配认证结果。每次实际操作仍由新鲜 HEAD 中的权限决定是否允许；配置凭据不是数据库权限的替代品。

HTTP 使用版本 1 的严格 JSON。所有 u64 身份、revision、sequence、nonce 和配额以规范十进制字符串表达；SQL i64 为字符串、f64 为 16 位小写 IEEE-754 bits、BLOB 为规范 base64。响应返回原 `SCAPRES1` 字节。SDK 从 receipt 和原字节重建 `SCAPOBJ2` Result frame，核对其摘要、scope、request、指纹、sequence 与 transition，不把裸结果摘要误当对象摘要。

`prepare` 固定原始 SQL、有序参数、请求世代与 ID；`save/restore` 使应用能持久保存这一身份。execute、lookup、cancel 和控制调用每次最多发送一个 POST，不追随重定向，也不因超时、断线、错误响应或本地解码预算不足重新执行 SQL。成功提交之后无法解码结果有独立的 committed 错误，保留 receipt 和可用的原字节。

## 调度与资源

- 数据 worker 使用稳定的数据库映射和有界队列；租户、数据库轮转避免同一排队主体长期占据下一次调度。
- 查证、取消、状态和元数据控制使用独立 worker 与 HTTP 准入配额；数据线程中的冷恢复不占满控制执行线程。
- 恢复有独立准入与并发 semaphore。`open` 显式准备读者/会话，`activate` 在完整恢复后激活；二者使用独立恢复期限。
- HTTP 配额覆盖读取请求、排队、执行、响应 body 及其发出的字节；body 已销毁但传输缓冲的字节或 clone／slice 仍存活时，准入配额继续占用。worker 内缓存有会话数和逻辑页预算，错误之后丢弃会话。
- 缓存身份包括 incarnation/generation，不能仅按物理 HEAD key 把新的 scope 别名到旧 handle。

固定 data lane 内的运行中请求不可抢占。不同数据库映射到同一 lane 时仍可能互相等待；cache 预算也不是进程 RSS 硬限额。完整冷热隔离、跨进程 owner 路由和规模性能有独立验收，不能从队列单测推导。

## 保持的持久合同

服务不改变对象格式 2、默认 10 GiB、条件 HEAD 发布、原始结果留存与 native publication。所有权转移仍是显式的 HEAD CAS；服务启动不自动接管所有数据库。一个 `worker_instance` 只能用于一次服务进程实例，重启分配新值，然后先 takeover 再 activate；旧写者由 HEAD fence。

`UNKNOWN` 后先使用保存的原身份 lookup，必要时 cancel；Unknown、Cancelled、Closed、Retired 和 Committed 不混同。取消不是取消网络请求：客户端 abort 只结束本地等待，已经开始的数据库操作仍可能提交。

## 验收与边界

正式代码的四维逐文件单元覆盖必须达到 100%；SDK 每个生产模块的 Node 和原始 V8 计数也分别核对。真实实验启动两台 daemon、正式 SDK、四进程 SeaweedFS 和受控网络代理，保存独立输入/ACK 账本，验证并发创建、无损值、权限撤销、取消、HEAD 响应丢失、S3 不可达、旧 writer 和全部计算缓存丢失恢复。真实实验不填充单元 profile。

本 ADR 不宣布 N2 整体退出，也不宣布生产启用。名称目录、自动协调、分段请求索引、GC/pin/PITR、AWS Standard、跨 AZ、长运行与成本收敛仍须按[主方案](../architecture/object-storage-native-proposal.md)实施和验收。数据库对象 GC 继续关闭。

实现入口：[服务源码](../../crates/scap-service/src/lib.rs)、[SDK](../../sdk/node/README.md)、[真实服务实验](../../experiments/object-service/README.md)。
