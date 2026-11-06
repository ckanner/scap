# 当前运行边界

当前提供内部Rust单库API与独立验证入口，未发布对外HTTP服务或新Node SDK。不要使用旧版本的三节点配置和SDK连接新协议；当前工作区没有旧权威或迁移工具。

装配S3时显式提供endpoint、region、bucket、access key、secret和可选session token。只在本地测试显式允许HTTP；正式端点要求TLS。凭据不写入仓库、日志或回执。

用固定scope显式create，得到Recovering HEAD；activate_session 恢复[当前数据与保留结果闭包](../engineering/object-runtime.md#recovery-closure)后开放写。计算丢失后，从新worker发起带原expected revision的takeover，再 activate_session，并保留返回的 Session 用于热读写。缺HEAD不能当成新库；UNKNOWN先用原epoch/id/principal/fingerprint查证。

控制操作重试保留原expected revision；已被后续转换越过但缺精确证明时不能虚报成功。不要把旧CAS换新ETag重发。结果已退休则按业务键对账，不能由SDK自动重做。

实际可复现测试与输出见[验证规范](../engineering/validation.md)。没有配置真实AWS时只运行本地兼容后端验证并保留NOT_RUN记录，不创建未知云资源。

## 配额与会话

创建默认 10 GiB；通过 `with_options` 选择创建配额或 `None`，既有库通过带原 revision 的 `set_quota` 修改。配额口径为 SQLite 主文件逻辑字节，不是 bucket 总量。管理员降低配额前必须大于等于当前已提交页数；接口会拒绝截断。

生产接线应在恢复期限内显式准备 Session。每次操作仍读取新 HEAD；出现 `StaleSnapshot` 后丢弃会话并重新恢复当前根。发生 UNKNOWN 或 CommittedButUnavailable 保留原 Request，先查证原结果，不能为了重试生成新 ID。恢复需要足够的本地文件空间，page cache 目标不等于 RSS 配额。

热发布复用原 HEAD 的不可变依赖；禁止外部覆盖、删除可达对象或设置 bucket TTL。损坏调查需完整冷校验并保全根。当前 GC 未实现，必须监控后端实际总量与 orphan 增长；默认单库文件配额不能代替对象存储预算。
