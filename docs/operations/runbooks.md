# 当前运行边界

当前提供内部Rust单库API与独立验证入口，未发布对外HTTP服务或新Node SDK。不要使用旧版本的三节点配置和SDK连接新协议；当前工作区没有旧权威或迁移工具。

装配S3时显式提供endpoint、region、bucket、access key、secret和可选session token。只在本地测试显式允许HTTP；正式端点要求TLS。凭据不写入仓库、日志或回执。

用固定scope显式create，得到Recovering HEAD；activate恢复[当前数据与保留结果闭包](../engineering/object-runtime.md#recovery-closure)后开放写。计算丢失后，从新worker发起带原expected revision的takeover，再activate。缺HEAD不能当成新库；UNKNOWN先用原epoch/id/principal/fingerprint查证。

控制操作重试保留原expected revision；已被后续转换越过但缺精确证明时不能虚报成功。不要把旧CAS换新ETag重发。结果已退休则按业务键对账，不能由SDK自动重做。

实际可复现测试与输出见[验证规范](../engineering/validation.md)。没有配置真实AWS时只运行本地兼容后端验证并保留NOT_RUN记录，不创建未知云资源。
