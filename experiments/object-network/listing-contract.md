# N2-A：有界 LIST 原语合同

此合同只验收 `scap-object-store::Listings` 的单页候选发现。名称目录遍历、
当前租户权限、公开 continuation、孤儿分类及全计算丢失后的完整恢复仍属于
后续批次。这里的 `Exhausted` 仅表示本次原始 ListObjectsV2 响应明确结束，
不是跨页快照或恢复完成证明。

## 固定边界

- 使用固定 `object_store 0.14.2` 的安全 `PaginatedListStore`、`HttpConnector`
  和 `HttpService` API，无第一方 unsafe、私有 SDK 符号或手写生产 SigV4。
- 每次只发一个带 `max-keys=32` 的签名请求，不自动重试，不跟随 continuation。
  下一页使用原始 UTF-8 字节序的独占 `StartAfter`。外层传入原绝对 deadline，
  响应收集、XML 解析与结果核对全部计入该 deadline。
- 所有 exact GET、条件 PUT 和 LIST 共用显式 reqwest client：禁用 redirect、
  reqwest protocol retry、自动代理与自动解压。SDK 的 `RetryConfig=0` 单独并
  不足以禁用这些更底层行为；HTTP 请求仍由 SDK 生成和签名。
- 请求 prefix 非空、规范化且以 `/` 结尾。`Keys` 返回规范对象键；`Children`
  返回直属对象和一层 CommonPrefix。返回条目分别验证各自严格递增，再按原始
  字节序合并。常规对象键末尾的 `/`、目录 bucket、非规范路径与不支持的 XML
  结构均失败关闭；不会规范化后悄悄改变对象身份。
- SDK 原来的 LIST 解码没有保留 `IsTruncated` 等控制字段，也先无界读取 XML。
  connector 在 SDK 解码前把成功响应限制为 1 MiB；原始 XML 再限制 512 个
  element、4 层结构、单标量 16 KiB 和 continuation token 4096 字节。
- XML 必须有正确 namespace、唯一完整的 Name/Prefix/MaxKeys/KeyCount/
  IsTruncated，与请求相同的 StartAfter/Delimiter，以及一致的截断与 token。
  当前严格 profile 接收无声明或规范 XML 1.0 UTF-8 声明，拒绝 DTD、CDATA、
  注释、额外文档和未知结构。不请求 fetch-owner，因此不接收 Owner 子树。
  不依据 LIST 的大小、ETag 或 LastModified 判断数据库权威。
- `IsTruncated=true` 但无条目无法推进，返回错误。非 200 响应不收集无用正文；
  403 返回 `Denied`，缺 bucket、超时和其它状态返回 `Unknown`，均不返回空页。
- SDK 解码必须带有该次原始响应的私有 proof extension，且对象/前缀和 token
  与原始验证结果一致。普通 exact GET/条件 PUT 不经过 LIST 的正文收集路径。

`More.after` 是网络页的最后一个候选，不表示候选已经分类。上层如果在页中
耗尽 GET/时间预算，必须只保存最后已分类条目的 frontier，不能跳过未处理尾项。

这个合同假设后端实现 S3 general-purpose bucket 的有序 LIST 语义。结构校验
不能证明恶意后端没有一致地伪造 KeyCount 和条目集。在线变更也可能在已扫过的
frontier 后方插入新键；本合同实际演示该键本轮遗漏、重新从头扫描后被发现。
任何更强的同时刻全量快照承诺都需要额外持久化协议。

## 独立真实实验

`listing_worker.rs` 是 Cargo example，只装配正式 storage port；不增加默认
`scap-object-network` build 的 executable 数量。`listing_contract.py` 启动
固定 SeaweedFS 4.51 和真实工作进程，通过代理转发实际签名请求，独立校验 SigV4
并保存原始请求意图、原始后端 XML、故障响应、生产返回值及 owned wait4 收据。
凭据仅保存在测试私有临时目录中。

```sh
python3 experiments/object-network/listing_build.py \
  --target-dir /absolute/development-target \
  --evidence /absolute/listing-build
python3 experiments/object-network/listing_contract.py \
  --worker /absolute/development-target/debug/examples/scap-object-listing \
  --weed /absolute/pinned/weed \
  --build-receipt /absolute/listing-build/build.json \
  --evidence /absolute/listing-run
```

构建收据记录实际工具/二进制 hash、Cargo 原始成功事件、当前输入 hash 和
profile。默认明确是开发构建；`--release` 可单独构建 release。
收据不代替完整候选 source manifest、SQLite/native 验收或全仓门禁。

实验包含多页 flat/children 集合、Unicode 字节序、实际空 prefix、exact GET、
在线前后插入、恰好 1 MiB 响应、17 种实际 LIST HTTP 故障、真实错误签名和缺失
bucket，以及 exact GET/条件 PUT 的真实带 Location redirect。代理完整清点
每次调用对应的后端 HTTP 请求，重定向后不能再发第二次请求。
独立 Python oracle 从实际历史核对请求参数、单次尝试、raw XML、返回页、完整
扫描集合及进程退出；另对真实历史施加 5 种内存负控，并保持原始历史 hash 不变。
本地兼容端点不构成 AWS Standard 云端合同的实测证明。
