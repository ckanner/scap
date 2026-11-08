# S3 错误响应的资源上限

固定 `object_store = 0.14.2` 的 `RetryableRequest::send` 在普通非 2xx 响应路径
调用 `HttpResponseBody::text`，后者先收集全部 bytes。这个步骤发生在
`Objects::get` 的成功对象大小校验之前。因此 `get(key, max_bytes, deadline)`
的 `max_bytes` 不能单独限制错误响应文本。固定 SDK 的普通 PUT 成功路径则只读取
ETag 等响应头并丢弃 body，没有相同的聚合行为。

共享 connector 现在对非 LIST、非 2xx 响应执行 **64 KiB** 流式上限。
不会根据不可信 `Content-Length` 预分配整个响应，超限或中断只产生传输错误；
写入仍返回 `UNKNOWN`，因为请求可能已经被对象存储接受。完整且未超限的正常
404 / 412 仍分别保留 `Missing` / `Conflict`。成功 GET 继续经过原有逐对象
stream 校验；成功 PUT 继续只读响应头。LIST 的 1 MiB / 严格 XML 规则不变。

64 KiB 是错误响应的独立上限，并不等于成功对象的 `max_bytes`。上层发现预算中的
`metadata_bytes` 是逻辑元数据请求的 reservation / refund 计数；最后剩余额度
小于 64 KiB 时，也不能把它声称为包含全部错误文本和 HTTP 开销的传输字节计数。
应分别保留元数据预算、HTTP 请求数、错误体上限与绝对 deadline，并独立审计原始
网络发送量。该上限约束本层收集的字节，不承诺传输实现自身缓冲区为零。

## 真实前后对照

`response_contract.py` 使用固定 LIST example 中的正式 `Objects` 实现，真实签名
请求经过代理到拥有的 SeaweedFS 4.51 进程。每个案例独立启动 worker 并保存
`wait4` / kernel RSS 收据，避免用当前线程内存或进程名代替实际子进程证据。

- GET 的成功体上限只有 1024 bytes，分别注入 64 KiB、4 MiB 和持续 chunked 错误体。
  旧版本完整收集大错误体；修复版在独立错误上限处结束。
- 后端已接受一次条件 PUT 后，代理将其响应换成 500 + 大错误体。客户端只能返回
  `UNKNOWN`，不能报告确定未写入的本地 `LIMIT` 或 `Conflict`；后续一个 exact GET
  必须取回原值与原 ETag，且没有第二次 PUT。
- 真实后端 412 加正常大小错误体保持条件冲突；超大错误体安全地降为 `UNKNOWN`。
- 成功 GET 过大仍受原 `max_bytes` 约束；成功 PUT 大 body 仍被丢弃，验证修复范围。

连续错误流的夹具本身有 16 MiB / socket deadline 上限，不需要耗尽机器内存来
证明原聚合路径。原始 RSS 值保留，但不从少量样本或父进程基线推导线性内存增长。
`response_oracle.py` 独立读取原始 HTTP、发送量、条件与原始结果；五个内存历史
负控验证无界消费、错误写入分类、错误回读和缺失 wait4 都不能通过。

```sh
python experiments/object-network/listing_build.py \
  --target-dir /absolute/development-target \
  --evidence /absolute/new-build-evidence

python experiments/object-network/response_contract.py \
  --worker /absolute/development-target/debug/examples/scap-object-listing \
  --weed /absolute/pinned/weed \
  --bounded --build-receipt /absolute/new-build-evidence/build.json \
  --evidence /absolute/new-response-evidence

python experiments/object-network/response_oracle.py \
  /absolute/new-response-evidence --bounded --controls
```

旧版本只允许通过显式 `--original-preservation` 输入已保存的 A927 二进制身份，
产生 `original_gap_reproduced`，不会冒充修复通过。上述均为 storage-port 开发合同，
不替代全部 native / 网络 / service 门禁，AWS Standard 仍为 `NOT_RUN`。
