# N3 物理回收的 S3 删除接口

状态：独立开发候选。核心 pin/drain、持久清扫计划及产品 GC 尚未接入，普通 SQL
服务不会因为本模块存在就开始删除对象。本文件也不是 AWS、物理空间收敛或长跑验收。

## 能力边界

`scap-object-store::GcS3` 必须使用单独的配置和 GC 存储凭据显式构造，绑定一个
非零 deployment。`S3`/`Objects` 没有 DELETE 方法，也没有自动升级转换。部署中
应在 IAM/bucket policy 中分别限制普通 writer 和 GC 角色；Rust 类型不能证明
操作者没有给两个配置填写同一组高权限凭据。

`begin_batch(prefix, deadline)` 只接受当前精确物理 payload 前缀：

```text
scap-object/v1/{deployment}/{tenant}/{database}/inc/{incarnation}/gen/{generation}/storage/{storage_generation}/objects/
```

全部六个数字是非零、无前导零的 `u64`，deployment 必须等于配置。返回的 batch
固定前缀与原始绝对 deadline，不可 Clone，每批最多 32 次 DELETE。其 `delete`
只接受 64 位小写内容 hash 与原始带引号 ETag，不能接受任意 key、通配 ETag、
versionId、治理绕过参数、HEAD 或 Catalogue 路径。调用者必须先 exact GET 候选
取得 ETag；LIST 只提供候选，不证明退休或当前权威。

**该接口只提供有界传输能力。** 它不理解 HEAD 中哪个 generation 当前有效，
不能代替核心对永久退休、当前/staging 排除、pin 为空以及持久计划的证明。
只有这些证明和完整真实暂停合同完成后，生产控制器才可以获得这项能力。

## 后端预检

每个 batch 开始时使用同一 endpoint、bucket 和凭据顺序读取：

1. `GET ?versioning`：仅接受 HTTP 200、严格 XML、正确 namespace、空的
   `VersioningConfiguration`。`Enabled`、`Suspended`、MFADelete 字段、未来状态、
   缺少权限、缺 bucket、畸形或超限响应均不产生 batch。
2. `GET ?object-lock`：仅 HTTP 404 且严格 Error 中的 Code 精确等于
   `ObjectLockConfigurationNotFoundError` 表示没有 Object Lock 配置。普通 404、
   `NoSuchBucket`、403、200 或不明响应均拒绝。

AWS 明确区分从未启用 versioning 的空配置与 `Suspended`；后者仍可能保留旧版本。
版本化 bucket 的默认 DELETE 可创建 delete marker，不能计作历史版本已物理释放。
来源：[GetBucketVersioning](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketVersioning.html)、
[DeleteObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html)、
[Object Lock 错误示例](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/s3_example_s3_GetObjectLockConfiguration_section.html)。

这两次 GET 不是配置锁。部署必须维持已验收的 bucket 配置，并阻止运行期间
绕过控制流程更改 versioning/Object Lock。管理员在检查之后改变配置的竞态，
不能由客户端预检消除。删除响应一旦含 `x-amz-version-id` 或
`x-amz-delete-marker`，本次结果为 UNKNOWN，立即停止该 batch；不能把它解释
成明确未删除，或宣称旧版本已全部消失。重新开始 batch 只重新检查配置，不解决
原 UNKNOWN 操作，也不证明该后端已经通过条件删除的语义合同。

## 删除及错误语义

每次调用只发一个已签名 `DELETE`，`If-Match` 必须保持候选原 ETag。SDK 使用
已固定版本的 `AwsAuthorizer` 签名；直接 HTTP client 关闭自动重试、redirect、
环境代理及透明解压。每个响应最多收集 32 KiB，CPU 解析也计入原 deadline。
这只是应用收集上界，不能表述为内核和网络缓冲区恰好只读 32 KiB。

| 结果 | 精确条件与含义 |
| --- | --- |
| Applied | HTTP 204、空 body、Content-Length 缺省或零，且无版本/delete-marker 响应字段；后端确认该次条件删除 |
| Missing | HTTP 404 且完整 Error 的 Code 为 `NoSuchKey`；不能从一般 404 推断 |
| Conflict | HTTP 412 条件不满足；不刷新原候选 ETag |
| Denied | 完整 HTTP 403；停止当前 batch |
| Unknown | deadline、传输/截断/超限、409、其它状态、异常版本头或不明响应；DELETE 可能已在后端执行 |

进入执行后的任何 error 都关闭当前 batch；Applied/Missing/Conflict 消耗一个
删除额度。无效本地 hash/ETag 或错误异步上下文不发请求、不消耗额度，batch
仍可接受后续合法调用。UNKNOWN 后核心必须按原持久计划查证，不能把新建 batch
当作已解决，也不能把缺少 ACK 当成 delete 未落地。
AWS 对条件删除的 204、412、并发 409/404 描述见
[conditional deletes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-deletes.html)。

Applied 不证明永远为空：已经接收但迟到的旧 CreateOnly PUT 仍可重建退休 key。
核心需要公平重复 sweep；永久完成和成本收敛仍受有限旧操作、最终完成、存储可用
与公平调度等前提约束。具体协议见[持续存储方案](storage-reclamation-plan.md)。

## 本批验证要求

单元覆盖配置、跨 deployment/metadata 路径拒绝、完整 XML/错误状态、条件签名、
批次额度、原 deadline、响应丢失、不重试和 version/delete-marker 防护。真实
兼容 S3 合同需使用生产 adapter 和固定实际 executable，验证错误 ETag 不删除、
正确 ETag 删除、重复删除、版本状态变化拒绝，以及代理在后端已应用 DELETE 后
丢失响应仍为 UNKNOWN。保留所有原调用及失败，不把单元 TCP fixture 当真实 S3。

产品清扫、完整 pin/HEAD 竞争、真实 AWS、版本化删除、Object Lock 保留绕过、
迟到 PUT/DELETE、多轮总物理成本收敛与 PITR 都不由本接口独立证明。
