# 有界目录 HTTP 与 Node SDK

状态：N2-C 实现候选。最终集成的原生、HTTP、签名 S3 及部署恢复门禁通过前，不把本文件视为发布验收。完整发现合同见 [目录发现方案](../architecture/catalogue-discovery-plan.md)，底层 LIST 合同见 [实际 LIST 夹具](../../experiments/object-network/listing-contract.md)。

## 两类只读操作

`POST /v1/discovery` 使用现有 Bearer 认证，要求单个 `Content-Type: application/json` 和 `X-Scap-Admission: discovery`。请求严格包含三个字段：

```json
{"version":1,"operation":"list_names","cursor":null}
```

`cursor: null` 从范围起点开始；后续页传回上一页的原始不透明 cursor。请求不能指定 deployment、tenant、principal、物理 prefix、页大小或预算。这些来自当前认证与固定协议配置。

| operation | 权限来源 | 返回内容 |
| --- | --- | --- |
| `list_names` | 当前凭据的 deployment/tenant/principal；逐个新读到的数据库 HEAD 上检查 READ | 当前页验证通过的 Ready 名称、完整 Creation、binding/head revision |
| `deployment_inventory` | 当前凭据显式 `deployment_inventory: true` | 该 deployment 的全部 tenant、五类永久元数据、永久 HEAD 与孤儿前缀分类 |

数据库 ADMIN、建库 provision 和 deployment inventory 是独立能力。目录清点不能代理原创建者、授予 SQL 权限或自动执行创建、取消、删除、接管。Control 记录返回已经验证过的原始 kind、principal、operation、nonce 和两个 revision 条件，供持有相应当前权限的调用者保留原意图；清点结果本身不构成执行授权。

服务配置缺少 `discovery` 时，该入口返回 UNAVAILABLE。启用配置为：

```json
"discovery": {"cursor_key_env":"SCAP_DISCOVERY_CURSOR_KEY"}
```

指定环境变量必须提供 32 字节小写十六进制密钥。凭据条目的 `deployment_inventory` 默认 false；只有受信部署配置能设置 true。配置示例中的环境变量名不包含密钥本身。

## 页面、部分结果与完成含义

名称页的 `value` 包含 `names`、`cursor`、`traversal_exhausted`、`stopped`。普通用户不会收到物理键、扫描前沿、被权限过滤的数量或内部 usage；页内每个名称均经过本次 READ 验证。后续访问仍需要重新读取权威与检查权限。

清点页包含 `records`、`cursor`、`completion`、`usage`、`stopped`。所有 u64 身份、revision、nonce 和累计 metadata_classified 都使用规范十进制字符串，避免 JavaScript 精度损失。清点中的 Control 投影仅在 `kind: control` 上存在，其他记录为 `control: null`。

`stopped: LIMIT` 表示本页预算耗尽，调用者可以显式提交返回的 cursor；前沿只包含已经完成分类的候选。UNKNOWN、DENIED、CORRUPT、CONFLICT 等原因也可能附带已经验证的部分记录，必须保留其未完成状态，不能换成完整空集。HTTP 层、游标或请求自身失败使用既有 `{ok:false,error:...}` 格式。只有有效终页才返回 `cursor: null` 与 traversal_exhausted=true。

清点的 `preexisting_slots_covered` 仅在全遍历结束时成立，依赖永久权威键不删除、受支持的有序 LIST 合同与不跳过候选。它覆盖开始前已经存在的槽，可包含并发新建的项；它不代表跨 key 的同一时刻快照。接口只做元数据分类，始终返回 `data_recovery: not_run`、`recovery_complete: false`。完整 data/result/native 恢复作业另行验收。

## 固定资源合同

| 资源 | v1 上限 |
| --- | --- |
| 活动扫描 | 全局 2，每个 deployment/tenant 1；立即 BACKPRESSURE，无等待队列 |
| 请求体 / 返回体 | 64 KiB / 1 MiB |
| 单次绝对 deadline | 从收到请求起 5 秒；包括 body、解析、LIST、嵌套 GET、编码和加密 |
| LIST 页 / 页大小 | 每次最多 4 页，每页 32 个候选 |
| 候选 / exact GET | 128 / 512；所有嵌套目录读取共享预算 |
| LIST 单页 / 总字节 | 1 MiB / 4 MiB |
| 元数据 GET 消费预算 | 16 MiB |
| 非 LIST 的 HTTP 错误响应体 | 应用收集最多 64 KiB；超限返回 UNKNOWN |
| 游标明文 / 编码后输入 | 8 KiB / 16 KiB |

这些是资源上限，不能据此推断一定返回多少条记录或在云端达到多少吞吐。重复、过滤、失败和控制记录验证都消耗实际读取预算。每次读操作最多一次物理 HTTP 尝试；需要继续或重读时由调用者显式决定。

`usage` 是本页的保守预算消费。LIST 在发起前预留单页 1 MiB，GET 预留该类对象上限与剩余预算的较小值；成功后退回实际对象字节以外的预留，失败则保留全部预留。因此正常的不存在证明、损坏或超限响应也会消耗预算，不能靠失败反复获得免费读取。`list_bytes` 与 `metadata_bytes` 不等于抓包中的成功响应体总和，也不涵盖全部 HTTP 错误文本、头部或传输开销；实际传输量应独立记录。

HTTP 错误体上限由共享传输 guard 在 SDK 整体收集前执行，独立于成功 GET 的对象大小上限和上述元数据预算。它限制应用收集量，网络缓冲可能已经接收额外字节。即使条件 PUT 的响应体超限，也不能推断写入未发生；调用者仍需用原始请求身份处理 UNKNOWN。实际前后对照见 [错误响应合同](../../experiments/object-network/response-contract.md)。

目录有独立准入，不占数据库 data/control/recovery 保留槽。执行使用有界普通 OS 线程，避开同步 S3 适配器禁止的 Tokio runtime 上下文。最多保留两个尚未退出的 worker 句柄，关闭时 join。工作、返回体与已发出的非空 bytes clone/slice 共同持有同一 reservation；超时或客户端断开不能提前释放尚在执行的读取容量。

这一合同限制单次工作与并发，不构成总账单、长期请求速率、整个进程 RSS 或跨服务集群资源上限。

## 游标与服务重启

每次启动用系统随机盐从配置密钥派生独立 AEAD 密钥。nonce 在此密钥下严格单调；计数耗尽拒绝发行。ChaCha20-Poly1305 保护完整 checkpoint，绑定存储 endpoint/region/bucket、固定协议/预算版本、worker、deployment、tenant、principal 和视图。游标在该进程的单调时钟上最多有效十分钟。

每页重新认证。游标不保留已撤销的 READ 或 deployment inventory 能力。篡改、过期、跨主体、跨视图、不同配置、另一个 daemon 或服务重启后的旧 cursor 返回 CURSOR_INVALID，SDK 不自动从头开始。多实例访问需要将续页交给发行游标的实例；本版没有跨实例游标路由。重新开始可能重复观察已读记录，调用者应按完整身份处理，不把名称当永久身份。

## Node 使用方式

```js
import { DiscoveryClient } from '@scap/node';

const directory = new DiscoveryClient({
  endpoint: 'https://service.example/v1/discovery',
  token: credential,
  deployment: '1', tenant: '2', principal: '7',
});

let cursor = null;
do {
  const page = await directory.listNames(cursor);
  consumeVerifiedNames(page.names);
  if (page.stopped !== null && page.stopped !== 'LIMIT') {
    handleIncompleteScan(page);
    break;
  }
  cursor = page.cursor;
} while (cursor !== null);
```

循环属于调用者。每个 SDK 方法只发一个 POST，不自动重试、吞掉页错误、改变原 cursor 或重启扫描。部署操作者使用 `deploymentInventory(cursor)`，并检查 metadata 与 data recovery 的不同状态。SDK 严格限制读取体积、校验页面字段和精确整数；不能仅凭 HTTP 200 推断恢复完整。
