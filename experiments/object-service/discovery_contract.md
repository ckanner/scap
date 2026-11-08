# 发现 HTTP / Node SDK 真实合同

这是 N2-C 的独立实验装配。服务、目录逻辑、签名 S3 客户端、游标加密和
Node SDK 均从同一冻结源码构建或导入，实验不提供替代目录实现。

本文件加入时只有 Python 语法编译及 Node `--check` 开发检查完成。
**真实运行为 NOT_RUN，不能把本夹具存在视为全目录功能验收通过。**
正式运行必须保存独立 release build receipt、原始 HTTP/S3 字节和拥有的子进程
`wait4` 收据。AWS Standard 云端合同、生产 SLO 与整个数据闭包恢复不由本实验证明。

## 覆盖合同

- 129 个同租户 Ready 名称超过固定 4 × 32 LIST 页预算，保证真实续页，不依赖
  每个候选的内部 GET 数量；首尾名称只授予
  reader READ。首个部分页之后撤回末尾名称的 READ，保留 ADMIN，使用原游标
  继续扫描，检查新 exact GET 权限与原始 Name → Proof → HEAD → Name 顺序。
- 另一个租户、另一个部署、只含 descriptor 的创建与不可变 control 记录构成
  独立候选集合。operator 能完成所属部署的元数据遍历，但该能力不给 SQL READ，
  provision 也不给 inventory 权限。库存记录的 control 投影必须来自实际 GET。
- 六个有明确原始后端响应的故障：LIST 403、404、缺少 `IsTruncated`、截断零进展，
  以及已分类一个条目之后的 exact HEAD 404 / 损坏。错误必须保留不完整游标与
  停止原因；恢复必须使用它并从最后已分类条目继续，不能跳到网络页末。
- 所有 exact GET 持续增加 30 ms 延迟，LIST 不延迟。逐次明确提交上页游标，
  至少两个达到扫描期限的部分页必须带 `UNKNOWN` 与有效游标，在原始 5 秒 HTTP
  期限内交付，最终完成同一名称集合。独立审计核对每次实际延迟、递增的原始
  LIST lower bound，以及它跨过的每个名称在上页的 Name → Proof → HEAD → Name
  与 descriptor 来源证明；不能只凭加密游标文本改变推断有进展。
- 游标篡改、principal / tenant / deployment / view / daemon 交叉使用必须拒绝；
  同时保留有效游标正控。重启前重新取得未过期游标，销毁全部计算和缓存，再验证
  新进程拒绝旧游标；显式新扫描能找回相同永久元数据，并通过原始结果 lookup 与
  SQLite 查询验证一个实际数据库。
- 第一个 LIST 持有期间，客户端真实超时；同租户被拒绝，第三租户能利用剩余
  全局槽位得到有真实空 LIST 证明的完整空页。第二个 LIST 持有期间，客户端主动
  abort；两个任务仍占用 global=2 / tenant=1 的运行名额。持有前先明确查询预热，
  持有期间的 query 必须恰好读取一个新 HEAD、下载零个数据对象；query、lookup、
  cancel 都必须在释放 LIST 之前完成。客户端断开本身不能释放正在运行的名额。

这里的 403 / 404 错误页是代理在收到真实签名后端响应后，明确记录的故障注入。
它们检验服务如何处理 S3 HTTP 结果，不能替代 AWS IAM 或云端 S3 的验收。
所有原始后端页都另与此前条件 PUT 成功的完整候选集核对。在线分页仍不是快照；
本场景没有用 LIST 来代替名称、HEAD、权限或控制意图的 exact GET 权威。

`usage.metadata_bytes` 按正式 B 层的逐次 reservation / refund 合同审计：canonical
目录记录预留最多 64 KiB，HEAD 最多 256 KiB，均再受本页剩余额度限制；成功返回
完整对象才退还未使用额度，404 等失败保留整个预留值。它不是实际 HTTP 错误文本
与协议开销的字节和。共享 connector 对错误体另有 64 KiB 上限，最后元数据剩余
额度更小时，这两个数值仍不得混为一谈。原始后端和交付响应体字节独立记录、求和；
审计器既不放宽元数据预算，也不把保守预留误认为实际下载量。

## 运行

从包含最终 DiscoveryClient 与控制记录投影的冻结 checkout 执行；不要从旧 SDK
目录混合导入。构建器的输入清单覆盖这些夹具文件，因此构建开始后不得再编辑。

```sh
python experiments/object-service/build.py \
  --target-dir /absolute/new-release-target \
  --evidence /absolute/new-build-evidence

python experiments/object-service/discovery_contract.py \
  --server /absolute/new-release-target/release/scapd \
  --weed /absolute/pinned/weed \
  --node /absolute/node-v22.16.0/bin/node \
  --build-record /absolute/new-build-evidence/build.json \
  --evidence /absolute/new-discovery-evidence

python experiments/object-service/discovery_oracle.py /absolute/new-discovery-evidence
python experiments/object-service/discovery_oracle.py /absolute/new-discovery-evidence --controls
```

开发运行可显式传入 `--diagnostic`，只会产生 `diagnostic_passed`，不会生成 release
验收结论。`--keep-private` 仅用于本地失败诊断；默认清理临时凭据和私有数据库目录。
证据目录不可重用，原始失败记录不得覆盖。

独立审计器不导入 controller、SDK 或生产发现代码。它解析原始 HTTP、JSON、XML、
条件 PUT / GET 的版本链和原生结果格式。实际历史负控在内存深拷贝中篡改完整空集、
游标结果、已完成库存的遗漏项、释放时序、wait4、原始结果回读、CAS 条件和缓存损失；
每次必须拒绝，原始证据文件的哈希前后不变。
新增实际历史负控还会丢弃延迟部分页的游标、把续页输入改回 `null`，以及把实际
预热阶段的数据 GET 移入持有期间的查询窗口，分别验证进展和驻留查询的断言。
