# 自动控制器与 HEAD9 的真实组合回归

此合同只覆盖一个固定的故障历史，不替代 owner、snapshot、资源或 AWS 专项。
实际组件为生产 controller CLI / Fleet / HTTP、Node SDK、三个独立 scapd、原生
SQLite 和 SeaweedFS 4.51。S3 代理只观察并逐请求验签；HTTP 代理只在两个指定
成功响应后关闭连接。不得用 mock 状态、模型输出或手工 owner RPC 替代接管。

## 固定历史

1. 单一 Scope `(1,7,8601,1,1)`；A=9601 为初始 owner，B=9602 为唯一更高 rank
   目标，C=9603 只提供独立 fresh metadata。业务 principal 11；专用 controller
   principal 12 仅 READ+ADMIN。所有进程、端口、私有目录和临时凭据由夹具创建。
2. 在发送前持久保存三笔不同请求。前两笔通过真实 HTTP 执行，保存原 ACK 和原
   result bytes；每次更新递增 counter、randomblob(64)、random()。事务二之后捕获
   一个 S1 snapshot，保存其原引用、point 和输入。
3. 事务三在真实 scapd 已成功返回后丢弃 HTTP ACK。SDK 必须只发送一次 execute
   并返回 UNKNOWN。原服务响应另由代理保存，不能伪称它是客户端 ACK。
4. 启动生产 controller CLI，必须先观察 healthy 且没有 mutation。SIGKILL A、
   owned wait4 后删除 A 的整个缓存。固定 policy、5s tick、3 次失败、5s span、
   每 tick 至多一次 owner mutation、8 个 HTTP 请求等生产限制保持不变。
5. 控制器自动 prepare、claim。B 的首次 owner_claim 成功响应被丢弃，controller
   报告 UNKNOWN 后正常停止并等待全部 owned HTTP 关闭。用同一配置、全新 CLI
   进程重新启动；不得手工推进 owner。新 controller 应发现原 Claimed descriptor，
   在新的 recovery tick 自动 resume，最终观察 B active。
6. 停止 controller 后，从 B 只 lookup 三个原请求，逐字节比较两笔原 ACK 和第三笔
   原服务响应；查询 counter 必须恰为 3，BLOB/nonce 与事务三原响应完全相等。
   snapshot inspect 必须仍 retained 且原 reference/point 不变。对 B 携带旧 A guard
   的 status 必须得到 TARGET_MISMATCH，并且该调用期间不产生 S3 I/O。
7. 关停全部进程/代理，保存 owned wait4、逐请求 HTTP/S3 原始记录、源码清单和
   release receipt。源码前后相同，原始失败与通过结果存到不同目录。

## 固定验收边界

- 三笔 execute、两笔客户端 ACK、一个业务 UNKNOWN、一个 claim UNKNOWN、两个
  controller 进程、三个服务进程、一笔 snapshot capture、三个冷 lookup。
- controller principal 的 HTTP 操作只能是 status、owner_inspect、owner_prepare、
  owner_claim、owner_resume、owner_abort；本历史实际 mutation 恰为 prepare/claim/resume
  各一次。不得执行业务 SQL。UNKNOWN 后不得重复原 execute 或原 claim。
- 后继 owner 的原始 S3 GET 必须发生在 A owned exit/cache removal 后，并在 resume
  成功前读取持久数据对象；必须有强条件 HEAD PUT，所有原始请求有闭合响应/交付记录。
- 总运行时限 180 秒；两个控制器阶段各 75 秒。它们是该本地组合回归的观察上限，
  不是生产 SLO。CLI 报告的每 tick 请求/变更预算必须满足固定生产 policy。
- 独立 oracle 不导入 controller/SDK/产品验证器；只读原进程和 HTTP/S3 原始证据。
  controls 在内存副本中改动证据，分别破坏签名、ACK、UNKNOWN、SQL 禁止、guard、
  缓存丢失、controller 重启和 tick 预算；必须命中指定检查。

AWS Standard/Express、跨 AZ、负载吞吐、故障检测误判、多个 controller 竞争、动态
fleet、公平性和所有 snapshot/GC 交错均不是本合同的通过含义。
